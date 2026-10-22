<#
.SYNOPSIS
    Azure Automation Runbook to discover expiring credentials and certificates across
    Entra ID App Registrations, Azure Key Vault Secrets, App Service Certificates,
    and Application Gateway SSL Certificates, and alert respective workload owners.

.NOTES
    Version : 2.0
    Changes :
        - IncludeAlreadyExpired changed to "Yes" (alerts for both pre-expiry and post-expiry)
        - Added: Key Vault Secret expiry monitoring  (Get-ExpiringKeyVaultSecrets)
        - Added: Application Gateway SSL cert monitoring (Get-ExpiringAppGatewayCerts)
        - Existing: Entra App Registration secret/certificate monitoring (unchanged)
        - Existing: Azure App Service certificate monitoring (unchanged)
        - All four sources merged into one consolidated alert email per owner
#>

[CmdletBinding()]
param ()

Write-Host "[INFO] $(Get-Date -Format o) - Runbook started. Preparing to evaluate credentials and certificates across Azure."

# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process
Write-Host "[INFO] $(Get-Date -Format o) - Azure context autosave disabled for this process."

# Connect to Azure with system-assigned managed identity
Connect-AzAccount -Identity
Write-Host "[INFO] $(Get-Date -Format o) - Connected via Managed Identity."

# =====================================================================
# FUNCTION: Get Access Token (for Graph API sendMail)
# =====================================================================
function Get-AccessToken {
    param (
        [string]$appID,
        [string]$appSecret,
        [string]$tenantID
    )
    try {
        $tokenEndpoint = "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token"
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $appID
            client_secret = $appSecret
            scope         = "https://graph.microsoft.com/.default"
        }
        Write-Host "[INFO] $(Get-Date -Format o) - Requesting access token from Azure AD."
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body
        Write-Host "[INFO] $(Get-Date -Format o) - Access token acquired successfully. Length: $($response.access_token.Length)."
        return $response.access_token
    }
    catch {
        Write-Host "[ERROR] $(Get-Date -Format o) - Failed to get access token (function Get-AccessToken): $($_.Exception.Response) - $($_.Exception.Message)"
        return $null
    }
}

# =====================================================================
# FUNCTION: Send Email via Microsoft Graph API (with CC and BCC support)
# =====================================================================
function Send-Email {
    param (
        [string]$accessToken,
        [array]$recipientEmail,
        [array]$ccRecipients,
        [array]$bccRecipients,
        [string]$subject,
        [string]$body,
        [string]$fromEmail
    )
    try {
        Write-Host "[INFO] $(Get-Date -Format o) - Sending email from '$fromEmail' to $($recipientEmail.Count) recipient(s), CC: $($ccRecipients.Count), BCC: $($bccRecipients.Count)."
        $graphApiEndpoint = "https://graph.microsoft.com/v1.0/users/$($fromEmail)/sendMail"
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type"  = "application/json"
        }

        # Build email data structure
        $emailData = @{
            message = @{
                subject      = $subject
                body         = @{
                    contentType = "HTML"
                    content     = $body
                }
                toRecipients = @($recipientEmail)
            }
        }

        # Add CC recipients if provided
        if ($ccRecipients -and $ccRecipients.Count -gt 0) {
            $emailData.message["ccRecipients"] = @($ccRecipients)
        }

        # Add BCC recipients if provided
        if ($bccRecipients -and $bccRecipients.Count -gt 0) {
            $emailData.message["bccRecipients"] = @($bccRecipients)
        }

        $emailJson = $emailData | ConvertTo-Json -Depth 100
        Invoke-RestMethod -Uri $graphApiEndpoint -Method Post -Headers $headers -Body $emailJson -ContentType "application/json"
        Write-Host "[INFO] $(Get-Date -Format o) - Email request submitted successfully."
    }
    catch {
        Write-Host "[ERROR] $(Get-Date -Format o) - Failed to send an email (function Send-Email): $($_.Exception.Message)"
    }
}

# =====================================================================
# FUNCTION: Get List of All Expiring App Registrations (Entra ID)
# =====================================================================
function Get-ExpiringAppRegistrations {
    param (
        [int]$DaysUntilExpiration,
        [string]$IncludeAlreadyExpired,
        [array]$GTAdminUsers
    )
    try {
        Write-Host "[INFO] $(Get-Date -Format o) - Starting discovery for app registrations expiring within $DaysUntilExpiration day(s). Include already expired: $IncludeAlreadyExpired."
        Write-Host "[INFO] $(Get-Date -Format o) - Authorized admin users count: $($GTAdminUsers.Count)"

        $allAppRegistrations = Get-MgApplication -All
        Write-Host "[INFO] $(Get-Date -Format o) - Retrieved $($allAppRegistrations.Count) app registration(s) from Microsoft Graph."
        $Logs = @()
        $counter = 0
        $totalApps = $allAppRegistrations.Count

        foreach ($App in $allAppRegistrations) {
            $counter++
            $AppName = $App.DisplayName
            Write-Host "[DEBUG] $(Get-Date -Format o) - Processing application $counter of $totalApps : '$AppName'."

            $AppID = $App.Id
            $ApplID = $App.AppId

            $AppCreds = Get-MgApplication -ApplicationId $AppID | Select-Object PasswordCredentials, KeyCredentials
            $Secrets = $AppCreds.PasswordCredentials
            $Certs = $AppCreds.KeyCredentials
            Write-Host "[DEBUG] $(Get-Date -Format o) - Application '$AppName' has $($Secrets.Count) secret(s) and $($Certs.Count) certificate(s)."

            if (($Secrets -and $Secrets.Count -gt 0) -or ($Certs -and $Certs.Count -gt 0)) {
                # Get app owners once per application with credentials
                $Owner = Get-MgApplicationOwner -ApplicationId $App.Id
                $Username = $Owner.AdditionalProperties.userPrincipalName -join ','
                $OwnerID = $Owner.Id -join ','
                $OwnerDisplayName = $Owner.AdditionalProperties.displayName -join ','

                # Handle missing owner information
                if ($null -eq $Owner.AdditionalProperties.userPrincipalName) {
                    $Username = @($Owner.AdditionalProperties.displayName, '**<This is an Application>**') -join ' '
                }
                if ($null -eq $Owner.AdditionalProperties.displayName) {
                    $Username = '<<No Owner>>'
                }

                # --- PROCESS SECRETS ---
                foreach ($Secret in $Secrets) {
                    $StartDate = $Secret.StartDateTime
                    $EndDate = $Secret.EndDateTime
                    $SecretName = $Secret.DisplayName

                    $RemainingDaysCount = ($EndDate - (Get-Date)).Days
                    Write-Host "[DEBUG] $(Get-Date -Format o) - Secret '$SecretName' for '$AppName' expires on $EndDate and has $RemainingDaysCount day(s) remaining."

                    # Determine if this secret should be included
                    $include = $false
                    if ($IncludeAlreadyExpired -eq 'No') {
                        if ($RemainingDaysCount -le $DaysUntilExpiration -and $RemainingDaysCount -ge 0) {
                            $include = $true
                        }
                    }
                    elseif ($IncludeAlreadyExpired -eq 'Yes') {
                        if ($RemainingDaysCount -le $DaysUntilExpiration) {
                            $include = $true
                        }
                    }

                    if ($include) {
                        $Logs += [PSCustomObject]@{
                            'WorkloadSource'         = 'Entra App Registration'
                            'ApplicationName'        = $AppName
                            'ApplicationID'          = $ApplID
                            'Secret Name'            = $SecretName
                            'Secret Start Date'      = $StartDate.ToString('MM/dd/yyyy')
                            'Secret End Date'        = $EndDate.ToString('MM/dd/yyyy')
                            'Certificate Name'       = "N/A"
                            'Certificate Start Date' = "N/A"
                            'Certificate End Date'   = "N/A"
                            'Owner'                  = $Username
                            'OwnerDisplayName'       = $OwnerDisplayName
                            'Owner_ObjectID'         = $OwnerID
                            'RemainingDaysCount'     = $RemainingDaysCount
                            'CredentialType'         = 'Secret'
                            'EndDateTime'            = $EndDate
                        }
                    }
                }

                # --- PROCESS CERTIFICATES ---
                foreach ($Cert in $Certs) {
                    $StartDate = $Cert.StartDateTime
                    $EndDate = $Cert.EndDateTime
                    $CertName = $Cert.DisplayName

                    $RemainingDaysCount = ($EndDate - (Get-Date)).Days
                    Write-Host "[DEBUG] $(Get-Date -Format o) - Certificate '$CertName' for '$AppName' expires on $EndDate and has $RemainingDaysCount day(s) remaining."

                    # Determine if this certificate should be included
                    $include = $false
                    if ($IncludeAlreadyExpired -eq 'No') {
                        if ($RemainingDaysCount -le $DaysUntilExpiration -and $RemainingDaysCount -ge 0) {
                            $include = $true
                        }
                    }
                    elseif ($IncludeAlreadyExpired -eq 'Yes') {
                        if ($RemainingDaysCount -le $DaysUntilExpiration) {
                            $include = $true
                        }
                    }

                    if ($include) {
                        $Logs += [PSCustomObject]@{
                            'WorkloadSource'         = 'Entra App Registration'
                            'ApplicationName'        = $AppName
                            'ApplicationID'          = $ApplID
                            'Secret Name'            = "N/A"
                            'Secret Start Date'      = "N/A"
                            'Secret End Date'        = "N/A"
                            'Certificate Name'       = $CertName
                            'Certificate Start Date' = $StartDate.ToString('MM/dd/yyyy')
                            'Certificate End Date'   = $EndDate.ToString('MM/dd/yyyy')
                            'Owner'                  = $Username
                            'OwnerDisplayName'       = $OwnerDisplayName
                            'Owner_ObjectID'         = $OwnerID
                            'RemainingDaysCount'     = $RemainingDaysCount
                            'CredentialType'         = 'Certificate'
                            'EndDateTime'            = $EndDate
                        }
                    }
                }
            }
        }

        Write-Host "[INFO] $(Get-Date -Format o) - Discovery completed. Found $($Logs.Count) matching secret/certificate record(s)."
        return $Logs
    }
    catch {
        Write-Host "[ERROR] $(Get-Date -Format o) - Failed to fetch expiring app registration details (function Get-ExpiringAppRegistrations): $($_.Exception.Message)"
        return $null
    }
}

# =====================================================================
# FUNCTION: Get List of All Expiring Enterprise Application SAML Certs (NEW)
# =====================================================================
function Get-ExpiringEnterpriseAppCerts {
    param (
        [int]$DaysUntilExpiration,
        [string]$IncludeAlreadyExpired,
        [string]$DefaultOwnerEmail
    )
    $EnterpriseLogs = @()
    try {
        Write-Host "[INFO] $(Get-Date -Format o) - Starting discovery for Enterprise Application SAML/SSO certificates."
        $allSPs = Get-MgServicePrincipal -All -Property "id", "appId", "displayName", "keyCredentials", "servicePrincipalType"
        Write-Host "[INFO] $(Get-Date -Format o) - Retrieved $($allSPs.Count) service principal(s) from Microsoft Graph."

        $spsWithCerts = $allSPs | Where-Object { 
            $null -ne $_.KeyCredentials -and $_.KeyCredentials.Count -gt 0 -and
            $_.ServicePrincipalType -ne "ManagedIdentity"
        }
        Write-Host "[INFO] $(Get-Date -Format o) - Found $($spsWithCerts.Count) Enterprise Application(s) with uploaded certificates."

        foreach ($sp in $spsWithCerts) {
            $spName = $sp.DisplayName
            $spAppId = $sp.AppId
            $spId = $sp.Id

            $ownerEmail = $DefaultOwnerEmail
            $ownerDisplayName = $DefaultOwnerEmail
            try {
                $spOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $spId -ErrorAction SilentlyContinue
                if ($spOwners -and $spOwners.Count -gt 0) {
                    $emails = @()
                    $names = @()
                    foreach ($o in $spOwners) {
                        $upn = $o.AdditionalProperties.userPrincipalName
                        $mail = $o.AdditionalProperties.mail
                        $dName = $o.AdditionalProperties.displayName
                        $pEmail = if (-not [string]::IsNullOrWhiteSpace($mail)) { $mail } elseif (-not [string]::IsNullOrWhiteSpace($upn)) { $upn } else { $null }
                        if ($pEmail) { $emails += $pEmail }
                        if ($dName) { $names += $dName }
                    }
                    if ($emails.Count -gt 0) { $ownerEmail = ($emails | Select-Object -Unique) -join ',' }
                    if ($names.Count -gt 0) { $ownerDisplayName = ($names | Select-Object -Unique) -join ',' }
                }
            }
            catch { }

            foreach ($cert in $sp.KeyCredentials) {
                $startDate = $cert.StartDateTime
                $endDate = $cert.EndDateTime
                $certName = if (-not [string]::IsNullOrWhiteSpace($cert.DisplayName)) {
                    $cert.DisplayName
                } elseif ($cert.Usage -eq "Sign") {
                    "SAML SSO Signing Certificate"
                } else {
                    "Enterprise App Certificate"
                }

                $remainingDays = if ($endDate) { ($endDate - (Get-Date)).Days } else { 9999 }

                $include = $false
                if ($IncludeAlreadyExpired -eq 'No') {
                    if ($remainingDays -le $DaysUntilExpiration -and $remainingDays -ge 0) { $include = $true }
                }
                else {
                    if ($remainingDays -le $DaysUntilExpiration) { $include = $true }
                }

                if ($include) {
                    $EnterpriseLogs += [PSCustomObject]@{
                        'WorkloadSource'         = 'Entra Enterprise Application'
                        'ApplicationName'        = $spName
                        'ApplicationID'          = $spAppId
                        'Secret Name'            = "N/A"
                        'Secret Start Date'      = "N/A"
                        'Secret End Date'        = "N/A"
                        'Certificate Name'       = $certName
                        'Certificate Start Date' = if ($startDate) { $startDate.ToString('MM/dd/yyyy') } else { "N/A" }
                        'Certificate End Date'   = if ($endDate) { $endDate.ToString('MM/dd/yyyy') } else { "N/A" }
                        'Owner'                  = $ownerEmail
                        'OwnerDisplayName'       = $ownerDisplayName
                        'Owner_ObjectID'         = "N/A"
                        'RemainingDaysCount'     = $remainingDays
                        'CredentialType'         = 'Certificate (SAML/SSO)'
                        'EndDateTime'            = $endDate
                    }
                }
            }
        }
        Write-Host "[INFO] $(Get-Date -Format o) - Enterprise Application discovery completed. Found $($EnterpriseLogs.Count) expiring certificate(s)."
        return $EnterpriseLogs
    }
    catch {
        Write-Host "[WARN] $(Get-Date -Format o) - Enterprise Application check encountered an issue: $($_.Exception.Message)"
        return $EnterpriseLogs
    }
}

# =====================================================================
# FUNCTION: Get Expiring Certificates across Azure Resources (ARG Query)
# =====================================================================
function Get-ExpiringAzureResourceCerts {
    param (
        [int]$DaysUntilExpiration,
        [string]$IncludeAlreadyExpired,
        [string]$DefaultOwnerEmail
    )
    $AzureResourceLogs = @()
    try {
        Write-Host "[INFO] $(Get-Date -Format o) - Querying Azure Resource Graph for App Service & Key Vault certificates."

        # ARG Query 1: App Service Certificates (Microsoft.Web/certificates)
        $argAppServiceCerts = @"
        resources
        | where type =~ 'microsoft.web/certificates'
        | project name, id, resourceGroup, subscriptionId, 
                  expirationDate = todatetime(properties.expirationDate), 
                  thumbprint = properties.thumbprint,
                  ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
        $webCerts = Search-AzGraph -Query $argAppServiceCerts -First 1000

        foreach ($row in $webCerts) {
            if ($row.expirationDate) {
                $expDate = [DateTime]$row.expirationDate
                $daysRemaining = ($expDate - (Get-Date)).Days
                $include = $false
                if ($IncludeAlreadyExpired -eq 'No') {
                    if ($daysRemaining -le $DaysUntilExpiration -and $daysRemaining -ge 0) { $include = $true }
                }
                else {
                    if ($daysRemaining -le $DaysUntilExpiration) { $include = $true }
                }

                if ($include) {
                    $ownerVal = if ([string]::IsNullOrWhiteSpace($row.ownerTag)) { $DefaultOwnerEmail } else { $row.ownerTag }
                    $AzureResourceLogs += [PSCustomObject]@{
                        'WorkloadSource'         = 'Azure App Service Cert'
                        'ApplicationName'        = "$($row.name) ($($row.resourceGroup))"
                        'ApplicationID'          = $row.id
                        'Secret Name'            = "N/A"
                        'Secret Start Date'      = "N/A"
                        'Secret End Date'        = "N/A"
                        'Certificate Name'       = $row.name
                        'Certificate Start Date' = "N/A"
                        'Certificate End Date'   = $expDate.ToString('MM/dd/yyyy')
                        'Owner'                  = $ownerVal
                        'OwnerDisplayName'       = $ownerVal
                        'Owner_ObjectID'         = "N/A"
                        'RemainingDaysCount'     = $daysRemaining
                        'CredentialType'         = 'Certificate'
                        'EndDateTime'            = $expDate
                    }
                }
            }
        }
        Write-Host "[INFO] $(Get-Date -Format o) - Retrieved $($AzureResourceLogs.Count) expiring Azure App Service certificate(s)."
        return $AzureResourceLogs
    }
    catch {
        Write-Host "[WARN] $(Get-Date -Format o) - Azure Resource Graph App Service certificate check encountered an issue: $($_.Exception.Message)"
        return $AzureResourceLogs
    }
}

# =====================================================================
# FUNCTION: Get Expiring Key Vault Secrets (NEW)
#           Scans all Key Vaults across all subscriptions for secrets
#           with expiry dates within the threshold window.
# =====================================================================
function Get-ExpiringKeyVaultSecrets {
    param (
        [int]$DaysUntilExpiration,
        [string]$IncludeAlreadyExpired,
        [string]$DefaultOwnerEmail
    )
    $KVLogs = @()
    try {
        Write-Host "[INFO] $(Get-Date -Format o) - Starting Key Vault secret expiry discovery across all subscriptions."
        $subscriptions = Get-AzSubscription
        Write-Host "[INFO] $(Get-Date -Format o) - Found $($subscriptions.Count) subscription(s) to scan."

        foreach ($sub in $subscriptions) {
            try {
                Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
                Write-Host "[INFO] $(Get-Date -Format o) - Scanning subscription: $($sub.Name) ($($sub.Id))"
                $keyVaults = Get-AzKeyVault
                Write-Host "[INFO] $(Get-Date -Format o) - Found $($keyVaults.Count) Key Vault(s) in subscription '$($sub.Name)'."

                foreach ($kv in $keyVaults) {
                    try {
                        $kvName    = $kv.VaultName
                        $kvRg      = $kv.ResourceGroupName
                        $kvDetails = Get-AzKeyVault -VaultName $kvName -ResourceGroupName $kvRg
                        $ownerTag  = $kvDetails.Tags['Owner']
                        if ([string]::IsNullOrWhiteSpace($ownerTag)) { $ownerTag = $kvDetails.Tags['owner'] }
                        if ([string]::IsNullOrWhiteSpace($ownerTag)) { $ownerTag = $kvDetails.Tags['WorkloadOwner'] }
                        if ([string]::IsNullOrWhiteSpace($ownerTag)) { $ownerTag = $kvDetails.Tags['TechnicalContact'] }
                        $ownerVal  = if ([string]::IsNullOrWhiteSpace($ownerTag)) { $DefaultOwnerEmail } else { $ownerTag }

                        # 1. Inspect Key Vault Certificates
                        try {
                            $certs = Get-AzKeyVaultCertificate -VaultName $kvName -ErrorAction SilentlyContinue
                            if ($certs) {
                                foreach ($c in $certs) {
                                    $expDate = if ($c.Expires) { $c.Expires } elseif ($c.Attributes -and $c.Attributes.Expires) { $c.Attributes.Expires } else { $null }
                                    if ($null -ne $expDate) {
                                        $daysRemaining = ($expDate - (Get-Date)).Days
                                        $include = if ($IncludeAlreadyExpired -eq 'No') { $daysRemaining -le $DaysUntilExpiration -and $daysRemaining -ge 0 } else { $daysRemaining -le $DaysUntilExpiration }
                                        if ($include) {
                                            Write-Host "[DEBUG] $(Get-Date -Format o) - KV Certificate '$($c.Name)' in '$kvName' expires on $expDate ($daysRemaining day(s) remaining)."
                                            $KVLogs += [PSCustomObject]@{
                                                'WorkloadSource'         = 'Azure Key Vault Certificate'
                                                'ApplicationName'        = "$kvName ($kvRg)"
                                                'ApplicationID'          = $kv.ResourceId
                                                'Secret Name'            = "N/A"
                                                'Secret Start Date'      = "N/A"
                                                'Secret End Date'        = "N/A"
                                                'Certificate Name'       = "$($c.Name) | Thumbprint: $($c.Thumbprint)"
                                                'Certificate Start Date' = "N/A"
                                                'Certificate End Date'   = $expDate.ToString('MM/dd/yyyy')
                                                'Owner'                  = $ownerVal
                                                'OwnerDisplayName'       = $ownerVal
                                                'Owner_ObjectID'         = "N/A"
                                                'RemainingDaysCount'     = $daysRemaining
                                                'CredentialType'         = 'Certificate'
                                                'EndDateTime'            = $expDate
                                            }
                                        }
                                    }
                                }
                            }
                        } catch { }

                        # 2. Inspect Key Vault Secrets
                        $secrets = Get-AzKeyVaultSecret -VaultName $kvName -ErrorAction Stop
                        foreach ($secret in $secrets) {
                            if ($null -ne $secret.Expires) {
                                $expDate       = $secret.Expires
                                $daysRemaining = ($expDate - (Get-Date)).Days
                                $include       = $false
                                if ($IncludeAlreadyExpired -eq 'No') {
                                    if ($daysRemaining -le $DaysUntilExpiration -and $daysRemaining -ge 0) { $include = $true }
                                }
                                else {
                                    if ($daysRemaining -le $DaysUntilExpiration) { $include = $true }
                                }
                                if ($include) {
                                    Write-Host "[DEBUG] $(Get-Date -Format o) - KV Secret '$($secret.Name)' in '$kvName' expires on $expDate ($daysRemaining day(s) remaining)."
                                    $KVLogs += [PSCustomObject]@{
                                        'WorkloadSource'         = 'Azure Key Vault Secret'
                                        'ApplicationName'        = "$kvName ($kvRg)"
                                        'ApplicationID'          = $kv.ResourceId
                                        'Secret Name'            = $secret.Name
                                        'Secret Start Date'      = "N/A"
                                        'Secret End Date'        = $expDate.ToString('MM/dd/yyyy')
                                        'Certificate Name'       = "N/A"
                                        'Certificate Start Date' = "N/A"
                                        'Certificate End Date'   = "N/A"
                                        'Owner'                  = $ownerVal
                                        'OwnerDisplayName'       = $ownerVal
                                        'Owner_ObjectID'         = "N/A"
                                        'RemainingDaysCount'     = $daysRemaining
                                        'CredentialType'         = 'Secret'
                                        'EndDateTime'            = $expDate
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Host "[WARN] $(Get-Date -Format o) - Could not read secrets from Key Vault '$($kv.VaultName)': $($_.Exception.Message)"
                    }
                }
            }
            catch {
                Write-Host "[WARN] $(Get-Date -Format o) - Could not switch to subscription '$($sub.Name)': $($_.Exception.Message)"
            }
        }
        Write-Host "[INFO] $(Get-Date -Format o) - Key Vault secret discovery completed. Found $($KVLogs.Count) expiring secret(s)."
        return $KVLogs
    }
    catch {
        Write-Host "[ERROR] $(Get-Date -Format o) - Failed in Get-ExpiringKeyVaultSecrets: $($_.Exception.Message)"
        return $KVLogs
    }
}

# =====================================================================
# FUNCTION: Get Expiring Application Gateway SSL Certificates (NEW)
#           Scans all Application Gateways across all subscriptions for
#           SSL certificates expiring within the threshold window.
# =====================================================================
function Get-ExpiringAppGatewayCerts {
    param (
        [int]$DaysUntilExpiration,
        [string]$IncludeAlreadyExpired,
        [string]$DefaultOwnerEmail
    )
    $AGLogs = @()
    try {
        Write-Host "[INFO] $(Get-Date -Format o) - Starting Application Gateway SSL certificate expiry discovery (directly-uploaded certs)."

        # Use ARG to enumerate all Application Gateways
        $argAppGwQuery = @"
        resources
        | where type =~ 'microsoft.network/applicationgateways'
        | project name, id, resourceGroup, subscriptionId,
                  ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
        $appGateways = Search-AzGraph -Query $argAppGwQuery -First 1000
        Write-Host "[INFO] $(Get-Date -Format o) - Found $($appGateways.Count) Application Gateway(s) to inspect."

        foreach ($agw in $appGateways) {
            $agwName  = $agw.name
            $agwRg    = $agw.resourceGroup
            $ownerVal = if ([string]::IsNullOrWhiteSpace($agw.ownerTag)) { $DefaultOwnerEmail } else { $agw.ownerTag }

            try {
                $subId = $agw.id.Split('/')[2]
                Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
                Write-Host "[INFO] $(Get-Date -Format o) - Inspecting AppGW '$agwName' in RG '$agwRg'."

                $fullAgw     = Get-AzApplicationGateway -Name $agwName -ResourceGroupName $agwRg -ErrorAction Stop
                $certCount   = $fullAgw.SslCertificates.Count
                Write-Host "[INFO] $(Get-Date -Format o) - AppGW '$agwName' has $certCount SSL certificate(s) attached."

                # Map HTTP Listeners and Hostnames
                $certListenerMap = @{}
                if ($fullAgw.HttpListeners) {
                    foreach ($lst in $fullAgw.HttpListeners) {
                        $certRef = $lst.SslCertificate.Id
                        if ($certRef) {
                            $cName = $certRef.Split('/')[-1]
                            $hVal = if ($lst.HostName) { $lst.HostName } elseif ($lst.HostNames) { $lst.HostNames -join ', ' } else { "" }
                            $lDesc = if ($hVal) { "$($lst.Name) ($hVal)" } else { $lst.Name }
                            if (-not $certListenerMap.ContainsKey($cName)) { $certListenerMap[$cName] = [System.Collections.Generic.List[string]]::new() }
                            $certListenerMap[$cName].Add($lDesc)
                        }
                    }
                }

                foreach ($sslCert in $fullAgw.SslCertificates) {
                    $certName = $sslCert.Name
                    $listenersDesc = if ($certListenerMap.ContainsKey($certName)) { $certListenerMap[$certName] -join "; " } else { "Unattached / No Listener" }
                    $x509     = $null

                    try {
                        # -------------------------------------------------------
                        # Extract cert data from PublicCertData or Data
                        # -------------------------------------------------------
                        $certData = if (-not [string]::IsNullOrWhiteSpace($sslCert.PublicCertData)) { $sslCert.PublicCertData }
                                    elseif (-not [string]::IsNullOrWhiteSpace($sslCert.Data)) { $sslCert.Data }
                                    elseif ($sslCert.properties -and -not [string]::IsNullOrWhiteSpace($sslCert.properties.publicCertData)) { $sslCert.properties.publicCertData }
                                    elseif ($sslCert.properties -and -not [string]::IsNullOrWhiteSpace($sslCert.properties.data)) { $sslCert.properties.data }
                                    else { $null }

                        if ([string]::IsNullOrWhiteSpace($certData)) {
                            # Check if this cert is Key Vault-linked
                            if ($sslCert.KeyVaultSecretId) {
                                Write-Host "[INFO] $(Get-Date -Format o) - SSL cert '$certName' on '$agwName' is Key Vault-linked (KV SecretId: $($sslCert.KeyVaultSecretId)). Skipping - covered by Key Vault monitoring."
                            }
                            else {
                                Write-Host "[WARN] $(Get-Date -Format o) - SSL cert '$certName' on '$agwName' has no PublicCertData/Data and no KV link. Skipping."
                            }
                            continue
                        }

                        # --- Strategy 1: Raw Base64 -> DER bytes -> X509Certificate2 (most common for direct upload) ---
                        $decoded = $false
                        try {
                            $certBytes = [System.Convert]::FromBase64String($certData.Trim())
                            $x509      = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                            $decoded   = $true
                            Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 1 (DER decode) succeeded for '$certName'."
                        }
                        catch {
                            Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 1 (DER decode) failed for '$certName': $($_.Exception.Message)"
                        }

                        # --- Strategy 2: Strip PEM headers if present, then decode inner Base64 ---
                        if (-not $decoded) {
                            try {
                                $pemContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($certData.Trim()))
                                if ($pemContent -match "-----BEGIN CERTIFICATE-----") {
                                    $innerB64  = ($pemContent -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
                                    $certBytes = [System.Convert]::FromBase64String($innerB64)
                                    $x509      = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                                    $decoded   = $true
                                    Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 2 (PEM strip) succeeded for '$certName'."
                                }
                            }
                            catch {
                                Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 2 (PEM strip) failed for '$certName': $($_.Exception.Message)"
                            }
                        }

                        # --- Strategy 3: Treat PublicCertData as already-decoded UTF8 PEM string ---
                        if (-not $decoded) {
                            try {
                                $rawString = $certData.Trim()
                                if ($rawString -match "-----BEGIN CERTIFICATE-----") {
                                    $innerB64  = ($rawString -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
                                    $certBytes = [System.Convert]::FromBase64String($innerB64)
                                    $x509      = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                                    $decoded   = $true
                                    Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 3 (raw PEM string) succeeded for '$certName'."
                                }
                            }
                            catch {
                                Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 3 (raw PEM string) failed for '$certName': $($_.Exception.Message)"
                            }
                        }

                        if (-not $decoded -or $null -eq $x509) {
                            Write-Host "[WARN] $(Get-Date -Format o) - All decode strategies failed for SSL cert '$certName' on AppGW '$agwName'. Skipping."
                            continue
                        }

                        # Extract expiry details
                        $expDate       = $x509.NotAfter
                        $startDate     = $x509.NotBefore
                        $daysRemaining = ($expDate - (Get-Date)).Days
                        $subject       = $x509.Subject
                        $thumbprint    = $x509.Thumbprint

                        Write-Host "[INFO] $(Get-Date -Format o) - AppGW '$agwName' | Cert: '$certName' | Subject: $subject | Thumbprint: $thumbprint | Expires: $expDate | Days Remaining: $daysRemaining"

                        # Apply expiry filter
                        $include = $false
                        if ($IncludeAlreadyExpired -eq 'No') {
                            if ($daysRemaining -le $DaysUntilExpiration -and $daysRemaining -ge 0) { $include = $true }
                        }
                        else {
                            if ($daysRemaining -le $DaysUntilExpiration) { $include = $true }
                        }

                        if ($include) {
                            $AGLogs += [PSCustomObject]@{
                                'WorkloadSource'         = 'Azure Application Gateway'
                                'ApplicationName'        = "$agwName ($agwRg)"
                                'ApplicationID'          = $agw.id
                                'Secret Name'            = "N/A"
                                'Secret Start Date'      = "N/A"
                                'Secret End Date'        = "N/A"
                                'Certificate Name'       = "$certName | Subject: $subject | Listeners: $listenersDesc | Thumbprint: $thumbprint"
                                'Certificate Start Date' = $startDate.ToString('MM/dd/yyyy')
                                'Certificate End Date'   = $expDate.ToString('MM/dd/yyyy')
                                'Owner'                  = $ownerVal
                                'OwnerDisplayName'       = $ownerVal
                                'Owner_ObjectID'         = "N/A"
                                'RemainingDaysCount'     = $daysRemaining
                                'CredentialType'         = 'Certificate'
                                'EndDateTime'            = $expDate
                            }
                        }

                        # Dispose x509 object to release resources
                        $x509.Dispose()
                    }
                    catch {
                        Write-Host "[WARN] $(Get-Date -Format o) - Unexpected error processing SSL cert '$certName' on AppGW '$agwName': $($_.Exception.Message)"
                        if ($null -ne $x509) { try { $x509.Dispose() } catch {} }
                    }
                }
            }
            catch {
                Write-Host "[WARN] $(Get-Date -Format o) - Could not retrieve Application Gateway '$agwName': $($_.Exception.Message)"
            }
        }
        Write-Host "[INFO] $(Get-Date -Format o) - Application Gateway cert discovery completed. Found $($AGLogs.Count) expiring certificate(s)."
        return $AGLogs
    }
    catch {
        Write-Host "[ERROR] $(Get-Date -Format o) - Failed in Get-ExpiringAppGatewayCerts: $($_.Exception.Message)"
        return $AGLogs
    }
}

# =====================================================================
# MAIN SCRIPT LOGIC
# =====================================================================
try {
    Write-Host "[INFO] $(Get-Date -Format o) - Entered main runbook logic."
    $DaysUntilExpiration   = 30
    $IncludeAlreadyExpired = "Yes"   # CHANGED: Now alerts on already-expired items too
    $WarningPreference     = 'SilentlyContinue'

    # =================================================================
    # READ RUNBOOK VARIABLES
    # =================================================================
    Write-Host "[INFO] $(Get-Date -Format o) - Reading Runbook Variables."

    # Read GTAdminUsers from runbook variable
    $GTAdminUsersVar = Get-AutomationVariable -Name "GTAdminUsers"
    $GTAdminUsers = @($GTAdminUsersVar.Split(",") | ForEach-Object { $_.Trim() })
    Write-Host "[INFO] $(Get-Date -Format o) - GTAdminUsers loaded: $($GTAdminUsers.Count) users"

    # Read CC recipients from runbook variable
    $CCRecipientsVar = Get-AutomationVariable -Name "EmailCC_AppRegistrationExpiry"
    $CCRecipients = @()
    if (-not [string]::IsNullOrEmpty($CCRecipientsVar)) {
        $CCRecipients = @($CCRecipientsVar.Split(",") | ForEach-Object {
                $trimmed = $_.Trim()
                if (-not [string]::IsNullOrEmpty($trimmed)) {
                    @{ emailAddress = @{ address = $trimmed } }
                }
            })
    }
    Write-Host "[INFO] $(Get-Date -Format o) - CC Recipients loaded: $($CCRecipients.Count) recipients"

    # Read BCC recipients from runbook variable
    $BCCRecipientsVar = Get-AutomationVariable -Name "EmailBCC_AppRegistrationExpiry"
    $BCCRecipients = @()
    if (-not [string]::IsNullOrEmpty($BCCRecipientsVar)) {
        $BCCRecipients = @($BCCRecipientsVar.Split(",") | ForEach-Object {
                $trimmed = $_.Trim()
                if (-not [string]::IsNullOrEmpty($trimmed)) {
                    @{ emailAddress = @{ address = $trimmed } }
                }
            })
    }
    Write-Host "[INFO] $(Get-Date -Format o) - BCC Recipients loaded: $($BCCRecipients.Count) recipients"

    Write-Host "[INFO] $(Get-Date -Format o) - Fetching credentials of shared service automation app registration from key vault."
    $subSharedService = Get-AzSubscription -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    Set-AzContext -Subscription $subSharedService.Id
    $kvSharedService = Get-AzKeyVault -VaultName "xxxx-keyvault-name" -ResourceGroupName "xxxx-resource-group-name"

    $appID = Get-AzKeyVaultSecret -VaultName $kvSharedService.VaultName -Name "xxxx-clientId-secret" -AsPlainText
    $tenantID = Get-AzKeyVaultSecret -VaultName $kvSharedService.VaultName -Name "xxxx-tenantId-secret" -AsPlainText
    $appSecret = Get-AzKeyVaultSecret -VaultName $kvSharedService.VaultName -Name "xxxx-appSecret-secret" -AsPlainText

    Write-Host "[INFO] $(Get-Date -Format o) - Fetching app registration details from Automation Credential asset."
    $Cred = Get-AutomationPSCredential -Name "xxxx-AutomationCredentialName"
    $appID_Graph = $Cred.UserName
    $appSecret_Graph = $Cred.Password
    $tenantID_Var = Get-AutomationVariable -Name "xxxx-tenantID-variable"

    # Get access token for email sending
    $accessToken = Get-AccessToken -appID $appID -appSecret $appSecret -tenantId $tenantID
    if ([string]::IsNullOrEmpty($accessToken)) {
        throw "Get-AccessToken returned null - check appID/tenantID/appSecret Automation Variables and that the secret isn't expired/rotated."
    }

    # Connect to Microsoft Graph using client secret
    Write-Host "[INFO] $(Get-Date -Format o) - Connecting to Microsoft Graph with the automation client secret."
    $ClientSecretCredential = New-Object System.Management.Automation.PSCredential($appID_Graph, $appSecret_Graph)

    Write-Host "[INFO] $(Get-Date -Format o) - Calling Connect-MgGraph."
    Connect-MgGraph -TenantId $tenantID_Var -ClientSecretCredential $ClientSecretCredential -NoWelcome
    Write-Host "[INFO] $(Get-Date -Format o) - Microsoft Graph connection established."

    $defaultFallbackOwner = Get-AutomationVariable -Name "DefaultOwnerEmail" -ErrorAction SilentlyContinue
    if ([string]::IsNullOrEmpty($defaultFallbackOwner)) {
        $defaultFallbackOwner = "xxxx-fallback-owner@yourdomain.com"
    }

    # =================================================================
    # DISCOVERY: Collect expiring items from all five sources
    # =================================================================

    # 1. Entra App Registrations
    Write-Host "[INFO] $(Get-Date -Format o) - [SOURCE 1/5] Collecting Entra App Registration expiring secrets/certs."
    $AppRegLogs = Get-ExpiringAppRegistrations `
        -DaysUntilExpiration $DaysUntilExpiration `
        -IncludeAlreadyExpired $IncludeAlreadyExpired `
        -GTAdminUsers $GTAdminUsers
    if ($null -eq $AppRegLogs) { $AppRegLogs = @() }
    Write-Host "[INFO] $(Get-Date -Format o) - App Registration records found: $($AppRegLogs.Count)"

    # 2. Entra Enterprise Applications (SAML SSO Certs - NEW)
    Write-Host "[INFO] $(Get-Date -Format o) - [SOURCE 2/5] Collecting Entra Enterprise Application expiring SAML/SSO certificates."
    $EnterpriseAppLogs = Get-ExpiringEnterpriseAppCerts `
        -DaysUntilExpiration $DaysUntilExpiration `
        -IncludeAlreadyExpired $IncludeAlreadyExpired `
        -DefaultOwnerEmail $defaultFallbackOwner
    if ($null -eq $EnterpriseAppLogs) { $EnterpriseAppLogs = @() }
    Write-Host "[INFO] $(Get-Date -Format o) - Enterprise Application Cert records found: $($EnterpriseAppLogs.Count)"

    # 3. Azure App Service Certificates
    Write-Host "[INFO] $(Get-Date -Format o) - [SOURCE 3/5] Collecting Azure App Service expiring certificates."
    $AppSvcCertLogs = Get-ExpiringAzureResourceCerts `
        -DaysUntilExpiration $DaysUntilExpiration `
        -IncludeAlreadyExpired $IncludeAlreadyExpired `
        -DefaultOwnerEmail $defaultFallbackOwner
    if ($null -eq $AppSvcCertLogs) { $AppSvcCertLogs = @() }
    Write-Host "[INFO] $(Get-Date -Format o) - App Service Cert records found: $($AppSvcCertLogs.Count)"

    # 4. Key Vault Secrets (NEW)
    Write-Host "[INFO] $(Get-Date -Format o) - [SOURCE 4/5] Collecting Azure Key Vault expiring secrets."
    $KVSecretLogs = Get-ExpiringKeyVaultSecrets `
        -DaysUntilExpiration $DaysUntilExpiration `
        -IncludeAlreadyExpired $IncludeAlreadyExpired `
        -DefaultOwnerEmail $defaultFallbackOwner
    if ($null -eq $KVSecretLogs) { $KVSecretLogs = @() }
    Write-Host "[INFO] $(Get-Date -Format o) - Key Vault Secret records found: $($KVSecretLogs.Count)"

    # 5. Application Gateway SSL Certificates (NEW)
    Write-Host "[INFO] $(Get-Date -Format o) - [SOURCE 5/5] Collecting Application Gateway expiring SSL certificates."
    $AppGwCertLogs = Get-ExpiringAppGatewayCerts `
        -DaysUntilExpiration $DaysUntilExpiration `
        -IncludeAlreadyExpired $IncludeAlreadyExpired `
        -DefaultOwnerEmail $defaultFallbackOwner
    if ($null -eq $AppGwCertLogs) { $AppGwCertLogs = @() }
    Write-Host "[INFO] $(Get-Date -Format o) - Application Gateway Cert records found: $($AppGwCertLogs.Count)"

    # Combine all sources
    $allExpiringRecords  = @()
    $allExpiringRecords += $AppRegLogs
    $allExpiringRecords += $EnterpriseAppLogs
    $allExpiringRecords += $AppSvcCertLogs
    $allExpiringRecords += $KVSecretLogs
    $allExpiringRecords += $AppGwCertLogs
    Write-Host "[INFO] $(Get-Date -Format o) - Total combined expiring records across all sources: $($allExpiringRecords.Count)"

    # =================================================================
    # CHECK IF ANY RECORDS FOUND
    # =================================================================
    if ($null -eq $allExpiringRecords -or $allExpiringRecords.Count -eq 0) {
        Write-Host "[INFO] $(Get-Date -Format o) - No expiring or expired credentials/certificates found across all sources. No emails sent."
    }
    else {
        Write-Host "[INFO] $(Get-Date -Format o) - Preparing notifications for $($allExpiringRecords.Count) matching record(s)."

        $allExpiringRecords   = $allExpiringRecords | Sort-Object RemainingDaysCount
        $groupedByAppAndOwner = $allExpiringRecords | Group-Object -Property ApplicationName, Owner
        Write-Host "[INFO] $(Get-Date -Format o) - Records grouped into $($groupedByAppAndOwner.Count) email(s) to send."

        foreach ($group in $groupedByAppAndOwner) {
            $mailbody       = ""
            $recipientEmail = @()

            $firstRecord   = $group.Group[0]
            $appName       = $firstRecord.'ApplicationName'
            $ownerEmail    = $firstRecord.'Owner'
            $ownerDisplay  = $firstRecord.'OwnerDisplayName'

            Write-Host "[INFO] $(Get-Date -Format o) - Processing group: Resource/App='$appName', Owner='$ownerDisplay', Records=$($group.Group.Count)."

            # Summary counts
            $totalCreds   = $group.Group.Count
            $expiredCount = ($group.Group | Where-Object { $_.RemainingDaysCount -le 0 }).Count
            $urgentCount  = ($group.Group | Where-Object { $_.RemainingDaysCount -le 7  -and $_.RemainingDaysCount -gt 0 }).Count
            $soonCount    = ($group.Group | Where-Object { $_.RemainingDaysCount -le 14 -and $_.RemainingDaysCount -gt 7 }).Count
            $countAppReg     = ($group.Group | Where-Object { $_.WorkloadSource -eq 'Entra App Registration' }).Count
            $countEnterprise = ($group.Group | Where-Object { $_.WorkloadSource -eq 'Entra Enterprise Application' }).Count
            $countAppSvc     = ($group.Group | Where-Object { $_.WorkloadSource -eq 'Azure App Service Cert' }).Count
            $countKV         = ($group.Group | Where-Object { $_.WorkloadSource -eq 'Azure Key Vault Secret' }).Count
            $countAppGw      = ($group.Group | Where-Object { $_.WorkloadSource -eq 'Azure Application Gateway' }).Count

            # BUILD EMAIL BODY
            $mailbody += '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
            $mailbody += '<style>'
            $mailbody += 'body { font-family: Calibri, Arial, sans-serif; font-size: 14px; color: #333; }'
            $mailbody += 'h2 { color: #c00000; }'
            $mailbody += 'table { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 13px; }'
            $mailbody += 'th { background-color: #203864; color: white; padding: 8px 10px; text-align: left; }'
            $mailbody += 'td { padding: 6px 10px; border: 1px solid #ddd; }'
            $mailbody += 'tr:nth-child(even) { background-color: #f2f2f2; }'
            $mailbody += '.crtexp { background-color: #ffcccc !important; font-weight: bold; }'
            $mailbody += '.crtsn  { background-color: #cce5ff !important; }'
            $mailbody += '.crtcn  { background-color: #fff2cc !important; }'
            $mailbody += '.summary { background-color: #f9f9f9; border-left: 4px solid #203864; padding: 10px 15px; margin-top: 15px; }'
            $mailbody += '.footer  { margin-top: 25px; font-size: 12px; color: #666; border-top: 1px solid #ccc; padding-top: 10px; }'
            $mailbody += '.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; color: white; }'
            $mailbody += '.src-appreg     { background-color: #203864; }'
            $mailbody += '.src-enterprise { background-color: #C00000; }'
            $mailbody += '.src-appsvc     { background-color: #217346; }'
            $mailbody += '.src-keyvault   { background-color: #7B3F00; }'
            $mailbody += '.src-appgw      { background-color: #6B2D8B; }'
            $mailbody += '</style></head><body>'

            $mailbody += '<h2>&#9888; Azure Credential &amp; Certificate Expiration Alert</h2>'
            $mailbody += '<p>Dear Team,</p>'
            $mailbody += "<p>The following credentials and/or certificates associated with <b>$appName</b> are expiring or have already expired. Immediate action is required to avoid service disruptions.</p>"
            $mailbody += "<p><b>Monitoring Window:</b> $DaysUntilExpiration days &nbsp;|&nbsp; <b>Include Already Expired:</b> $IncludeAlreadyExpired</p>"

            # Table
            $mailbody += '<p><table>'
            $mailbody += '<tr><th>Resource / App ID</th><th>Name</th><th>Source</th><th>Type</th><th>Credential / Cert Name</th><th>Start Date</th><th>End Date</th><th>Days Remaining</th></tr>'

            foreach ($record in ($group.Group | Sort-Object RemainingDaysCount)) {
                $daysRemaining = $record.RemainingDaysCount
                $credType      = $record.CredentialType
                $source        = $record.WorkloadSource

                $rowClass = ""
                if ($daysRemaining -le 0)      { $rowClass = "crtexp" }
                elseif ($daysRemaining -le 7)  { $rowClass = "crtsn" }
                elseif ($daysRemaining -le 14) { $rowClass = "crtcn" }

                $sourceBadgeClass = switch ($source) {
                    'Entra App Registration'       { 'src-appreg' }
                    'Entra Enterprise Application' { 'src-enterprise' }
                    'Azure App Service Cert'       { 'src-appsvc' }
                    'Azure Key Vault Secret'       { 'src-keyvault' }
                    'Azure Application Gateway'    { 'src-appgw' }
                    default                        { 'src-appreg' }
                }

                if ($credType -eq "Secret") {
                    $credName  = $record.'Secret Name'
                    $startDate = $record.'Secret Start Date'
                    $endDate   = $record.'Secret End Date'
                }
                else {
                    $credName  = $record.'Certificate Name'
                    $startDate = $record.'Certificate Start Date'
                    $endDate   = $record.'Certificate End Date'
                }

                $mailbody += "<tr class='$rowClass'>"
                $mailbody += "<td>" + $record.'ApplicationID'   + "</td>"
                $mailbody += "<td>" + $record.'ApplicationName' + "</td>"
                $mailbody += "<td><span class='badge $sourceBadgeClass'>$source</span></td>"
                $mailbody += "<td>" + $credType   + "</td>"
                $mailbody += "<td>" + $credName   + "</td>"
                $mailbody += "<td>" + $startDate  + "</td>"
                $mailbody += "<td>" + $endDate    + "</td>"

                if ($daysRemaining -le 0)      { $mailbody += "<td class='crtexp'>EXPIRED</td>" }
                elseif ($daysRemaining -le 7)  { $mailbody += "<td class='crtsn'>$daysRemaining day(s)</td>" }
                elseif ($daysRemaining -le 14) { $mailbody += "<td class='crtcn'>$daysRemaining day(s)</td>" }
                else                           { $mailbody += "<td>$daysRemaining day(s)</td>" }
                $mailbody += "</tr>"
            }

            $mailbody += '</table></p>'

            # Summary block
            $mailbody += '<div class="summary">'
            $mailbody += "<p><b>Summary for $($appName):</b></p><ul>"
            $mailbody += "<li>Total Credentials/Certificates: $totalCreds</li>"
            if ($expiredCount -gt 0) { $mailbody += "<li><b style='color: #c00000;'>Already Expired: $expiredCount</b></li>" }
            if ($urgentCount  -gt 0) { $mailbody += "<li><b style='color: #0070c0;'>Expiring within 7 days: $urgentCount</b></li>" }
            if ($soonCount    -gt 0) { $mailbody += "<li><b style='color: #ff9800;'>Expiring within 14 days: $soonCount</b></li>" }
            $mailbody += '</ul><p><b>Source Breakdown:</b></p><ul>'
            if ($countAppReg -gt 0)     { $mailbody += "<li>Entra App Registration: $countAppReg item(s)</li>" }
            if ($countEnterprise -gt 0) { $mailbody += "<li>Entra Enterprise Application: $countEnterprise item(s)</li>" }
            if ($countAppSvc -gt 0)     { $mailbody += "<li>Azure App Service Cert: $countAppSvc item(s)</li>" }
            if ($countKV     -gt 0)     { $mailbody += "<li>Azure Key Vault Secret: $countKV item(s)</li>" }
            if ($countAppGw  -gt 0)     { $mailbody += "<li>Azure Application Gateway: $countAppGw item(s)</li>" }
            $mailbody += '</ul></div>'

            # Action steps
            $mailbody += '<p style="margin-top: 15px;"><b>ACTION REQUIRED:</b></p><p>'
            $mailbody += 'Please rotate these credentials or renew certificates as soon as possible to avoid service disruption.'
            $mailbody += '<br><b>Steps to rotate/renew credentials:</b><ol>'
            $mailbody += "<li>Navigate to Azure Portal &rarr; locate the affected resource: <b>$appName</b></li>"
            $mailbody += '<li>For <b>App Registrations</b>: Go to <b>Certificates &amp; secrets</b> and add a new secret or certificate</li>'
            $mailbody += '<li>For <b>Enterprise Applications</b>: Go to <b>Enterprise applications</b> &rarr; Single sign-on &rarr; SAML Certificates &rarr; Edit/Rotate certificate</li>'
            $mailbody += '<li>For <b>Key Vault Secrets</b>: Go to the Key Vault &rarr; Secrets &rarr; create a new version or update the expiry date</li>'
            $mailbody += '<li>For <b>App Service Certificates</b>: Navigate to the certificate resource and click Renew</li>'
            $mailbody += '<li>For <b>Application Gateway</b>: Go to the gateway &rarr; Listeners &rarr; SSL Certificate &rarr; upload the renewed certificate</li>'
            $mailbody += '<li>Update your application / pipeline configuration to use the newly created credential</li>'
            $mailbody += '<li>Delete or revoke old credentials after cutover confirmation</li>'
            $mailbody += '</ol></p>'

            # Color legend
            $mailbody += '<p style="margin-top: 15px;"><b>Color Legend:</b></p><ul>'
            $mailbody += '<li><span style="background-color: #ffcccc; padding: 3px 6px;">Red Background</span> = Already Expired (0 days)</li>'
            $mailbody += '<li><span style="background-color: #cce5ff; padding: 3px 6px;">Blue Background</span> = Expiring Very Soon (&le; 7 days)</li>'
            $mailbody += '<li><span style="background-color: #fff2cc; padding: 3px 6px;">Orange Background</span> = Expiring Soon (&le; 14 days)</li>'
            $mailbody += '</ul>'

            # Source badge legend
            $mailbody += '<p style="margin-top: 10px;"><b>Source Badge Legend:</b></p><ul>'
            $mailbody += '<li><span style="background-color: #203864; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px;">Entra App Registration</span> = Entra ID App Registration Secrets &amp; Certs</li>'
            $mailbody += '<li><span style="background-color: #C00000; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px;">Entra Enterprise Application</span> = Enterprise App SAML SSO &amp; Token Signing Certs</li>'
            $mailbody += '<li><span style="background-color: #217346; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px;">Azure App Service Cert</span> = Azure App Service Certificates</li>'
            $mailbody += '<li><span style="background-color: #7B3F00; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px;">Azure Key Vault Secret</span> = Key Vault Secrets with Expiry Set</li>'
            $mailbody += '<li><span style="background-color: #6B2D8B; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px;">Azure Application Gateway</span> = Application Gateway SSL Certificates</li>'
            $mailbody += '</ul>'

            # Footer
            $mailbody += '<div class="footer">'
            $mailbody += '<p>This is an auto-generated email. Please do not reply directly to this message.</p>'
            $mailbody += '<p>If you have any questions regarding this notification, please contact:'
            $mailbody += '<br>&nbsp;&nbsp;&nbsp;&nbsp;<a href="mailto:xxxx-team-alerts@yourdomain.com">xxxx-team-alerts@yourdomain.com</a>'
            $mailbody += '<br>&nbsp;&nbsp;&nbsp;&nbsp;<a href="mailto:xxxx-lead-alerts@yourdomain.com">xxxx-lead-alerts@yourdomain.com</a></p>'
            $mailbody += '<p>Regards,<br><b>xxxx Cloud Infrastructure Team</b></p>'
            $mailbody += '</div></body></html>'

            # Prepare and send email
            $sender  = "xxxx-notification@yourdomain.com"
            $subject = "ALERT: Azure Credential/Certificate Expiration - $appName ($($group.Group.Count) item(s))"
            Write-Host "[INFO] $(Get-Date -Format o) - Preparing email for '$appName' with $($group.Group.Count) item(s)."

            $mailRecipients = $ownerEmail.Split(",")
            foreach ($recipientAddr in $mailRecipients) {
                $trimmedAddr = $recipientAddr.Trim()
                if (-not [string]::IsNullOrEmpty($trimmedAddr) -and $trimmedAddr -notlike "*<*") {
                    $recipientEmail += @{ emailAddress = @{ address = $trimmedAddr } }
                }
            }
            if ($recipientEmail.Count -eq 0) {
                $recipientEmail += @{ emailAddress = @{ address = $defaultFallbackOwner } }
            }

            Send-Email -accessToken $accessToken -recipientEmail $recipientEmail -ccRecipients $CCRecipients -bccRecipients $BCCRecipients -subject $subject -body $mailbody -fromEmail $sender
            Write-Host "[INFO] $(Get-Date -Format o) - Email sent for '$appName' with $($group.Group.Count) item(s)."
        }

        Write-Host "[INFO] $(Get-Date -Format o) - All notifications sent. Total: $($groupedByAppAndOwner.Count) email(s)."
    }

    Write-Host "[INFO] $(Get-Date -Format o) - Runbook execution completed successfully."
}
catch {
    Write-Host "[ERROR] $(Get-Date -Format o) - Runbook execution failed: $($_.Exception.Message)"
    Write-Host "[ERROR] $(Get-Date -Format o) - Stack Trace: $($_.Exception.StackTrace)"
}
finally {
    Write-Host "[INFO] $(Get-Date -Format o) - Runbook finished."
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}