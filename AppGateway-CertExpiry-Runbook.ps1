<#
.SYNOPSIS
    Dedicated Azure Automation Runbook to discover expiring and expired SSL/TLS
    certificates on Azure Application Gateways across subscriptions, and alert
    the respective workload owners and operations team via Microsoft Graph API.

.DESCRIPTION
    This runbook performs an automated audit of all Azure Application Gateways:
      1. Discovers all Application Gateways across accessible Azure subscriptions
         using Azure Resource Graph (ARG) for maximum speed and scalability.
      2. Inspects every SSL certificate configured on the Application Gateway:
         - Directly uploaded certificates (PFX/CER): Parses PublicCertData using
           X509Certificate2Collection to support leaf certs and PKCS#7 chains.
         - Key Vault-linked certificates: Extracts Key Vault Secret URI and checks
           expiry from Key Vault if permissions are available.
      3. Maps certificates to their respective HTTPS Listeners and Hostnames (SNI).
      4. Identifies the workload owner from resource tags (e.g. Owner, WorkloadOwner,
         TechnicalContact) with automatic fallback to a default admin contact.
      5. Formats a high-visibility, color-coded HTML report (Red: Expired, Blue: <=7 days,
         Orange: <=14 days, Yellow: <=30 days).
      6. Sends targeted alert emails to each owner via Microsoft Graph API with
         support for CC and BCC recipients.

.NOTES
    Author  : Cloud Infrastructure & Security Engineering Team
    Version : 1.0 (Dedicated Application Gateway Edition)
    Runtime : PowerShell 7.2 (or PowerShell 5.1) Runbook
#>

[CmdletBinding()]
param ()

Write-Host "[INFO] $(Get-Date -Format o) - Runbook started. Preparing to evaluate SSL certificates across Azure Application Gateways."

# Ensures you do not inherit an AzContext in your runbook process
Disable-AzContextAutosave -Scope Process
Write-Host "[INFO] $(Get-Date -Format o) - Azure context autosave disabled for this process."

# Connect to Azure with system-assigned managed identity
try {
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    $currentCtx = Get-AzContext
    Write-Host "[INFO] $(Get-Date -Format o) - Connected successfully via Managed Identity. Account: $($currentCtx.Account.Id), Tenant: $($currentCtx.Tenant.Id)."
}
catch {
    Write-Host "[ERROR] $(Get-Date -Format o) - Failed to authenticate using Managed Identity: $($_.Exception.Message)"
    throw $_
}

# =====================================================================
# FUNCTION: Get Microsoft Graph OAuth2 Access Token (for sendMail)
# =====================================================================
function Get-GraphAccessToken {
    param (
        [string]$AppId,
        [string]$AppSecret,
        [string]$TenantId
    )
    try {
        $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $AppId
            client_secret = $AppSecret
            scope         = "https://graph.microsoft.com/.default"
        }
        Write-Host "[INFO] $(Get-Date -Format o) - Requesting Microsoft Graph OAuth2 access token for client ID '$AppId'."
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ErrorAction Stop
        Write-Host "[INFO] $(Get-Date -Format o) - Access token acquired successfully. Length: $($response.access_token.Length)."
        return $response.access_token
    }
    catch {
        Write-Host "[ERROR] $(Get-Date -Format o) - Failed to acquire Graph access token: $($_.Exception.Message)"
        return $null
    }
}

# =====================================================================
# FUNCTION: Send Email via Microsoft Graph API
# =====================================================================
function Send-GraphEmail {
    param (
        [string]$AccessToken,
        [array]$RecipientEmail,
        [array]$CcRecipients,
        [array]$BccRecipients,
        [string]$Subject,
        [string]$Body,
        [string]$FromEmail
    )
    try {
        Write-Host "[INFO] $(Get-Date -Format o) - Sending alert email from '$FromEmail' to $($RecipientEmail.Count) recipient(s), CC: $($CcRecipients.Count), BCC: $($BccRecipients.Count)."
        $graphApiEndpoint = "https://graph.microsoft.com/v1.0/users/$($FromEmail)/sendMail"
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }

        # Build email data structure
        $emailData = @{
            message = @{
                subject      = $Subject
                body         = @{
                    contentType = "HTML"
                    content     = $Body
                }
                toRecipients = @($RecipientEmail)
            }
        }

        # Add CC recipients if provided
        if ($CcRecipients -and $CcRecipients.Count -gt 0) {
            $emailData.message["ccRecipients"] = @($CcRecipients)
        }

        # Add BCC recipients if provided
        if ($BccRecipients -and $BccRecipients.Count -gt 0) {
            $emailData.message["bccRecipients"] = @($BccRecipients)
        }

        $emailJson = $emailData | ConvertTo-Json -Depth 100
        Invoke-RestMethod -Uri $graphApiEndpoint -Method Post -Headers $headers -Body $emailJson -ContentType "application/json" -ErrorAction Stop
        Write-Host "[INFO] $(Get-Date -Format o) - Email request successfully accepted by Microsoft Graph for '$Subject'."
    }
    catch {
        Write-Host "[ERROR] $(Get-Date -Format o) - Failed to send email via Microsoft Graph: $($_.Exception.Message)"
    }
}

# =====================================================================
# FUNCTION: Parse X509 Certificate from Base64 Data
# =====================================================================
function Parse-AppGwCertificate {
    param (
        [string]$RawCertData,
        [string]$CertName,
        [string]$AgwName
    )

    if ([string]::IsNullOrWhiteSpace($RawCertData)) {
        return $null
    }

    # Strategy 1: Use X509Certificate2Collection on raw Base64 bytes (supports leaf certs & PKCS#7 chains)
    try {
        $certBytes = [System.Convert]::FromBase64String($RawCertData.Trim())
        $collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $collection.Import($certBytes)
        if ($collection.Count -gt 0) {
            Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 1 (X509Certificate2Collection) succeeded for cert '$CertName' on '$AgwName'."
            return $collection[0]
        }
    }
    catch {
        Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 1 failed for '$CertName': $($_.Exception.Message)"
    }

    # Strategy 2: Single X509Certificate2 DER decode
    try {
        $certBytes = [System.Convert]::FromBase64String($RawCertData.Trim())
        $singleCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
        Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 2 (single DER) succeeded for cert '$CertName' on '$AgwName'."
        return $singleCert
    }
    catch {
        Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 2 failed for '$CertName': $($_.Exception.Message)"
    }

    # Strategy 3: Strip PEM headers if present
    try {
        $pemContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($RawCertData.Trim()))
        if ($pemContent -match "-----BEGIN CERTIFICATE-----") {
            $innerB64 = ($pemContent -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
            $certBytes = [System.Convert]::FromBase64String($innerB64)
            $singleCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
            Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 3 (PEM stripped) succeeded for cert '$CertName' on '$AgwName'."
            return $singleCert
        }
    }
    catch {
        Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 3 failed for '$CertName': $($_.Exception.Message)"
    }

    # Strategy 4: Raw text PEM string
    try {
        $rawString = $RawCertData.Trim()
        if ($rawString -match "-----BEGIN CERTIFICATE-----") {
            $innerB64 = ($rawString -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
            $certBytes = [System.Convert]::FromBase64String($innerB64)
            $singleCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
            Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 4 (Raw PEM string) succeeded for cert '$CertName' on '$AgwName'."
            return $singleCert
        }
    }
    catch {
        Write-Host "[DEBUG] $(Get-Date -Format o) - Strategy 4 failed for '$CertName': $($_.Exception.Message)"
    }

    Write-Host "[WARN] $(Get-Date -Format o) - All certificate parsing strategies failed for cert '$CertName' on AppGW '$AgwName'."
    return $null
}

# =====================================================================
# FUNCTION: Inspect All Application Gateways across Subscriptions
# =====================================================================
function Get-ExpiringApplicationGatewayCertificates {
    param (
        [int]$DaysUntilExpiration,
        [string]$IncludeAlreadyExpired,
        [string]$DefaultOwnerEmail
    )

    $results = @()
    Write-Host "[INFO] $(Get-Date -Format o) - Starting Application Gateway SSL certificate discovery."

    # Use Azure Resource Graph for tenant-wide discovery
    $argQuery = @"
resources
| where type =~ 'microsoft.network/applicationgateways'
| project name, id, resourceGroup, subscriptionId, location,
          ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact), tostring(tags.ApplicationOwner))
"@

    $appGateways = @()
    try {
        $appGateways = Search-AzGraph -Query $argQuery -First 1000 -ErrorAction Stop
        Write-Host "[INFO] $(Get-Date -Format o) - Found $($appGateways.Count) Application Gateway(s) across subscriptions via Azure Resource Graph."
    }
    catch {
        Write-Host "[WARN] $(Get-Date -Format o) - Azure Resource Graph query failed ($($_.Exception.Message)). Falling back to subscription iteration."
        $subscriptions = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
            $subGws = Get-AzApplicationGateway -ErrorAction SilentlyContinue
            if ($subGws) {
                foreach ($gw in $subGws) {
                    $ownerVal = if ($gw.Tags -and $gw.Tags.ContainsKey('Owner')) { $gw.Tags['Owner'] } else { $null }
                    $appGateways += [PSCustomObject]@{
                        name           = $gw.Name
                        id             = $gw.Id
                        resourceGroup  = $gw.ResourceGroupName
                        subscriptionId = $sub.Id
                        location       = $gw.Location
                        ownerTag       = $ownerVal
                    }
                }
            }
        }
    }

    if ($null -eq $appGateways -or $appGateways.Count -eq 0) {
        Write-Host "[INFO] $(Get-Date -Format o) - No Application Gateways found in the current environment."
        return $results
    }

    $currentSubscription = ""
    $now = Get-Date

    foreach ($agw in $appGateways) {
        $agwName  = $agw.name
        $agwRg    = $agw.resourceGroup
        $subId    = if ($agw.subscriptionId) { $agw.subscriptionId } else { $agw.id.Split('/')[2] }
        $ownerVal = if (-not [string]::IsNullOrWhiteSpace($agw.ownerTag)) { $agw.ownerTag } else { $DefaultOwnerEmail }

        try {
            # Switch subscription context if necessary
            if ($currentSubscription -ne $subId) {
                Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
                $currentSubscription = $subId
                Write-Host "[INFO] $(Get-Date -Format o) - Switched Azure context to subscription: $subId"
            }

            Write-Host "[INFO] $(Get-Date -Format o) - Inspecting AppGW '$agwName' in RG '$agwRg'..."
            $fullAgw = Get-AzApplicationGateway -Name $agwName -ResourceGroupName $agwRg -ErrorAction Stop

            if (-not $fullAgw.SslCertificates -or $fullAgw.SslCertificates.Count -eq 0) {
                Write-Host "[INFO] $(Get-Date -Format o) - AppGW '$agwName' has no SSL certificates configured."
                continue
            }

            Write-Host "[INFO] $(Get-Date -Format o) - AppGW '$agwName' has $($fullAgw.SslCertificates.Count) SSL certificate(s) configured."

            # Build HTTP Listener to Certificate Name mapping
            $certListenerMap = @{}
            if ($fullAgw.HttpListeners) {
                foreach ($lst in $fullAgw.HttpListeners) {
                    if ($lst.SslCertificate -and $lst.SslCertificate.Id) {
                        $cName = $lst.SslCertificate.Id.Split('/')[-1]
                        $hVal = if ($lst.HostName) {
                            $lst.HostName
                        }
                        elseif ($lst.HostNames -and $lst.HostNames.Count -gt 0) {
                            $lst.HostNames -join ', '
                        }
                        else {
                            "Multi-site / Any"
                        }
                        $portVal = if ($lst.FrontendPort -and $lst.FrontendPort.Port) { $lst.FrontendPort.Port } else { "HTTPS" }
                        $lDesc = "$($lst.Name) (Host: $hVal, Port: $portVal)"
                        if (-not $certListenerMap.ContainsKey($cName)) {
                            $certListenerMap[$cName] = [System.Collections.Generic.List[string]]::new()
                        }
                        $certListenerMap[$cName].Add($lDesc)
                    }
                }
            }

            # Evaluate each SSL certificate
            foreach ($sslCert in $fullAgw.SslCertificates) {
                $certName = $sslCert.Name
                $listenersDesc = if ($certListenerMap.ContainsKey($certName)) {
                    $certListenerMap[$certName] -join "<br>"
                } else {
                    "<span style='color:#888;'>Unattached / No Active Listener</span>"
                }

                # Case A: Directly Uploaded Certificate (PublicCertData / Data)
                $certData = if (-not [string]::IsNullOrWhiteSpace($sslCert.PublicCertData)) { $sslCert.PublicCertData }
                            elseif (-not [string]::IsNullOrWhiteSpace($sslCert.Data)) { $sslCert.Data }
                            elseif ($sslCert.properties -and -not [string]::IsNullOrWhiteSpace($sslCert.properties.publicCertData)) { $sslCert.properties.publicCertData }
                            elseif ($sslCert.properties -and -not [string]::IsNullOrWhiteSpace($sslCert.properties.data)) { $sslCert.properties.data }
                            else { $null }

                if (-not [string]::IsNullOrWhiteSpace($certData)) {
                    $x509 = Parse-AppGwCertificate -RawCertData $certData -CertName $certName -AgwName $agwName

                    if ($x509) {
                        $expDate       = $x509.NotAfter
                        $startDate     = $x509.NotBefore
                        $daysRemaining = [int][Math]::Floor(($expDate - $now).TotalDays)
                        $subject       = $x509.Subject
                        $thumbprint    = $x509.Thumbprint
                        $issuer        = $x509.Issuer

                        Write-Host "[INFO] $(Get-Date -Format o) - AppGW: '$agwName' | Cert: '$certName' | Subject: '$subject' | Expires: $($expDate.ToString('yyyy-MM-dd HH:mm:ss UTC')) | Days Left: $daysRemaining"

                        $include = $false
                        if ($IncludeAlreadyExpired -eq 'No') {
                            if ($daysRemaining -le $DaysUntilExpiration -and $daysRemaining -ge 0) { $include = $true }
                        }
                        else {
                            if ($daysRemaining -le $DaysUntilExpiration) { $include = $true }
                        }

                        if ($include) {
                            $results += [PSCustomObject]@{
                                WorkloadSource     = 'Azure Application Gateway'
                                ApplicationGateway = $agwName
                                ResourceGroup      = $agwRg
                                SubscriptionId     = $subId
                                CertificateType    = 'Directly Uploaded (PFX/CER)'
                                CertificateName    = $certName
                                ListenersAndHosts  = $listenersDesc
                                Subject            = $subject
                                Issuer             = $issuer
                                Thumbprint         = $thumbprint
                                StartDate          = $startDate.ToString('yyyy-MM-dd HH:mm:ss')
                                EndDate            = $expDate.ToString('yyyy-MM-dd HH:mm:ss')
                                RemainingDaysCount = $daysRemaining
                                Owner              = $ownerVal
                                KeyVaultReference  = "N/A"
                            }
                        }

                        try { $x509.Dispose() } catch {}
                    }
                }
                # Case B: Key Vault-Linked Certificate
                elseif (-not [string]::IsNullOrWhiteSpace($sslCert.KeyVaultSecretId)) {
                    Write-Host "[INFO] $(Get-Date -Format o) - AppGW: '$agwName' | Cert: '$certName' is Key Vault-linked ($($sslCert.KeyVaultSecretId))."

                    $kvSecretId = $sslCert.KeyVaultSecretId
                    $vaultName  = $kvSecretId.Split('/')[2].Split('.')[0]
                    $secretName = $kvSecretId.Split('/')[4]
                    $kvExpDate  = $null
                    $kvStatus   = "Key Vault-Linked"
                    $daysRemaining = 9999

                    # Attempt to fetch Key Vault secret expiry if managed identity has permissions
                    try {
                        $kvSecret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -ErrorAction SilentlyContinue
                        if ($kvSecret -and $kvSecret.Expires) {
                            $kvExpDate = $kvSecret.Expires
                            $daysRemaining = [int][Math]::Floor(($kvExpDate - $now).TotalDays)
                            Write-Host "[INFO] $(Get-Date -Format o) - Successfully retrieved KV expiry for '$secretName': $($kvExpDate.ToString('yyyy-MM-dd HH:mm:ss UTC')) ($daysRemaining days left)."
                        }
                    }
                    catch {
                        Write-Host "[DEBUG] $(Get-Date -Format o) - Key Vault get permission not assigned or secret query skipped: $($_.Exception.Message)"
                    }

                    $include = $false
                    if ($kvExpDate) {
                        if ($IncludeAlreadyExpired -eq 'No') {
                            if ($daysRemaining -le $DaysUntilExpiration -and $daysRemaining -ge 0) { $include = $true }
                        }
                        else {
                            if ($daysRemaining -le $DaysUntilExpiration) { $include = $true }
                        }
                    }

                    if ($include) {
                        $results += [PSCustomObject]@{
                            WorkloadSource     = 'Azure Application Gateway'
                            ApplicationGateway = $agwName
                            ResourceGroup      = $agwRg
                            SubscriptionId     = $subId
                            CertificateType    = 'Key Vault Secret Reference'
                            CertificateName    = $certName
                            ListenersAndHosts  = $listenersDesc
                            Subject            = "Key Vault Secret: $secretName"
                            Issuer             = "Azure Key Vault ($vaultName)"
                            Thumbprint         = "Managed in Key Vault"
                            StartDate          = "N/A"
                            EndDate            = $kvExpDate.ToString('yyyy-MM-dd HH:mm:ss')
                            RemainingDaysCount = $daysRemaining
                            Owner              = $ownerVal
                            KeyVaultReference  = $kvSecretId
                        }
                    }
                }
                else {
                    Write-Host "[WARN] $(Get-Date -Format o) - Cert '$certName' on AppGW '$agwName' has neither PublicCertData nor KeyVaultSecretId."
                }
            }
        }
        catch {
            Write-Host "[WARN] $(Get-Date -Format o) - Failed to process Application Gateway '$agwName': $($_.Exception.Message)"
        }
    }

    Write-Host "[INFO] $(Get-Date -Format o) - Application Gateway discovery completed. Total expiring/expired certificates found: $($results.Count)."
    return $results
}

# =====================================================================
# MAIN RUNBOOK EXECUTION
# =====================================================================
try {
    Write-Host "[INFO] $(Get-Date -Format o) - Loading Runbook Configuration & Variables."

    # 1. Threshold & Inclusion Settings
    $DaysUntilExpirationVar = Get-AutomationVariable -Name "DaysUntilExpiration" -ErrorAction SilentlyContinue
    $DaysUntilExpiration = if (-not [string]::IsNullOrEmpty($DaysUntilExpirationVar)) { [int]$DaysUntilExpirationVar } else { 30 }

    $IncludeAlreadyExpiredVar = Get-AutomationVariable -Name "IncludeAlreadyExpired" -ErrorAction SilentlyContinue
    $IncludeAlreadyExpired = if (-not [string]::IsNullOrEmpty($IncludeAlreadyExpiredVar)) { $IncludeAlreadyExpiredVar } else { "Yes" }

    # 2. Default Fallback Owner Email
    $DefaultOwnerEmail = Get-AutomationVariable -Name "DefaultOwnerEmail" -ErrorAction SilentlyContinue
    if ([string]::IsNullOrEmpty($DefaultOwnerEmail)) {
        $DefaultOwnerEmail = "cloud-infrastructure-alerts@yourdomain.com"
    }

    # 3. CC & BCC Email Lists
    $CCRecipientsVar = Get-AutomationVariable -Name "EmailCC_AppGatewayCertExpiry" -ErrorAction SilentlyContinue
    $CCRecipients = @()
    if (-not [string]::IsNullOrEmpty($CCRecipientsVar)) {
        $CCRecipients = @($CCRecipientsVar.Split(",") | ForEach-Object {
            $addr = $_.Trim()
            if (-not [string]::IsNullOrEmpty($addr)) {
                @{ emailAddress = @{ address = $addr } }
            }
        })
    }

    $BCCRecipientsVar = Get-AutomationVariable -Name "EmailBCC_AppGatewayCertExpiry" -ErrorAction SilentlyContinue
    $BCCRecipients = @()
    if (-not [string]::IsNullOrEmpty($BCCRecipientsVar)) {
        $BCCRecipients = @($BCCRecipientsVar.Split(",") | ForEach-Object {
            $addr = $_.Trim()
            if (-not [string]::IsNullOrEmpty($addr)) {
                @{ emailAddress = @{ address = $addr } }
            }
        })
    }

    # 4. Microsoft Graph Mail Sender & App Registration Credentials
    $GraphSenderEmail = Get-AutomationVariable -Name "GraphSenderEmail" -ErrorAction SilentlyContinue
    if ([string]::IsNullOrEmpty($GraphSenderEmail)) {
        $GraphSenderEmail = "azure-cloud-alerts@yourdomain.com"
    }

    $GraphAppId = Get-AutomationVariable -Name "GraphAppId" -ErrorAction SilentlyContinue
    $GraphTenantId = Get-AutomationVariable -Name "GraphTenantId" -ErrorAction SilentlyContinue
    $GraphAppSecret = Get-AutomationVariable -Name "GraphAppSecret" -ErrorAction SilentlyContinue

    # Fallback to Automation Credential asset if variables are not set
    if ([string]::IsNullOrEmpty($GraphAppId) -or [string]::IsNullOrEmpty($GraphAppSecret)) {
        $credAsset = Get-AutomationPSCredential -Name "GraphMailCredential" -ErrorAction SilentlyContinue
        if ($credAsset) {
            $GraphAppId = $credAsset.UserName
            $GraphAppSecret = $credAsset.GetNetworkCredential().Password
            if ([string]::IsNullOrEmpty($GraphTenantId)) {
                $GraphTenantId = (Get-AzContext).Tenant.Id
            }
        }
    }

    Write-Host "[INFO] $(Get-Date -Format o) - Config Summary: Threshold=$DaysUntilExpiration days, IncludeExpired=$IncludeAlreadyExpired, FallbackOwner=$DefaultOwnerEmail, Sender=$GraphSenderEmail, CC Count=$($CCRecipients.Count)."

    # 5. Acquire Graph Token for Email Sending
    $graphToken = $null
    if (-not [string]::IsNullOrEmpty($GraphAppId) -and -not [string]::IsNullOrEmpty($GraphAppSecret) -and -not [string]::IsNullOrEmpty($GraphTenantId)) {
        $graphToken = Get-GraphAccessToken -AppId $GraphAppId -AppSecret $GraphAppSecret -TenantId $GraphTenantId
    }
    else {
        Write-Host "[WARN] $(Get-Date -Format o) - Graph API credentials (GraphAppId, GraphAppSecret, GraphTenantId) not fully configured. Email sending will be skipped."
    }

    # 6. Run Discovery
    $expiringCerts = Get-ExpiringApplicationGatewayCertificates `
        -DaysUntilExpiration $DaysUntilExpiration `
        -IncludeAlreadyExpired $IncludeAlreadyExpired `
        -DefaultOwnerEmail $DefaultOwnerEmail

    if ($null -eq $expiringCerts -or $expiringCerts.Count -eq 0) {
        Write-Host "[INFO] $(Get-Date -Format o) - All Application Gateway SSL certificates are healthy! No certificates expiring within $DaysUntilExpiration days. No emails needed."
        return
    }

    Write-Host "[INFO] $(Get-Date -Format o) - Found $($expiringCerts.Count) certificate(s) requiring attention. Grouping by Application Gateway and Owner..."

    # Group by Application Gateway & Owner
    $groupedResults = $expiringCerts | Group-Object -Property ApplicationGateway, Owner

    foreach ($group in $groupedResults) {
        $firstItem     = $group.Group[0]
        $agwName       = $firstItem.ApplicationGateway
        $rgName        = $firstItem.ResourceGroup
        $subId         = $firstItem.SubscriptionId
        $targetOwner   = $firstItem.Owner
        $totalCerts    = $group.Group.Count

        $expiredCount  = ($group.Group | Where-Object { $_.RemainingDaysCount -le 0 }).Count
        $urgentCount   = ($group.Group | Where-Object { $_.RemainingDaysCount -le 7  -and $_.RemainingDaysCount -gt 0 }).Count
        $soonCount     = ($group.Group | Where-Object { $_.RemainingDaysCount -le 14 -and $_.RemainingDaysCount -gt 7 }).Count
        $standardCount = ($group.Group | Where-Object { $_.RemainingDaysCount -gt 14 }).Count

        Write-Host "[INFO] $(Get-Date -Format o) - Building email for '$agwName' (Owner: $targetOwner, Items: $totalCerts, Expired: $expiredCount, Urgent: $urgentCount)..."

        # Build HTML Email
        $mailHtml  = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
        $mailHtml += '<style>'
        $mailHtml += 'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 14px; color: #24292e; line-height: 1.5; margin: 20px; }'
        $mailHtml += '.header-container { background: linear-gradient(135deg, #1f4068 0%, #162447 100%); color: white; padding: 20px 25px; border-radius: 6px 6px 0 0; }'
        $mailHtml += '.header-container h2 { margin: 0 0 6px 0; font-size: 20px; font-weight: 600; }'
        $mailHtml += '.header-container p { margin: 0; font-size: 13px; opacity: 0.9; }'
        $mailHtml += '.content-box { border: 1px solid #e1e4e8; border-top: none; padding: 25px; border-radius: 0 0 6px 6px; background-color: #ffffff; }'
        $mailHtml += 'table { border-collapse: collapse; width: 100%; margin-top: 15px; font-size: 13px; }'
        $mailHtml += 'th { background-color: #203864; color: #ffffff; padding: 10px 12px; text-align: left; font-weight: 600; border: 1px solid #203864; }'
        $mailHtml += 'td { padding: 9px 12px; border: 1px solid #dcdfe4; vertical-align: middle; }'
        $mailHtml += 'tr:nth-child(even) { background-color: #f9fbfd; }'
        $mailHtml += '.row-expired { background-color: #ffeef0 !important; font-weight: 600; color: #b31d28; }'
        $mailHtml += '.row-urgent  { background-color: #fff8c5 !important; font-weight: 600; color: #735c0f; }'
        $mailHtml += '.row-soon    { background-color: #dbedff !important; color: #0366d6; }'
        $mailHtml += '.summary-card { background-color: #f6f8fa; border: 1px solid #d1d5da; border-left: 4px solid #203864; border-radius: 4px; padding: 15px; margin: 20px 0; }'
        $mailHtml += '.summary-card ul { margin: 6px 0 0 20px; padding: 0; }'
        $mailHtml += '.summary-card li { margin-bottom: 4px; }'
        $mailHtml += '.badge { display: inline-block; padding: 2px 7px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }'
        $mailHtml += '.badge-expired { background-color: #d73a49; color: white; }'
        $mailHtml += '.badge-urgent  { background-color: #e36209; color: white; }'
        $mailHtml += '.badge-soon    { background-color: #005cc5; color: white; }'
        $mailHtml += '.badge-active  { background-color: #28a745; color: white; }'
        $mailHtml += '.action-box { background-color: #fffbf0; border: 1px solid #fae392; border-left: 4px solid #d99b00; padding: 15px; border-radius: 4px; margin-top: 20px; }'
        $mailHtml += '.action-box ol { margin: 8px 0 0 20px; padding: 0; }'
        $mailHtml += '.action-box li { margin-bottom: 5px; }'
        $mailHtml += '.footer { margin-top: 30px; font-size: 12px; color: #6a737d; border-top: 1px solid #e1e4e8; padding-top: 15px; }'
        $mailHtml += '</style></head><body>'

        # Header Section
        $mailHtml += '<div class="header-container">'
        $mailHtml += "<h2>&#9888; Application Gateway SSL Certificate Alert: $agwName</h2>"
        $mailHtml += "<p>Azure Resource Group: <b>$rgName</b> &nbsp;|&nbsp; Subscription: <b>$subId</b></p>"
        $mailHtml += '</div>'

        $mailHtml += '<div class="content-box">'
        $mailHtml += "<p>Dear <b>$targetOwner</b>,</p>"
        $mailHtml += "<p>One or more SSL/TLS certificates configured on your Azure Application Gateway <b>$agwName</b> have either expired or are approaching expiration. Please review the details below and initiate certificate rotation immediately to prevent production HTTPS outage.</p>"

        # Summary Block
        $mailHtml += '<div class="summary-card">'
        $mailHtml += "<strong>Summary for $($agwName):</strong>"
        $mailHtml += '<ul>'
        $mailHtml += "<li>Total Monitored Certificates: <b>$totalCerts</b></li>"
        if ($expiredCount -gt 0) {
            $mailHtml += "<li><span class='badge badge-expired'>ALREADY EXPIRED</span> : <b style='color:#d73a49;'>$expiredCount certificate(s)</b> (Users seeing SSL Warning/Service Interrupted!)</li>"
        }
        if ($urgentCount -gt 0) {
            $mailHtml += "<li><span class='badge badge-urgent'>EXPIRING WITHIN 7 DAYS</span> : <b style='color:#e36209;'>$urgentCount certificate(s)</b> (Critical action required)</li>"
        }
        if ($soonCount -gt 0) {
            $mailHtml += "<li><span class='badge badge-soon'>EXPIRING WITHIN 14 DAYS</span> : <b>$soonCount certificate(s)</b></li>"
        }
        if ($standardCount -gt 0) {
            $mailHtml += "<li><span class='badge badge-active'>EXPIRING IN &le; $DaysUntilExpiration DAYS</span> : <b>$standardCount certificate(s)</b></li>"
        }
        $mailHtml += '</ul></div>'

        # Table Section
        $mailHtml += '<table>'
        $mailHtml += '<thead><tr>'
        $mailHtml += '<th>Certificate Name</th>'
        $mailHtml += '<th>Type</th>'
        $mailHtml += '<th>Subject (CN) / Details</th>'
        $mailHtml += '<th>Bound HTTPS Listeners</th>'
        $mailHtml += '<th>Thumbprint</th>'
        $mailHtml += '<th>Valid From</th>'
        $mailHtml += '<th>Expiration Date (UTC)</th>'
        $mailHtml += '<th>Days Remaining</th>'
        $mailHtml += '<th>Status</th>'
        $mailHtml += '</tr></thead><tbody>'

        foreach ($certItem in ($group.Group | Sort-Object RemainingDaysCount)) {
            $daysLeft = $certItem.RemainingDaysCount

            $rowClass = ""
            $badgeHtml = ""
            if ($daysLeft -le 0) {
                $rowClass = "row-expired"
                $badgeHtml = "<span class='badge badge-expired'>EXPIRED</span>"
            }
            elseif ($daysLeft -le 7) {
                $rowClass = "row-urgent"
                $badgeHtml = "<span class='badge badge-urgent'>&le; 7 DAYS</span>"
            }
            elseif ($daysLeft -le 14) {
                $rowClass = "row-soon"
                $badgeHtml = "<span class='badge badge-soon'>&le; 14 DAYS</span>"
            }
            else {
                $badgeHtml = "<span class='badge badge-active'>ACTIVE</span>"
            }

            $mailHtml += "<tr class='$rowClass'>"
            $mailHtml += "<td><b>$($certItem.CertificateName)</b></td>"
            $mailHtml += "<td>$($certItem.CertificateType)</td>"
            $mailHtml += "<td>$($certItem.Subject)</td>"
            $mailHtml += "<td>$($certItem.ListenersAndHosts)</td>"
            $mailHtml += "<td style='font-family:monospace; font-size:11px;'>$($certItem.Thumbprint)</td>"
            $mailHtml += "<td>$($certItem.StartDate)</td>"
            $mailHtml += "<td><b>$($certItem.EndDate)</b></td>"
            $mailHtml += "<td style='text-align:center;'><b>$daysLeft</b> day(s)</td>"
            $mailHtml += "<td style='text-align:center;'>$badgeHtml</td>"
            $mailHtml += '</tr>'
        }

        $mailHtml += '</tbody></table>'

        # Action Steps for Application Gateway
        $mailHtml += '<div class="action-box">'
        $mailHtml += '<strong>&#128736; RECOMMENDED ROTATION PROCEDURE:</strong>'
        $mailHtml += '<ol>'
        $mailHtml += "<li>Log in to the <b>Azure Portal</b> and navigate to <b>Application Gateways &rarr; $agwName</b>.</li>"
        $mailHtml += '<li><b>For Directly Uploaded Certificates:</b>'
        $mailHtml += '<ul>'
        $mailHtml += '<li>Navigate to <b>Listeners</b> on the left sidebar &rarr; select the HTTPS listener associated with the domain.</li>'
        $mailHtml += '<li>Under <b>Choose a certificate</b>, select <i>Create new</i> (or update existing) and upload your new password-protected <b>.pfx</b> bundle.</li>'
        $mailHtml += '<li>Click <b>Save</b> to initiate gateway configuration sync (takes 1-3 minutes without downtime).</li>'
        $mailHtml += '</ul></li>'
        $mailHtml += '<li><b>For Key Vault-Linked Certificates:</b>'
        $mailHtml += '<ul>'
        $mailHtml += '<li>Navigate to your Azure Key Vault &rarr; <b>Certificates</b> &rarr; import or generate the new version.</li>'
        $mailHtml += '<li>Application Gateway automatically polls and updates Key Vault version within 4 hours, or you can force sync by updating the listener in portal or running <code>Set-AzApplicationGateway</code>.</li>'
        $mailHtml += '</ul></li>'
        $mailHtml += '<li>Verify the endpoint using your browser or run <code>openssl s_client -connect &lt;domain&gt;:443 -servername &lt;domain&gt;</code> to confirm the new expiry date.</li>'
        $mailHtml += '</ol></div>'

        # Footer
        $mailHtml += '<div class="footer">'
        $mailHtml += '<p>This is an automated notification from your <b>Azure Cloud Automation Platform</b>. Please do not reply directly to this email.</p>'
        $mailHtml += '<p>For assistance, open a ticket with the <b>Cloud Infrastructure &amp; Security Team</b> at <a href="mailto:cloud-team@yourdomain.com">cloud-team@yourdomain.com</a>.</p>'
        $mailHtml += '</div></div></body></html>'

        # Send Email
        if ($graphToken) {
            $subject = "ALERT: Application Gateway SSL Certificate Expiration - $agwName ($totalCerts item(s))"
            $recipients = @()

            foreach ($addr in $targetOwner.Split(",")) {
                $trimmed = $addr.Trim()
                if (-not [string]::IsNullOrEmpty($trimmed) -and $trimmed -notlike "*<*") {
                    $recipients += @{ emailAddress = @{ address = $trimmed } }
                }
            }
            if ($recipients.Count -eq 0) {
                $recipients += @{ emailAddress = @{ address = $DefaultOwnerEmail } }
            }

            Send-GraphEmail `
                -AccessToken $graphToken `
                -RecipientEmail $recipients `
                -CcRecipients $CCRecipients `
                -BccRecipients $BCCRecipients `
                -Subject $subject `
                -Body $mailHtml `
                -FromEmail $GraphSenderEmail

            Write-Host "[INFO] $(Get-Date -Format o) - Successfully dispatched alert email for '$agwName'."
        }
        else {
            Write-Host "[WARN] $(Get-Date -Format o) - Skipping email dispatch for '$agwName' because Graph token is unavailable."
        }
    }

    Write-Host "[INFO] $(Get-Date -Format o) - Application Gateway SSL certificate audit and notification run completed successfully."
}
catch {
    Write-Host "[ERROR] $(Get-Date -Format o) - Runbook execution failed: $($_.Exception.Message)"
    Write-Host "[ERROR] $(Get-Date -Format o) - Stack Trace: $($_.Exception.StackTrace)"
    throw $_
}
finally {
    Write-Host "[INFO] $(Get-Date -Format o) - Runbook execution terminated."
}
