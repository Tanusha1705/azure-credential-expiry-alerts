<#
.SYNOPSIS
    Azure Automation Runbook to discover expiring credentials and certificates across 
    Entra ID App Registrations and Azure Resources (Key Vaults, App Services), 
    and alert respective workload owners.
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

            # --- PROCESS SECRETS ---
            foreach ($Secret in $Secrets) {
                $StartDate = $Secret.StartDateTime
                $EndDate = $Secret.EndDateTime
                $SecretName = $Secret.DisplayName

                # Get app owners
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

                $RemainingDaysCount = ($EndDate - (Get-Date)).Days
                $UsernameToCompare = if ($Username.Contains(",")) { $Username.Split(",") } else { $Username }
                $isGTAdminUser = Compare-Object -IncludeEqual -ExcludeDifferent $UsernameToCompare $GTAdminUsers
                Write-Host "[DEBUG] $(Get-Date -Format o) - Secret '$SecretName' for '$AppName' expires on $EndDate and has $RemainingDaysCount day(s) remaining."

                # Determine if this secret should be included
                $include = $false
                if ($IncludeAlreadyExpired -eq 'No') {
                    if ($RemainingDaysCount -le $DaysUntilExpiration -and $RemainingDaysCount -ge 0 -and $isGTAdminUser) {
                        $include = $true
                    }
                }
                elseif ($IncludeAlreadyExpired -eq 'Yes') {
                    if ($RemainingDaysCount -le $DaysUntilExpiration -and $isGTAdminUser) {
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

                # Get app owners
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

                $RemainingDaysCount = ($EndDate - (Get-Date)).Days
                $UsernameToCompare = if ($Username.Contains(",")) { $Username.Split(",") } else { $Username }
                $isGTAdminUser = Compare-Object -IncludeEqual -ExcludeDifferent $UsernameToCompare $GTAdminUsers
                Write-Host "[DEBUG] $(Get-Date -Format o) - Certificate '$CertName' for '$AppName' expires on $EndDate and has $RemainingDaysCount day(s) remaining."

                # Determine if this certificate should be included
                $include = $false
                if ($IncludeAlreadyExpired -eq 'No') {
                    if ($RemainingDaysCount -le $DaysUntilExpiration -and $RemainingDaysCount -ge 0 -and $isGTAdminUser) {
                        $include = $true
                    }
                }
                elseif ($IncludeAlreadyExpired -eq 'Yes') {
                    if ($RemainingDaysCount -le $DaysUntilExpiration -and $isGTAdminUser) {
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

        Write-Host "[INFO] $(Get-Date -Format o) - Discovery completed. Found $($Logs.Count) matching secret/certificate record(s)."
        return $Logs
    }
    catch {
        Write-Host "[ERROR] $(Get-Date -Format o) - Failed to fetch expiring app registration details (function Get-ExpiringAppRegistrations): $($_.Exception.Message)"
        return $null
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
        Write-Host "[INFO] $(Get-Date -Format o) - Retrieved $($AzureResourceLogs.Count) expiring Azure resource certificate(s)."
        return $AzureResourceLogs
    }
    catch {
        Write-Host "[WARN] $(Get-Date -Format o) - Azure Resource Graph certificate check encountered an issue: $($_.Exception.Message)"
        return $AzureResourceLogs
    }
}

# =====================================================================
# MAIN SCRIPT LOGIC
# =====================================================================
try {
    Write-Host "[INFO] $(Get-Date -Format o) - Entered main runbook logic."
    $DaysUntilExpiration = 30
    $IncludeAlreadyExpired = "No"
    $WarningPreference = 'SilentlyContinue'

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

    # Get the list of all app registrations expiring in the configured window
    $expiringAppRegistrations = Get-ExpiringAppRegistrations -DaysUntilExpiration $DaysUntilExpiration -IncludeAlreadyExpired $IncludeAlreadyExpired -GTAdminUsers $GTAdminUsers

    # Get expiring Azure resource certificates (Resource Graph)
    $defaultFallbackOwner = "xxxx-fallback-owner@yourdomain.com"
    $expiringAzureCerts = Get-ExpiringAzureResourceCerts -DaysUntilExpiration $DaysUntilExpiration -IncludeAlreadyExpired $IncludeAlreadyExpired -DefaultOwnerEmail $defaultFallbackOwner

    # Combine all records
    $allExpiringRecords = @()
    if ($expiringAppRegistrations) { $allExpiringRecords += $expiringAppRegistrations }
    if ($expiringAzureCerts) { $allExpiringRecords += $expiringAzureCerts }

    # =================================================================
    # EMAIL STYLING (consistent across all emails)
    # =================================================================
    $style = @"
<style>
    body {
        font-family: 'Calibri', 'sans-serif';
        font-size: 14px;
        color: #333333;
    }
    table {
        border: 1px solid #cccccc;
        border-collapse: collapse;
        mso-table-lspace: 0pt;
        mso-table-rspace: 0pt;
        width: 100%;
    }
    th {
        border: 1px solid #cccccc;
        background: #0472C4;
        color: white;
        padding: 8px;
        text-align: left;
        font-weight: bold;
    }
    td {
        border: 1px solid #cccccc;
        padding: 8px;
    }
    tr:nth-child(even) {
        background-color: #f2f2f2;
    }
    .crtexp {
        background-color: #ffcccc;
        color: #c00000;
        font-weight: bold;
    }
    .crtsn {
        background-color: #cce5ff;
        color: #0070c0;
        font-weight: bold;
    }
    .crtcn {
        background-color: #fff2cc;
        color: #ff9800;
        font-weight: bold;
    }
    .summary {
        background-color: #e7e6e6;
        padding: 10px;
        margin-top: 15px;
        border-left: 4px solid #0472C4;
    }
    .footer {
        font-size: 12px;
        color: #666666;
        margin-top: 20px;
    }
</style>
"@

    # =================================================================
    # CHECK IF ANY RECORDS FOUND
    # =================================================================
    if ($null -eq $allExpiringRecords -or $allExpiringRecords.Count -eq 0) {
        Write-Host "[INFO] $(Get-Date -Format o) - No app registration or Azure certificate secret/certificate expiring in the next $DaysUntilExpiration day(s)."
    }
    else {
        Write-Host "[INFO] $(Get-Date -Format o) - Preparing notifications for $($allExpiringRecords.Count) matching record(s)."

        # GROUP BY APPLICATION/RESOURCE NAME AND OWNER
        $groupedByAppAndOwner = $allExpiringRecords | Group-Object -Property ApplicationName, Owner
        Write-Host "[INFO] $(Get-Date -Format o) - Records grouped into $($groupedByAppAndOwner.Count) email(s) to send."

        # PROCESS EACH GROUP AND SEND EMAIL
        foreach ($group in $groupedByAppAndOwner) {
            $mailbody = ""
            $recipientEmail = @()

            # Get details from first record in group
            $firstRecord = $group.Group[0]
            $appName = $firstRecord.'ApplicationName'
            $appID_Display = $firstRecord.'ApplicationID'
            $ownerEmail = $firstRecord.'Owner'
            $ownerDisplay = $firstRecord.'OwnerDisplayName'

            Write-Host "[INFO] $(Get-Date -Format o) - Processing group: Resource/App='$appName', Owner='$ownerDisplay', Records=$($group.Group.Count)."

            # BUILD EMAIL BODY
            $mailbody += '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">' + $style + '</head><body>'

            # Email Introduction
            $mailbody += '<p style="font-size: 16px; font-weight: bold; color: #c00000;">'
            $mailbody += 'ACTION REQUIRED: Azure Credential & Certificate Expiration Alert'
            $mailbody += '</p>'
            $mailbody += '<p>'
            $mailbody += 'The following Azure workload resource / application credential(s) or certificate(s) owned by you are expiring soon:'
            $mailbody += '</p>'

            # Start table
            $mailbody += '<p><table>'
            $mailbody += '<tr>'
            $mailbody += '<th>Resource / App ID</th>'
            $mailbody += '<th>Name</th>'
            $mailbody += '<th>Source</th>'
            $mailbody += '<th>Credential Type</th>'
            $mailbody += '<th>Item Name</th>'
            $mailbody += '<th>Start Date</th>'
            $mailbody += '<th>End Date</th>'
            $mailbody += '<th>Days Remaining</th>'
            $mailbody += '</tr>'

            # ADD ALL SECRETS/CERTIFICATES FOR THIS WORKLOAD+OWNER COMBINATION
            foreach ($record in ($group.Group | Sort-Object RemainingDaysCount)) {
                $daysRemaining = $record.RemainingDaysCount
                $credType = $record.CredentialType
                $source = $record.WorkloadSource

                # Determine CSS class based on days remaining
                $rowClass = ""
                if ($daysRemaining -le 0) {
                    $rowClass = "crtexp"  # Red - already expired
                }
                elseif ($daysRemaining -le 7) {
                    $rowClass = "crtsn"   # Blue - expiring very soon
                }
                elseif ($daysRemaining -le 14) {
                    $rowClass = "crtcn"   # Orange - expiring soon
                }

                # Determine credential name and dates
                if ($credType -eq "Secret") {
                    $credName = $record.'Secret Name'
                    $startDate = $record.'Secret Start Date'
                    $endDate = $record.'Secret End Date'
                }
                else {
                    $credName = $record.'Certificate Name'
                    $startDate = $record.'Certificate Start Date'
                    $endDate = $record.'Certificate End Date'
                }

                # Add row to table
                $mailbody += "<tr class='$rowClass'>"
                $mailbody += "<td>" + $record.'ApplicationID' + "</td>"
                $mailbody += "<td>" + $record.'ApplicationName' + "</td>"
                $mailbody += "<td>" + $source + "</td>"
                $mailbody += "<td>" + $credType + "</td>"
                $mailbody += "<td>" + $credName + "</td>"
                $mailbody += "<td>" + $startDate + "</td>"
                $mailbody += "<td>" + $endDate + "</td>"

                # Highlight days remaining
                if ($daysRemaining -le 0) {
                    $mailbody += "<td class='crtexp'>EXPIRED</td>"
                }
                elseif ($daysRemaining -le 7) {
                    $mailbody += "<td class='crtsn'>$daysRemaining day(s)</td>"
                }
                elseif ($daysRemaining -le 14) {
                    $mailbody += "<td class='crtcn'>$daysRemaining day(s)</td>"
                }
                else {
                    $mailbody += "<td>$daysRemaining day(s)</td>"
                }
                $mailbody += "</tr>"
            }

            # Close table
            $mailbody += '</table></p>'

            # ADD SUMMARY
            $totalCreds = $group.Group.Count
            $expiredCount = ($group.Group | Where-Object { $_.RemainingDaysCount -le 0 }).Count
            $urgentCount = ($group.Group | Where-Object { $_.RemainingDaysCount -le 7 -and $_.RemainingDaysCount -gt 0 }).Count
            $soonCount = ($group.Group | Where-Object { $_.RemainingDaysCount -le 14 -and $_.RemainingDaysCount -gt 7 }).Count

            $mailbody += '<div class="summary">'
            $mailbody += "<p><b>Summary for $appName:</b></p>"
            $mailbody += '<ul>'
            $mailbody += "<li>Total Credentials/Certificates: $totalCreds</li>"
            if ($expiredCount -gt 0) {
                $mailbody += "<li><b style='color: #c00000;'>Already Expired: $expiredCount</b></li>"
            }
            if ($urgentCount -gt 0) {
                $mailbody += "<li><b style='color: #0070c0;'>Expiring within 7 days: $urgentCount</b></li>"
            }
            if ($soonCount -gt 0) {
                $mailbody += "<li><b style='color: #ff9800;'>Expiring within 14 days: $soonCount</b></li>"
            }
            $mailbody += '</ul>'
            $mailbody += '</div>'

            # Action Items
            $mailbody += '<p style="margin-top: 15px;"><b>ACTION REQUIRED:</b></p>'
            $mailbody += '<p>'
            $mailbody += 'Please rotate these credentials or renew certificates as soon as possible to avoid service disruption.'
            $mailbody += '<br><b>Steps to rotate/renew credentials:</b>'
            $mailbody += '<ol>'
            $mailbody += "<li>Navigate to Azure Portal &rarr; locate the affected resource or App Registration: <b>$appName</b></li>"
            $mailbody += '<li>For App Registrations: Navigate to <b>Certificates &amp; secrets</b></li>'
            $mailbody += '<li>Generate a new secret/certificate before the current one expires</li>'
            $mailbody += '<li>Update your application / pipeline configuration to use the newly created credential</li>'
            $mailbody += '<li>Delete or revoke old credentials after cutover confirmation</li>'
            $mailbody += '</ol>'
            $mailbody += '</p>'

            # Color Legend
            $mailbody += '<p style="margin-top: 15px;"><b>Color Legend:</b></p>'
            $mailbody += '<ul>'
            $mailbody += '<li><span style="background-color: #ffcccc; padding: 3px 6px;">Red Background</span> = Already Expired (0 days)</li>'
            $mailbody += '<li><span style="background-color: #cce5ff; padding: 3px 6px;">Blue Background</span> = Expiring Very Soon (&le; 7 days)</li>'
            $mailbody += '<li><span style="background-color: #fff2cc; padding: 3px 6px;">Orange Background</span> = Expiring Soon (&le; 14 days)</li>'
            $mailbody += '</ul>'

            # Footer
            $mailbody += '<div class="footer">'
            $mailbody += '<p>This is an auto-generated email. Please do not reply directly to this message.</p>'
            $mailbody += '<p>If you have any questions regarding this notification, please contact:'
            $mailbody += '<br>&nbsp;&nbsp;&nbsp;&nbsp;<a href="mailto:xxxx-team-alerts@yourdomain.com">xxxx-team-alerts@yourdomain.com</a>'
            $mailbody += '<br>&nbsp;&nbsp;&nbsp;&nbsp;<a href="mailto:xxxx-lead-alerts@yourdomain.com">xxxx-lead-alerts@yourdomain.com</a></p>'
            $mailbody += '<p>Regards,<br><b>xxxx Cloud Infrastructure Team</b></p>'
            $mailbody += '</div>'
            $mailbody += '</body></html>'

            # PREPARE EMAIL PARAMETERS
            $sender = "xxxx-notification@yourdomain.com"
            $subject = "ALERT: Azure Credential/Certificate Expiration - $appName ($($group.Group.Count) item(s))"

            Write-Host "[INFO] $(Get-Date -Format o) - Preparing email for '$appName' with $($group.Group.Count) item(s)."

            # Extract TO recipients
            $mailRecipients = $ownerEmail.Split(",")
            foreach ($recipientAddr in $mailRecipients) {
                $trimmedAddr = $recipientAddr.Trim()
                if (-not [string]::IsNullOrEmpty($trimmedAddr) -and $trimmedAddr -notlike "*<*") {
                    $recipientEmail += @{
                        emailAddress = @{
                            address = $trimmedAddr
                        }
                    }
                }
            }

            # If no valid recipient email found from owner field, fallback to default team email
            if ($recipientEmail.Count -eq 0) {
                $recipientEmail += @{
                    emailAddress = @{
                        address = $defaultFallbackOwner
                    }
                }
            }

            # SEND EMAIL WITH CC AND BCC
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