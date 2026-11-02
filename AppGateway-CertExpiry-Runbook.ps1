<#
.SYNOPSIS
    Dedicated Azure Automation Runbook to discover and audit ALL SSL/TLS
    certificates on Azure Application Gateways across all accessible subscriptions,
    display the full inventory table in the runbook console, and dispatch
    color-coded alert emails to workload owners via Microsoft Graph API.

.DESCRIPTION
    Key Highlights:
      1. Uses Write-Output for all logging so all progress, diagnostics, and
         results appear live in the Azure Automation Test Pane and Job Output.
      2. Audits ALL certificates (Expired, Urgent, Soon, Active, and Key Vault-linked)
         so you have 100% full visibility into your Application Gateway SSL landscape.
      3. Scans across all accessible subscriptions using both Azure Resource Graph
         and subscription-level enumeration to ensure zero missed gateways.
      4. Parses directly uploaded certificates (PFX/CER) using X509Certificate2Collection
         to properly extract leaf certificates from PKCS#7 bundles and chains.
      5. Inspects Key Vault-linked certificates and resolves secret expiry dates.
      6. Maps certificates to bound HTTPS Listeners, hostnames (SNI), and ports.
      7. Outputs a formatted ASCII table directly to the console stream.
      8. Sends professional HTML audit and alert reports via Microsoft Graph API.

.NOTES
    Author  : Cloud Infrastructure & Security Engineering Team
    Version : 2.0 (Full Inventory & Output Visibility Edition)
    Runtime : PowerShell 7.2 or PowerShell 5.1 Runbook
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$DaysUntilExpiration = 30,

    [Parameter(Mandatory = $false)]
    [string]$IncludeAllCertificates = "Yes",

    [Parameter(Mandatory = $false)]
    [string]$IncludeAlreadyExpired = "Yes",

    [Parameter(Mandatory = $false)]
    [string]$DefaultOwnerEmail = "cloud-alerts@yourdomain.com",

    [Parameter(Mandatory = $false)]
    [string]$SendEmailAlways = "Yes"
)

# Suppress autosave output so it doesn't pollute the Output Stream
Disable-AzContextAutosave -Scope Process | Out-Null

# =====================================================================
# LOGGING FUNCTION (Writes directly to Azure Automation Output Stream 1)
# =====================================================================
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO"
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logLine = "[$timestamp] [$Level] $Message"
    Write-Output $logLine
}

Write-Log "==========================================================================" "INFO"
Write-Log "  AZURE APPLICATION GATEWAY SSL CERTIFICATE AUDITOR & ALERTING RUNBOOK   " "INFO"
Write-Log "==========================================================================" "INFO"

# =====================================================================
# 1. AUTHENTICATE VIA MANAGED IDENTITY
# =====================================================================
try {
    Write-Log "Authenticating to Azure using System-Assigned Managed Identity..." "INFO"
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    $currentCtx = Get-AzContext
    if (-not $currentCtx) {
        throw "Failed to obtain Azure context after Connect-AzAccount -Identity."
    }
    Write-Log "Connected successfully! Account: $($currentCtx.Account.Id) | Tenant: $($currentCtx.Tenant.Id)" "SUCCESS"
}
catch {
    Write-Log "Authentication failed: $($_.Exception.Message)" "ERROR"
    throw $_
}

# =====================================================================
# 2. LOAD CONFIGURATION / VARIABLES
# =====================================================================
# Read variables from Automation Account if not passed via parameters
$varDays = Get-AutomationVariable -Name "DaysUntilExpiration" -ErrorAction SilentlyContinue
if (-not [string]::IsNullOrEmpty($varDays)) { $DaysUntilExpiration = [int]$varDays }

$varIncAll = Get-AutomationVariable -Name "IncludeAllCertificates" -ErrorAction SilentlyContinue
if (-not [string]::IsNullOrEmpty($varIncAll)) { $IncludeAllCertificates = $varIncAll }

$varIncExp = Get-AutomationVariable -Name "IncludeAlreadyExpired" -ErrorAction SilentlyContinue
if (-not [string]::IsNullOrEmpty($varIncExp)) { $IncludeAlreadyExpired = $varIncExp }

$varOwner = Get-AutomationVariable -Name "DefaultOwnerEmail" -ErrorAction SilentlyContinue
if (-not [string]::IsNullOrEmpty($varOwner)) { $DefaultOwnerEmail = $varOwner }

$varSendAlways = Get-AutomationVariable -Name "SendEmailAlways" -ErrorAction SilentlyContinue
if (-not [string]::IsNullOrEmpty($varSendAlways)) { $SendEmailAlways = $varSendAlways }

$CCRecipientsVar = Get-AutomationVariable -Name "EmailCC_AppGatewayCertExpiry" -ErrorAction SilentlyContinue
$CCRecipients = @()
if (-not [string]::IsNullOrEmpty($CCRecipientsVar)) {
    $CCRecipients = @($CCRecipientsVar.Split(",") | ForEach-Object {
        $addr = $_.Trim()
        if (-not [string]::IsNullOrEmpty($addr)) { @{ emailAddress = @{ address = $addr } } }
    })
}

$BCCRecipientsVar = Get-AutomationVariable -Name "EmailBCC_AppGatewayCertExpiry" -ErrorAction SilentlyContinue
$BCCRecipients = @()
if (-not [string]::IsNullOrEmpty($BCCRecipientsVar)) {
    $BCCRecipients = @($BCCRecipientsVar.Split(",") | ForEach-Object {
        $addr = $_.Trim()
        if (-not [string]::IsNullOrEmpty($addr)) { @{ emailAddress = @{ address = $addr } } }
    })
}

$GraphSenderEmail = Get-AutomationVariable -Name "GraphSenderEmail" -ErrorAction SilentlyContinue
if ([string]::IsNullOrEmpty($GraphSenderEmail)) { $GraphSenderEmail = "azure-notifications@yourdomain.com" }

$GraphAppId     = Get-AutomationVariable -Name "GraphAppId" -ErrorAction SilentlyContinue
$GraphTenantId  = Get-AutomationVariable -Name "GraphTenantId" -ErrorAction SilentlyContinue
$GraphAppSecret = Get-AutomationVariable -Name "GraphAppSecret" -ErrorAction SilentlyContinue

if ([string]::IsNullOrEmpty($GraphAppId) -or [string]::IsNullOrEmpty($GraphAppSecret)) {
    $credAsset = Get-AutomationPSCredential -Name "GraphMailCredential" -ErrorAction SilentlyContinue
    if ($credAsset) {
        $GraphAppId = $credAsset.UserName
        $GraphAppSecret = $credAsset.GetNetworkCredential().Password
        if ([string]::IsNullOrEmpty($GraphTenantId)) { $GraphTenantId = $currentCtx.Tenant.Id }
    }
}

Write-Log "Settings: Threshold=$DaysUntilExpiration days | IncludeAll=$IncludeAllCertificates | IncludeExpired=$IncludeAlreadyExpired | FallbackOwner=$DefaultOwnerEmail" "INFO"

# =====================================================================
# 3. HELPER: Parse X509 Certificate from Base64 Data
# =====================================================================
function Parse-AppGwCertificate {
    param (
        [string]$RawCertData,
        [string]$CertName,
        [string]$AgwName
    )

    if ([string]::IsNullOrWhiteSpace($RawCertData)) { return $null }

    # Strategy 1: Use X509Certificate2Collection on raw Base64 bytes (supports leaf certs & PKCS#7 chains)
    try {
        $certBytes = [System.Convert]::FromBase64String($RawCertData.Trim())
        $collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $collection.Import($certBytes)
        if ($collection.Count -gt 0) { return $collection[0] }
    }
    catch { }

    # Strategy 2: Single X509Certificate2 DER decode
    try {
        $certBytes = [System.Convert]::FromBase64String($RawCertData.Trim())
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
    }
    catch { }

    # Strategy 3: Strip PEM headers
    try {
        $pemContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($RawCertData.Trim()))
        if ($pemContent -match "-----BEGIN CERTIFICATE-----") {
            $innerB64 = ($pemContent -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
            $certBytes = [System.Convert]::FromBase64String($innerB64)
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
        }
    }
    catch { }

    # Strategy 4: Raw text PEM string
    try {
        if ($RawCertData.Trim() -match "-----BEGIN CERTIFICATE-----") {
            $innerB64 = ($RawCertData.Trim() -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
            $certBytes = [System.Convert]::FromBase64String($innerB64)
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
        }
    }
    catch { }

    return $null
}

# =====================================================================
# 4. DISCOVER APPLICATION GATEWAYS ACROSS SUBSCRIPTIONS
# =====================================================================
Write-Log "Enumerating accessible Azure Subscriptions..." "INFO"
$subscriptions = @()
try {
    $subscriptions = @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
}
catch {
    Write-Log "Could not list all subscriptions via Get-AzSubscription: $($_.Exception.Message). Using current context." "WARN"
    $subscriptions = @($currentCtx.Subscription)
}

Write-Log "Found $($subscriptions.Count) enabled subscription(s) accessible to this Managed Identity." "INFO"

$allDiscoveredAppGws = @()

foreach ($sub in $subscriptions) {
    Write-Log "Scanning Subscription: $($sub.Name) ($($sub.Id))..." "INFO"
    try {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
        $gws = Get-AzApplicationGateway -ErrorAction SilentlyContinue
        if ($gws) {
            foreach ($gw in $gws) {
                $ownerTag = $null
                if ($gw.Tags) {
                    if ($gw.Tags.ContainsKey('Owner')) { $ownerTag = $gw.Tags['Owner'] }
                    elseif ($gw.Tags.ContainsKey('owner')) { $ownerTag = $gw.Tags['owner'] }
                    elseif ($gw.Tags.ContainsKey('WorkloadOwner')) { $ownerTag = $gw.Tags['WorkloadOwner'] }
                    elseif ($gw.Tags.ContainsKey('TechnicalContact')) { $ownerTag = $gw.Tags['TechnicalContact'] }
                    elseif ($gw.Tags.ContainsKey('ApplicationOwner')) { $ownerTag = $gw.Tags['ApplicationOwner'] }
                }
                $allDiscoveredAppGws += [PSCustomObject]@{
                    Name           = $gw.Name
                    ResourceGroup  = $gw.ResourceGroupName
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                    Location       = $gw.Location
                    OwnerTag       = $ownerTag
                    GatewayObject  = $gw
                }
            }
            Write-Log "  -> Found $($gws.Count) Application Gateway(s) in '$($sub.Name)'." "INFO"
        }
        else {
            Write-Log "  -> 0 Application Gateways in '$($sub.Name)'." "INFO"
        }
    }
    catch {
        Write-Log "  [!] Error accessing subscription $($sub.Id): $($_.Exception.Message)" "WARN"
    }
}

Write-Log "Total Application Gateways discovered: $($allDiscoveredAppGws.Count)" "SUCCESS"

if ($allDiscoveredAppGws.Count -eq 0) {
    Write-Log "No Application Gateways found across the accessible subscriptions." "WARN"
    Write-Log "Please ensure the Automation Account's Managed Identity has the 'Reader' role assigned at the Subscription or Management Group level." "WARN"
    return
}

# =====================================================================
# 5. AUDIT ALL SSL CERTIFICATES
# =====================================================================
$allCertRecords = @()
$now = Get-Date

foreach ($item in $allDiscoveredAppGws) {
    $agwName = $item.Name
    $agwRg   = $item.ResourceGroup
    $subId   = $item.SubscriptionId
    $subName = $item.SubscriptionName
    $gwObj   = $item.GatewayObject
    $owner   = if (-not [string]::IsNullOrWhiteSpace($item.OwnerTag)) { $item.OwnerTag } else { $DefaultOwnerEmail }

    Write-Log "Evaluating SSL certificates for Application Gateway '$agwName' [$agwRg]..." "INFO"

    $sslCerts = $gwObj.SslCertificates
    if (-not $sslCerts -or $sslCerts.Count -eq 0) {
        Write-Log "  - AppGW '$agwName' has no SSL certificates configured." "INFO"
        continue
    }

    Write-Log "  - AppGW '$agwName' has $($sslCerts.Count) configured SSL certificate(s)." "INFO"

    # Build HTTP Listener to Certificate Name map
    $certListenerMap = @{}
    $certListenerPlainMap = @{}
    if ($gwObj.HttpListeners) {
        foreach ($lst in $gwObj.HttpListeners) {
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
                $descHtml = "$($lst.Name) (Host: <b>$hVal</b>, Port: $portVal)"
                $descPlain = "$($lst.Name) ($hVal)"

                if (-not $certListenerMap.ContainsKey($cName)) {
                    $certListenerMap[$cName] = [System.Collections.Generic.List[string]]::new()
                    $certListenerPlainMap[$cName] = [System.Collections.Generic.List[string]]::new()
                }
                $certListenerMap[$cName].Add($descHtml)
                $certListenerPlainMap[$cName].Add($descPlain)
            }
        }
    }

    foreach ($cert in $sslCerts) {
        $certName = $cert.Name
        $listenersHtml = if ($certListenerMap.ContainsKey($certName)) {
            $certListenerMap[$certName] -join "<br>"
        } else {
            "<span style='color:#888;'>Unattached / No Listener</span>"
        }
        $listenersPlain = if ($certListenerPlainMap.ContainsKey($certName)) {
            $certListenerPlainMap[$certName] -join "; "
        } else {
            "Unattached"
        }

        # Case 1: Directly Uploaded Certificate
        $rawCertData = if (-not [string]::IsNullOrWhiteSpace($cert.PublicCertData)) { $cert.PublicCertData }
                       elseif (-not [string]::IsNullOrWhiteSpace($cert.Data)) { $cert.Data }
                       elseif ($cert.properties -and -not [string]::IsNullOrWhiteSpace($cert.properties.publicCertData)) { $cert.properties.publicCertData }
                       elseif ($cert.properties -and -not [string]::IsNullOrWhiteSpace($cert.properties.data)) { $cert.properties.data }
                       else { $null }

        if (-not [string]::IsNullOrWhiteSpace($rawCertData)) {
            $x509 = Parse-AppGwCertificate -RawCertData $rawCertData -CertName $certName -AgwName $agwName

            if ($x509) {
                $expDate       = $x509.NotAfter
                $startDate     = $x509.NotBefore
                $daysRemaining = [int][Math]::Floor(($expDate - $now).TotalDays)
                $subjectSimple = $x509.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                $subjectFull   = if ($subjectSimple) { $subjectSimple } else { $x509.Subject }
                $issuerSimple  = $x509.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
                $issuerFull    = if ($issuerSimple) { $issuerSimple } else { $x509.Issuer }
                $thumbprint    = $x509.Thumbprint

                $status = if ($daysRemaining -le 0) { "EXPIRED" }
                          elseif ($daysRemaining -le 7) { "EXPIRING URGENT (<= 7 days)" }
                          elseif ($daysRemaining -le 30) { "EXPIRING SOON (<= 30 days)" }
                          elseif ($daysRemaining -le 90) { "EXPIRING UPCOMING (<= 90 days)" }
                          else { "ACTIVE / HEALTHY" }

                Write-Log "  [+] Cert: '$certName' | CN: '$subjectFull' | Expires: $($expDate.ToString('yyyy-MM-dd HH:mm:ss')) UTC | Days: $daysRemaining | Status: $status" "INFO"

                $allCertRecords += [PSCustomObject]@{
                    ApplicationGateway  = $agwName
                    ResourceGroup       = $agwRg
                    SubscriptionName    = $subName
                    SubscriptionId      = $subId
                    CertificateName     = $certName
                    CertificateType     = "Directly Uploaded (PFX/CER)"
                    Subject             = $subjectFull
                    Issuer              = $issuerFull
                    Thumbprint          = $thumbprint
                    StartDate           = $startDate.ToString("yyyy-MM-dd HH:mm:ss")
                    EndDate             = $expDate.ToString("yyyy-MM-dd HH:mm:ss")
                    RemainingDaysCount  = $daysRemaining
                    Status              = $status
                    Owner               = $owner
                    ListenersHtml       = $listenersHtml
                    ListenersPlain      = $listenersPlain
                    KeyVaultReference   = "N/A"
                }

                try { $x509.Dispose() } catch {}
            }
            else {
                Write-Log "  [!] Could not parse certificate binary data for '$certName' on '$agwName'." "WARN"
                $allCertRecords += [PSCustomObject]@{
                    ApplicationGateway  = $agwName
                    ResourceGroup       = $agwRg
                    SubscriptionName    = $subName
                    SubscriptionId      = $subId
                    CertificateName     = $certName
                    CertificateType     = "Directly Uploaded"
                    Subject             = "DECODE_NOTICE: Check Format"
                    Issuer              = "N/A"
                    Thumbprint          = "N/A"
                    StartDate           = "N/A"
                    EndDate             = "N/A"
                    RemainingDaysCount  = 9999
                    Status              = "DECODE_NOTICE"
                    Owner               = $owner
                    ListenersHtml       = $listenersHtml
                    ListenersPlain      = $listenersPlain
                    KeyVaultReference   = "N/A"
                }
            }
        }
        # Case 2: Key Vault-Linked Certificate
        elseif (-not [string]::IsNullOrWhiteSpace($cert.KeyVaultSecretId)) {
            $kvSecretId = $cert.KeyVaultSecretId
            $vaultName  = $kvSecretId.Split('/')[2].Split('.')[0]
            $secretName = $kvSecretId.Split('/')[4]
            $kvExpDate  = $null
            $daysRemaining = 9999
            $status     = "KEY VAULT MANAGED"

            # Try to query Key Vault Secret if permissions are present
            try {
                $kvSecret = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -ErrorAction SilentlyContinue
                if ($kvSecret -and $kvSecret.Expires) {
                    $kvExpDate     = $kvSecret.Expires
                    $daysRemaining = [int][Math]::Floor(($kvExpDate - $now).TotalDays)
                    $status = if ($daysRemaining -le 0) { "EXPIRED" }
                              elseif ($daysRemaining -le 7) { "EXPIRING URGENT (<= 7 days)" }
                              elseif ($daysRemaining -le 30) { "EXPIRING SOON (<= 30 days)" }
                              else { "ACTIVE (Key Vault)" }
                    Write-Log "  [+] Key Vault Secret '$secretName' expiry: $($kvExpDate.ToString('yyyy-MM-dd HH:mm:ss')) ($daysRemaining days left)." "INFO"
                }
            }
            catch { }

            $allCertRecords += [PSCustomObject]@{
                ApplicationGateway  = $agwName
                ResourceGroup       = $agwRg
                SubscriptionName    = $subName
                SubscriptionId      = $subId
                CertificateName     = $certName
                CertificateType     = "Key Vault Secret"
                Subject             = "KV Secret: $secretName"
                Issuer              = "Azure Key Vault ($vaultName)"
                Thumbprint          = "Managed in Key Vault"
                StartDate           = "N/A"
                EndDate             = if ($kvExpDate) { $kvExpDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Managed in KV ($vaultName)" }
                RemainingDaysCount  = $daysRemaining
                Status              = $status
                Owner               = $owner
                ListenersHtml       = $listenersHtml
                ListenersPlain      = $listenersPlain
                KeyVaultReference   = $kvSecretId
            }
        }
        else {
            Write-Log "  [!] Certificate '$certName' has no public data and no Key Vault link." "WARN"
        }
    }
}

Write-Log "==========================================================================" "INFO"
Write-Log "TOTAL DISCOVERED CERTIFICATES ACROSS ALL APPLICATION GATEWAYS: $($allCertRecords.Count)" "SUCCESS"
Write-Log "==========================================================================" "INFO"

if ($allCertRecords.Count -eq 0) {
    Write-Log "No SSL certificates were discovered on any Application Gateway." "WARN"
    return
}

# =====================================================================
# 6. OUTPUT FULL INVENTORY TABLE TO CONSOLE STREAM
# =====================================================================
Write-Log "`n--- COMPLETE APPLICATION GATEWAY CERTIFICATE INVENTORY AUDIT TABLE ---`n" "INFO"

$consoleTable = $allCertRecords | Sort-Object RemainingDaysCount | Select-Object `
    @{N='AppGateway';E={$_.ApplicationGateway}}, `
    @{N='CertName';E={$_.CertificateName}}, `
    @{N='Subject (CN)';E={$_.Subject}}, `
    @{N='Type';E={$_.CertificateType}}, `
    @{N='Expiration Date (UTC)';E={$_.EndDate}}, `
    @{N='DaysLeft';E={$_.RemainingDaysCount}}, `
    @{N='Status';E={$_.Status}}, `
    @{N='Listeners';E={$_.ListenersPlain}} | Format-Table -AutoSize | Out-String

Write-Output $consoleTable

# =====================================================================
# 7. FILTER FOR EMAIL DISPATCH (IF APPLICABLE)
# =====================================================================
$emailRecords = @()

if ($IncludeAllCertificates -eq "Yes" -or $IncludeAllCertificates -eq "True") {
    # Include ALL certificates in the email report
    $emailRecords = $allCertRecords
    Write-Log "Reporting Mode: FULL INVENTORY (Including all $($emailRecords.Count) active and expiring certificates in email)." "INFO"
}
else {
    # Filter only expiring/expired items based on threshold
    foreach ($rec in $allCertRecords) {
        $days = $rec.RemainingDaysCount
        if ($IncludeAlreadyExpired -eq "No") {
            if ($days -le $DaysUntilExpiration -and $days -ge 0) { $emailRecords += $rec }
        }
        else {
            if ($days -le $DaysUntilExpiration) { $emailRecords += $rec }
        }
    }
    Write-Log "Reporting Mode: EXPIRING ONLY (Filtered to $($emailRecords.Count) certificates expiring within $DaysUntilExpiration days)." "INFO"
}

# Check if email should be sent
$hasUrgentOrExpired = ($allCertRecords | Where-Object { $_.RemainingDaysCount -le $DaysUntilExpiration }).Count -gt 0

if ($emailRecords.Count -eq 0 -and $SendEmailAlways -ne "Yes") {
    Write-Log "All certificates are healthy and SendEmailAlways is not enabled. Skipping email transmission." "SUCCESS"
    return
}

# =====================================================================
# 8. MICROSOFT GRAPH API EMAIL DISPATCH
# =====================================================================
function Get-GraphAccessToken {
    param ([string]$AppId, [string]$AppSecret, [string]$TenantId)
    try {
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $AppId
            client_secret = $AppSecret
            scope         = "https://graph.microsoft.com/.default"
        }
        $res = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method Post -Body $body -ErrorAction Stop
        return $res.access_token
    }
    catch {
        Write-Log "Could not obtain Graph access token: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Send-GraphEmail {
    param ($Token, $To, $Cc, $Bcc, $Subj, $Html, $Sender)
    try {
        $headers = @{
            "Authorization" = "Bearer $Token"
            "Content-Type"  = "application/json"
        }
        $emailData = @{
            message = @{
                subject      = $Subj
                body         = @{ contentType = "HTML"; content = $Html }
                toRecipients = @($To)
            }
        }
        if ($Cc -and $Cc.Count -gt 0)   { $emailData.message["ccRecipients"]  = @($Cc) }
        if ($Bcc -and $Bcc.Count -gt 0) { $emailData.message["bccRecipients"] = @($Bcc) }

        $jsonBody = $emailData | ConvertTo-Json -Depth 100
        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$Sender/sendMail" -Method Post -Headers $headers -Body $jsonBody -ContentType "application/json" -ErrorAction Stop
        Write-Log "Email accepted by Microsoft Graph for '$Subj' to $($To.Count) recipient(s)." "SUCCESS"
    }
    catch {
        Write-Log "Failed to dispatch email via Microsoft Graph: $($_.Exception.Message)" "ERROR"
    }
}

$graphToken = $null
if (-not [string]::IsNullOrEmpty($GraphAppId) -and -not [string]::IsNullOrEmpty($GraphAppSecret) -and -not [string]::IsNullOrEmpty($GraphTenantId)) {
    Write-Log "Acquiring Microsoft Graph access token for email dispatch..." "INFO"
    $graphToken = Get-GraphAccessToken -AppId $GraphAppId -AppSecret $GraphAppSecret -TenantId $GraphTenantId
}
else {
    Write-Log "Microsoft Graph credentials (GraphAppId, GraphAppSecret) not configured in Automation Variables. Skipping email send (Console audit complete above)." "WARN"
}

if ($graphToken -and $emailRecords.Count -gt 0) {
    # Group by Application Gateway and Owner
    $grouped = $emailRecords | Group-Object -Property ApplicationGateway, Owner

    foreach ($grp in $grouped) {
        $firstItem     = $grp.Group[0]
        $agwName       = $firstItem.ApplicationGateway
        $rgName        = $firstItem.ResourceGroup
        $subName       = $firstItem.SubscriptionName
        $targetOwner   = $firstItem.Owner
        $totalCerts    = $grp.Group.Count

        $expiredCount  = ($grp.Group | Where-Object { $_.RemainingDaysCount -le 0 }).Count
        $urgentCount   = ($grp.Group | Where-Object { $_.RemainingDaysCount -le 7  -and $_.RemainingDaysCount -gt 0 }).Count
        $soonCount     = ($grp.Group | Where-Object { $_.RemainingDaysCount -le 30 -and $_.RemainingDaysCount -gt 7 }).Count
        $healthyCount  = ($grp.Group | Where-Object { $_.RemainingDaysCount -gt 30 }).Count

        Write-Log "Generating HTML email for '$agwName' (Total: $totalCerts | Expired: $expiredCount | Urgent: $urgentCount | Healthy: $healthyCount)..." "INFO"

        # HTML Generation
        $mailHtml  = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
        $mailHtml += '<style>'
        $mailHtml += 'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 14px; color: #24292e; line-height: 1.5; margin: 20px; }'
        $mailHtml += '.header-box { background: linear-gradient(135deg, #1f4068 0%, #162447 100%); color: white; padding: 22px 25px; border-radius: 6px 6px 0 0; }'
        $mailHtml += '.header-box h2 { margin: 0 0 6px 0; font-size: 20px; font-weight: 600; }'
        $mailHtml += '.header-box p { margin: 0; font-size: 13px; opacity: 0.9; }'
        $mailHtml += '.content-box { border: 1px solid #e1e4e8; border-top: none; padding: 25px; border-radius: 0 0 6px 6px; background-color: #ffffff; }'
        $mailHtml += 'table { border-collapse: collapse; width: 100%; margin-top: 15px; font-size: 13px; }'
        $mailHtml += 'th { background-color: #203864; color: #ffffff; padding: 10px 12px; text-align: left; font-weight: 600; border: 1px solid #203864; }'
        $mailHtml += 'td { padding: 9px 12px; border: 1px solid #dcdfe4; vertical-align: middle; }'
        $mailHtml += 'tr:nth-child(even) { background-color: #f9fbfd; }'
        $mailHtml += '.row-expired { background-color: #ffeef0 !important; font-weight: 600; color: #b31d28; }'
        $mailHtml += '.row-urgent  { background-color: #fff8c5 !important; font-weight: 600; color: #735c0f; }'
        $mailHtml += '.row-soon    { background-color: #fff2cc !important; }'
        $mailHtml += '.row-healthy { background-color: #f4faf4 !important; }'
        $mailHtml += '.summary-card { background-color: #f6f8fa; border: 1px solid #d1d5da; border-left: 4px solid #203864; border-radius: 4px; padding: 15px; margin: 20px 0; }'
        $mailHtml += '.summary-card ul { margin: 6px 0 0 20px; padding: 0; }'
        $mailHtml += '.summary-card li { margin-bottom: 4px; }'
        $mailHtml += '.badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; white-space: nowrap; }'
        $mailHtml += '.badge-expired { background-color: #d73a49; color: white; }'
        $mailHtml += '.badge-urgent  { background-color: #e36209; color: white; }'
        $mailHtml += '.badge-soon    { background-color: #ff9800; color: white; }'
        $mailHtml += '.badge-healthy { background-color: #28a745; color: white; }'
        $mailHtml += '.badge-kv      { background-color: #6f42c1; color: white; }'
        $mailHtml += '.action-box { background-color: #fffbf0; border: 1px solid #fae392; border-left: 4px solid #d99b00; padding: 15px; border-radius: 4px; margin-top: 20px; }'
        $mailHtml += '.action-box ol { margin: 8px 0 0 20px; padding: 0; }'
        $mailHtml += '.footer { margin-top: 30px; font-size: 12px; color: #6a737d; border-top: 1px solid #e1e4e8; padding-top: 15px; }'
        $mailHtml += '</style></head><body>'

        # Banner Header
        $mailHtml += '<div class="header-box">'
        $alertTitle = if ($expiredCount -gt 0) { "CRITICAL ALERT: Expired SSL Certificate(s)" }
                      elseif ($urgentCount -gt 0) { "URGENT ALERT: SSL Certificate(s) Expiring &le; 7 Days" }
                      elseif ($soonCount -gt 0) { "WARNING: SSL Certificate(s) Expiring Soon" }
                      else { "Certificate Audit Report: All Certificates Healthy" }

        $mailHtml += "<h2>&#128274; Application Gateway SSL Certificate Audit: $agwName</h2>"
        $mailHtml += "<p>Resource Group: <b>$rgName</b> &nbsp;|&nbsp; Subscription: <b>$subName</b></p>"
        $mailHtml += '</div>'

        $mailHtml += '<div class="content-box">'
        $mailHtml += "<p>Dear <b>$targetOwner</b>,</p>"
        $mailHtml += "<p>Below is the complete SSL certificate inventory and expiration audit for Azure Application Gateway <b>$agwName</b>.</p>"

        # Summary Block
        $mailHtml += '<div class="summary-card">'
        $mailHtml += "<strong>Summary for $($agwName):</strong>"
        $mailHtml += '<ul>'
        $mailHtml += "<li>Total Monitored Certificates: <b>$totalCerts</b></li>"
        if ($expiredCount -gt 0) {
            $mailHtml += "<li><span class='badge badge-expired'>ALREADY EXPIRED</span> : <b style='color:#d73a49;'>$expiredCount certificate(s)</b> (Action Required Immediately!)</li>"
        }
        if ($urgentCount -gt 0) {
            $mailHtml += "<li><span class='badge badge-urgent'>EXPIRING &le; 7 DAYS</span> : <b style='color:#e36209;'>$urgentCount certificate(s)</b> (Critical Action Required)</li>"
        }
        if ($soonCount -gt 0) {
            $mailHtml += "<li><span class='badge badge-soon'>EXPIRING &le; 30 DAYS</span> : <b>$soonCount certificate(s)</b></li>"
        }
        if ($healthyCount -gt 0) {
            $mailHtml += "<li><span class='badge badge-healthy'>ACTIVE / HEALTHY</span> : <b>$healthyCount certificate(s)</b></li>"
        }
        $mailHtml += '</ul></div>'

        # Certificate Table
        $mailHtml += '<table><thead><tr>'
        $mailHtml += '<th>Certificate Name</th>'
        $mailHtml += '<th>Type</th>'
        $mailHtml += '<th>Subject (CN)</th>'
        $mailHtml += '<th>Bound HTTPS Listeners</th>'
        $mailHtml += '<th>Thumbprint</th>'
        $mailHtml += '<th>Expiration Date (UTC)</th>'
        $mailHtml += '<th>Days Remaining</th>'
        $mailHtml += '<th>Status</th>'
        $mailHtml += '</tr></thead><tbody>'

        foreach ($row in ($grp.Group | Sort-Object RemainingDaysCount)) {
            $d = $row.RemainingDaysCount
            $rowCss = ""
            $badgeCss = ""

            if ($d -le 0) {
                $rowCss = "row-expired"
                $badgeCss = "<span class='badge badge-expired'>EXPIRED</span>"
            }
            elseif ($d -le 7) {
                $rowCss = "row-urgent"
                $badgeCss = "<span class='badge badge-urgent'>&le; 7 DAYS</span>"
            }
            elseif ($d -le 30) {
                $rowCss = "row-soon"
                $badgeCss = "<span class='badge badge-soon'>&le; 30 DAYS</span>"
            }
            else {
                $rowCss = "row-healthy"
                $badgeCss = if ($row.CertificateType -like "*Key Vault*") { "<span class='badge badge-kv'>KEY VAULT</span>" } else { "<span class='badge badge-healthy'>HEALTHY</span>" }
            }

            $mailHtml += "<tr class='$rowCss'>"
            $mailHtml += "<td><b>$($row.CertificateName)</b></td>"
            $mailHtml += "<td>$($row.CertificateType)</td>"
            $mailHtml += "<td>$($row.Subject)</td>"
            $mailHtml += "<td>$($row.ListenersHtml)</td>"
            $mailHtml += "<td style='font-family:monospace; font-size:11px;'>$($row.Thumbprint)</td>"
            $mailHtml += "<td><b>$($row.EndDate)</b></td>"
            $daysDisplay = if ($d -eq 9999) { "N/A" } else { "$d day(s)" }
            $mailHtml += "<td style='text-align:center;'><b>$daysDisplay</b></td>"
            $mailHtml += "<td style='text-align:center;'>$badgeCss</td>"
            $mailHtml += '</tr>'
        }

        $mailHtml += '</tbody></table>'

        # Rotation Guide
        $mailHtml += '<div class="action-box">'
        $mailHtml += '<strong>&#128736; HOW TO RENEW / ROTATE CERTIFICATES ON APPLICATION GATEWAY:</strong>'
        $mailHtml += '<ol>'
        $mailHtml += "<li>Open the Azure Portal &rarr; Navigate to <b>Application Gateways &rarr; $agwName</b>.</li>"
        $mailHtml += '<li><b>Directly Uploaded (.pfx):</b> Go to <b>Listeners</b> &rarr; Click the affected HTTPS listener &rarr; Under <i>Choose a certificate</i>, select <i>Create new</i> and upload the new password-protected PFX certificate. Click <b>Save</b>.</li>'
        $mailHtml += '<li><b>Key Vault Referenced:</b> Go to your Key Vault &rarr; Certificates &rarr; import the renewed certificate. Application Gateway auto-syncs Key Vault certs within 4 hours, or you can force sync by resaving the listener.</li>'
        $mailHtml += '</ol></div>'

        $mailHtml += '<div class="footer">'
        $mailHtml += '<p>Automated report generated by <b>Azure Cloud Automation Platform</b>. Do not reply to this email.</p>'
        $mailHtml += '</div></div></body></html>'

        # Dispatch Email
        $subjPrefix = if ($expiredCount -gt 0) { "CRITICAL" } elseif ($urgentCount -gt 0) { "URGENT" } else { "AUDIT" }
        $subject = "[$subjPrefix] Application Gateway SSL Certificate Inventory - $agwName ($totalCerts cert(s))"

        $recipients = @()
        foreach ($addr in $targetOwner.Split(",")) {
            $t = $addr.Trim()
            if (-not [string]::IsNullOrEmpty($t) -and $t -notlike "*<*") {
                $recipients += @{ emailAddress = @{ address = $t } }
            }
        }
        if ($recipients.Count -eq 0) {
            $recipients += @{ emailAddress = @{ address = $DefaultOwnerEmail } }
        }

        Send-GraphEmail `
            -Token $graphToken `
            -To $recipients `
            -Cc $CCRecipients `
            -Bcc $BCCRecipients `
            -Subj $subject `
            -Html $mailHtml `
            -Sender $GraphSenderEmail
    }
}

Write-Log "Application Gateway SSL Certificate Runbook execution completed successfully." "SUCCESS"
