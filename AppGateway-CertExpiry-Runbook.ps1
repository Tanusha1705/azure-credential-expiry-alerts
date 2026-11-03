<#
.SYNOPSIS
    Dedicated Azure Automation Runbook to discover and audit ALL SSL/TLS certificates
    on Azure Application Gateways across all accessible subscriptions. Accurately extracts
    the leaf (PFX endpoint/server) certificate expiration rather than the root CA,
    displays the formatted results in the console, and sends alert emails via Microsoft Graph API.

.DESCRIPTION
    Key Highlights:
      1. Accurately identifies the true LEAF / End-Entity server certificate from
         uploaded PFX / PKCS#7 chains by evaluating CA flags, self-signed root status,
         and earliest expiration date, preventing false reports of Root CA expiry.
      2. Audits ALL certificates (Expired, Urgent, Soon, Active, and Key Vault-linked)
         for complete visibility into your Application Gateway SSL landscape.
      3. Outputs the exact formatted table (CertificateName, CommonName, ExpirationDateTime,
         DaysRemaining, Status, AssociatedListeners) directly to the Azure Automation
         Test Pane and Job Output stream.
      4. Discovers Application Gateways across all accessible subscriptions.
      5. Sends color-coded HTML email reports via Microsoft Graph API.

.NOTES
    Author  : Cloud Infrastructure & Security Engineering Team
    Version : 3.0 (Accurate Leaf PFX Extraction Edition)
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
Write-Log "  AZURE APPLICATION GATEWAY SSL CERTIFICATE AUDITOR (PFX LEAF EXTRACTOR) " "INFO"
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
# 3. HELPER: Accurately Extract True Leaf (Server/Endpoint) Certificate
# =====================================================================
function Get-LeafCertificateFromBase64 {
    param (
        [string]$Base64Data,
        [string]$CertName = "ssl-cert"
    )

    if ([string]::IsNullOrWhiteSpace($Base64Data)) { return $null }
    $raw = $Base64Data.Trim()

    $candidates = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()

    # Strategy 1: Import into X509Certificate2Collection (handles DER and PKCS#7 bundles)
    try {
        $bytes = [System.Convert]::FromBase64String($raw)
        $col = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $col.Import($bytes)
        foreach ($c in $col) {
            if ($c -and $c.Thumbprint) { $candidates.Add($c) }
        }
    }
    catch { }

    # Strategy 2: If collection didn't yield certs, parse PEM blocks from decoded Base64
    if ($candidates.Count -eq 0) {
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($raw))
            $matches = [regex]::Matches($decoded, '(?ms)-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----')
            foreach ($m in $matches) {
                $innerB64 = ($m.Groups[1].Value -replace '\r','' -replace '\n','' -replace ' ','').Trim()
                $certBytes = [System.Convert]::FromBase64String($innerB64)
                $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                if ($c -and $c.Thumbprint) { $candidates.Add($c) }
            }
        }
        catch { }
    }

    # Strategy 3: Raw PEM string containing multiple certificate blocks
    if ($candidates.Count -eq 0) {
        try {
            $matches = [regex]::Matches($raw, '(?ms)-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----')
            foreach ($m in $matches) {
                $innerB64 = ($m.Groups[1].Value -replace '\r','' -replace '\n','' -replace ' ','').Trim()
                $certBytes = [System.Convert]::FromBase64String($innerB64)
                $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                if ($c -and $c.Thumbprint) { $candidates.Add($c) }
            }
        }
        catch { }
    }

    # Strategy 4: Direct single DER bytes
    if ($candidates.Count -eq 0) {
        try {
            $bytes = [System.Convert]::FromBase64String($raw)
            $c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
            if ($c -and $c.Thumbprint) { $candidates.Add($c) }
        }
        catch { }
    }

    if ($candidates.Count -eq 0) { return $null }
    if ($candidates.Count -eq 1) { return $candidates[0] }

    # =========================================================================
    # MULTI-CERT CHAIN RESOLUTION: SELECT THE TRUE ENDPOINT LEAF CERTIFICATE
    # =========================================================================
    # A complete uploaded chain often contains:
    #   - Leaf Certificate: Valid for ~1 year (earliest NotAfter), Not a CA, Subject != Issuer
    #   - Intermediate CA: Valid for 5-10 years, BasicConstraints: CA=True
    #   - Root CA: Valid for 15-25 years, BasicConstraints: CA=True, Subject == Issuer

    # Step A: Filter out Root CAs (Self-signed: Subject == Issuer)
    $nonSelfSigned = @($candidates | Where-Object { $_.Subject -ne $_.Issuer })
    if ($nonSelfSigned.Count -eq 0) {
        $nonSelfSigned = @($candidates)
    }

    # Step B: Filter out CAs using the Basic Constraints extension
    $leafCerts = @()
    foreach ($cert in $nonSelfSigned) {
        $isCA = $false
        foreach ($ext in $cert.Extensions) {
            if ($ext.Oid.Value -eq "2.5.29.19") { # Basic Constraints OID
                try {
                    $bc = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$ext
                    if ($bc.CertificateAuthority) { $isCA = $true }
                }
                catch { }
            }
        }
        if (-not $isCA) {
            $leafCerts += $cert
        }
    }

    # If explicit non-CA certificates were identified, pick the one with the earliest expiration date
    if ($leafCerts.Count -gt 0) {
        return ($leafCerts | Sort-Object NotAfter)[0]
    }

    # Step C: Fallback - in any valid PKCS#7 or PFX bundle, the end-entity leaf
    # certificate ALWAYS has the shortest validity and earliest NotAfter date.
    return ($nonSelfSigned | Sort-Object NotAfter)[0]
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
                    Name             = $gw.Name
                    ResourceGroup    = $gw.ResourceGroupName
                    SubscriptionId   = $sub.Id
                    SubscriptionName = $sub.Name
                    Location         = $gw.Location
                    OwnerTag         = $ownerTag
                    GatewayObject    = $gw
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
# 5. AUDIT ALL SSL CERTIFICATES (TRUE LEAF RESOLUTION)
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
                $descPlain = if ($hVal -and $hVal -ne "Multi-site / Any") { "$($lst.Name) ($hVal)" } else { $lst.Name }

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
            "Unattached / No Listener"
        }

        # Case 1: Directly Uploaded Certificate (PFX)
        $rawCertData = if (-not [string]::IsNullOrWhiteSpace($cert.PublicCertData)) { $cert.PublicCertData }
                       elseif (-not [string]::IsNullOrWhiteSpace($cert.Data)) { $cert.Data }
                       elseif ($cert.properties -and -not [string]::IsNullOrWhiteSpace($cert.properties.publicCertData)) { $cert.properties.publicCertData }
                       elseif ($cert.properties -and -not [string]::IsNullOrWhiteSpace($cert.properties.data)) { $cert.properties.data }
                       else { $null }

        if (-not [string]::IsNullOrWhiteSpace($rawCertData)) {
            $leafCert = Get-LeafCertificateFromBase64 -Base64Data $rawCertData -CertName $certName

            if ($leafCert) {
                $notAfterLocal = $leafCert.NotAfter
                $notAfterUtc   = $notAfterLocal.ToUniversalTime()
                $daysRemaining = [int][Math]::Floor(($notAfterLocal - $now).TotalDays)
                
                $commonName = $leafCert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                if ([string]::IsNullOrWhiteSpace($commonName)) { $commonName = $leafCert.Subject }
                
                $issuerName = $leafCert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
                if ([string]::IsNullOrWhiteSpace($issuerName)) { $issuerName = $leafCert.Issuer }
                
                $thumbprint = $leafCert.Thumbprint

                # Standard Status String matching your reference format
                $status = if ($notAfterLocal -lt $now) {
                    "EXPIRED ($([Math]::Abs($daysRemaining)) days ago)"
                }
                elseif ($daysRemaining -le 7) {
                    "EXPIRING URGENT ($daysRemaining days left)"
                }
                elseif ($daysRemaining -le 30) {
                    "EXPIRING SOON ($daysRemaining days left)"
                }
                elseif ($daysRemaining -le 90) {
                    "EXPIRING UPCOMING ($daysRemaining days left)"
                }
                else {
                    "ACTIVE ($daysRemaining days left)"
                }

                Write-Log "  [+] PFX Leaf: '$certName' | CN: '$commonName' | Expires (UTC): $($notAfterUtc.ToString('yyyy-MM-dd HH:mm:ss')) | Days: $daysRemaining | Status: $status" "INFO"

                $allCertRecords += [PSCustomObject]@{
                    SubscriptionId      = $subId
                    SubscriptionName    = $subName
                    ResourceGroupName   = $agwRg
                    AppGatewayName      = $agwName
                    CertificateName     = $certName
                    CommonName          = $commonName
                    Issuer              = $issuerName
                    Thumbprint          = $thumbprint
                    ExpirationDateTime  = $notAfterLocal.ToString("yyyy-MM-dd HH:mm:ss")
                    ExpirationDate_UTC  = $notAfterUtc.ToString("yyyy-MM-dd HH:mm:ss")
                    DaysRemaining       = $daysRemaining
                    Status              = $status
                    AssociatedListeners = $listenersPlain
                    ListenersHtml       = $listenersHtml
                    CertificateType     = "Uploaded PFX (Leaf Server Cert)"
                    Owner               = $owner
                    KeyVaultReference   = "N/A"
                }

                try { $leafCert.Dispose() } catch {}
            }
            else {
                Write-Log "  [!] Could not parse certificate binary data for '$certName' on '$agwName'." "WARN"
                $allCertRecords += [PSCustomObject]@{
                    SubscriptionId      = $subId
                    SubscriptionName    = $subName
                    ResourceGroupName   = $agwRg
                    AppGatewayName      = $agwName
                    CertificateName     = $certName
                    CommonName          = "DECODE_FAILED"
                    Issuer              = "N/A"
                    Thumbprint          = "N/A"
                    ExpirationDateTime  = "N/A"
                    ExpirationDate_UTC  = "N/A"
                    DaysRemaining       = 9999
                    Status              = "ERROR: Decode Failed"
                    AssociatedListeners = $listenersPlain
                    ListenersHtml       = $listenersHtml
                    CertificateType     = "Uploaded PFX"
                    Owner               = $owner
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

            try {
                $kvCert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $secretName -ErrorAction SilentlyContinue
                if ($kvCert) {
                    if ($kvCert.Expires) { $kvExpDate = $kvCert.Expires }
                    elseif ($kvCert.Attributes -and $kvCert.Attributes.Expires) { $kvExpDate = $kvCert.Attributes.Expires }
                }
                else {
                    $kvSec = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -ErrorAction SilentlyContinue
                    if ($kvSec -and $kvSec.Expires) { $kvExpDate = $kvSec.Expires }
                }

                if ($kvExpDate) {
                    $daysRemaining = [int][Math]::Floor(($kvExpDate - $now).TotalDays)
                    $status = if ($kvExpDate -lt $now) {
                        "EXPIRED ($([Math]::Abs($daysRemaining)) days ago)"
                    }
                    elseif ($daysRemaining -le 7) {
                        "EXPIRING URGENT ($daysRemaining days left)"
                    }
                    elseif ($daysRemaining -le 30) {
                        "EXPIRING SOON ($daysRemaining days left)"
                    }
                    else {
                        "ACTIVE ($daysRemaining days left)"
                    }
                    Write-Log "  [+] Key Vault '$secretName' expiry: $($kvExpDate.ToString('yyyy-MM-dd HH:mm:ss')) ($daysRemaining days left)." "INFO"
                }
            }
            catch { }

            $allCertRecords += [PSCustomObject]@{
                SubscriptionId      = $subId
                SubscriptionName    = $subName
                ResourceGroupName   = $agwRg
                AppGatewayName      = $agwName
                CertificateName     = $certName
                CommonName          = "KeyVault: $secretName"
                Issuer              = "Azure Key Vault ($vaultName)"
                Thumbprint          = "Managed in Key Vault"
                ExpirationDateTime  = if ($kvExpDate) { $kvExpDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Managed in KV ($vaultName)" }
                ExpirationDate_UTC  = if ($kvExpDate) { $kvExpDate.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { "Managed in KV ($vaultName)" }
                DaysRemaining       = $daysRemaining
                Status              = $status
                AssociatedListeners = $listenersPlain
                ListenersHtml       = $listenersHtml
                CertificateType     = "Key Vault Secret Reference"
                Owner               = $owner
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
# 6. OUTPUT TEST RESULTS IN EXACT REQUESTED FORMAT
# =====================================================================
Write-Output ""
Write-Output "============================= APPLICATION GATEWAY CERTIFICATE TEST RESULTS ============================="

# Format-Table matches the exact columns from Test-AppGwCertExpiry.ps1
$consoleTable = $allCertRecords | Sort-Object DaysRemaining | Format-Table -Property CertificateName, CommonName, ExpirationDateTime, DaysRemaining, Status, AssociatedListeners -AutoSize | Out-String

Write-Output $consoleTable
Write-Output "========================================================================================================"

# =====================================================================
# 7. FILTER FOR EMAIL DISPATCH
# =====================================================================
$emailRecords = @()

if ($IncludeAllCertificates -eq "Yes" -or $IncludeAllCertificates -eq "True") {
    $emailRecords = $allCertRecords
    Write-Log "Email Reporting Mode: FULL INVENTORY (Including all $($emailRecords.Count) certificates)." "INFO"
}
else {
    foreach ($rec in $allCertRecords) {
        $days = $rec.DaysRemaining
        if ($IncludeAlreadyExpired -eq "No") {
            if ($days -le $DaysUntilExpiration -and $days -ge 0) { $emailRecords += $rec }
        }
        else {
            if ($days -le $DaysUntilExpiration) { $emailRecords += $rec }
        }
    }
    Write-Log "Email Reporting Mode: EXPIRING ONLY (Filtered to $($emailRecords.Count) certificates expiring within $DaysUntilExpiration days)." "INFO"
}

if ($emailRecords.Count -eq 0 -and $SendEmailAlways -ne "Yes") {
    Write-Log "All certificates are healthy and SendEmailAlways is not set. Skipping email dispatch." "SUCCESS"
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
    $grouped = $emailRecords | Group-Object -Property AppGatewayName, Owner

    foreach ($grp in $grouped) {
        $firstItem     = $grp.Group[0]
        $agwName       = $firstItem.AppGatewayName
        $rgName        = $firstItem.ResourceGroupName
        $subName       = $firstItem.SubscriptionName
        $targetOwner   = $firstItem.Owner
        $totalCerts    = $grp.Group.Count

        $expiredCount  = ($grp.Group | Where-Object { $_.DaysRemaining -le 0 }).Count
        $urgentCount   = ($grp.Group | Where-Object { $_.DaysRemaining -le 7  -and $_.DaysRemaining -gt 0 }).Count
        $soonCount     = ($grp.Group | Where-Object { $_.DaysRemaining -le 30 -and $_.DaysRemaining -gt 7 }).Count
        $healthyCount  = ($grp.Group | Where-Object { $_.DaysRemaining -gt 30 }).Count

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
        $mailHtml += "<h2>&#128274; Application Gateway SSL Certificate Inventory: $agwName</h2>"
        $mailHtml += "<p>Resource Group: <b>$rgName</b> &nbsp;|&nbsp; Subscription: <b>$subName</b></p>"
        $mailHtml += '</div>'

        $mailHtml += '<div class="content-box">'
        $mailHtml += "<p>Dear <b>$targetOwner</b>,</p>"
        $mailHtml += "<p>Below is the accurate SSL certificate inventory and expiration audit for Azure Application Gateway <b>$agwName</b>.</p>"

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

        # Certificate Table Matching Format
        $mailHtml += '<table><thead><tr>'
        $mailHtml += '<th>Certificate Name</th>'
        $mailHtml += '<th>Common Name (Leaf Domain)</th>'
        $mailHtml += '<th>Bound HTTPS Listeners</th>'
        $mailHtml += '<th>Issuer</th>'
        $mailHtml += '<th>Thumbprint</th>'
        $mailHtml += '<th>Expiration Date (Local)</th>'
        $mailHtml += '<th>Expiration Date (UTC)</th>'
        $mailHtml += '<th>Days Remaining</th>'
        $mailHtml += '<th>Status</th>'
        $mailHtml += '</tr></thead><tbody>'

        foreach ($row in ($grp.Group | Sort-Object DaysRemaining)) {
            $d = $row.DaysRemaining
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
                $badgeCss = if ($row.CertificateType -like "*Key Vault*") { "<span class='badge badge-kv'>KEY VAULT</span>" } else { "<span class='badge badge-healthy'>ACTIVE</span>" }
            }

            $mailHtml += "<tr class='$rowCss'>"
            $mailHtml += "<td><b>$($row.CertificateName)</b></td>"
            $mailHtml += "<td><b>$($row.CommonName)</b></td>"
            $mailHtml += "<td>$($row.ListenersHtml)</td>"
            $mailHtml += "<td>$($row.Issuer)</td>"
            $mailHtml += "<td style='font-family:monospace; font-size:11px;'>$($row.Thumbprint)</td>"
            $mailHtml += "<td>$($row.ExpirationDateTime)</td>"
            $mailHtml += "<td><b>$($row.ExpirationDate_UTC)</b></td>"
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
