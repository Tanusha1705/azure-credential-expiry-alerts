<#
.SYNOPSIS
    Discovers, inspects, and exports ALL SSL/TLS certificates configured in Azure Application Gateways
    (specifically certificates updated/uploaded directly in the Application Gateway itself as PFX)
    across all accessible subscriptions into a detailed CSV file.

.DESCRIPTION
    Key Highlights:
      1. Accurately extracts the true LEAF / End-Entity server certificate from uploaded PFX / PKCS#7 chains
         by filtering out Root CAs and Intermediate CAs (via Basic Constraints OID 2.5.29.19 and validity analysis),
         preventing false reports of Root CA expiry.
      2. Audits all certificate states: EXPIRED, EXPIRING URGENT (<= 7 days), EXPIRING SOON (<= 30 days),
         EXPIRING UPCOMING (<= 90 days), and ACTIVE (> 90 days).
      3. Maps each certificate to its associated HTTP/HTTPS listeners, hostnames (SNI), ports, and routing rules.
      4. Exports all required fields to a structured CSV file (Subscription, RG, AppGateway, CommonName,
         Subject, Issuer, SerialNumber, Thumbprint, Signature Algorithm, ValidFrom, ExpirationDateTime [Local & UTC],
         DaysRemaining, Status, AssociatedListeners, KeyVaultSecretId, Tags, Scan Timestamp).
      5. Supports scanning entire tenant, specific Management Groups, specific Subscriptions, or targeted Resource Groups.
      6. Formats and displays an interactive summary table on the console and returns PSCustomObjects to the pipeline.

.PARAMETER SubscriptionIds
    Optional list of specific subscription GUIDs or names to scan. If omitted, scans all accessible subscriptions.

.PARAMETER ManagementGroupId
    Optional Management Group ID(s) or Display Name(s) to recursively discover and scan all child subscriptions.

.PARAMETER ResourceGroupName
    Optional target Resource Group name to filter Application Gateways.

.PARAMETER AppGatewayName
    Optional target Application Gateway name to filter.

.PARAMETER IncludeKeyVaultCertificates
    Switch to also include Azure Key Vault-referenced certificates in the audit.
    By default, focuses on directly uploaded/updated PFX certificates in Application Gateway itself.

.PARAMETER DaysUntilExpiration
    Optional threshold in days to flag upcoming expirations (default is 30 days).

.PARAMETER CsvPath
    Optional destination path for the exported CSV file.
    Default: .\AppGateway-CertExpiry-<timestamp>.csv

.EXAMPLE
    # Scan all Application Gateways across all accessible subscriptions and export to CSV:
    .\Export-AppGwCertExpiry.ps1

.EXAMPLE
    # Scan a specific subscription:
    .\Export-AppGwCertExpiry.ps1 -SubscriptionIds "242eb51a-ca35-493b-b2d7-941aa572c048"

.EXAMPLE
    # Scan a specific Application Gateway in a Resource Group:
    .\Export-AppGwCertExpiry.ps1 -ResourceGroupName "my-rg" -AppGatewayName "my-appgw-01"

.EXAMPLE
    # Include Key Vault-referenced certificates as well:
    .\Export-AppGwCertExpiry.ps1 -IncludeKeyVaultCertificates -CsvPath "C:\Reports\AppGw-AllCerts.csv"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string[]]$ManagementGroupId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$AppGatewayName,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeKeyVaultCertificates = $true,

    [Parameter(Mandatory = $false)]
    [int]$DaysUntilExpiration = 30,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

# Suppress Azure context autosave noise
Disable-AzContextAutosave -Scope Process | Out-Null

$scanStartTime = Get-Date
$scanTimestampUtc = $scanStartTime.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")

# =============================================================================
# BANNER
# =============================================================================
Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "    AZURE APPLICATION GATEWAY SSL/TLS CERTIFICATE AUDIT & EXPORT         " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  Target Workload : Azure Application Gateway (Uploaded PFX Leaf Certificates)" -ForegroundColor Yellow
Write-Host "  Include KV Certs: $(if ($IncludeKeyVaultCertificates) { 'Yes' } else { 'No (Uploaded PFX Focus)' })" -ForegroundColor Gray
Write-Host "  Started At      : $($scanStartTime.ToString('yyyy-MM-dd HH:mm:ss')) (Local)" -ForegroundColor Gray
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 1. AUTHENTICATION CHECK
# =============================================================================
$currentCtx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $currentCtx -or -not $currentCtx.Account) {
    Write-Host "[AUTH] No active Azure session found. Initiating Connect-AzAccount..." -ForegroundColor Yellow
    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null
        $currentCtx = Get-AzContext
    }
    catch {
        Write-Error "[AUTH ERROR] Failed to connect to Azure: $($_.Exception.Message)"
        return
    }
}

Write-Host "[AUTH] Signed in as : $($currentCtx.Account.Id)" -ForegroundColor Green
Write-Host "[AUTH] Tenant ID    : $($currentCtx.Tenant.Id)" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 2. RESOLVE TARGET SUBSCRIPTIONS
# =============================================================================
function Get-MgSubscriptionIds {
    param([object]$MgNode)
    $ids = [System.Collections.Generic.List[string]]::new()
    if ($MgNode.Children) {
        foreach ($child in $MgNode.Children) {
            if ($child.Type -match 'subscriptions' -and $child.Name) {
                $ids.Add($child.Name)
            }
            elseif ($child.Type -match 'managementGroups') {
                try {
                    $subMg = Get-AzManagementGroup -GroupId $child.Name -Expand -Recurse -ErrorAction SilentlyContinue
                    if ($subMg) {
                        foreach ($subId in (Get-MgSubscriptionIds -MgNode $subMg)) {
                            if (-not $ids.Contains($subId)) { $ids.Add($subId) }
                        }
                    }
                }
                catch { }
            }
        }
    }
    return $ids
}

$targetSubscriptions = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    Write-Host "[SCOPE] Resolving explicitly specified subscriptions..." -ForegroundColor Cyan
    foreach ($s in $SubscriptionIds) {
        $subObj = Get-AzSubscription -SubscriptionId $s -ErrorAction SilentlyContinue
        if (-not $subObj) {
            $subObj = Get-AzSubscription -SubscriptionName $s -ErrorAction SilentlyContinue
        }
        if ($subObj) {
            $targetSubscriptions.Add([PSCustomObject]@{ Id = $subObj.Id; Name = $subObj.Name })
            Write-Host "  -> Added subscription: $($subObj.Name) ($($subObj.Id))" -ForegroundColor Gray
        }
        else {
            Write-Warning "Could not find subscription: '$s'"
        }
    }
}
elseif ($ManagementGroupId -and $ManagementGroupId.Count -gt 0) {
    Write-Host "[SCOPE] Resolving subscriptions from Management Group(s)..." -ForegroundColor Cyan
    $discoveredIds = [System.Collections.Generic.List[string]]::new()
    foreach ($mgId in $ManagementGroupId) {
        try {
            $mg = Get-AzManagementGroup -GroupId $mgId -Expand -Recurse -ErrorAction SilentlyContinue
            if (-not $mg) {
                $mg = Get-AzManagementGroup -GroupName $mgId -Expand -Recurse -ErrorAction SilentlyContinue
            }
            if ($mg) {
                $childSubs = Get-MgSubscriptionIds -MgNode $mg
                foreach ($cs in $childSubs) {
                    if (-not $discoveredIds.Contains($cs)) { $discoveredIds.Add($cs) }
                }
            }
            else {
                Write-Warning "Could not find Management Group: '$mgId'"
            }
        }
        catch {
            Write-Warning "Error resolving Management Group '$mgId': $($_.Exception.Message)"
        }
    }

    foreach ($subId in $discoveredIds) {
        $subObj = Get-AzSubscription -SubscriptionId $subId -ErrorAction SilentlyContinue
        if ($subObj) {
            $targetSubscriptions.Add([PSCustomObject]@{ Id = $subObj.Id; Name = $subObj.Name })
        }
    }
}
else {
    Write-Host "[SCOPE] Discovering all accessible subscriptions in tenant..." -ForegroundColor Cyan
    $allSubs = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' }
    foreach ($s in $allSubs) {
        $targetSubscriptions.Add([PSCustomObject]@{ Id = $s.Id; Name = $s.Name })
    }
}

if ($targetSubscriptions.Count -eq 0) {
    Write-Error "[SCOPE ERROR] No enabled subscriptions found in the specified scope."
    return
}

Write-Host "[SCOPE] Total subscriptions to scan: $($targetSubscriptions.Count)" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 3. HELPER: ACCURATELY EXTRACT TRUE LEAF (SERVER / END-ENTITY) CERTIFICATE
# =============================================================================
function Get-LeafCertificateFromBase64 {
    param (
        [string]$Base64Data,
        [string]$CertName = "ssl-cert"
    )

    if ([string]::IsNullOrWhiteSpace($Base64Data)) { return $null }
    $raw = $Base64Data.Trim()

    $candidates = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()

    # Strategy 1: Import into X509Certificate2Collection (handles DER, PKCS#7 and multi-cert bundles)
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
                $innerB64 = ($m.Groups[1].Value -replace '\r', '' -replace '\n', '' -replace ' ', '').Trim()
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
                $innerB64 = ($m.Groups[1].Value -replace '\r', '' -replace '\n', '' -replace ' ', '').Trim()
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

    # Multiple certs found in chain:
    # 1. Filter out self-signed Root CAs (Subject == Issuer)
    $nonSelfSigned = @($candidates | Where-Object { $_.Subject -ne $_.Issuer })
    if ($nonSelfSigned.Count -eq 0) { $nonSelfSigned = @($candidates) }

    # 2. Filter out Intermediate CAs via Basic Constraints extension (OID 2.5.29.19)
    $leafCerts = @()
    foreach ($cert in $nonSelfSigned) {
        $isCA = $false
        foreach ($ext in $cert.Extensions) {
            if ($ext.Oid.Value -eq "2.5.29.19") {
                try {
                    $bc = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$ext
                    if ($bc.CertificateAuthority) { $isCA = $true }
                }
                catch { }
            }
        }
        if (-not $isCA) { $leafCerts += $cert }
    }

    # 3. Server leaf cert has the earliest expiration date / shortest validity in the chain
    if ($leafCerts.Count -gt 0) {
        return ($leafCerts | Sort-Object NotAfter)[0]
    }

    # Fallback if no cert without CA flag: take earliest expiration date
    return ($nonSelfSigned | Sort-Object NotAfter)[0]
}

# =============================================================================
# 4. DISCOVER APPLICATION GATEWAYS AND COLLECT CERTIFICATES
# =============================================================================
$allCertRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$now = Get-Date
$appGwCounter = 0

foreach ($sub in $targetSubscriptions) {
    $subId = $sub.Id
    $subName = $sub.Name

    try {
        Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Cannot set subscription context to '$subName' ($subId): $($_.Exception.Message)"
        continue
    }

    Write-Host "[SUB] Scanning: $subName ($subId)..." -ForegroundColor Cyan

    $appGws = @()
    try {
        if (-not [string]::IsNullOrWhiteSpace($ResourceGroupName) -and -not [string]::IsNullOrWhiteSpace($AppGatewayName)) {
            $agwItem = Get-AzApplicationGateway -ResourceGroupName $ResourceGroupName -Name $AppGatewayName -ErrorAction SilentlyContinue
            if ($agwItem) { $appGws = @($agwItem) }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($ResourceGroupName)) {
            $appGws = @(Get-AzApplicationGateway -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue)
        }
        else {
            $appGws = @(Get-AzApplicationGateway -ErrorAction SilentlyContinue)
            if (-not [string]::IsNullOrWhiteSpace($AppGatewayName)) {
                $appGws = @($appGws | Where-Object { $_.Name -eq $AppGatewayName })
            }
        }
    }
    catch {
        Write-Warning "Error listing Application Gateways in '$subName': $($_.Exception.Message)"
    }

    if (-not $appGws -or $appGws.Count -eq 0) {
        Write-Host "  -> No Application Gateways found in this subscription." -ForegroundColor DarkGray
        continue
    }

    foreach ($agw in $appGws) {
        $appGwCounter++
        $agwName = $agw.Name
        $agwRg = $agw.ResourceGroupName
        $agwLocation = $agw.Location
        $agwState = if ($agw.OperationalState) { $agw.OperationalState } else { $agw.ProvisioningState }

        # Convert tags to formatted string
        $tagStr = ""
        if ($agw.Tags -and $agw.Tags.Count -gt 0) {
            $tagParts = @()
            foreach ($k in $agw.Tags.Keys) { $tagParts += "$k=$($agw.Tags[$k])" }
            $tagStr = $tagParts -join "; "
        }

        Write-Host "  [+] AppGateway: $agwName (RG: $agwRg | Region: $agwLocation)" -ForegroundColor Green

        # Build mapping of certificate name -> HTTPS listener details & hostnames
        $certListenerMap = @{}
        $certHostnamesMap = @{}
        $certListenerCountMap = @{}

        if ($agw.HttpListeners) {
            foreach ($lst in $agw.HttpListeners) {
                $certNameRef = $null
                if ($lst.SslCertificate -and $lst.SslCertificate.Id) {
                    $certNameRef = $lst.SslCertificate.Id.Split('/')[-1]
                }

                if ($certNameRef) {
                    $hosts = [System.Collections.Generic.List[string]]::new()
                    if (-not [string]::IsNullOrWhiteSpace($lst.HostName)) {
                        $hosts.Add($lst.HostName)
                    }
                    if ($lst.HostNames -and $lst.HostNames.Count -gt 0) {
                        foreach ($hn in $lst.HostNames) {
                            if (-not [string]::IsNullOrWhiteSpace($hn) -and -not $hosts.Contains($hn)) {
                                $hosts.Add($hn)
                            }
                        }
                    }

                    $hostDisplay = if ($hosts.Count -gt 0) { $hosts -join ", " } else { "Wildcard / Any (*)" }
                    $listenerDesc = "$($lst.Name) [$hostDisplay]"

                    if (-not $certListenerMap.ContainsKey($certNameRef)) {
                        $certListenerMap[$certNameRef] = [System.Collections.Generic.List[string]]::new()
                        $certHostnamesMap[$certNameRef] = [System.Collections.Generic.List[string]]::new()
                        $certListenerCountMap[$certNameRef] = 0
                    }

                    $certListenerMap[$certNameRef].Add($listenerDesc)
                    $certListenerCountMap[$certNameRef]++
                    foreach ($h in $hosts) {
                        if (-not $certHostnamesMap[$certNameRef].Contains($h)) {
                            $certHostnamesMap[$certNameRef].Add($h)
                        }
                    }
                }
            }
        }

        # Inspect SSL certificates configured on the Application Gateway
        if (-not $agw.SslCertificates -or $agw.SslCertificates.Count -eq 0) {
            Write-Host "      No SSL certificates configured on this gateway." -ForegroundColor DarkGray
            continue
        }

        foreach ($cert in $agw.SslCertificates) {
            $certName = $cert.Name
            $isKvLinked = -not [string]::IsNullOrWhiteSpace($cert.KeyVaultSecretId)

            # Check if user only wants uploaded PFX certificates
            if ($isKvLinked -and -not $IncludeKeyVaultCertificates) {
                Write-Host "      [SKIP] '$certName' is Key Vault referenced (use -IncludeKeyVaultCertificates to include)." -ForegroundColor DarkGray
                continue
            }

            # Listeners info
            $listenersPlain = if ($certListenerMap.ContainsKey($certName)) {
                $certListenerMap[$certName] -join " | "
            }
            else {
                "Unattached / No Listener"
            }

            $hostnamesPlain = if ($certHostnamesMap.ContainsKey($certName) -and $certHostnamesMap[$certName].Count -gt 0) {
                $certHostnamesMap[$certName] -join ", "
            }
            else {
                "N/A"
            }

            $listenerCount = if ($certListenerCountMap.ContainsKey($certName)) {
                $certListenerCountMap[$certName]
            }
            else {
                0
            }

            $isAttached = if ($listenerCount -gt 0) { "Yes" } else { "No / Unattached" }

            # CASE A: Directly Uploaded PFX Certificate (Stored in Gateway)
            if (-not $isKvLinked) {
                # Retrieve base64 certificate data from available properties
                $rawCertData = if (-not [string]::IsNullOrWhiteSpace($cert.PublicCertData)) { $cert.PublicCertData }
                elseif (-not [string]::IsNullOrWhiteSpace($cert.Data)) { $cert.Data }
                elseif ($cert.properties -and -not [string]::IsNullOrWhiteSpace($cert.properties.publicCertData)) { $cert.properties.publicCertData }
                elseif ($cert.properties -and -not [string]::IsNullOrWhiteSpace($cert.properties.data)) { $cert.properties.data }
                else { $null }

                if (-not [string]::IsNullOrWhiteSpace($rawCertData)) {
                    $leafCert = $null
                    try {
                        $leafCert = Get-LeafCertificateFromBase64 -Base64Data $rawCertData -CertName $certName
                    }
                    catch {
                        Write-Warning "Error decoding certificate '$certName': $($_.Exception.Message)"
                    }

                    if ($leafCert) {
                        $notBeforeLocal = $leafCert.NotBefore
                        $notBeforeUtc = $notBeforeLocal.ToUniversalTime()
                        $notAfterLocal = $leafCert.NotAfter
                        $notAfterUtc = $notAfterLocal.ToUniversalTime()
                        $daysRemaining = [int][Math]::Floor(($notAfterLocal - $now).TotalDays)

                        $cn = $leafCert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                        if ([string]::IsNullOrWhiteSpace($cn)) { $cn = $leafCert.Subject }

                        $issuerCN = $leafCert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
                        if ([string]::IsNullOrWhiteSpace($issuerCN)) { $issuerCN = $leafCert.Issuer }

                        $thumbprint = $leafCert.Thumbprint
                        $serialNumber = $leafCert.SerialNumber
                        $sigAlg = $leafCert.SignatureAlgorithm.FriendlyName
                        $keyAlg = "$($leafCert.PublicKey.Oid.FriendlyName) ($($leafCert.PublicKey.Key.KeySize) bits)"

                        # Status Label
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

                        $statusColor = if ($notAfterLocal -lt $now) { "Red" }
                        elseif ($daysRemaining -le 7) { "Magenta" }
                        elseif ($daysRemaining -le 30) { "Yellow" }
                        else { "Green" }

                        Write-Host "      [PFX] $certName | CN: $cn | Expiry: $($notAfterLocal.ToString('yyyy-MM-dd HH:mm:ss')) | Days: $daysRemaining | Status: $status" -ForegroundColor $statusColor

                        $record = [PSCustomObject]@{
                            SubscriptionId           = $subId
                            SubscriptionName         = $subName
                            ResourceGroupName        = $agwRg
                            AppGatewayName           = $agwName
                            GatewayState             = $agwState
                            GatewayLocation          = $agwLocation
                            CertificateName          = $certName
                            CertificateSource        = "Directly Uploaded (PFX)"
                            CommonName               = $cn
                            Subject                  = $leafCert.Subject
                            Issuer                   = $issuerCN
                            IssuerDN                 = $leafCert.Issuer
                            SerialNumber             = $serialNumber
                            Thumbprint               = $thumbprint
                            SignatureAlgorithm       = $sigAlg
                            PublicKeyAlgorithm       = $keyAlg
                            ValidFrom_Local          = $notBeforeLocal.ToString("yyyy-MM-dd HH:mm:ss")
                            ValidFrom_UTC            = $notBeforeUtc.ToString("yyyy-MM-dd HH:mm:ss")
                            ExpirationDateTime_Local = $notAfterLocal.ToString("yyyy-MM-dd HH:mm:ss")
                            ExpirationDateTime_UTC   = $notAfterUtc.ToString("yyyy-MM-dd HH:mm:ss")
                            DaysRemaining            = $daysRemaining
                            ExpiryStatus             = $status
                            AssociatedListeners      = $listenersPlain
                            AssociatedHostNames      = $hostnamesPlain
                            ListenerCount            = $listenerCount
                            IsAttachedToListener     = $isAttached
                            KeyVaultSecretId         = "N/A - Direct Upload"
                            GatewayTags              = $tagStr
                            ScanTimestamp_UTC        = $scanTimestampUtc
                        }

                        $allCertRecords.Add($record)
                        try { $leafCert.Dispose() } catch { }
                    }
                    else {
                        Write-Warning "Failed to extract leaf certificate from binary data for '$certName' on '$agwName'."
                        $allCertRecords.Add([PSCustomObject]@{
                                SubscriptionId           = $subId
                                SubscriptionName         = $subName
                                ResourceGroupName        = $agwRg
                                AppGatewayName           = $agwName
                                GatewayState             = $agwState
                                GatewayLocation          = $agwLocation
                                CertificateName          = $certName
                                CertificateSource        = "Directly Uploaded (PFX)"
                                CommonName               = "DECODE_FAILED"
                                Subject                  = "DECODE_FAILED"
                                Issuer                   = "N/A"
                                IssuerDN                 = "N/A"
                                SerialNumber             = "N/A"
                                Thumbprint               = "N/A"
                                SignatureAlgorithm       = "N/A"
                                PublicKeyAlgorithm       = "N/A"
                                ValidFrom_Local          = "N/A"
                                ValidFrom_UTC            = "N/A"
                                ExpirationDateTime_Local = "DECODE_FAILED"
                                ExpirationDateTime_UTC   = "DECODE_FAILED"
                                DaysRemaining            = $null
                                ExpiryStatus             = "ERROR: Decode Failed"
                                AssociatedListeners      = $listenersPlain
                                AssociatedHostNames      = $hostnamesPlain
                                ListenerCount            = $listenerCount
                                IsAttachedToListener     = $isAttached
                                KeyVaultSecretId         = "N/A - Direct Upload"
                                GatewayTags              = $tagStr
                                ScanTimestamp_UTC        = $scanTimestampUtc
                            })
                    }
                }
                else {
                    Write-Warning "Certificate '$certName' on '$agwName' has no public binary data."
                }
            }
            # CASE B: Key Vault-Linked Certificate (When -IncludeKeyVaultCertificates is enabled)
            elseif ($isKvLinked -and $IncludeKeyVaultCertificates) {
                $kvSecretId = $cert.KeyVaultSecretId
                $vaultName = $kvSecretId.Split('/')[2].Split('.')[0]
                $secretName = $kvSecretId.Split('/')[4]
                $kvExpDate = $null
                $daysRemaining = $null
                $status = "KEY VAULT MANAGED"

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
                        elseif ($daysRemaining -le 90) {
                            "EXPIRING UPCOMING ($daysRemaining days left)"
                        }
                        else {
                            "ACTIVE ($daysRemaining days left)"
                        }
                    }
                }
                catch { }

                Write-Host "      [KV] $certName | Secret: $secretName | Vault: $vaultName | Status: $status" -ForegroundColor Cyan

                $allCertRecords.Add([PSCustomObject]@{
                        SubscriptionId           = $subId
                        SubscriptionName         = $subName
                        ResourceGroupName        = $agwRg
                        AppGatewayName           = $agwName
                        GatewayState             = $agwState
                        GatewayLocation          = $agwLocation
                        CertificateName          = $certName
                        CertificateSource        = "Key Vault Secret Reference"
                        CommonName               = "KeyVault: $secretName"
                        Subject                  = "KeyVault: $secretName (Vault: $vaultName)"
                        Issuer                   = "Azure Key Vault ($vaultName)"
                        IssuerDN                 = "Azure Key Vault ($vaultName)"
                        SerialNumber             = "Managed in Key Vault"
                        Thumbprint               = "Managed in Key Vault"
                        SignatureAlgorithm       = "N/A"
                        PublicKeyAlgorithm       = "N/A"
                        ValidFrom_Local          = "N/A"
                        ValidFrom_UTC            = "N/A"
                        ExpirationDateTime_Local = if ($kvExpDate) { $kvExpDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Managed in KV ($vaultName)" }
                        ExpirationDateTime_UTC   = if ($kvExpDate) { $kvExpDate.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { "Managed in KV ($vaultName)" }
                        DaysRemaining            = $daysRemaining
                        ExpiryStatus             = $status
                        AssociatedListeners      = $listenersPlain
                        AssociatedHostNames      = $hostnamesPlain
                        ListenerCount            = $listenerCount
                        IsAttachedToListener     = $isAttached
                        KeyVaultSecretId         = $kvSecretId
                        GatewayTags              = $tagStr
                        ScanTimestamp_UTC        = $scanTimestampUtc
                    })
            }
        }
    }
}

# =============================================================================
# 5. SUMMARY METRICS & CONSOLE DISPLAY
# =============================================================================
Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "                           AUDIT SUMMARY METRICS                          " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

$totalCerts = $allCertRecords.Count
$expiredCerts = ($allCertRecords | Where-Object { $_.DaysRemaining -ne $null -and $_.DaysRemaining -lt 0 }).Count
$urgentCerts = ($allCertRecords | Where-Object { $_.DaysRemaining -ne $null -and $_.DaysRemaining -ge 0 -and $_.DaysRemaining -le 7 }).Count
$soonCerts = ($allCertRecords | Where-Object { $_.DaysRemaining -ne $null -and $_.DaysRemaining -gt 7 -and $_.DaysRemaining -le 30 }).Count
$upcomingCerts = ($allCertRecords | Where-Object { $_.DaysRemaining -ne $null -and $_.DaysRemaining -gt 30 -and $_.DaysRemaining -le 90 }).Count
$activeCerts = ($allCertRecords | Where-Object { $_.DaysRemaining -ne $null -and $_.DaysRemaining -gt 90 }).Count
$uploadedCount = ($allCertRecords | Where-Object { $_.CertificateSource -eq "Directly Uploaded (PFX)" }).Count

Write-Host "  Total Gateways Audited     : $appGwCounter" -ForegroundColor White
Write-Host "  Total Certificates Found   : $totalCerts" -ForegroundColor White
Write-Host "  Uploaded PFX Certificates  : $uploadedCount" -ForegroundColor Green
Write-Host "  --------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  [!] EXPIRED                : $expiredCerts" -ForegroundColor $(if ($expiredCerts -gt 0) { "Red" } else { "DarkGray" })
Write-Host "  [!] URGENT (<= 7 days)     : $urgentCerts" -ForegroundColor $(if ($urgentCerts -gt 0) { "Magenta" } else { "DarkGray" })
Write-Host "  [*] SOON (<= 30 days)      : $soonCerts" -ForegroundColor $(if ($soonCerts -gt 0) { "Yellow" } else { "DarkGray" })
Write-Host "  [+] UPCOMING (<= 90 days)  : $upcomingCerts" -ForegroundColor Cyan
Write-Host "  [+] ACTIVE (> 90 days)     : $activeCerts" -ForegroundColor Green
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 6. EXPORT RESULTS TO CSV FILE
# =============================================================================
if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $CsvPath = Join-Path $baseDir "AppGateway-CertExpiry-$timestamp.csv"
}
else {
    # If a directory was provided instead of a file name
    if (Test-Path -Path $CsvPath -PathType Container) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $CsvPath = Join-Path $CsvPath "AppGateway-CertExpiry-$timestamp.csv"
    }
}

try {
    if ($allCertRecords.Count -gt 0) {
        $allCertRecords | Sort-Object DaysRemaining | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    }
    else {
        # Create empty CSV with proper headers
        [PSCustomObject]@{
            SubscriptionId           = ""
            SubscriptionName         = ""
            ResourceGroupName        = ""
            AppGatewayName           = ""
            GatewayState             = ""
            GatewayLocation          = ""
            CertificateName          = ""
            CertificateSource        = ""
            CommonName               = ""
            Subject                  = ""
            Issuer                   = ""
            IssuerDN                 = ""
            SerialNumber             = ""
            Thumbprint               = ""
            SignatureAlgorithm       = ""
            PublicKeyAlgorithm       = ""
            ValidFrom_Local          = ""
            ValidFrom_UTC            = ""
            ExpirationDateTime_Local = ""
            ExpirationDateTime_UTC   = ""
            DaysRemaining            = ""
            ExpiryStatus             = ""
            AssociatedListeners      = ""
            AssociatedHostNames      = ""
            ListenerCount            = ""
            IsAttachedToListener     = ""
            KeyVaultSecretId         = ""
            GatewayTags              = ""
            ScanTimestamp_UTC        = ""
        } | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    }
}
catch {
    Write-Error "Failed to export CSV to '$CsvPath': $($_.Exception.Message)"
}

# Display Table in Console (Using Out-String to prevent pipeline collision)
if ($allCertRecords.Count -gt 0) {
    Write-Host "============================== CERTIFICATE DETAILS ==============================" -ForegroundColor Yellow
    $tableOutput = $allCertRecords | Sort-Object DaysRemaining | Format-Table -Property CertificateName, CommonName, ExpirationDateTime_Local, DaysRemaining, ExpiryStatus, AssociatedListeners -AutoSize | Out-String
    Write-Host $tableOutput
}

# Resolve full absolute path and file name
$csvFileName = [System.IO.Path]::GetFileName($CsvPath)
$resolvedFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvPath)

# Prominently display the final CSV path and Cloud Shell download command
Write-Host ""
Write-Host "==========================================================================================" -ForegroundColor Green
Write-Host " [SUCCESS] FULL CERTIFICATE EXPIRY AUDIT REPORT GENERATED!                                " -ForegroundColor Green
Write-Host "==========================================================================================" -ForegroundColor Green
Write-Host "  CSV FILE NAME : $csvFileName" -ForegroundColor Yellow
Write-Host "  CSV FULL PATH : $resolvedFullPath" -ForegroundColor Yellow
Write-Host "  TOTAL RECORDS : $($allCertRecords.Count) certificate(s)" -ForegroundColor White
Write-Host "------------------------------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  >>> TO DOWNLOAD THIS CSV TO YOUR COMPUTER IN AZURE CLOUD SHELL, RUN THIS COMMAND:" -ForegroundColor Cyan
Write-Host "      download ""$csvFileName""" -ForegroundColor White
Write-Host "==========================================================================================" -ForegroundColor Green
Write-Host ""

# Store records in global variable for interactive inspection
$global:AppGwCertResults = $allCertRecords
$global:AppGwCertCsvPath = $resolvedFullPath

return $resolvedFullPath

