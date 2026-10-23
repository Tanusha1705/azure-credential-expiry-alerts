<#
.SYNOPSIS
    Tenant-wide scan of exact certificate expiry date & time for
    Application Gateways, App Services, and Key Vaults (v2).
    Excludes certificates that expired more than 6 months ago (configurable).

.DESCRIPTION
    Scans every accessible subscription in the tenant (or scoped by Management Group / Subscription IDs).
    All three workloads use raw-byte X509 parsing so that ExpirationDateTime always reflects
    the exact local and UTC time embedded inside the leaf certificate.

    WORKLOADS COVERED:
      1. Application Gateway  — directly uploaded SSL certs (PublicCertData -> X509Collection)
      2. App Service          — microsoft.web/certificates (publicCertData from ARM -> X509Collection)
      3. Key Vault            — KV Certificates: .Certificate.NotAfter (already X509Certificate2)
                              — KV Secrets with expiry date (attributes.Expires or PFX/PEM bytes)

    NEW IN V2 (Configurable Expiration Filter):
      - Excludes certificates that expired more than 6 months ago (default: 6 months).
      - Configurable via -ExcludeExpiredOlderThanMonths (default = 6).
      - Configurable via -ExcludeExpiredOlderThanDays (alternative days threshold).
      - Set -IncludeAllExpired switch to disable filtering and keep all historic expired certs.
      - Guaranteed CSV export: Always exports to a timestamped CSV file with full path printed.

.PARAMETER ManagementGroupId
    Optional. One or more Management Group IDs/Display Names to scope the scan.
    Leave empty to scan ALL accessible subscriptions in the tenant.

.PARAMETER SubscriptionIds
    Optional. Explicit list of subscription GUIDs to scan.

.PARAMETER ExcludeExpiredOlderThanMonths
    Number of months to keep past-expired certificates.
    Certificates expired older than this cutoff will be excluded.
    Default is 6 months.

.PARAMETER ExcludeExpiredOlderThanDays
    Alternative threshold in days (e.g. 180).
    If specified (> 0), overrides ExcludeExpiredOlderThanMonths.
    Default is 0 (uses ExcludeExpiredOlderThanMonths).

.PARAMETER IncludeAllExpired
    Switch to include ALL historic expired certificates regardless of expiration date.

.PARAMETER CsvPath
    Full path for the CSV output file.
    Default: .\AzureInfra-CertExpiry-v2-<timestamp>.csv

.EXAMPLE
    # Run full tenant scan excluding certs expired > 6 months ago:
    .\Export-AllInfraCertExpiry-v2.ps1

.EXAMPLE
    # Test on a specific subscription with default 6-month filter:
    .\Export-AllInfraCertExpiry-v2.ps1 -SubscriptionIds "242eb51a-ca35-493b-b2d7-941aa572c048"

.EXAMPLE
    # Custom filter: Exclude certs expired older than 3 months:
    .\Export-AllInfraCertExpiry-v2.ps1 -ExcludeExpiredOlderThanMonths 3

.EXAMPLE
    # Custom filter: Exclude certs expired older than 90 days:
    .\Export-AllInfraCertExpiry-v2.ps1 -ExcludeExpiredOlderThanDays 90

.EXAMPLE
    # Include all historic expired certificates (no exclusion):
    .\Export-AllInfraCertExpiry-v2.ps1 -IncludeAllExpired
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage = "One or more Management Group IDs or Display Names to scope the scan")]
    [string[]]$ManagementGroupId,

    [Parameter(Mandatory = $false, HelpMessage = "Explicit list of subscription GUIDs to scan")]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false, HelpMessage = "Exclude certificates expired older than this number of months (default 6)")]
    [int]$ExcludeExpiredOlderThanMonths = 6,

    [Parameter(Mandatory = $false, HelpMessage = "Alternative threshold in days (e.g. 180). If > 0, overrides months parameter")]
    [int]$ExcludeExpiredOlderThanDays = 0,

    [Parameter(Mandatory = $false, HelpMessage = "Switch to include all historic expired certificates without age filtering")]
    [switch]$IncludeAllExpired,

    [Parameter(Mandatory = $false, HelpMessage = "Destination path for the exported CSV file")]
    [string]$CsvPath
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

# =============================================================================
# 0. RESOLVE CUTOFF DATE FOR EXPIRED CERTIFICATES FILTER
# =============================================================================
$script:ExcludedCount = 0

if ($IncludeAllExpired) {
    $script:CutoffDate = [DateTime]::MinValue
    $filterDescription = "None (IncludeAllExpired switch specified - all historic expired certs included)"
}
elseif ($ExcludeExpiredOlderThanDays -gt 0) {
    $script:CutoffDate = (Get-Date).AddDays(-$ExcludeExpiredOlderThanDays)
    $filterDescription = "Excluding certificates expired > $ExcludeExpiredOlderThanDays days ago (Cutoff: $($script:CutoffDate.ToString('yyyy-MM-dd HH:mm:ss')))"
}
elseif ($ExcludeExpiredOlderThanMonths -gt 0) {
    $script:CutoffDate = (Get-Date).AddMonths(-$ExcludeExpiredOlderThanMonths)
    $filterDescription = "Excluding certificates expired > $ExcludeExpiredOlderThanMonths months ago (Cutoff: $($script:CutoffDate.ToString('yyyy-MM-dd HH:mm:ss')))"
}
else {
    $script:CutoffDate = [DateTime]::MinValue
    $filterDescription = "None (Threshold set to 0 - all historic expired certs included)"
}

# Resolve destination CSV path upfront
if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $baseDir   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $CsvPath   = Join-Path $baseDir "AzureInfra-CertExpiry-v2-$timestamp.csv"
}
$fullCsvPath = [System.IO.Path]::GetFullPath($CsvPath)

# =============================================================================
# BANNER
# =============================================================================
Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  Azure Infrastructure — Certificate Expiry Export (v2 - Filtered)"             -ForegroundColor Cyan
Write-Host "  Workloads     : Application Gateways | App Services | Key Vaults"               -ForegroundColor Yellow
Write-Host "  Method        : X509Certificate2Collection.Import() on raw cert bytes"           -ForegroundColor Yellow
Write-Host "  Expiry Filter : $filterDescription"                                             -ForegroundColor Yellow
Write-Host "  Destination   : $fullCsvPath"                                                   -ForegroundColor Cyan
Write-Host "  Started       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"                      -ForegroundColor Gray
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 1. AUTHENTICATION
# =============================================================================
$azCtx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $azCtx) {
    Write-Host "[AUTH] No active session. Connecting..." -ForegroundColor Yellow
    Connect-AzAccount -ErrorAction Stop | Out-Null
    $azCtx = Get-AzContext
}
Write-Host "[AUTH] Signed in as : $($azCtx.Account.Id)" -ForegroundColor Green
Write-Host "[AUTH] Tenant ID    : $($azCtx.Tenant.Id)"  -ForegroundColor Green
Write-Host ""

# =============================================================================
# 2. RESOLVE TARGET SUBSCRIPTIONS
# =============================================================================
function Get-MgSubscriptionIds {
    param([object]$MgNode)
    $ids = [System.Collections.Generic.List[string]]::new()
    if ($MgNode.Children) {
        foreach ($child in $MgNode.Children) {
            if ($child.Type -match 'subscriptions' -and $child.Name) { $ids.Add($child.Name) }
            if ($child.Children) {
                foreach ($id in (Get-MgSubscriptionIds -MgNode $child)) { $ids.Add($id) }
            }
        }
    }
    return $ids
}

$targetSubs = @()

if ($ManagementGroupId -and $ManagementGroupId.Count -gt 0) {
    Write-Host "[SCOPE] Resolving Management Group(s): $($ManagementGroupId -join ', ')" -ForegroundColor Cyan
    $collectedIds = [System.Collections.Generic.List[string]]::new()
    foreach ($mgId in $ManagementGroupId) {
        $mg = Get-AzManagementGroup -GroupId $mgId -Expand -Recurse -ErrorAction SilentlyContinue
        if (-not $mg) {
            $mg = Get-AzManagementGroup -ErrorAction SilentlyContinue |
                  Where-Object { $_.DisplayName -eq $mgId } | Select-Object -First 1
            if ($mg) { $mg = Get-AzManagementGroup -GroupId $mg.Name -Expand -Recurse -ErrorAction SilentlyContinue }
        }
        if ($mg) {
            Write-Host "  -> Matched MG : $($mg.DisplayName) ($($mg.Name))" -ForegroundColor Green
            $subIds = Get-MgSubscriptionIds -MgNode $mg
            if ($subIds.Count -eq 0) {
                $mgSubs = Get-AzManagementGroupSubscription -GroupName $mg.Name -ErrorAction SilentlyContinue
                foreach ($s in $mgSubs) {
                    $sid = if ($s.SubscriptionId) { $s.SubscriptionId } else { $s.Name }
                    if ($sid) { $subIds.Add($sid) }
                }
            }
            foreach ($id in $subIds) { $collectedIds.Add($id) }
        } else {
            Write-Host "  -> [WARN] MG '$mgId' not found, skipping." -ForegroundColor Red
        }
    }
    $targetSubs = Get-AzSubscription -ErrorAction SilentlyContinue |
                  Where-Object { ($collectedIds | Select-Object -Unique) -contains $_.Id }
}
elseif ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    Write-Host "[SCOPE] Using $($SubscriptionIds.Count) explicit subscription ID(s)." -ForegroundColor Cyan
    $targetSubs = Get-AzSubscription -ErrorAction SilentlyContinue |
                  Where-Object { $SubscriptionIds -contains $_.Id }
}
else {
    Write-Host "[SCOPE] No filter — scanning ALL accessible subscriptions in tenant." -ForegroundColor Cyan
    $targetSubs = Get-AzSubscription -ErrorAction SilentlyContinue
}

if (-not $targetSubs -or $targetSubs.Count -eq 0) {
    throw "[ERROR] No accessible subscriptions found. Check permissions."
}
Write-Host "[SCOPE] Subscriptions to scan: $($targetSubs.Count)" -ForegroundColor Green
Write-Host ""

# =============================================================================
# 3. SHARED HELPERS
# =============================================================================

# HELPER A: Parse raw base64 certificate data -> leaf X509Certificate2
function Get-LeafCertFromBase64 {
    param([string]$Base64Data)

    if ([string]::IsNullOrWhiteSpace($Base64Data)) { return $null }
    $raw = $Base64Data.Trim()

    # Strategy 1: Direct base64 -> bytes -> X509Certificate2Collection (DER / PKCS#7)
    try {
        $bytes = [System.Convert]::FromBase64String($raw)
        $col   = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $col.Import($bytes)
        if ($col.Count -gt 0 -and $col[0].Thumbprint) { return $col[0] }
    } catch { }

    # Strategy 2: Outer base64 wraps a PEM string
    try {
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($raw))
        if ($decoded -match '-----BEGIN CERTIFICATE-----') {
            $inner = ($decoded -replace '-----BEGIN CERTIFICATE-----','' `
                               -replace '-----END CERTIFICATE-----',''  `
                               -replace '\r',''-replace '\n',''-replace ' ','').Trim()
            $bytes = [System.Convert]::FromBase64String($inner)
            $col   = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
            $col.Import($bytes)
            if ($col.Count -gt 0 -and $col[0].Thumbprint) { return $col[0] }
        }
    } catch { }

    return $null
}

# HELPER B: Build a result row and apply the historic expiry filter
function New-CertRow {
    param(
        [string]    $WorkloadType,
        [string]    $SubscriptionName,
        [string]    $SubscriptionId,
        [string]    $ResourceGroup,
        [string]    $ResourceName,
        [string]    $CertificateName,
        [object]    $X509,             # X509Certificate2 — if $null, fallback fields used
        [datetime]  $FallbackExpiry,   # Used only when X509 is null
        [bool]      $FallbackValid,    # Whether FallbackExpiry is usable
        [string]    $AssociatedHosts,
        [string]    $Source,           # e.g. "KV-Certificate", "ARM-PublicCertData", "KV-Secret"
        [string]    $Notes
    )

    if ($X509) {
        $expDT = $X509.NotAfter     # Full [DateTime] with exact time

        # Filter check: Exclude if expired older than cutoff date
        if ($script:CutoffDate -gt [DateTime]::MinValue -and $expDT -lt $script:CutoffDate) {
            Write-Host "      [FILTERED] '$CertificateName' expired on $($expDT.ToString('yyyy-MM-dd')) (older than cutoff), excluded." -ForegroundColor DarkGray
            $script:ExcludedCount++
            return $null
        }

        $daysLeft = ($expDT - (Get-Date)).Days
        $cn       = $X509.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        $issuerCN = $X509.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
        $thumb    = $X509.Thumbprint

        return [PSCustomObject]@{
            WorkloadType        = $WorkloadType
            SubscriptionName    = $SubscriptionName
            SubscriptionId      = $SubscriptionId
            ResourceGroup       = $ResourceGroup
            ResourceName        = $ResourceName
            CertificateName     = $CertificateName
            CommonName          = $cn
            Issuer              = $issuerCN
            Thumbprint          = $thumb
            ExpirationDateTime  = $expDT.ToString("yyyy-MM-dd HH:mm:ss")
            ExpirationDate_UTC  = $expDT.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            DaysRemaining       = $daysLeft
            Status              = Get-CertStatus -ExpiryDate $expDT
            AssociatedHosts     = $AssociatedHosts
            ParseSource         = $Source
            Notes               = $Notes
        }
    }
    elseif ($FallbackValid) {
        $expDT = $FallbackExpiry

        # Filter check: Exclude if expired older than cutoff date
        if ($script:CutoffDate -gt [DateTime]::MinValue -and $expDT -lt $script:CutoffDate) {
            Write-Host "      [FILTERED] '$CertificateName' expired on $($expDT.ToString('yyyy-MM-dd')) (older than cutoff), excluded." -ForegroundColor DarkGray
            $script:ExcludedCount++
            return $null
        }

        $daysLeft = ($expDT - (Get-Date)).Days
        return [PSCustomObject]@{
            WorkloadType        = $WorkloadType
            SubscriptionName    = $SubscriptionName
            SubscriptionId      = $SubscriptionId
            ResourceGroup       = $ResourceGroup
            ResourceName        = $ResourceName
            CertificateName     = $CertificateName
            CommonName          = "N/A (fallback)"
            Issuer              = "N/A (fallback)"
            Thumbprint          = "N/A"
            ExpirationDateTime  = $expDT.ToString("yyyy-MM-dd HH:mm:ss")
            ExpirationDate_UTC  = $expDT.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            DaysRemaining       = $daysLeft
            Status              = Get-CertStatus -ExpiryDate $expDT
            AssociatedHosts     = $AssociatedHosts
            ParseSource         = "$Source (fallback - metadata only)"
            Notes               = $Notes
        }
    }
    else {
        # Certificate with no decode / no expiry metadata — always keep for manual review
        return [PSCustomObject]@{
            WorkloadType        = $WorkloadType
            SubscriptionName    = $SubscriptionName
            SubscriptionId      = $SubscriptionId
            ResourceGroup       = $ResourceGroup
            ResourceName        = $ResourceName
            CertificateName     = $CertificateName
            CommonName          = "DECODE FAILED"
            Issuer              = "DECODE FAILED"
            Thumbprint          = "DECODE FAILED"
            ExpirationDateTime  = "DECODE FAILED"
            ExpirationDate_UTC  = "DECODE FAILED"
            DaysRemaining       = $null
            Status              = "DECODE FAILED — REVIEW MANUALLY"
            AssociatedHosts     = $AssociatedHosts
            ParseSource         = $Source
            Notes               = $Notes
        }
    }
}

# HELPER C: Status label from expiry datetime
function Get-CertStatus {
    param([datetime]$ExpiryDate)
    $d = ($ExpiryDate - (Get-Date)).Days
    if ($d -lt 0)   { return "EXPIRED ($([math]::Abs($d)) days ago)" }
    if ($d -le 14)  { return "EXPIRING URGENT (<= 14 days)"          }
    if ($d -le 30)  { return "EXPIRING SOON (<= 30 days)"            }
    if ($d -le 60)  { return "EXPIRING UPCOMING (<= 60 days)"        }
    return "HEALTHY / ACTIVE"
}

# =============================================================================
# 4. RESULTS LIST
# =============================================================================
$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# =============================================================================
# 5. MAIN LOOP — PER SUBSCRIPTION
# =============================================================================
$subIndex = 0
foreach ($sub in $targetSubs) {
    $subIndex++
    $subId   = $sub.Id
    $subName = $sub.Name

    Write-Host "[$subIndex/$($targetSubs.Count)] ── Subscription: $subName ($subId)" -ForegroundColor Cyan

    try { Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null }
    catch {
        Write-Host "  [WARN] Cannot set context — skipping. $($_.Exception.Message)" -ForegroundColor DarkYellow
        continue
    }

    # =========================================================================
    # WORKLOAD 1: APPLICATION GATEWAYS — Uploaded SSL Certificates
    # =========================================================================
    Write-Host "  [1/3] Application Gateways — scanning for uploaded SSL certs..." -ForegroundColor Yellow

    $appGws = @()
    try { $appGws = Get-AzApplicationGateway -ErrorAction SilentlyContinue }
    catch { Write-Host "    [WARN] $($_.Exception.Message)" -ForegroundColor DarkYellow }

    foreach ($agw in $appGws) {
        Write-Host "    -> AppGW: $($agw.Name) [$($agw.ResourceGroupName)]" -ForegroundColor Gray

        # Map cert name -> listener labels
        $listenerMap = @{}
        foreach ($lst in $agw.HttpListeners) {
            $certRef = if ($lst.SslCertificate -and $lst.SslCertificate.Id) {
                $lst.SslCertificate.Id.Split('/')[-1]
            } else { $null }

            if ($certRef) {
                $host = if ($lst.HostName) { $lst.HostName }
                        elseif ($lst.HostNames -and $lst.HostNames.Count -gt 0) { $lst.HostNames -join ', ' }
                        else { $lst.Name }
                if (-not $listenerMap.ContainsKey($certRef)) {
                    $listenerMap[$certRef] = [System.Collections.Generic.List[string]]::new()
                }
                $listenerMap[$certRef].Add("$($lst.Name) [$host]")
            }
        }

        # Only directly-uploaded certs have PublicCertData
        $uploadedCerts = $agw.SslCertificates | Where-Object {
            [string]::IsNullOrEmpty($_.KeyVaultSecretId) -and
            -not [string]::IsNullOrEmpty($_.PublicCertData)
        }

        if (-not $uploadedCerts -or @($uploadedCerts).Count -eq 0) {
            Write-Host "      No directly uploaded SSL certs (may all be KV-linked or none)." -ForegroundColor DarkGray
            continue
        }

        foreach ($sslCert in $uploadedCerts) {
            $listenerInfo = if ($listenerMap.ContainsKey($sslCert.Name)) {
                $listenerMap[$sslCert.Name] -join ' | '
            } else { "Unattached / No Listener" }

            $leaf = $null
            try { $leaf = Get-LeafCertFromBase64 -Base64Data $sslCert.PublicCertData }
            catch { Write-Host "      [WARN] Decode failed for '$($sslCert.Name)': $($_.Exception.Message)" -ForegroundColor DarkYellow }

            $row = New-CertRow `
                -WorkloadType      "Application Gateway — Uploaded SSL" `
                -SubscriptionName  $subName `
                -SubscriptionId    $subId `
                -ResourceGroup     $agw.ResourceGroupName `
                -ResourceName      $agw.Name `
                -CertificateName   $sslCert.Name `
                -X509              $leaf `
                -FallbackValid     $false `
                -AssociatedHosts   $listenerInfo `
                -Source            "AppGW.PublicCertData -> X509Collection.Import()" `
                -Notes             ""

            if ($leaf) { try { $leaf.Dispose() } catch { } }
            if ($row)  { $allResults.Add($row) }
        }
    }

    # =========================================================================
    # WORKLOAD 2: APP SERVICE CERTIFICATES (microsoft.web/certificates)
    # =========================================================================
    Write-Host "  [2/3] App Service Certificates — parsing X509 bytes from ARM..." -ForegroundColor Yellow

    $appSvcCertResources = @()
    try {
        $appSvcCertResources = Get-AzResource `
            -ResourceType 'Microsoft.Web/certificates' `
            -ExpandProperties `
            -ErrorAction SilentlyContinue
    }
    catch { Write-Host "    [WARN] $($_.Exception.Message)" -ForegroundColor DarkYellow }

    if (-not $appSvcCertResources -or @($appSvcCertResources).Count -eq 0) {
        try {
            $restUri = "/subscriptions/$subId/providers/Microsoft.Web/certificates?api-version=2023-01-01"
            $restResp = Invoke-AzRestMethod -Method GET -Path $restUri -ErrorAction SilentlyContinue
            if ($restResp -and $restResp.StatusCode -eq 200) {
                $parsed = ($restResp.Content | ConvertFrom-Json).value
                if ($parsed) {
                    $appSvcCertResources = $parsed | ForEach-Object {
                        [PSCustomObject]@{
                            Name              = $_.name
                            ResourceGroupName = $_.id.Split('/')[4]
                            Properties        = $_.properties
                            Tags              = $_.tags
                        }
                    }
                }
            }
        }
        catch { Write-Host "    [WARN] ARM REST fallback failed: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    }

    Write-Host "    Found $(@($appSvcCertResources).Count) App Service certificate resource(s)." -ForegroundColor Gray

    foreach ($wcRes in $appSvcCertResources) {
        $certName  = $wcRes.Name
        $rg        = $wcRes.ResourceGroupName
        $props     = $wcRes.Properties

        $pubCertData = $null
        if ($props) {
            if ($props.publicCertData)   { $pubCertData = $props.publicCertData }
            elseif ($props.PublicCertData) { $pubCertData = $props.PublicCertData }
        }

        $fallbackExpiry = $null
        $hasFallback    = $false
        if ($props -and $props.expirationDate) {
            try { $fallbackExpiry = [DateTime]$props.expirationDate; $hasFallback = $true } catch { }
        }
        if (-not $hasFallback -and $props -and $props.ExpirationDate) {
            try { $fallbackExpiry = [DateTime]$props.ExpirationDate; $hasFallback = $true } catch { }
        }

        $hostNames = if ($props -and $props.hostNames) { $props.hostNames -join ' | ' }
                     elseif ($props -and $props.HostNames) { $props.HostNames -join ' | ' }
                     else { "N/A" }

        $leaf = $null
        if (-not [string]::IsNullOrWhiteSpace($pubCertData)) {
            try { $leaf = Get-LeafCertFromBase64 -Base64Data $pubCertData }
            catch { Write-Host "    [WARN] X509 decode failed for '$certName': $($_.Exception.Message)" -ForegroundColor DarkYellow }
        }

        $source = if ($leaf) { "AppSvc.ARM.publicCertData -> X509Collection.Import()" }
                  elseif ($hasFallback) { "AppSvc.ARM.expirationDate (metadata only)" }
                  else { "AppSvc — no cert data available" }

        $notes = if ([string]::IsNullOrWhiteSpace($pubCertData)) {
            "publicCertData not returned by ARM (check permissions or cert type)"
        } else { "" }

        $row = New-CertRow `
            -WorkloadType      "App Service Certificate" `
            -SubscriptionName  $subName `
            -SubscriptionId    $subId `
            -ResourceGroup     $rg `
            -ResourceName      $certName `
            -CertificateName   $(if ($props -and $props.subjectName) { $props.subjectName } else { $certName }) `
            -X509              $leaf `
            -FallbackExpiry    $(if ($hasFallback) { $fallbackExpiry } else { [DateTime]::MinValue }) `
            -FallbackValid     $hasFallback `
            -AssociatedHosts   $hostNames `
            -Source            $source `
            -Notes             $notes

        if ($leaf) { try { $leaf.Dispose() } catch { } }
        if ($row)  { $allResults.Add($row) }
    }

    # =========================================================================
    # WORKLOAD 3: KEY VAULT — Certificates and Secrets
    # =========================================================================
    Write-Host "  [3/3] Key Vaults — scanning certificates & secrets..." -ForegroundColor Yellow

    $keyVaults = @()
    try { $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue }
    catch { Write-Host "    [WARN] Could not list Key Vaults: $($_.Exception.Message)" -ForegroundColor DarkYellow }

    Write-Host "    Found $(@($keyVaults).Count) Key Vault(s)." -ForegroundColor Gray

    foreach ($kv in $keyVaults) {
        $kvName = $kv.VaultName
        $kvRg   = $kv.ResourceGroupName
        Write-Host "    -> KV: $kvName [$kvRg]" -ForegroundColor Gray

        # ---- KV CERTIFICATES ----
        $kvCertItems = @()
        try { $kvCertItems = Get-AzKeyVaultCertificate -VaultName $kvName -ErrorAction SilentlyContinue }
        catch { Write-Host "      [WARN] Cannot list KV certs for '$kvName': $($_.Exception.Message)" -ForegroundColor DarkYellow }

        foreach ($certItem in $kvCertItems) {
            $certName = $certItem.Name

            $fullCert = $null
            try { $fullCert = Get-AzKeyVaultCertificate -VaultName $kvName -Name $certName -ErrorAction SilentlyContinue }
            catch { Write-Host "      [WARN] Cannot get cert '$certName' from '$kvName': $($_.Exception.Message)" -ForegroundColor DarkYellow }

            $x509 = if ($fullCert -and $fullCert.Certificate) { $fullCert.Certificate } else { $null }

            $fallbackExpiry = $null
            $hasFallback    = $false
            if (-not $x509) {
                $expiresRaw = if ($fullCert -and $fullCert.Expires) { $fullCert.Expires }
                              elseif ($certItem -and $certItem.Expires) { $certItem.Expires }
                              else { $null }
                if ($expiresRaw) {
                    try { $fallbackExpiry = [DateTime]$expiresRaw; $hasFallback = $true } catch { }
                }
            }

            $source = if ($x509) { "KV.Certificate.PSKeyVaultCertificate.Certificate (X509Certificate2.NotAfter)" }
                      elseif ($hasFallback) { "KV.Certificate.Attributes.Expires (metadata only)" }
                      else { "KV Certificate — no expiry data accessible" }

            $notes = if (-not $x509 -and -not $hasFallback) {
                "Check Key Vault data-plane RBAC (Certificate Officer/Reader required)"
            } else { "" }

            $row = New-CertRow `
                -WorkloadType      "Key Vault Certificate" `
                -SubscriptionName  $subName `
                -SubscriptionId    $subId `
                -ResourceGroup     $kvRg `
                -ResourceName      $kvName `
                -CertificateName   $certName `
                -X509              $x509 `
                -FallbackExpiry    $(if ($hasFallback) { $fallbackExpiry } else { [DateTime]::MinValue }) `
                -FallbackValid     $hasFallback `
                -AssociatedHosts   "Key Vault: $kvName" `
                -Source            $source `
                -Notes             $notes

            if ($row) { $allResults.Add($row) }
        }

        # ---- KV SECRETS (with expiry dates set) ----
        $kvSecrets = @()
        try { $kvSecrets = Get-AzKeyVaultSecret -VaultName $kvName -ErrorAction SilentlyContinue }
        catch { Write-Host "      [WARN] Cannot list KV secrets for '$kvName': $($_.Exception.Message)" -ForegroundColor DarkYellow }

        $expiringSecrets = $kvSecrets | Where-Object {
            ($_.Expires -ne $null) -or ($_.Attributes -and $_.Attributes.Expires -ne $null)
        }

        foreach ($sec in $expiringSecrets) {
            $secName    = $sec.Name
            $contentType = if ($sec.ContentType) { $sec.ContentType } else { "" }
            $isCertSecret = $contentType -match 'pkcs12|pfx|pem|x-pkcs|certificate'

            $x509         = $null
            $fallbackExpiry = $null
            $hasFallback    = $false
            $source         = ""
            $notes          = ""

            if ($isCertSecret) {
                try {
                    $secretVal = Get-AzKeyVaultSecret -VaultName $kvName -Name $secName -AsPlainText -ErrorAction SilentlyContinue
                    if ($secretVal) {
                        try {
                            $bytes = [System.Convert]::FromBase64String($secretVal)
                            $col   = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
                            $col.Import($bytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
                            if ($col.Count -gt 0 -and $col[0].Thumbprint) { $x509 = $col[0] }
                        } catch { }

                        if (-not $x509) {
                            try { $x509 = Get-LeafCertFromBase64 -Base64Data $secretVal } catch { }
                        }
                        $source = "KV.Secret ($contentType) -> X509Collection.Import() (exact time)"
                    }
                } catch {
                    Write-Host "      [WARN] Cannot read secret value '$secName': $($_.Exception.Message)" -ForegroundColor DarkYellow
                }
            }

            if (-not $x509) {
                $expiresRaw = if ($sec.Expires) { $sec.Expires }
                              elseif ($sec.Attributes -and $sec.Attributes.Expires) { $sec.Attributes.Expires }
                              else { $null }
                if ($expiresRaw) {
                    try { $fallbackExpiry = [DateTime]$expiresRaw; $hasFallback = $true } catch { }
                }
                $source = if ($isCertSecret) { "KV.Secret (cert, decode failed) — using Attributes.Expires" }
                          else { "KV.Secret.Attributes.Expires (non-cert secret, metadata only)" }
                $notes  = if ($isCertSecret) { "Certificate secret: X509 decode failed — expiry from KV attributes" }
                          else { "Non-certificate secret — no X509 parse; expiry date from KV metadata" }
            }

            $row = New-CertRow `
                -WorkloadType      "Key Vault Secret (with expiry)" `
                -SubscriptionName  $subName `
                -SubscriptionId    $subId `
                -ResourceGroup     $kvRg `
                -ResourceName      $kvName `
                -CertificateName   $secName `
                -X509              $x509 `
                -FallbackExpiry    $(if ($hasFallback) { $fallbackExpiry } else { [DateTime]::MinValue }) `
                -FallbackValid     $hasFallback `
                -AssociatedHosts   "Key Vault: $kvName | ContentType: $contentType" `
                -Source            $source `
                -Notes             $notes

            if ($x509) { try { $x509.Dispose() } catch { } }
            if ($row)  { $allResults.Add($row) }
        }

        $kvCertCount = ($allResults | Where-Object { $_.ResourceName -eq $kvName -and $_.WorkloadType -eq "Key Vault Certificate" }).Count
        $kvSecCount  = ($allResults | Where-Object { $_.ResourceName -eq $kvName -and $_.WorkloadType -like "*Secret*" }).Count
        Write-Host "      KV Certs: $kvCertCount | KV Secrets (with expiry): $kvSecCount" -ForegroundColor Gray
    }

    Write-Host ""
}

# =============================================================================
# 6. SUMMARY DASHBOARD
# =============================================================================
Write-Host "===============================================================================" -ForegroundColor Green
Write-Host "  SCAN COMPLETE — SUMMARY (v2)"                                                 -ForegroundColor Green
Write-Host "  Subscriptions Scanned     : $($targetSubs.Count)"                             -ForegroundColor Cyan
Write-Host "  Certificates Retained     : $($allResults.Count)"                             -ForegroundColor Cyan
Write-Host "  Excluded (> Cutoff Old)   : $script:ExcludedCount"                            -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Green

if ($allResults.Count -gt 0) {

    Write-Host "`nStatus Breakdown (Retained):" -ForegroundColor Yellow
    $allResults | Group-Object Status | Sort-Object Name | ForEach-Object {
        $color = switch -Wildcard ($_.Name) {
            "*EXPIRED*"        { "Red"        }
            "*URGENT*"         { "Yellow"     }
            "*SOON*"           { "Magenta"    }
            "*UPCOMING*"       { "DarkYellow" }
            "*DECODE FAILED*"  { "Red"        }
            default            { "Green"      }
        }
        Write-Host ("  -> {0,-55}: {1}" -f $_.Name, $_.Count) -ForegroundColor $color
    }

    Write-Host "`nBreakdown by Workload:" -ForegroundColor Yellow
    $allResults | Group-Object WorkloadType | ForEach-Object {
        Write-Host ("  -> {0,-45}: {1}" -f $_.Name, $_.Count) -ForegroundColor Gray
    }

    Write-Host "`nPreview (Top 20 — sorted by DaysRemaining, expired first):" -ForegroundColor Yellow
    $allResults |
        Where-Object { $_.DaysRemaining -ne $null } |
        Sort-Object DaysRemaining |
        Select-Object -First 20 WorkloadType, ResourceName, CertificateName, ExpirationDateTime, DaysRemaining, Status |
        Format-Table -AutoSize | Out-String | Write-Host

    # -------------------------------------------------------------------------
    # CSV EXPORT
    # -------------------------------------------------------------------------
    $allResults |
        Sort-Object DaysRemaining |
        Export-Csv -Path $fullCsvPath -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "[+] CSV exported successfully!" -ForegroundColor Green
    Write-Host "    Absolute Path: $fullCsvPath" -ForegroundColor Green
    Write-Host "    To open file : Invoke-Item `"$fullCsvPath`"" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Column guide:" -ForegroundColor Gray
    Write-Host "      WorkloadType       : App Gateway / App Service / Key Vault Cert / KV Secret"     -ForegroundColor Gray
    Write-Host "      CommonName         : CN from X509 leaf cert (when parsed)"                       -ForegroundColor Gray
    Write-Host "      Issuer             : Issuer CN from X509 (when parsed)"                          -ForegroundColor Gray
    Write-Host "      Thumbprint         : SHA1 thumbprint from X509 (when parsed)"                    -ForegroundColor Gray
    Write-Host "      ExpirationDateTime : LOCAL date+time from X509 NotAfter (yyyy-MM-dd HH:mm:ss)"  -ForegroundColor Green
    Write-Host "      ExpirationDate_UTC : UTC  date+time (yyyy-MM-dd HH:mm:ss)"                      -ForegroundColor Green
    Write-Host "      DaysRemaining      : Negative = already expired"                                 -ForegroundColor Gray
    Write-Host "      Status             : EXPIRED / URGENT / SOON / UPCOMING / HEALTHY"               -ForegroundColor Gray
    Write-Host "      AssociatedHosts    : AppGW listeners or Web App hostnames"                       -ForegroundColor Gray
    Write-Host "      ParseSource        : How the expiry was obtained (X509 or metadata fallback)"    -ForegroundColor Gray
    Write-Host "      Notes              : Warnings (decode failures, permission issues)"               -ForegroundColor Gray
    Write-Host ""
}
else {
    Write-Host "`n[INFO] No certificates retained matching the filter criteria." -ForegroundColor Yellow
    if ($script:ExcludedCount -gt 0) {
        Write-Host "       ($script:ExcludedCount certificates were excluded because they expired older than $filterDescription)" -ForegroundColor DarkGray
    }

    $infoRow = [PSCustomObject]@{
        WorkloadType        = "INFO"
        SubscriptionName    = "N/A"
        SubscriptionId      = ($SubscriptionIds -join ', ')
        ResourceGroup       = "N/A"
        ResourceName        = "N/A"
        CertificateName     = "No certificates matching filter"
        CommonName          = "N/A"
        Issuer              = "N/A"
        Thumbprint          = "N/A"
        ExpirationDateTime  = "N/A"
        ExpirationDate_UTC  = "N/A"
        DaysRemaining       = $null
        Status              = "NO_CERTIFICATES_MATCHING_FILTER"
        AssociatedHosts     = "N/A"
        ParseSource         = "N/A"
        Notes               = "Excluded $script:ExcludedCount old certs (> cutoff). Use -IncludeAllExpired to see all."
    }
    $infoRow | Export-Csv -Path $fullCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV generated: $fullCsvPath" -ForegroundColor Green
}

return $allResults
