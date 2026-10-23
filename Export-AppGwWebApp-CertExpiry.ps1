<#
.SYNOPSIS
    Tenant-wide scan of SSL certificate exact expiry date & time for
    Application Gateways (uploaded certs) and App Service Web Apps.

.DESCRIPTION
    Scans every accessible subscription in the tenant and collects:
      1. Application Gateway - directly uploaded SSL certificates
         (uses X509Certificate2Collection.Import for accurate leaf-cert parsing)
      2. App Service Web App Certificates (microsoft.web/certificates)
         (retrieves full datetime from ARM, including time component)

    KEY DESIGN DECISIONS:
      - ALL certificates are exported regardless of expiry (expired + active).
      - ExpirationDateTime column preserves the full UTC timestamp (yyyy-MM-dd HH:mm:ss).
      - Uses X509Certificate2Collection (your reference approach) for App Gateway
        certs so PKCS#7 / certificate chains are handled correctly.
      - Skips Key-Vault-linked App Gateway certs (no public cert data to parse).
      - Requires Az PowerShell module (Az.Accounts, Az.Network, Az.Websites).

.PARAMETER ManagementGroupId
    Optional. One or more Management Group IDs to restrict the subscription scope.
    Leave empty to scan all accessible subscriptions in the tenant.

.PARAMETER SubscriptionIds
    Optional. Explicit list of subscription IDs to scan.

.PARAMETER CsvPath
    Full path for the output CSV file.
    Defaults to  .\AppGw-WebApp-CertExpiry-<timestamp>.csv

.EXAMPLE
    # Scan entire tenant, export CSV to current directory:
    .\Export-AppGwWebApp-CertExpiry.ps1

.EXAMPLE
    # Scope to two Management Groups:
    .\Export-AppGwWebApp-CertExpiry.ps1 -ManagementGroupId "ac-1.1","ac-1.2"

.EXAMPLE
    # Specific subscriptions only:
    .\Export-AppGwWebApp-CertExpiry.ps1 -SubscriptionIds "242eb51a-ca35-493b-b2d7-941aa572c048","<sub2-id>"

.EXAMPLE
    # Custom CSV output path:
    .\Export-AppGwWebApp-CertExpiry.ps1 -CsvPath "C:\Reports\cert-expiry.csv"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$ManagementGroupId,

    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "  Tenant-Wide Certificate Expiry Export" -ForegroundColor Cyan
Write-Host "  Scope   : Application Gateways (Uploaded SSL) + App Service Web Apps"   -ForegroundColor Yellow
Write-Host "  Output  : ALL certificates (expired + active) with exact date & time"   -ForegroundColor Yellow
Write-Host "  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"                    -ForegroundColor Gray
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. AUTHENTICATION CHECK
# ---------------------------------------------------------------------------
$azCtx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $azCtx) {
    Write-Host "[AUTH] No active Az session found. Connecting..." -ForegroundColor Yellow
    Connect-AzAccount -ErrorAction Stop | Out-Null
    $azCtx = Get-AzContext
}
Write-Host "[AUTH] Signed in as : $($azCtx.Account.Id)" -ForegroundColor Green
Write-Host "[AUTH] Tenant ID    : $($azCtx.Tenant.Id)"  -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 2. RESOLVE TARGET SUBSCRIPTIONS
# ---------------------------------------------------------------------------

# Helper: walk Management Group tree recursively to collect subscription IDs
function Get-MgSubscriptionIds {
    param([object]$MgNode)
    $ids = [System.Collections.Generic.List[string]]::new()
    if ($MgNode.Children) {
        foreach ($child in $MgNode.Children) {
            if ($child.Type -match 'subscriptions' -and $child.Name) {
                $ids.Add($child.Name)
            }
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
            # Try matching by display name
            $allMgs = Get-AzManagementGroup -ErrorAction SilentlyContinue
            $mg = $allMgs | Where-Object { $_.DisplayName -eq $mgId } | Select-Object -First 1
            if ($mg) {
                $mg = Get-AzManagementGroup -GroupId $mg.Name -Expand -Recurse -ErrorAction SilentlyContinue
            }
        }
        if ($mg) {
            Write-Host "  -> Matched MG: $($mg.DisplayName) ($($mg.Name))" -ForegroundColor Green
            $subIds = Get-MgSubscriptionIds -MgNode $mg

            # Fallback: use Get-AzManagementGroupSubscription if tree walk returned nothing
            if ($subIds.Count -eq 0) {
                $mgSubs = Get-AzManagementGroupSubscription -GroupName $mg.Name -ErrorAction SilentlyContinue
                foreach ($s in $mgSubs) {
                    $sid = if ($s.SubscriptionId) { $s.SubscriptionId } else { $s.Name }
                    if ($sid) { $subIds.Add($sid) }
                }
            }
            foreach ($id in $subIds) { $collectedIds.Add($id) }
        }
        else {
            Write-Host "  -> [WARN] Management Group '$mgId' not found, skipping." -ForegroundColor Red
        }
    }

    $uniqueIds = @($collectedIds | Select-Object -Unique)
    $targetSubs = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $uniqueIds -contains $_.Id }
}
elseif ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    Write-Host "[SCOPE] Using $($SubscriptionIds.Count) explicit subscription ID(s)." -ForegroundColor Cyan
    $targetSubs = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $SubscriptionIds -contains $_.Id }
}
else {
    Write-Host "[SCOPE] No filter specified — scanning ALL accessible subscriptions in tenant." -ForegroundColor Cyan
    $targetSubs = Get-AzSubscription -ErrorAction SilentlyContinue
}

if (-not $targetSubs -or $targetSubs.Count -eq 0) {
    throw "[ERROR] No accessible subscriptions found. Verify your permissions and try again."
}

Write-Host "[SCOPE] Target subscriptions resolved: $($targetSubs.Count)" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 3. INITIALISE RESULTS COLLECTION
# ---------------------------------------------------------------------------
$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# ---------------------------------------------------------------------------
# 4. HELPER: Decode base64 cert data and return leaf X509Certificate2
# ---------------------------------------------------------------------------
function Get-LeafCertFromPublicData {
    param([string]$Base64Data)

    if ([string]::IsNullOrWhiteSpace($Base64Data)) { return $null }

    # Strategy 1: Direct base64 -> bytes -> X509Certificate2Collection (handles PKCS#7 chains)
    try {
        $bytes = [System.Convert]::FromBase64String($Base64Data.Trim())
        $col   = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $col.Import($bytes)
        if ($col.Count -gt 0) { return $col[0] }
    }
    catch { }

    # Strategy 2: Outer base64 wraps a PEM string
    try {
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Base64Data.Trim()))
        if ($decoded -match '-----BEGIN CERTIFICATE-----') {
            $inner = ($decoded -replace '-----BEGIN CERTIFICATE-----','' `
                               -replace '-----END CERTIFICATE-----',''  `
                               -replace '\r',''-replace '\n',''-replace ' ','').Trim()
            $bytes = [System.Convert]::FromBase64String($inner)
            $col   = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
            $col.Import($bytes)
            if ($col.Count -gt 0) { return $col[0] }
        }
    }
    catch { }

    # Strategy 3: Raw PEM string passed directly
    try {
        if ($Base64Data.Trim() -match '-----BEGIN CERTIFICATE-----') {
            $inner = ($Base64Data.Trim() -replace '-----BEGIN CERTIFICATE-----','' `
                                          -replace '-----END CERTIFICATE-----',''  `
                                          -replace '\r',''-replace '\n',''-replace ' ','').Trim()
            $bytes = [System.Convert]::FromBase64String($inner)
            $col   = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
            $col.Import($bytes)
            if ($col.Count -gt 0) { return $col[0] }
        }
    }
    catch { }

    return $null
}

# ---------------------------------------------------------------------------
# 5. STATUS HELPER
# ---------------------------------------------------------------------------
function Get-CertStatus {
    param([datetime]$ExpiryDate)
    $daysLeft = ($ExpiryDate - (Get-Date)).Days
    if ($daysLeft -lt 0)  { return "EXPIRED ($([math]::Abs($daysLeft)) days ago)" }
    if ($daysLeft -le 14) { return "EXPIRING URGENT (<= 14 days)" }
    if ($daysLeft -le 30) { return "EXPIRING SOON (<= 30 days)" }
    if ($daysLeft -le 60) { return "EXPIRING UPCOMING (<= 60 days)" }
    return "HEALTHY / ACTIVE"
}

# ---------------------------------------------------------------------------
# 6. SCAN SUBSCRIPTIONS
# ---------------------------------------------------------------------------
$subIndex = 0
foreach ($sub in $targetSubs) {
    $subIndex++
    $subId   = $sub.Id
    $subName = $sub.Name

    Write-Host "[$subIndex/$($targetSubs.Count)] Subscription: $subName ($subId)" -ForegroundColor Cyan

    try {
        Set-AzContext -SubscriptionId $subId -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host "  [WARN] Could not set context for '$subName' — skipping. Error: $($_.Exception.Message)" -ForegroundColor DarkYellow
        continue
    }

    # -----------------------------------------------------------------------
    # 6A. APPLICATION GATEWAYS — Uploaded SSL Certificates
    # -----------------------------------------------------------------------
    Write-Host "  [AppGW] Scanning Application Gateways..." -ForegroundColor Gray
    $appGws = @()
    try { $appGws = Get-AzApplicationGateway -ErrorAction SilentlyContinue }
    catch { Write-Host "    [WARN] Could not list App Gateways: $($_.Exception.Message)" -ForegroundColor DarkYellow }

    foreach ($agw in $appGws) {
        Write-Host "    -> AppGW: $($agw.Name) [$($agw.ResourceGroupName)]" -ForegroundColor Gray

        # Build listener->hostname map for context
        $listenerMap = @{}
        foreach ($lst in $agw.HttpListeners) {
            $certRef = $null
            if ($lst.SslCertificate -and $lst.SslCertificate.Id) {
                $certRef = $lst.SslCertificate.Id.Split('/')[-1]
            }
            if ($certRef) {
                $hostLabel = if ($lst.HostName) { $lst.HostName }
                             elseif ($lst.HostNames -and $lst.HostNames.Count -gt 0) { $lst.HostNames -join ', ' }
                             else { $lst.Name }
                if (-not $listenerMap.ContainsKey($certRef)) {
                    $listenerMap[$certRef] = [System.Collections.Generic.List[string]]::new()
                }
                $listenerMap[$certRef].Add("$($lst.Name) ($hostLabel)")
            }
        }

        # Only directly-uploaded certs have PublicCertData (KV-linked ones do not)
        $uploadedSslCerts = $agw.SslCertificates | Where-Object {
            [string]::IsNullOrEmpty($_.KeyVaultSecretId) -and
            -not [string]::IsNullOrEmpty($_.PublicCertData)
        }

        if (-not $uploadedSslCerts -or @($uploadedSslCerts).Count -eq 0) {
            Write-Host "      No directly uploaded SSL certs (may be KV-linked or none configured)." -ForegroundColor DarkGray
            continue
        }

        foreach ($sslCert in $uploadedSslCerts) {
            $leafCert = $null
            try { $leafCert = Get-LeafCertFromPublicData -Base64Data $sslCert.PublicCertData }
            catch { Write-Host "      [WARN] Decode failed for '$($sslCert.Name)': $($_.Exception.Message)" -ForegroundColor DarkYellow }

            $listenerInfo = if ($listenerMap.ContainsKey($sslCert.Name)) {
                $listenerMap[$sslCert.Name] -join ' | '
            } else { "Unattached / No Listener" }

            if ($leafCert) {
                $expDT    = $leafCert.NotAfter      # Full [DateTime] including time
                $daysLeft = ($expDT - (Get-Date)).Days
                $cn       = $leafCert.GetNameInfo(
                                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                $issuerCN = $leafCert.GetNameInfo(
                                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)

                $allResults.Add([PSCustomObject]@{
                    WorkloadType        = "Application Gateway - Uploaded SSL"
                    SubscriptionName    = $subName
                    SubscriptionId      = $subId
                    ResourceGroup       = $agw.ResourceGroupName
                    ResourceName        = $agw.Name
                    CertificateName     = $sslCert.Name
                    CommonName          = $cn
                    Issuer              = $issuerCN
                    Thumbprint          = $leafCert.Thumbprint
                    ExpirationDateTime  = $expDT.ToString("yyyy-MM-dd HH:mm:ss")
                    ExpirationDate_UTC  = $expDT.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
                    DaysRemaining       = $daysLeft
                    Status              = Get-CertStatus -ExpiryDate $expDT
                    AssociatedListeners = $listenerInfo
                    KeyVaultLinked      = "No"
                    Notes               = ""
                })
                $leafCert.Dispose()
            }
            else {
                # Surface decode failures so nothing is silently dropped
                $allResults.Add([PSCustomObject]@{
                    WorkloadType        = "Application Gateway - Uploaded SSL"
                    SubscriptionName    = $subName
                    SubscriptionId      = $subId
                    ResourceGroup       = $agw.ResourceGroupName
                    ResourceName        = $agw.Name
                    CertificateName     = $sslCert.Name
                    CommonName          = "DECODE FAILED"
                    Issuer              = "DECODE FAILED"
                    Thumbprint          = "DECODE FAILED"
                    ExpirationDateTime  = "DECODE FAILED"
                    ExpirationDate_UTC  = "DECODE FAILED"
                    DaysRemaining       = $null
                    Status              = "DECODE FAILED - REVIEW MANUALLY"
                    AssociatedListeners = $listenerInfo
                    KeyVaultLinked      = "No"
                    Notes               = "PublicCertData present but could not be parsed"
                })
            }
        }
    }

    # -----------------------------------------------------------------------
    # 6B. APP SERVICE WEB APP CERTIFICATES (microsoft.web/certificates)
    # -----------------------------------------------------------------------
    Write-Host "  [WebApp] Scanning App Service Certificates..." -ForegroundColor Gray
    $webCerts = @()
    try { $webCerts = Get-AzWebAppCertificate -ErrorAction SilentlyContinue }
    catch { Write-Host "    [WARN] Could not list App Service certs: $($_.Exception.Message)" -ForegroundColor DarkYellow }

    foreach ($wc in $webCerts) {
        $expDT    = $null
        $daysLeft = $null
        $status   = "NO EXPIRY DATE"

        if ($wc.ExpirationDate) {
            $expDT    = [DateTime]$wc.ExpirationDate
            $daysLeft = ($expDT - (Get-Date)).Days
            $status   = Get-CertStatus -ExpiryDate $expDT
        }

        $allResults.Add([PSCustomObject]@{
            WorkloadType        = "App Service Web App Certificate"
            SubscriptionName    = $subName
            SubscriptionId      = $subId
            ResourceGroup       = $wc.ResourceGroupName
            ResourceName        = $wc.Name
            CertificateName     = $wc.SubjectName
            CommonName          = $wc.SubjectName
            Issuer              = if ($wc.Issuer) { $wc.Issuer } else { "App Service Managed" }
            Thumbprint          = if ($wc.Thumbprint) { $wc.Thumbprint } else { "N/A" }
            ExpirationDateTime  = if ($expDT) { $expDT.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
            ExpirationDate_UTC  = if ($expDT) { $expDT.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
            DaysRemaining       = $daysLeft
            Status              = $status
            AssociatedListeners = if ($wc.HostNames) { $wc.HostNames -join ' | ' } else { "N/A" }
            KeyVaultLinked      = "N/A"
            Notes               = ""
        })
    }

    $subAppGwCount  = ($allResults | Where-Object { $_.SubscriptionId -eq $subId -and $_.WorkloadType -like "*Gateway*" }).Count
    $subWebAppCount = ($allResults | Where-Object { $_.SubscriptionId -eq $subId -and $_.WorkloadType -like "*App Service*" }).Count
    Write-Host "  [DONE] AppGW certs: $subAppGwCount | WebApp certs: $subWebAppCount" -ForegroundColor Green
    Write-Host ""
}

# ---------------------------------------------------------------------------
# 7. SUMMARY DASHBOARD
# ---------------------------------------------------------------------------
Write-Host "==========================================================================" -ForegroundColor Green
Write-Host "  SCAN COMPLETE — SUMMARY" -ForegroundColor Green
Write-Host "  Subscriptions Scanned   : $($targetSubs.Count)"  -ForegroundColor Cyan
Write-Host "  Total Certificates Found: $($allResults.Count)"  -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Green

if ($allResults.Count -gt 0) {

    # Status breakdown
    Write-Host "`nStatus Breakdown:" -ForegroundColor Yellow
    $allResults | Group-Object Status | Sort-Object Name | ForEach-Object {
        $color = switch -Wildcard ($_.Name) {
            "*EXPIRED*"       { "Red"        }
            "*URGENT*"        { "Yellow"     }
            "*SOON*"          { "Magenta"    }
            "*UPCOMING*"      { "DarkYellow" }
            "*DECODE FAILED*" { "Red"        }
            default           { "Green"      }
        }
        Write-Host ("  -> {0,-50}: {1}" -f $_.Name, $_.Count) -ForegroundColor $color
    }

    # Workload breakdown
    Write-Host "`nBreakdown by Workload:" -ForegroundColor Yellow
    $allResults | Group-Object WorkloadType | ForEach-Object {
        Write-Host ("  -> {0,-50}: {1}" -f $_.Name, $_.Count) -ForegroundColor Gray
    }

    # Console preview — sorted earliest expiry first (expired certs surface first)
    Write-Host "`nPreview (Top 15 — sorted by expiry, earliest first):" -ForegroundColor Yellow
    $allResults |
        Where-Object { $_.DaysRemaining -ne $null } |
        Sort-Object DaysRemaining |
        Select-Object -First 15 `
            WorkloadType, ResourceName, CertificateName, ExpirationDateTime, DaysRemaining, Status |
        Format-Table -AutoSize | Out-String | Write-Host

    # ---------------------------------------------------------------------------
    # 8. CSV EXPORT
    # ---------------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($CsvPath)) {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $baseDir   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $CsvPath   = Join-Path $baseDir "AppGw-WebApp-CertExpiry-$timestamp.csv"
    }

    $allResults |
        Sort-Object DaysRemaining |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "[+] CSV exported to : $CsvPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "    CSV Columns:" -ForegroundColor Gray
    Write-Host "      WorkloadType          - 'Application Gateway - Uploaded SSL' or 'App Service Web App Certificate'" -ForegroundColor Gray
    Write-Host "      SubscriptionName      - Subscription display name" -ForegroundColor Gray
    Write-Host "      SubscriptionId        - Subscription GUID" -ForegroundColor Gray
    Write-Host "      ResourceGroup         - Resource group name" -ForegroundColor Gray
    Write-Host "      ResourceName          - App Gateway or App Service cert name" -ForegroundColor Gray
    Write-Host "      CertificateName       - SSL cert / subject name" -ForegroundColor Gray
    Write-Host "      CommonName            - Leaf cert CN (parsed from X509)" -ForegroundColor Gray
    Write-Host "      Issuer                - Certificate issuer CN" -ForegroundColor Gray
    Write-Host "      Thumbprint            - SHA1 thumbprint" -ForegroundColor Gray
    Write-Host "      ExpirationDateTime    - Full local date & time  (yyyy-MM-dd HH:mm:ss)" -ForegroundColor Green
    Write-Host "      ExpirationDate_UTC    - Full UTC date & time    (yyyy-MM-dd HH:mm:ss)" -ForegroundColor Green
    Write-Host "      DaysRemaining         - Negative = already expired" -ForegroundColor Gray
    Write-Host "      Status                - EXPIRED / URGENT / SOON / UPCOMING / HEALTHY" -ForegroundColor Gray
    Write-Host "      AssociatedListeners   - AppGW listeners bound to this cert" -ForegroundColor Gray
    Write-Host "      KeyVaultLinked        - No / N/A" -ForegroundColor Gray
    Write-Host "      Notes                 - Any warnings (e.g. decode failures)" -ForegroundColor Gray
    Write-Host ""
}
else {
    Write-Host "`n[INFO] No certificates found across scanned subscriptions." -ForegroundColor Yellow
}

# Return all objects for Azure Automation / pipeline consumption
return $allResults
