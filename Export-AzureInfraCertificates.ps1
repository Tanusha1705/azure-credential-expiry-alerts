<#
.SYNOPSIS
    Discovers expiring and active certificates across Azure Infrastructure Workloads
    (App Services, Key Vaults, and Application Gateways) without requiring Microsoft Graph or Device Authentication.

.DESCRIPTION
    Audits certificates and secrets across your Azure subscriptions and Management Groups:
      1. Azure App Service Certificates (microsoft.web/certificates)
      2. Azure Key Vault Secrets and Certificates (microsoft.keyvault/vaults)
      3. Azure Application Gateway SSL Certificates (microsoft.network/applicationgateways)

    KEY HIGHLIGHTS:
      - 100% Azure ARM & Resource Graph native (NO Microsoft Graph / Entra ID admin permissions required).
      - ZERO Device Code Authentication (runs directly in Azure Portal PowerShell Cloud Shell or local PC).
      - Multi-Management Group support (e.g. -ManagementGroupId "ac-1.1","ac-1.2").
      - Color-coded dashboard preview and automatic CSV/Excel export.
      - Ready for both local interactive testing and Azure Automation Account runbooks.

.PARAMETER ManagementGroupId
    Optional one or more Management Group IDs or Display Names to audit.
    If specified, automatically resolves and scans only subscriptions under these groups.

.PARAMETER SubscriptionIds
    Optional list of specific subscription IDs to audit. If omitted, scans all accessible subscriptions.

.PARAMETER DaysUntilExpiration
    Threshold in days to flag certificates expiring soon. Default is 30 days.

.PARAMETER AllCertificates
    Switch to output ALL certificates regardless of expiration date (active, upcoming, or expired).

.PARAMETER IncludeAlreadyExpired
    Include certificates that have already expired. Default is $true.

.PARAMETER ExportCsv
    Export results to a CSV file. Default is $true.

.PARAMETER CsvPath
    Custom path for the exported CSV file. Default is a timestamped file in the current directory.

.PARAMETER ExportExcel
    Export results to a formatted Excel file (.xlsx) if the ImportExcel module is available.

.PARAMETER FallbackOwnerEmail
    Default email address to assign when a resource does not have an owner tag configured.

.EXAMPLE
    # 1. Quick run across all subscriptions in Azure Portal PowerShell:
    .\Export-AzureInfraCertificates.ps1

.EXAMPLE
    # 2. View ALL infrastructure certificates (including active/healthy ones):
    .\Export-AzureInfraCertificates.ps1 -AllCertificates

.EXAMPLE
    # 3. Scope to specific Management Groups (e.g. ac-1.1 and ac-1.2):
    .\Export-AzureInfraCertificates.ps1 -ManagementGroupId "ac-1.1","ac-1.2"

.EXAMPLE
    # 4. Custom threshold (e.g. expiring within 60 days):
    .\Export-AzureInfraCertificates.ps1 -DaysUntilExpiration 60 -ExportExcel
#>

[CmdletBinding()]
param (
    # =========================================================================
    # OPTIONAL SCOPE CONFIGURATION:
    # Set default Management Group(s) or leave empty to scan all subscriptions:
    # =========================================================================
    [Parameter(Mandatory = $false, HelpMessage = "One or more Management Group IDs or Display Names")]
    [string[]]$ManagementGroupId,

    [Parameter(Mandatory = $false, HelpMessage = "Specific subscription IDs to scan")]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [int]$DaysUntilExpiration = 30,

    [Parameter(Mandatory = $false)]
    [switch]$AllCertificates,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeAlreadyExpired = $true,

    [Parameter(Mandatory = $false)]
    [bool]$ExportCsv = $true,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$ExportExcel,

    [Parameter(Mandatory = $false)]
    [string]$FallbackOwnerEmail = "azurecloudinfra.team@yourdomain.com"
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Azure Infrastructure Certificate & Secret Audit" -ForegroundColor Cyan
Write-Host " Workloads  : App Services | Key Vaults | Application Gateways" -ForegroundColor Yellow
Write-Host " Mode       : Zero Device Auth (Pure Azure ARM / Resource Graph)" -ForegroundColor Green
Write-Host " Threshold  : $($DaysUntilExpiration) Days $(if ($AllCertificates) { '(Flagging mode; ALL certificates output)' } else { '(Expiring items)' })" -ForegroundColor Gray
Write-Host " Timestamp  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "==========================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# 1. AUTHENTICATION & CONTEXT VERIFICATION
# -------------------------------------------------------------------------
$currentAzContext = Get-AzContext -ErrorAction SilentlyContinue
if (-not $currentAzContext) {
    Write-Host "`n[AUTH] No active Azure session found. Initiating interactive sign-in..." -ForegroundColor Yellow
    $null = Connect-AzAccount -ErrorAction Stop
    $currentAzContext = Get-AzContext
}

Write-Host "`n[AUTH] Connected as : $($currentAzContext.Account.Id)" -ForegroundColor Green
Write-Host "[AUTH] Tenant ID    : $($currentAzContext.Tenant.Id)" -ForegroundColor Green

# -------------------------------------------------------------------------
# 2. RESOLVE TARGET SUBSCRIPTIONS (MANAGEMENT GROUP SCOPE OR TENANT)
# -------------------------------------------------------------------------
$targetSubs = @()

# Helper: recursively collect subscription IDs from a resolved MG node
function Find-MgSubsRecursive($node, $collector) {
    if ($node.Children) {
        foreach ($c in $node.Children) {
            if ($c.Type -match 'subscriptions' -and $c.Name) {
                $collector.Add($c.Name)
            }
            if ($c.Children) {
                Find-MgSubsRecursive $c $collector
            }
        }
    }
}

if ($ManagementGroupId -and $ManagementGroupId.Count -gt 0) {
    Write-Host "`n[SCOPE] Resolving $($ManagementGroupId.Count) Management Group(s): $($ManagementGroupId -join ', ')..." -ForegroundColor Cyan
    $allDiscoveredSubIds = [System.Collections.Generic.List[string]]::new()
    $allMgsCache = $null

    foreach ($mgInput in $ManagementGroupId) {
        Write-Host "  -> Resolving: '$mgInput'" -ForegroundColor Yellow
        $mg = Get-AzManagementGroup -GroupId $mgInput -Expand -Recurse -ErrorAction SilentlyContinue
        if (-not $mg) {
            if (-not $allMgsCache) { $allMgsCache = Get-AzManagementGroup -ErrorAction SilentlyContinue }
            $matched = $allMgsCache | Where-Object { $_.Name -eq $mgInput -or $_.DisplayName -eq $mgInput } | Select-Object -First 1
            if ($matched) {
                $mg = Get-AzManagementGroup -GroupId $matched.Name -Expand -Recurse -ErrorAction SilentlyContinue
            }
        }

        if ($mg) {
            Write-Host "     [+] Matched: $($mg.DisplayName) (ID: $($mg.Name))" -ForegroundColor Green
            $mgSubIds = [System.Collections.Generic.List[string]]::new()
            Find-MgSubsRecursive $mg $mgSubIds

            if ($mgSubIds.Count -eq 0) {
                $mgSubs = Get-AzManagementGroupSubscription -GroupName $mg.Name -ErrorAction SilentlyContinue
                if ($mgSubs) {
                    foreach ($s in $mgSubs) {
                        $sid = if ($s.SubscriptionId) { $s.SubscriptionId } elseif ($s.Name) { $s.Name } else { $s.Id }
                        if ($sid) { $mgSubIds.Add($sid) }
                    }
                }
            }

            foreach ($sid in $mgSubIds) { $allDiscoveredSubIds.Add($sid) }
        } else {
            Write-Host "     [WARN] Management Group '$mgInput' not found, skipping." -ForegroundColor Red
        }
    }

    $uniqueSubIds = @($allDiscoveredSubIds | Select-Object -Unique)
    if ($uniqueSubIds.Count -gt 0) {
        $targetSubs = Get-AzSubscription | Where-Object { $uniqueSubIds -contains $_.Id }
    }
    Write-Host "[+] Resolved $($targetSubs.Count) subscription(s) across specified Management Group(s)." -ForegroundColor Green
}
elseif ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    Write-Host "`n[SCOPE] Targeting $($SubscriptionIds.Count) explicitly provided subscription ID(s)..." -ForegroundColor Cyan
    $targetSubs = Get-AzSubscription | Where-Object { $SubscriptionIds -contains $_.Id }
}
else {
    Write-Host "`n[SCOPE] No Management Group or Subscription filter provided. Scanning all accessible subscriptions..." -ForegroundColor Cyan
    $targetSubs = Get-AzSubscription
    Write-Host "[+] Found $($targetSubs.Count) accessible subscription(s)." -ForegroundColor Green
}

if ($targetSubs.Count -eq 0) {
    Throw "[ERROR] No target subscriptions found to audit. Execution stopped."
}

# Build KQL filter for Azure Resource Graph queries
$targetSubIds = @($targetSubs | ForEach-Object { $_.Id })
$formattedKqlSubFilter = ($targetSubIds | ForEach-Object { "'$_'" }) -join ", "

$allInfraRecords = [System.Collections.Generic.List[PSCustomObject]]::new()

# Helper: Map Days Remaining to Status
function Get-ExpiryStatus([int]$days) {
    if ($days -lt 0) { return "EXPIRED" }
    if ($days -le 14) { return "EXPIRING URGENT (<= 14 Days)" }
    if ($days -le 30) { return "EXPIRING SOON (<= 30 Days)" }
    return "HEALTHY / ACTIVE"
}

# Helper: Map Subscription Name
$subNameLookup = @{}
foreach ($s in $targetSubs) { $subNameLookup[$s.Id] = $s.Name }

$hasArg = [bool](Get-Command Search-AzGraph -ErrorAction SilentlyContinue)

# -------------------------------------------------------------------------
# 3. WORKLOAD 1: AZURE APP SERVICE CERTIFICATES
# -------------------------------------------------------------------------
Write-Host "`n[1/3] Scanning Azure App Service Certificates (Microsoft.Web/certificates)..." -ForegroundColor Cyan

if ($hasArg) {
    try {
        $argAppService = @"
        resources
        | where type =~ 'microsoft.web/certificates'
        | where subscriptionId in ($formattedKqlSubFilter)
        | project name, id, resourceGroup, subscriptionId,
                  expirationDate = todatetime(properties.expirationDate),
                  thumbprint     = tostring(properties.thumbprint),
                  issuer         = tostring(properties.issuer),
                  subjectName    = tostring(properties.subjectName),
                  ownerTag       = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
        $webCerts = Search-AzGraph -Subscription $targetSubIds -Query $argAppService -First 1000 -ErrorAction SilentlyContinue
        Write-Host "      Found $($webCerts.Count) App Service Certificate resource(s)." -ForegroundColor Gray

        foreach ($wc in $webCerts) {
            if ($wc.expirationDate) {
                $expDate  = [DateTime]$wc.expirationDate
                $daysLeft = ($expDate - (Get-Date)).Days
                $ownerVal = if (-not [string]::IsNullOrWhiteSpace($wc.ownerTag)) { $wc.ownerTag } else { $FallbackOwnerEmail }

                $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }

                if ($include) {
                    $subName = if ($subNameLookup.ContainsKey($wc.subscriptionId)) { $subNameLookup[$wc.subscriptionId] } else { $wc.subscriptionId }

                    $allInfraRecords.Add([PSCustomObject]@{
                        WorkloadSource         = "Azure App Service Certificate"
                        ResourceName           = $wc.name
                        ResourceGroupName      = $wc.resourceGroup
                        SubscriptionName       = $subName
                        SubscriptionId         = $wc.subscriptionId
                        CertificateOrSecret    = if ($wc.subjectName) { $wc.subjectName } else { $wc.name }
                        Thumbprint             = $wc.thumbprint
                        IssuerOrSubject        = $wc.issuer
                        ExpirationDate         = $expDate.ToString("yyyy-MM-dd")
                        DaysRemaining          = $daysLeft
                        Status                 = Get-ExpiryStatus $daysLeft
                        Owner                  = $ownerVal
                        ResourceId             = $wc.id
                    })
                }
            }
        }
        Write-Host "      Matched $($allInfraRecords.Count) App Service certificate record(s)." -ForegroundColor Green
    }
    catch {
        Write-Host "      [WARN] App Service Certificate scan error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "      [WARN] Az.ResourceGraph module not available. Install it for maximum performance." -ForegroundColor Yellow
}

# -------------------------------------------------------------------------
# 4. WORKLOAD 2: AZURE KEY VAULT SECRETS & CERTIFICATES
# -------------------------------------------------------------------------
Write-Host "`n[2/3] Scanning Azure Key Vault Secrets and Certificates..." -ForegroundColor Cyan

$kvDiscoveredCount = 0
foreach ($sub in $targetSubs) {
    try {
        $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue
        Write-Host "  -> Subscription: $($sub.Name)..." -ForegroundColor Gray

        $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        if (-not $keyVaults) { continue }

        foreach ($kv in $keyVaults) {
            $kvName = $kv.VaultName
            $kvRg   = $kv.ResourceGroupName
            $ownerVal = if ($kv.Tags -and $kv.Tags.Owner) {
                $kv.Tags.Owner
            } elseif ($kv.Tags -and $kv.Tags.WorkloadOwner) {
                $kv.Tags.WorkloadOwner
            } else {
                $FallbackOwnerEmail
            }

            # Inspect Key Vault Secrets with expiration dates
            try {
                $secrets = Get-AzKeyVaultSecret -VaultName $kvName -ErrorAction SilentlyContinue
                foreach ($sec in $secrets) {
                    if ($sec.Expires) {
                        $expDate  = [DateTime]$sec.Expires
                        $daysLeft = ($expDate - (Get-Date)).Days

                        $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }

                        if ($include) {
                            $kvDiscoveredCount++
                            $allInfraRecords.Add([PSCustomObject]@{
                                WorkloadSource         = "Azure Key Vault Secret"
                                ResourceName           = "$kvName ($kvRg)"
                                ResourceGroupName      = $kvRg
                                SubscriptionName       = $sub.Name
                                SubscriptionId         = $sub.Id
                                CertificateOrSecret    = $sec.Name
                                Thumbprint             = "N/A"
                                IssuerOrSubject        = if ($sec.ContentType) { $sec.ContentType } else { "Key Vault Secret" }
                                ExpirationDate         = $expDate.ToString("yyyy-MM-dd")
                                DaysRemaining          = $daysLeft
                                Status                 = Get-ExpiryStatus $daysLeft
                                Owner                  = $ownerVal
                                ResourceId             = $sec.Id
                            })
                        }
                    }
                }
            }
            catch { }

            # Inspect Key Vault Certificates with expiration dates
            try {
                $certs = Get-AzKeyVaultCertificate -VaultName $kvName -ErrorAction SilentlyContinue
                foreach ($c in $certs) {
                    if ($c.Expires) {
                        $expDate  = [DateTime]$c.Expires
                        $daysLeft = ($expDate - (Get-Date)).Days

                        $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }

                        if ($include) {
                            $kvDiscoveredCount++
                            $allInfraRecords.Add([PSCustomObject]@{
                                WorkloadSource         = "Azure Key Vault Certificate"
                                ResourceName           = "$kvName ($kvRg)"
                                ResourceGroupName      = $kvRg
                                SubscriptionName       = $sub.Name
                                SubscriptionId         = $sub.Id
                                CertificateOrSecret    = $c.Name
                                Thumbprint             = $c.Thumbprint
                                IssuerOrSubject        = "Key Vault Managed Certificate"
                                ExpirationDate         = $expDate.ToString("yyyy-MM-dd")
                                DaysRemaining          = $daysLeft
                                Status                 = Get-ExpiryStatus $daysLeft
                                Owner                  = $ownerVal
                                ResourceId             = $c.Id
                            })
                        }
                    }
                }
            }
            catch { }
        }
    }
    catch { }
}
Write-Host "      Matched $kvDiscoveredCount Key Vault item(s)." -ForegroundColor Green

# -------------------------------------------------------------------------
# 5. WORKLOAD 3: AZURE APPLICATION GATEWAY SSL CERTIFICATES
# -------------------------------------------------------------------------
Write-Host "`n[3/3] Scanning Azure Application Gateway SSL Certificates..." -ForegroundColor Cyan

$agwDiscoveredCount = 0
if ($hasArg) {
    try {
        $argAppGw = @"
        resources
        | where type =~ 'microsoft.network/applicationgateways'
        | where subscriptionId in ($formattedKqlSubFilter)
        | project name, id, resourceGroup, subscriptionId,
                  ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
        $appGws = Search-AzGraph -Subscription $targetSubIds -Query $argAppGw -First 1000 -ErrorAction SilentlyContinue
        Write-Host "      Found $($appGws.Count) Application Gateway(s) to inspect." -ForegroundColor Gray

        foreach ($ag in $appGws) {
            try {
                $null = Set-AzContext -SubscriptionId $ag.subscriptionId -ErrorAction SilentlyContinue
                $fullAgw = Get-AzApplicationGateway -Name $ag.name -ResourceGroupName $ag.resourceGroup -ErrorAction SilentlyContinue
                if ($fullAgw.SslCertificates) {
                    $ownerVal = if (-not [string]::IsNullOrWhiteSpace($ag.ownerTag)) { $ag.ownerTag } else { $FallbackOwnerEmail }
                    $subName = if ($subNameLookup.ContainsKey($ag.subscriptionId)) { $subNameLookup[$ag.subscriptionId] } else { $ag.subscriptionId }

                    foreach ($sslCert in $fullAgw.SslCertificates) {
                        $certName = $sslCert.Name
                        $x509 = $null

                        try {
                            if ([string]::IsNullOrWhiteSpace($sslCert.PublicCertData)) {
                                if ($sslCert.KeyVaultSecretId) {
                                    # Key Vault-linked SSL cert
                                    continue
                                }
                                continue
                            }

                            # Decode Strategy 1: Raw Base64
                            $decoded = $false
                            try {
                                $certBytes = [System.Convert]::FromBase64String($sslCert.PublicCertData)
                                $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                                $decoded = $true
                            } catch { }

                            # Decode Strategy 2: PEM strip
                            if (-not $decoded) {
                                try {
                                    $pem = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($sslCert.PublicCertData))
                                    $inner = ($pem -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","").Trim()
                                    $certBytes = [System.Convert]::FromBase64String($inner)
                                    $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                                    $decoded = $true
                                } catch { }
                            }

                            if ($x509) {
                                $expDate  = $x509.NotAfter
                                $daysLeft = ($expDate - (Get-Date)).Days

                                $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }

                                if ($include) {
                                    $agwDiscoveredCount++
                                    $allInfraRecords.Add([PSCustomObject]@{
                                        WorkloadSource         = "Azure Application Gateway SSL"
                                        ResourceName           = "$($ag.name) ($($ag.resourceGroup))"
                                        ResourceGroupName      = $ag.resourceGroup
                                        SubscriptionName       = $subName
                                        SubscriptionId         = $ag.subscriptionId
                                        CertificateOrSecret    = $certName
                                        Thumbprint             = $x509.Thumbprint
                                        IssuerOrSubject        = $x509.Subject
                                        ExpirationDate         = $expDate.ToString("yyyy-MM-dd")
                                        DaysRemaining          = $daysLeft
                                        Status                 = Get-ExpiryStatus $daysLeft
                                        Owner                  = $ownerVal
                                        ResourceId             = $sslCert.Id
                                    })
                                }
                                $x509.Dispose()
                            }
                        }
                        catch {
                            if ($x509) { try { $x509.Dispose() } catch {} }
                        }
                    }
                }
            }
            catch { }
        }
    }
    catch {
        Write-Host "      [WARN] Application Gateway SSL Certificate scan error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
Write-Host "      Matched $agwDiscoveredCount Application Gateway SSL certificate(s)." -ForegroundColor Green

# -------------------------------------------------------------------------
# 6. DASHBOARD SUMMARY & REPORT EXPORTS
# -------------------------------------------------------------------------
Write-Host "`n==========================================================================" -ForegroundColor Green
Write-Host " INFRASTRUCTURE CERTIFICATE AUDIT SUMMARY" -ForegroundColor Green
Write-Host " Total Discovered Items : $($allInfraRecords.Count)" -ForegroundColor Cyan
Write-Host " Subscriptions Scanned  : $($targetSubs.Count)" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Green

if ($allInfraRecords.Count -gt 0) {
    # Status breakdown
    $statusGroup = $allInfraRecords | Group-Object Status
    foreach ($sg in $statusGroup) {
        $color = switch -Wildcard ($sg.Name) {
            "*EXPIRED*" { "Red" }
            "*URGENT*"  { "Yellow" }
            "*SOON*"    { "Magenta" }
            default     { "Green" }
        }
        Write-Host "  -> $($sg.Name.PadRight(30)) : $($sg.Count)" -ForegroundColor $color
    }

    # Workload breakdown
    Write-Host "`nBreakdown by Workload Source:" -ForegroundColor Cyan
    $sourceGroup = $allInfraRecords | Group-Object WorkloadSource
    foreach ($src in $sourceGroup) {
        Write-Host "  -> $($src.Name.PadRight(35)) : $($src.Count)" -ForegroundColor Gray
    }

    # Console preview table
    Write-Host "`nPreview (Top 10 Records):" -ForegroundColor Yellow
    $allInfraRecords |
        Sort-Object DaysRemaining |
        Select-Object -First 10 WorkloadSource, ResourceName, CertificateOrSecret, ExpirationDate, DaysRemaining, Status, SubscriptionName |
        Format-Table -AutoSize | Out-String | Write-Host

    # Export to CSV
    if ($ExportCsv) {
        if ([string]::IsNullOrWhiteSpace($CsvPath)) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $CsvPath = Join-Path $PSScriptRoot "AzureInfra-Certificates-$timestamp.csv"
        }
        $allInfraRecords | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8
        Write-Host "`n[+] Full Audit Exported to CSV: $CsvPath" -ForegroundColor Green
    }

    # Export to Excel
    if ($ExportExcel -and (Get-Command Export-Excel -ErrorAction SilentlyContinue)) {
        $xlsxPath = [System.IO.Path]::ChangeExtension($CsvPath, ".xlsx")
        $allInfraRecords | Export-Excel -Path $xlsxPath -WorksheetName "InfraCertificates" -AutoSize -AutoFilter -BoldTopRow -FreezeTopRow
        Write-Host "[+] Formatted Excel Exported: $xlsxPath" -ForegroundColor Green
    }
}
else {
    Write-Host "`n[+] No expiring certificates or secrets found matching the threshold ($DaysUntilExpiration days)." -ForegroundColor Green
    Write-Host "    Tip: To see all active certificates regardless of expiration, run with: -AllCertificates" -ForegroundColor Gray
}

# Return pipeline objects for Azure Automation Runbook consumption
return $allInfraRecords
