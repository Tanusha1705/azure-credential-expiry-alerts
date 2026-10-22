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
$currentAzContext = $null
$hasAzCmdlets = [bool](Get-Command Get-AzContext -ErrorAction SilentlyContinue)
$hasAzCli     = [bool](Get-Command az -ErrorAction SilentlyContinue)

if ($hasAzCmdlets) {
    $currentAzContext = Get-AzContext -ErrorAction SilentlyContinue
}

$cliAccount = $null
if (-not $currentAzContext -and $hasAzCli) {
    try {
        $rawAccount = az account show -o json 2>$null
        if ($LASTEXITCODE -eq 0 -and $rawAccount) {
            $cliAccount = ($rawAccount -join "`n") | ConvertFrom-Json
        }
    } catch { }
}

if ($currentAzContext) {
    Write-Host "`n[AUTH] Connected via Az PowerShell : $($currentAzContext.Account.Id)" -ForegroundColor Green
    Write-Host "[AUTH] Tenant ID                   : $($currentAzContext.Tenant.Id)" -ForegroundColor Green
}
elseif ($cliAccount) {
    Write-Host "`n[AUTH] Connected via Azure CLI (az) : $($cliAccount.user.name)" -ForegroundColor Green
    Write-Host "[AUTH] Default Subscription        : $($cliAccount.name) ($($cliAccount.id))" -ForegroundColor Green
    Write-Host "[AUTH] Tenant ID                   : $($cliAccount.tenantId)" -ForegroundColor Green
}
else {
    if ($hasAzCmdlets) {
        Write-Host "`n[AUTH] No active session found. Initiating interactive sign-in..." -ForegroundColor Yellow
        $null = Connect-AzAccount -ErrorAction Stop
        $currentAzContext = Get-AzContext
        Write-Host "`n[AUTH] Connected as : $($currentAzContext.Account.Id)" -ForegroundColor Green
    }
    elseif ($hasAzCli) {
        Write-Host "`n[AUTH] No active session found. Initiating login via Azure CLI (az login)..." -ForegroundColor Yellow
        & az login
        $rawAccount = az account show -o json
        $cliAccount = ($rawAccount -join "`n") | ConvertFrom-Json
        Write-Host "`n[AUTH] Connected via Azure CLI as : $($cliAccount.user.name)" -ForegroundColor Green
    }
    else {
        Throw "[ERROR] Neither Az PowerShell module nor Azure CLI (az) is installed. Please install Az PowerShell module or Azure CLI to proceed."
    }
}

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
    if ($hasAzCmdlets -and (Get-Command Get-AzSubscription -ErrorAction SilentlyContinue)) {
        $targetSubs = Get-AzSubscription | Where-Object { $SubscriptionIds -contains $_.Id }
    }
    elseif ($hasAzCli) {
        $rawSubs = az account list --all -o json 2>$null
        if ($rawSubs) {
            $cliSubs = ($rawSubs -join "`n") | ConvertFrom-Json
            $targetSubs = @($cliSubs | Where-Object { $SubscriptionIds -contains $_.id } | ForEach-Object {
                [PSCustomObject]@{ Id = $_.id; Name = $_.name }
            })
        }
    }
}
else {
    Write-Host "`n[SCOPE] No Management Group or Subscription filter provided. Scanning all accessible subscriptions..." -ForegroundColor Cyan
    if ($hasAzCmdlets -and (Get-Command Get-AzSubscription -ErrorAction SilentlyContinue)) {
        $targetSubs = Get-AzSubscription
    }
    elseif ($hasAzCli) {
        $rawSubs = az account list --all -o json 2>$null
        if ($rawSubs) {
            $cliSubs = ($rawSubs -join "`n") | ConvertFrom-Json
            $targetSubs = @($cliSubs | ForEach-Object {
                [PSCustomObject]@{ Id = $_.id; Name = $_.name }
            })
        }
    }
    Write-Host "[+] Found $($targetSubs.Count) accessible subscription(s)." -ForegroundColor Green
}

if ($targetSubs.Count -eq 0) {
    Throw "[ERROR] No target subscriptions found to audit. Execution stopped."
}

# Build KQL filter for Azure Resource Graph queries
$targetSubIds = @($targetSubs | ForEach-Object { $_.Id.ToString().ToLower() })
$formattedKqlSubFilter = ($targetSubIds | ForEach-Object { "'$_'" }) -join ", "

$allInfraRecords = [System.Collections.Generic.List[PSCustomObject]]::new()

# Helper: Map Days Remaining to Status
function Get-ExpiryStatus([int]$days) {
    if ($days -eq 9999) { return "NO EXPIRY / ACTIVE" }
    if ($days -lt 0) { return "EXPIRED" }
    if ($days -le 14) { return "EXPIRING URGENT (<= 14 Days)" }
    if ($days -le 30) { return "EXPIRING SOON (<= 30 Days)" }
    return "HEALTHY / ACTIVE"
}

# Helper: Decode multi-format PublicCertData (DER Base64, PEM Base64, raw PEM)
function ConvertFrom-PublicCertData {
    param([string]$certData)

    if ([string]::IsNullOrWhiteSpace($certData)) { return $null }

    $clean = $certData.Trim()
    
    # Strategy 1: Direct Base64 to DER bytes -> X509Certificate2
    try {
        $bytes = [System.Convert]::FromBase64String($clean)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
        if ($cert -and $cert.Thumbprint) { return $cert }
    } catch { }

    # Strategy 2: Base64-encoded PEM string -> decode outer base64, extract PEM body, decode inner base64
    try {
        $decodedText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($clean))
        if ($decodedText -match "-----BEGIN CERTIFICATE-----") {
            $inner = ($decodedText -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
            $bytes = [System.Convert]::FromBase64String($inner)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
            if ($cert -and $cert.Thumbprint) { return $cert }
        }
    } catch { }

    # Strategy 3: Raw PEM string (not outer base64)
    try {
        if ($clean -match "-----BEGIN CERTIFICATE-----") {
            $inner = ($clean -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
            $bytes = [System.Convert]::FromBase64String($inner)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
            if ($cert -and $cert.Thumbprint) { return $cert }
        }
    } catch { }

    # Strategy 4: Raw UTF8 bytes directly
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($clean)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
        if ($cert -and $cert.Thumbprint) { return $cert }
    } catch { }

    return $null
}

# Helper: Map Subscription Name
$subNameLookup = @{}
foreach ($s in $targetSubs) { $subNameLookup[$s.Id] = $s.Name }

$hasArg = [bool](Get-Command Search-AzGraph -ErrorAction SilentlyContinue)

# -------------------------------------------------------------------------
# 3. WORKLOAD 1: AZURE APP SERVICE CERTIFICATES
# -------------------------------------------------------------------------
Write-Host "`n[1/3] Scanning Azure App Service Certificates..." -ForegroundColor Cyan

$appServiceDiscoveredCount = 0
if ($hasArg) {
    try {
        $argAppService = @"
        resources
        | where type in~ ('microsoft.web/certificates', 'microsoft.certificateregistration/certificateorders')
        | where tolower(subscriptionId) in ($formattedKqlSubFilter)
        | project name, id, resourceGroup, subscriptionId, type,
                  expirationDate = coalesce(todatetime(properties.expirationDate), todatetime(properties.expirationTime)),
                  thumbprint     = coalesce(tostring(properties.thumbprint), "N/A"),
                  issuer         = coalesce(tostring(properties.issuer), "App Service Managed"),
                  subjectName    = coalesce(tostring(properties.subjectName), tostring(properties.distinguishedName), name),
                  ownerTag       = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
        $webCerts = Search-AzGraph -Query $argAppService -First 1000 -ErrorAction SilentlyContinue
        Write-Host "      Found $($webCerts.Count) App Service Certificate resource(s)." -ForegroundColor Gray

        foreach ($wc in $webCerts) {
            if ($wc.expirationDate) {
                $expDate  = [DateTime]$wc.expirationDate
                $daysLeft = ($expDate - (Get-Date)).Days
                $ownerVal = if (-not [string]::IsNullOrWhiteSpace($wc.ownerTag)) { $wc.ownerTag } else { $FallbackOwnerEmail }

                $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }

                if ($include) {
                    $appServiceDiscoveredCount++
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
        Write-Host "      Matched $appServiceDiscoveredCount App Service certificate record(s)." -ForegroundColor Green
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
$totalKvSecretsCount = 0
$totalKvCertsCount = 0
$keyVaults = @()

if ($hasArg) {
    try {
        $argKeyVaults = @"
        resources
        | where type =~ 'microsoft.keyvault/vaults'
        | where tolower(subscriptionId) in ($formattedKqlSubFilter)
        | project name, id, resourceGroup, subscriptionId, location,
                  vaultUri = tostring(properties.vaultUri),
                  enableRbac = tobool(properties.enableRbacAuthorization),
                  publicNetworkAccess = tostring(properties.publicNetworkAccess),
                  defaultAction = tostring(properties.networkAcls.defaultAction),
                  ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
        $keyVaults = Search-AzGraph -Query $argKeyVaults -First 1000 -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "      [!] Resource Graph query for Key Vaults: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

# Fallback to Get-AzKeyVault or az keyvault list if ARG returned 0 or wasn't available
if (-not $keyVaults -or $keyVaults.Count -eq 0) {
    Write-Host "      Scanning Key Vaults across subscriptions via Azure Resource Manager..." -ForegroundColor Gray
    $keyVaults = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($sub in $targetSubs) {
        try {
            $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue
            $subKvs = Get-AzKeyVault -ErrorAction SilentlyContinue
            if ($subKvs) {
                foreach ($skv in $subKvs) {
                    $keyVaults.Add([PSCustomObject]@{
                        name           = $skv.VaultName
                        id             = $skv.ResourceId
                        resourceGroup  = $skv.ResourceGroupName
                        subscriptionId = $sub.Id
                        vaultUri       = $skv.VaultUri
                        enableRbac     = $skv.EnableRbacAuthorization
                        ownerTag       = $null
                    })
                }
            }
        }
        catch { }
    }
}

# Fallback to az CLI if keyVaults is still empty
if ((-not $keyVaults -or $keyVaults.Count -eq 0) -and $hasAzCli) {
    try {
        $rawCliKvs = az keyvault list -o json 2>$null
        if ($LASTEXITCODE -eq 0 -and $rawCliKvs) {
            $cliKvs = ($rawCliKvs -join "`n") | ConvertFrom-Json
            if ($cliKvs) {
                $keyVaults = [System.Collections.Generic.List[PSObject]]::new()
                foreach ($ckv in $cliKvs) {
                    $subFromId = if ($ckv.id) { $ckv.id.Split('/')[2] } else { "" }
                    $keyVaults.Add([PSCustomObject]@{
                        name           = $ckv.name
                        id             = $ckv.id
                        resourceGroup  = $ckv.resourceGroup
                        subscriptionId = $subFromId
                        vaultUri       = $ckv.properties.vaultUri
                        enableRbac     = $ckv.properties.enableRbacAuthorization
                        ownerTag       = $null
                    })
                }
            }
        }
    } catch { }
}

Write-Host "      Found $($keyVaults.Count) Key Vault(s) across target scope." -ForegroundColor Gray

foreach ($kv in $keyVaults) {
    $kvName = $kv.name
    $kvRg   = $kv.resourceGroup
    $subId  = $kv.subscriptionId
    $subName = if ($subNameLookup.ContainsKey($subId)) { $subNameLookup[$subId] } else { $subId }
    $ownerVal = if (-not [string]::IsNullOrWhiteSpace($kv.ownerTag)) { $kv.ownerTag } else { $FallbackOwnerEmail }

    # Set context to subscription of the vault for proper token audience
    $null = Set-AzContext -SubscriptionId $subId -ErrorAction SilentlyContinue

    $kvCertCountThisVault = 0
    $kvSecCountThisVault = 0
    $accessRestricted = $false
    $accessErrorReason = ""

    # 1. Inspect Key Vault Certificates
    $certs = $null
    try {
        $certs = Get-AzKeyVaultCertificate -VaultName $kvName -ErrorAction Stop
    }
    catch {
        # Fallback to az keyvault certificate list
        if ($hasAzCli) {
            try {
                $rawCliCerts = az keyvault certificate list --vault-name $kvName -o json 2>$null
                if ($LASTEXITCODE -eq 0 -and $rawCliCerts) {
                    $cliCerts = ($rawCliCerts -join "`n") | ConvertFrom-Json
                    if ($cliCerts) {
                        $certs = @($cliCerts | ForEach-Object {
                            [PSCustomObject]@{
                                Name       = $_.name
                                Id         = $_.id
                                Thumbprint = if ($_.x509ThumbprintHex) { $_.x509ThumbprintHex } else { "KV-Managed" }
                                Expires    = if ($_.attributes -and $_.attributes.expires) { [DateTime]$_.attributes.expires } else { $null }
                            }
                        })
                    }
                }
            } catch { }
        }

        if (-not $certs) {
            $errMsg = $_.Exception.Message
            $accessRestricted = $true
            if ($errMsg -match "Forbidden|AccessDenied|Unauthorized|authorization") {
                $accessErrorReason = "Data-plane RBAC / Access Policy required"
            } elseif ($errMsg -match "Firewall|network|Client address") {
                $accessErrorReason = "Blocked by Key Vault Firewall/Private Endpoint"
            } else {
                $accessErrorReason = $errMsg
            }
        }
    }

    if ($certs) {
        foreach ($c in $certs) {
            $totalKvCertsCount++
            $kvCertCountThisVault++

            $expDate = if ($c.Expires) { [DateTime]$c.Expires } elseif ($c.Attributes -and $c.Attributes.Expires) { [DateTime]$c.Attributes.Expires } else { $null }

            if ($expDate) {
                $daysLeft = ($expDate - (Get-Date)).Days
                $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }
            } else {
                $daysLeft = 9999
                $include = $AllCertificates
            }

            if ($include) {
                $kvDiscoveredCount++
                $allInfraRecords.Add([PSCustomObject]@{
                    WorkloadSource         = "Azure Key Vault Certificate"
                    ResourceName           = "$kvName ($kvRg)"
                    ResourceGroupName      = $kvRg
                    SubscriptionName       = $subName
                    SubscriptionId         = $subId
                    CertificateOrSecret    = $c.Name
                    Thumbprint             = if ($c.Thumbprint) { $c.Thumbprint } else { "KV-Managed" }
                    IssuerOrSubject        = "Key Vault Managed Certificate"
                    ExpirationDate         = if ($expDate) { $expDate.ToString("yyyy-MM-dd") } else { "No Expiry Date Configured" }
                    DaysRemaining          = $daysLeft
                    Status                 = if ($expDate) { Get-ExpiryStatus $daysLeft } else { "NO EXPIRY CONFIGURED" }
                    Owner                  = $ownerVal
                    ResourceId             = $c.Id
                })
            }
        }
    }

    # 2. Inspect Key Vault Secrets
    $secrets = $null
    try {
        $secrets = Get-AzKeyVaultSecret -VaultName $kvName -ErrorAction Stop
    }
    catch {
        # Fallback to az keyvault secret list
        if ($hasAzCli) {
            try {
                $rawCliSecs = az keyvault secret list --vault-name $kvName -o json 2>$null
                if ($LASTEXITCODE -eq 0 -and $rawCliSecs) {
                    $cliSecs = ($rawCliSecs -join "`n") | ConvertFrom-Json
                    if ($cliSecs) {
                        $secrets = @($cliSecs | ForEach-Object {
                            [PSCustomObject]@{
                                Name        = $_.name
                                Id          = $_.id
                                ContentType = $_.contentType
                                Expires     = if ($_.attributes -and $_.attributes.expires) { [DateTime]$_.attributes.expires } else { $null }
                            }
                        })
                    }
                }
            } catch { }
        }

        if (-not $secrets) {
            $errMsg = $_.Exception.Message
            $accessRestricted = $true
            if (-not $accessErrorReason) {
                if ($errMsg -match "Forbidden|AccessDenied|Unauthorized|authorization") {
                    $accessErrorReason = "Data-plane RBAC / Access Policy required"
                } elseif ($errMsg -match "Firewall|network|Client address") {
                    $accessErrorReason = "Blocked by Key Vault Firewall/Private Endpoint"
                } else {
                    $accessErrorReason = $errMsg
                }
            }
        }
    }

    if ($secrets) {
        foreach ($sec in $secrets) {
            $totalKvSecretsCount++
            $kvSecCountThisVault++

            $expDate = if ($sec.Expires) { [DateTime]$sec.Expires } elseif ($sec.Attributes -and $sec.Attributes.Expires) { [DateTime]$sec.Attributes.Expires } else { $null }

            if ($expDate) {
                $daysLeft = ($expDate - (Get-Date)).Days
                $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }
            } else {
                $daysLeft = 9999
                $include = $AllCertificates
            }

            if ($include) {
                $kvDiscoveredCount++
                $allInfraRecords.Add([PSCustomObject]@{
                    WorkloadSource         = "Azure Key Vault Secret"
                    ResourceName           = "$kvName ($kvRg)"
                    ResourceGroupName      = $kvRg
                    SubscriptionName       = $subName
                    SubscriptionId         = $subId
                    CertificateOrSecret    = $sec.Name
                    Thumbprint             = "N/A"
                    IssuerOrSubject        = if ($sec.ContentType) { $sec.ContentType } else { "Key Vault Secret" }
                    ExpirationDate         = if ($expDate) { $expDate.ToString("yyyy-MM-dd") } else { "No Expiry Date Configured" }
                    DaysRemaining          = $daysLeft
                    Status                 = if ($expDate) { Get-ExpiryStatus $daysLeft } else { "NO EXPIRY CONFIGURED" }
                    Owner                  = $ownerVal
                    ResourceId             = $sec.Id
                })
            }
        }
    }

    if ($accessRestricted -and $kvCertCountThisVault -eq 0 -and $kvSecCountThisVault -eq 0) {
        Write-Host "  -> Key Vault: $kvName ($kvRg) -> [!] $accessErrorReason" -ForegroundColor DarkYellow
    } else {
        Write-Host "  -> Key Vault: $kvName ($kvRg) -> Read $kvCertCountThisVault certificate(s), $kvSecCountThisVault secret(s)." -ForegroundColor Gray
    }
}
Write-Host "      Matched $kvDiscoveredCount Key Vault item(s) within threshold." -ForegroundColor Green

# -------------------------------------------------------------------------
# 5. WORKLOAD 3: AZURE APPLICATION GATEWAY SSL CERTIFICATES
# -------------------------------------------------------------------------
Write-Host "`n[3/3] Scanning Azure Application Gateway SSL Certificates..." -ForegroundColor Cyan

$agwDiscoveredCount = 0
$appGws = @()

if ($hasArg) {
    try {
        $argAppGw = @"
        resources
        | where type =~ 'microsoft.network/applicationgateways'
        | where tolower(subscriptionId) in ($formattedKqlSubFilter)
        | project name, id, resourceGroup, subscriptionId, location,
                  sslCertificates = properties.sslCertificates,
                  trustedRootCertificates = properties.trustedRootCertificates,
                  httpListeners = properties.httpListeners,
                  ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
        $appGws = Search-AzGraph -Query $argAppGw -First 1000 -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "      [!] Resource Graph query for Application Gateways: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

# Fallback to Get-AzApplicationGateway if ARG returned 0 or wasn't available
if (-not $appGws -or $appGws.Count -eq 0) {
    Write-Host "      Scanning Application Gateways across subscriptions via Azure Resource Manager..." -ForegroundColor Gray
    $appGws = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($sub in $targetSubs) {
        try {
            $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue
            $subAgws = Get-AzApplicationGateway -ErrorAction SilentlyContinue
            if ($subAgws) {
                foreach ($sag in $subAgws) {
                    $appGws.Add([PSCustomObject]@{
                        name                    = $sag.Name
                        id                      = $sag.Id
                        resourceGroup           = $sag.ResourceGroupName
                        subscriptionId          = $sub.Id
                        sslCertificates         = $sag.SslCertificates
                        trustedRootCertificates = $sag.TrustedRootCertificates
                        httpListeners           = $sag.HttpListeners
                        ownerTag                = $null
                    })
                }
            }
        }
        catch { }
    }
}

# Fallback to az CLI if appGws is still empty
if ((-not $appGws -or $appGws.Count -eq 0) -and $hasAzCli) {
    try {
        $rawCliAgw = az network application-gateway list -o json 2>$null
        if ($LASTEXITCODE -eq 0 -and $rawCliAgw) {
            $cliGateways = ($rawCliAgw -join "`n") | ConvertFrom-Json
            if ($cliGateways) {
                $appGws = [System.Collections.Generic.List[PSObject]]::new()
                foreach ($cag in $cliGateways) {
                    $subFromId = if ($cag.id) { $cag.id.Split('/')[2] } else { "" }
                    $appGws.Add([PSCustomObject]@{
                        name                    = $cag.name
                        id                      = $cag.id
                        resourceGroup           = $cag.resourceGroup
                        subscriptionId          = $subFromId
                        sslCertificates         = $cag.sslCertificates
                        trustedRootCertificates = $cag.trustedRootCertificates
                        httpListeners           = $cag.httpListeners
                        ownerTag                = $null
                    })
                }
            }
        }
    } catch { }
}

Write-Host "      Found $($appGws.Count) Application Gateway(s) to inspect." -ForegroundColor Gray

foreach ($ag in $appGws) {
    $agwName = $ag.name
    $agwRg   = $ag.resourceGroup
    $subId   = $ag.subscriptionId
    $subName = if ($subNameLookup.ContainsKey($subId)) { $subNameLookup[$subId] } else { $subId }
    $ownerVal = if (-not [string]::IsNullOrWhiteSpace($ag.ownerTag)) { $ag.ownerTag } else { $FallbackOwnerEmail }

    # CRITICAL: Azure Resource Graph (Search-AzGraph) does NOT include 'publicCertData' for SSL certificates!
    # To fetch directly uploaded certificates, we MUST obtain the full Application Gateway object from ARM.
    $fullAgw = $null
    if (Get-Command Get-AzApplicationGateway -ErrorAction SilentlyContinue) {
        try {
            $null = Set-AzContext -SubscriptionId $subId -ErrorAction SilentlyContinue
            $fullAgw = Get-AzApplicationGateway -Name $agwName -ResourceGroupName $agwRg -ErrorAction SilentlyContinue
        } catch { }
    }

    if (-not $fullAgw -and $hasAzCli) {
        try {
            $rawAgwJson = az network application-gateway show --subscription $subId -g $agwRg -n $agwName -o json 2>$null
            if ($LASTEXITCODE -eq 0 -and $rawAgwJson) {
                $fullAgw = ($rawAgwJson -join "`n") | ConvertFrom-Json
            }
        } catch { }
    }

    # Extract sslCertificates from full object or fallback to ARG stub
    $sslCerts = $null
    if ($fullAgw) {
        if ($fullAgw.SslCertificates) { $sslCerts = $fullAgw.SslCertificates }
        elseif ($fullAgw.properties -and $fullAgw.properties.sslCertificates) { $sslCerts = $fullAgw.properties.sslCertificates }
        elseif ($fullAgw.sslCertificates) { $sslCerts = $fullAgw.sslCertificates }
    }
    if (-not $sslCerts) { $sslCerts = $ag.sslCertificates }

    if (-not $sslCerts -or $sslCerts.Count -eq 0) {
        Write-Host "  -> Application Gateway: $agwName ($agwRg) -> No SSL certificates configured" -ForegroundColor DarkGray
        continue
    }

    # Build Listener & Hostname Mapping
    $certListenerMap = @{}
    $listeners = if ($fullAgw.HttpListeners) { $fullAgw.HttpListeners }
                 elseif ($fullAgw.properties -and $fullAgw.properties.httpListeners) { $fullAgw.properties.httpListeners }
                 elseif ($fullAgw.httpListeners) { $fullAgw.httpListeners }
                 elseif ($ag.httpListeners) { $ag.httpListeners }
                 else { @() }

    foreach ($lst in $listeners) {
        $certRef = $null
        if ($lst.SslCertificate -and $lst.SslCertificate.Id) { $certRef = $lst.SslCertificate.Id }
        elseif ($lst.sslCertificate -and $lst.sslCertificate.id) { $certRef = $lst.sslCertificate.id }
        elseif ($lst.properties -and $lst.properties.sslCertificate -and $lst.properties.sslCertificate.id) { $certRef = $lst.properties.sslCertificate.id }

        if ($certRef) {
            $cName = $certRef.Split('/')[-1]
            $lstName = if ($lst.Name) { $lst.Name } elseif ($lst.name) { $lst.name } else { "Listener" }
            $hostVal = if ($lst.HostName) { $lst.HostName }
                       elseif ($lst.hostName) { $lst.hostName }
                       elseif ($lst.properties -and $lst.properties.hostName) { $lst.properties.hostName }
                       elseif ($lst.HostNames) { $lst.HostNames -join ", " }
                       elseif ($lst.properties -and $lst.properties.hostNames) { $lst.properties.hostNames -join ", " }
                       else { "" }
            
            $listenerLabel = if ($hostVal) { "$lstName ($hostVal)" } else { $lstName }
            if (-not $certListenerMap.ContainsKey($cName)) {
                $certListenerMap[$cName] = [System.Collections.Generic.List[string]]::new()
            }
            $certListenerMap[$cName].Add($listenerLabel)
        }
    }

    Write-Host "  -> Application Gateway: $agwName ($agwRg) -> Inspecting $($sslCerts.Count) SSL certificate(s)..." -ForegroundColor Gray

    foreach ($certItem in $sslCerts) {
        $certName = if ($certItem.Name) { $certItem.Name } elseif ($certItem.name) { $certItem.name } else { "ssl-cert" }
        $certId   = if ($certItem.Id) { $certItem.Id } elseif ($certItem.id) { $certItem.id } else { "$($ag.id)/sslCertificates/$certName" }
        $listenersDesc = if ($certListenerMap.ContainsKey($certName)) { $certListenerMap[$certName] -join "; " } else { "Unattached / No Listener" }

        # Extract KeyVaultSecretId (handle both ARM & ARG object models)
        $kvSecretId = $null
        if ($certItem.KeyVaultSecretId) { $kvSecretId = $certItem.KeyVaultSecretId }
        elseif ($certItem.properties -and $certItem.properties.keyVaultSecretId) { $kvSecretId = $certItem.properties.keyVaultSecretId }
        elseif ($certItem.keyVaultSecretId) { $kvSecretId = $certItem.keyVaultSecretId }

        # Extract PublicCertData / Data (handle ARM, ARG, and CLI models)
        $publicData = $null
        if ($certItem.PublicCertData) { $publicData = $certItem.PublicCertData }
        elseif ($certItem.properties -and $certItem.properties.publicCertData) { $publicData = $certItem.properties.publicCertData }
        elseif ($certItem.publicCertData) { $publicData = $certItem.publicCertData }
        elseif ($certItem.Data) { $publicData = $certItem.Data }
        elseif ($certItem.properties -and $certItem.properties.data) { $publicData = $certItem.properties.data }
        elseif ($certItem.data) { $publicData = $certItem.data }

        # SCENARIO A: Key Vault-Linked Certificate
        if (-not [string]::IsNullOrWhiteSpace($kvSecretId)) {
            $vaultName = "Unknown"
            $secretName = $certName

            try {
                $kvUri = [System.Uri]$kvSecretId
                $vaultName = $kvUri.Host.Split('.')[0]
                $uriSegments = $kvUri.AbsolutePath.Trim('/').Split('/')
                if ($uriSegments.Length -gt 1) { $secretName = $uriSegments[1] }
            } catch { }

            # Attempt to resolve certificate expiry directly from Key Vault
            $resolvedExpDate = $null
            $resolvedThumbprint = "KeyVault-Linked"
            $resolvedSubject = "Key Vault Reference: $vaultName / $secretName | Listener: $listenersDesc"
            $resolvedStatus = $null

            try {
                $null = Set-AzContext -SubscriptionId $subId -ErrorAction SilentlyContinue
                $kvCert = Get-AzKeyVaultCertificate -VaultName $vaultName -Name $secretName -ErrorAction SilentlyContinue
                if ($kvCert) {
                    if ($kvCert.Expires) { $resolvedExpDate = [DateTime]$kvCert.Expires }
                    elseif ($kvCert.Attributes -and $kvCert.Attributes.Expires) { $resolvedExpDate = [DateTime]$kvCert.Attributes.Expires }
                    if ($kvCert.Thumbprint) { $resolvedThumbprint = $kvCert.Thumbprint }
                    $resolvedSubject = "Key Vault Certificate: $vaultName / $secretName | Listener: $listenersDesc"
                } else {
                    $kvSec = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -ErrorAction SilentlyContinue
                    if ($kvSec) {
                        if ($kvSec.Expires) { $resolvedExpDate = [DateTime]$kvSec.Expires }
                        elseif ($kvSec.Attributes -and $kvSec.Attributes.Expires) { $resolvedExpDate = [DateTime]$kvSec.Attributes.Expires }
                        $resolvedSubject = if ($kvSec.ContentType) { "$($kvSec.ContentType) | Listener: $listenersDesc" } else { "Key Vault Secret: $vaultName / $secretName | Listener: $listenersDesc" }
                    }
                }
            } catch { }

            if ($resolvedExpDate) {
                $daysLeft = ($resolvedExpDate - (Get-Date)).Days
                $resolvedStatus = Get-ExpiryStatus $daysLeft
                $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }
            } else {
                $daysLeft = 9999
                $resolvedStatus = "KEYVAULT LINKED (Review Vault: $vaultName)"
                $include = $true
            }

            if ($include) {
                $agwDiscoveredCount++
                $allInfraRecords.Add([PSCustomObject]@{
                    WorkloadSource         = "Azure Application Gateway SSL (Key Vault)"
                    ResourceName           = "$agwName ($agwRg)"
                    ResourceGroupName      = $agwRg
                    SubscriptionName       = $subName
                    SubscriptionId         = $subId
                    CertificateOrSecret    = "$certName (KV: $secretName)"
                    Thumbprint             = $resolvedThumbprint
                    IssuerOrSubject        = $resolvedSubject
                    ExpirationDate         = if ($resolvedExpDate) { $resolvedExpDate.ToString("yyyy-MM-dd") } else { "Managed in KV ($vaultName)" }
                    DaysRemaining          = $daysLeft
                    Status                 = $resolvedStatus
                    Owner                  = $ownerVal
                    ResourceId             = $kvSecretId
                })
            }
            continue
        }

        # SCENARIO B: Directly Uploaded Certificate (PFX / PublicCertData)
        $x509 = ConvertFrom-PublicCertData -certData $publicData

        if ($x509) {
            $expDate  = $x509.NotAfter
            $daysLeft = ($expDate - (Get-Date)).Days
            $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }

            if ($include) {
                $agwDiscoveredCount++
                $simpleSubject = $x509.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                $issuerName    = $x509.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)

                $allInfraRecords.Add([PSCustomObject]@{
                    WorkloadSource         = "Azure Application Gateway SSL (Uploaded)"
                    ResourceName           = "$agwName ($agwRg)"
                    ResourceGroupName      = $agwRg
                    SubscriptionName       = $subName
                    SubscriptionId         = $subId
                    CertificateOrSecret    = $certName
                    Thumbprint             = $x509.Thumbprint
                    IssuerOrSubject        = "CN=$simpleSubject | Issuer: $issuerName | Listeners: $listenersDesc"
                    ExpirationDate         = $expDate.ToString("yyyy-MM-dd")
                    DaysRemaining          = $daysLeft
                    Status                 = Get-ExpiryStatus $daysLeft
                    Owner                  = $ownerVal
                    ResourceId             = $certId
                })
            }
            $x509.Dispose()
        }
        else {
            # Directly uploaded certificate exists on App Gateway, but publicCertData could not be decoded
            # DO NOT SILENTLY DROP - Surface as directly uploaded certificate so admins are aware!
            $agwDiscoveredCount++
            $allInfraRecords.Add([PSCustomObject]@{
                WorkloadSource         = "Azure Application Gateway SSL (Uploaded)"
                ResourceName           = "$agwName ($agwRg)"
                ResourceGroupName      = $agwRg
                SubscriptionName       = $subName
                SubscriptionId         = $subId
                CertificateOrSecret    = $certName
                Thumbprint             = "Directly-Uploaded"
                IssuerOrSubject        = "Direct AppGW Upload | Listeners: $listenersDesc"
                ExpirationDate         = "Uploaded Directly to AppGW"
                DaysRemaining          = 9999
                Status                 = "DIRECTLY UPLOADED TO APPGW (Review Expiry)"
                Owner                  = $ownerVal
                ResourceId             = $certId
            })
        }
    }

    # Inspect TrustedRootCertificates if present
    $rootCerts = if ($fullAgw.TrustedRootCertificates) { $fullAgw.TrustedRootCertificates }
                 elseif ($fullAgw.properties -and $fullAgw.properties.trustedRootCertificates) { $fullAgw.properties.trustedRootCertificates }
                 elseif ($ag.trustedRootCertificates) { $ag.trustedRootCertificates }
                 else { @() }

    foreach ($rc in $rootCerts) {
        $rcName = if ($rc.Name) { $rc.Name } elseif ($rc.name) { $rc.name } else { "root-cert" }
        $rcData = if ($rc.Data) { $rc.Data } elseif ($rc.data) { $rc.data } elseif ($rc.properties -and $rc.properties.data) { $rc.properties.data } else { $null }
        $rcX509 = ConvertFrom-PublicCertData -certData $rcData
        if ($rcX509) {
            $expDate  = $rcX509.NotAfter
            $daysLeft = ($expDate - (Get-Date)).Days
            $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }
            if ($include) {
                $agwDiscoveredCount++
                $allInfraRecords.Add([PSCustomObject]@{
                    WorkloadSource         = "Azure App Gateway (Trusted Root Cert)"
                    ResourceName           = "$agwName ($agwRg)"
                    ResourceGroupName      = $agwRg
                    SubscriptionName       = $subName
                    SubscriptionId         = $subId
                    CertificateOrSecret    = $rcName
                    Thumbprint             = $rcX509.Thumbprint
                    IssuerOrSubject        = "CN=$($rcX509.Subject) (Trusted Root)"
                    ExpirationDate         = $expDate.ToString("yyyy-MM-dd")
                    DaysRemaining          = $daysLeft
                    Status                 = Get-ExpiryStatus $daysLeft
                    Owner                  = $ownerVal
                    ResourceId             = "$($ag.id)/trustedRootCertificates/$rcName"
                })
            }
            $rcX509.Dispose()
        }
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
