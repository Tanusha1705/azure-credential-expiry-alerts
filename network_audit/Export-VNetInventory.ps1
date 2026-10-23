<#
.SYNOPSIS
    Exports Azure Virtual Network (VNet) inventory details for one or more Management Groups.

.DESCRIPTION
    Discovers all subscriptions under the specified Management Group(s) (including deeply nested
    child Management Groups) and extracts VNet configurations matching 9 exact attributes:
      1. vnetname
      2. vnetid
      3. addressspace
      4. provisioningstate
      5. dnsservers
      6. isdefault
      7. azureregion
      8. subscriptionid
      9. subscriptionname

    MULTIPLE MANAGEMENT GROUPS SUPPORT:
      - Accepts multiple Management Groups as an array (-ManagementGroupId "mg-1","mg-2")
        or as a comma-separated string (-ManagementGroupId "mg-1,mg-2,mg-3").
      - Subscriptions that exist under more than one MG or nested levels are automatically
        deduplicated so they are only queried once.
      - Uses Azure Resource Graph (ARG) for high-speed batch querying across all discovered
        subscriptions, with automatic fallback to Get-AzVirtualNetwork.
      - Generates safe, sanitized report filenames even when many MGs are specified.

.PARAMETER ManagementGroupId
    One or more Management Group IDs or Display Names to audit.
    Accepts:
      - Array: -ManagementGroupId "mg-1","mg-2"
      - Comma-delimited: -ManagementGroupId "mg-1,mg-2,mg-3"
    Default is @("ac-1.1", "ac-1.2").

.PARAMETER OutputPath
    Directory where reports will be saved. Default is the current script directory.

.PARAMETER Format
    Export format: 'Csv' (default), 'Excel', or 'Both'.

.EXAMPLE
    # Single Management Group:
    .\Export-VNetInventory.ps1 -ManagementGroupId "ac-1.1"

.EXAMPLE
    # Multiple Management Groups as an array:
    .\Export-VNetInventory.ps1 -ManagementGroupId "ac-1.1","ac-1.2","ac-1.3" -Format Both

.EXAMPLE
    # Multiple Management Groups as comma-separated string:
    .\Export-VNetInventory.ps1 -ManagementGroupId "ac-1.1,ac-1.2,ac-1.3"

.EXAMPLE
    # Default (runs with both ac-1.1 and ac-1.2):
    .\Export-VNetInventory.ps1
#>

[CmdletBinding()]
param (
    # =========================================================================
    # EDIT MANAGEMENT GROUP(S) HERE:
    # You can modify, add, or remove Management Group IDs in this array:
    # =========================================================================
    [Parameter(Mandatory = $false, HelpMessage = "One or more Management Group IDs or Display Names. E.g.: -ManagementGroupId 'ac-1.1','ac-1.2'")]
    [string[]]$ManagementGroupId = @("ac-1.1", "ac-1.2"),

    [Parameter(Mandatory = $false, HelpMessage = "Directory where reports will be saved")]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, HelpMessage = "Export format: Csv (default), Excel, or Both")]
    [ValidateSet('Csv', 'Excel', 'Both')]
    [string]$Format = 'Csv'
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# -------------------------------------------------------------------------
# NORMALIZE MANAGEMENT GROUP INPUT (Supports arrays, comma-delimited strings)
# -------------------------------------------------------------------------
$normalizedMgList = [System.Collections.Generic.List[string]]::new()
foreach ($item in $ManagementGroupId) {
    if ([string]::IsNullOrWhiteSpace($item)) { continue }
    if ($item -match ',') {
        foreach ($subItem in ($item -split ',')) {
            $clean = $subItem.Trim()
            if (-not [string]::IsNullOrWhiteSpace($clean) -and -not $normalizedMgList.Contains($clean)) {
                $normalizedMgList.Add($clean)
            }
        }
    }
    else {
        $clean = $item.Trim()
        if (-not [string]::IsNullOrWhiteSpace($clean) -and -not $normalizedMgList.Contains($clean)) {
            $normalizedMgList.Add($clean)
        }
    }
}

if ($normalizedMgList.Count -eq 0) {
    Throw "[ERROR] No valid Management Group IDs provided."
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Azure Virtual Network (VNet) Inventory Extraction" -ForegroundColor Cyan
Write-Host " Target Scope : $($normalizedMgList.Count) Management Group(s): $($normalizedMgList -join ', ')" -ForegroundColor Yellow
Write-Host " Attributes   : vnetname | vnetid | addressspace | provisioningstate" -ForegroundColor Cyan
Write-Host "                dnsservers | isdefault | azureregion | subscriptionid | subscriptionname" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# 1. AUTHENTICATION & ENVIRONMENT CHECK
# -------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Throw "The 'Az.Accounts' PowerShell module is required. Run: Install-Module -Name Az.Accounts -Scope CurrentUser"
}

$currentContext = Get-AzContext -ErrorAction SilentlyContinue
if (-not $currentContext) {
    Write-Host "[INFO] No active Azure context detected. Initiating interactive login..." -ForegroundColor Yellow
    Connect-AzAccount | Out-Null
    $currentContext = Get-AzContext
}

Write-Host "[+] Connected as : $($currentContext.Account.Id)" -ForegroundColor Green
Write-Host "[+] Tenant ID    : $($currentContext.Tenant.Id)" -ForegroundColor Green

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$fullOutputPath = [System.IO.Path]::GetFullPath($OutputPath)

$hasImportExcel = [bool](Get-Module -ListAvailable -Name ImportExcel)
if (($Format -in @('Excel', 'Both')) -and -not $hasImportExcel) {
    Write-Host "[WARN] 'ImportExcel' module is not installed. Defaulting to CSV export." -ForegroundColor Yellow
    if ($Format -eq 'Excel') { $Format = 'Csv' }
}

# -------------------------------------------------------------------------
# 2. RESOLVE SUBSCRIPTIONS ACROSS ALL SUPPLIED MANAGEMENT GROUPS
# -------------------------------------------------------------------------
Write-Host "`n[STEP 1/3] Resolving $($normalizedMgList.Count) Management Group(s)..." -ForegroundColor Cyan

# Helper: recursively collect subscription IDs from a resolved MG node (handles nested child MGs)
function Find-MgSubsRecursive($node, $collector) {
    if ($node.Children) {
        foreach ($c in $node.Children) {
            # Direct subscription child
            if ($c.Type -match 'subscriptions' -and $c.Name) {
                if (-not $collector.Contains($c.Name)) {
                    $collector.Add($c.Name)
                }
            }
            # Child Management Group with expanded children
            elseif ($c.Children) {
                Find-MgSubsRecursive $c $collector
            }
            # Child Management Group whose children were not expanded by REST API
            elseif ($c.Type -match 'managementGroups' -and $c.Name) {
                $childMg = Get-AzManagementGroup -GroupId $c.Name -Expand -Recurse -ErrorAction SilentlyContinue
                if ($childMg) {
                    Find-MgSubsRecursive $childMg $collector
                }
                else {
                    $childSubs = Get-AzManagementGroupSubscription -GroupName $c.Name -ErrorAction SilentlyContinue
                    if ($childSubs) {
                        foreach ($cs in $childSubs) {
                            $csId = if ($cs.SubscriptionId) { $cs.SubscriptionId } elseif ($cs.Name) { $cs.Name } else { $cs.Id }
                            if ($csId -and -not $collector.Contains($csId)) { $collector.Add($csId) }
                        }
                    }
                }
            }
        }
    }
}

$allMgsCache         = $null
$allDiscoveredSubIds = [System.Collections.Generic.List[string]]::new()
$mgSummaryMap        = [System.Collections.Generic.Dictionary[string, int]]::new()

foreach ($mgInput in $normalizedMgList) {

    Write-Host "`n  [MG] Resolving: '$mgInput'" -ForegroundColor Yellow

    $mg = Get-AzManagementGroup -GroupId $mgInput -Expand -Recurse -ErrorAction SilentlyContinue
    if (-not $mg) {
        if (-not $allMgsCache) { $allMgsCache = Get-AzManagementGroup -ErrorAction SilentlyContinue }
        $matched = $allMgsCache | Where-Object { $_.Name -eq $mgInput -or $_.DisplayName -eq $mgInput } | Select-Object -First 1
        if ($matched) {
            $mg = Get-AzManagementGroup -GroupId $matched.Name -Expand -Recurse -ErrorAction SilentlyContinue
        }
    }

    if (-not $mg) {
        Write-Host "  [WARN] Management Group '$mgInput' was NOT found - skipping." -ForegroundColor Red
        continue
    }

    Write-Host "  [+] Matched: $($mg.DisplayName) (ID: $($mg.Name))" -ForegroundColor Green

    $mgSubIds = [System.Collections.Generic.List[string]]::new()
    Find-MgSubsRecursive $mg $mgSubIds

    # Fallback / Direct check: Get-AzManagementGroupSubscription
    $mgSubs = Get-AzManagementGroupSubscription -GroupName $mg.Name -ErrorAction SilentlyContinue
    if ($mgSubs) {
        foreach ($s in $mgSubs) {
            $sid = if ($s.SubscriptionId) { $s.SubscriptionId } elseif ($s.Name) { $s.Name } else { $s.Id }
            if ($sid -and -not $mgSubIds.Contains($sid)) {
                $mgSubIds.Add($sid)
            }
        }
    }

    Write-Host "  [+] Found $($mgSubIds.Count) subscription(s) under '$($mg.DisplayName)':" -ForegroundColor Green
    $mgSubIds | ForEach-Object { Write-Host "      -> $_" -ForegroundColor DarkGray }

    $mgSummaryMap[$mg.DisplayName] = $mgSubIds.Count
    foreach ($sid in $mgSubIds) {
        if (-not $allDiscoveredSubIds.Contains($sid)) {
            $allDiscoveredSubIds.Add($sid)
        }
    }
}

$targetSubs = @($allDiscoveredSubIds | Select-Object -Unique)
if ($targetSubs.Count -eq 0) {
    Throw "[ERROR] No subscriptions found across any of the supplied Management Groups. Stopped."
}

Write-Host "`n[+] Combined unique subscription(s) across all $($normalizedMgList.Count) Management Group(s): $($targetSubs.Count)" -ForegroundColor Cyan
foreach ($kv in $mgSummaryMap.GetEnumerator()) {
    Write-Host "    * $($kv.Key): $($kv.Value) subscription(s)" -ForegroundColor DarkGray
}

# -------------------------------------------------------------------------
# 3. EXTRACT VNET INVENTORY DATA
# -------------------------------------------------------------------------
$vnetRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$hasArg = [bool](Get-Module -ListAvailable -Name Az.ResourceGraph)

if ($hasArg) {
    Write-Host "`n[STEP 2/3] Extracting VNets via Azure Resource Graph (High-Speed Batch)..." -ForegroundColor Cyan
    try {
        # Process in chunks of 800 subscriptions to safely respect Azure Resource Graph limits
        $chunkSize = 800
        for ($i = 0; $i -lt $targetSubs.Count; $i += $chunkSize) {
            $chunkLength = [Math]::Min($chunkSize, $targetSubs.Count - $i)
            $subChunk    = $targetSubs[$i..($i + $chunkLength - 1)]
            $formattedKqlSubFilter = ($subChunk | ForEach-Object { "'$_'" }) -join ", "

            $kqlLines = @(
                "resources",
                "| where type =~ 'microsoft.network/virtualnetworks'",
                "| where subscriptionId in ($formattedKqlSubFilter)",
                "| join kind=leftouter (",
                "    resourcecontainers",
                "    | where type =~ 'microsoft.resources/subscriptions'",
                "    | project subscriptionId, subscriptionName = name",
                ") on subscriptionId",
                "| project",
                "    vnetname          = name,",
                "    vnetid            = id,",
                "    addressspace      = strcat_array(properties.addressSpace.addressPrefixes, ', '),",
                "    provisioningstate = tostring(properties.provisioningState),",
                "    dnsservers        = iff(isnotempty(properties.dhcpOptions.dnsServers), strcat_array(properties.dhcpOptions.dnsServers, ', '), 'Azure provided (Default)'),",
                "    isdefault         = tostring(coalesce(tags.isDefault, tags.Default, iff(name =~ 'default', 'true', 'false'))),",
                "    azureregion       = location,",
                "    subscriptionid    = subscriptionId,",
                "    subscriptionname  = coalesce(subscriptionName, subscriptionId)",
                "| order by subscriptionname asc, vnetname asc"
            )
            $kqlQuery = $kqlLines -join "`n"

            $rawResults = Search-AzGraph -Subscription $subChunk -Query $kqlQuery -First 5000
            if ($rawResults) {
                foreach ($row in $rawResults) {
                    $vnetRecords.Add([PSCustomObject]@{
                        vnetname          = $row.vnetname
                        vnetid            = $row.vnetid
                        addressspace      = $row.addressspace
                        provisioningstate = $row.provisioningstate
                        dnsservers        = $row.dnsservers
                        isdefault         = $row.isdefault
                        azureregion       = $row.azureregion
                        subscriptionid    = $row.subscriptionid
                        subscriptionname  = $row.subscriptionname
                    })
                }
            }
        }
        Write-Host "[+] Retrieved $($vnetRecords.Count) Virtual Network(s) across target subscriptions." -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Azure Resource Graph error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "       Falling back to standard Az cmdlets (Get-AzVirtualNetwork)..." -ForegroundColor Yellow
        $hasArg = $false
        $vnetRecords.Clear()
    }
}

if (-not $hasArg) {
    Write-Host "`n[STEP 2/3] Extracting VNets via Az cmdlets (Get-AzVirtualNetwork)..." -ForegroundColor Cyan
    $subs = Get-AzSubscription | Where-Object { $targetSubs -contains $_.Id }

    foreach ($sub in $subs) {
        Write-Host "  -> Scanning Subscription: $($sub.Name) ($($sub.Id))..." -ForegroundColor Gray
        $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue

        $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
        if (-not $vnets) { continue }

        foreach ($vnet in $vnets) {
            $addr = if ($vnet.AddressSpace.AddressPrefixes) { $vnet.AddressSpace.AddressPrefixes -join ", " } else { "" }
            $dns = if ($vnet.DhcpOptions.DnsServers -and $vnet.DhcpOptions.DnsServers.Count -gt 0) {
                $vnet.DhcpOptions.DnsServers -join ", "
            } else {
                "Azure provided (Default)"
            }
            $isDef = if ($vnet.Tags -and $vnet.Tags.ContainsKey('isDefault')) {
                $vnet.Tags['isDefault']
            } elseif ($vnet.Tags -and $vnet.Tags.ContainsKey('Default')) {
                $vnet.Tags['Default']
            } elseif ($vnet.Name -match 'default') {
                "true"
            } else {
                "false"
            }

            $vnetRecords.Add([PSCustomObject]@{
                vnetname          = $vnet.Name
                vnetid            = $vnet.Id
                addressspace      = $addr
                provisioningstate = $vnet.ProvisioningState
                dnsservers        = $dns
                isdefault         = $isDef
                azureregion       = $vnet.Location
                subscriptionid    = $sub.Id
                subscriptionname  = $sub.Name
            })
        }
    }
}

# -------------------------------------------------------------------------
# 4. EXPORT REPORTS (Safe multi-MG filenames)
# -------------------------------------------------------------------------
Write-Host "`n[STEP 3/3] Exporting VNet Inventory..." -ForegroundColor Cyan

# Build a safe filename label that will never exceed path limits or contain invalid characters
$cleanMgList = $normalizedMgList | ForEach-Object { $_ -replace '[\\/:*?"<>| ]', '_' }
$mgFileLabel = if ($cleanMgList.Count -eq 1) {
    $cleanMgList[0]
} elseif ($cleanMgList.Count -eq 2) {
    "$($cleanMgList[0])_and_$($cleanMgList[1])"
} else {
    "$($cleanMgList[0])_and_$($cleanMgList.Count - 1)_other_MGs"
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$fileBase  = Join-Path $fullOutputPath "VNet-Inventory-$mgFileLabel-$timestamp"

if ($Format -in @('Csv', 'Both')) {
    $csvPath = "$fileBase.csv"
    $vnetRecords | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
    Write-Host "[+] Generated CSV: $csvPath" -ForegroundColor Green
    Write-Host "    Columns: vnetname | vnetid | addressspace | provisioningstate | dnsservers | isdefault | azureregion | subscriptionid | subscriptionname" -ForegroundColor DarkGray
    Write-Host "    Total VNets Exported: $($vnetRecords.Count)" -ForegroundColor DarkGray
}

if ($Format -in @('Excel', 'Both') -and $hasImportExcel) {
    $xlsxPath = "$fileBase.xlsx"
    $excelParams = @{
        BoldTopRow   = $true
        AutoSize     = $true
        AutoFilter   = $true
        FreezeTopRow = $true
    }
    $vnetRecords | Export-Excel -Path $xlsxPath -WorksheetName "VNetInventory" @excelParams
    Write-Host "[+] Generated Excel: $xlsxPath" -ForegroundColor Green
}

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " EXTRACTION COMPLETE" -ForegroundColor Green
Write-Host " Management Groups : $($normalizedMgList -join ', ')"
Write-Host " Subscriptions     : $($targetSubs.Count)"
Write-Host " Total VNets       : $($vnetRecords.Count)"
Write-Host " Output Directory  : $fullOutputPath"
Write-Host "========================================================" -ForegroundColor Green

if ($vnetRecords.Count -gt 0) {
    Write-Host "`nSample Data (First 3 VNets):" -ForegroundColor Yellow
    $vnetRecords | Select-Object -First 3 vnetname, addressspace, provisioningstate, azureregion, subscriptionname | Format-Table -AutoSize | Out-String | Write-Host
}

return $vnetRecords
