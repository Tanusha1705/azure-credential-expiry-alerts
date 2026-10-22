<#
.SYNOPSIS
    Exports all Azure Virtual Network (VNet) Subnet details for one or more Management Groups.
    
.DESCRIPTION
    Discovers all subscriptions under the specified Management Group(s) and extracts
    comprehensive VNet and Subnet configuration data matching 14 exact attributes:
      1.  SubnetName
      2.  Region
      3.  ZoneRedundancyScope
      4.  AvailableIPAddressCount
      5.  AddressPrefix
      6.  ProvisioningState
      7.  SubnetId
      8.  VNetName
      9.  TenantOrSubscriptionId
      10. EnableIPv6
      11. SubnetResourceId
      12. SubscriptionId
      13. SubscriptionName
      14. ResourceGroupName

    Multiple Management Groups are supported. Subscriptions that exist under more than
    one MG are automatically deduplicated so they are only queried once.

.PARAMETER ManagementGroupId
    One or more Management Group IDs or Display Names to audit.
    Accepts an array: -ManagementGroupId "ac-1.1","ac-1.2"

.PARAMETER OutputPath
    Directory where reports will be saved. Default is the script directory.

.PARAMETER Format
    Output format: 'Csv' (default), 'Excel', or 'Both'.

.EXAMPLE
    # Single Management Group:
    .\Export-VNetSubnetDetails.ps1 -ManagementGroupId "ac-1.1"

.EXAMPLE
    # Both ac-1.1 and ac-1.2 combined into one report:
    .\Export-VNetSubnetDetails.ps1 -ManagementGroupId "ac-1.1","ac-1.2" -Format Both

.EXAMPLE
    # Save combined results to a specific folder:
    .\Export-VNetSubnetDetails.ps1 -ManagementGroupId "ac-1.1","ac-1.2" -OutputPath "C:\Reports" -Format Both
#>

[CmdletBinding()]
param (
    # =========================================================================
    # EDIT MANAGEMENT GROUP(S) HERE:
    # You can modify, add, or remove Management Group IDs in this array:
    # =========================================================================
    [Parameter(Mandatory = $false, HelpMessage = "One or more Management Group IDs or Display Names. E.g.: -ManagementGroupId 'ac-1.1','ac-1.2'")]
    [string[]]$ManagementGroupId = @("ac-1.1", "ac-1.2"),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Csv', 'Excel', 'Both')]
    [string]$Format = 'Csv'
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Azure VNet Subnet Details Extraction" -ForegroundColor Cyan
Write-Host " Target Scope : $($ManagementGroupId.Count) Management Group(s): $($ManagementGroupId -join ', ')" -ForegroundColor Yellow
Write-Host " Attributes   : 14 Detailed Subnet, VNet, & IP Inventory Fields" -ForegroundColor Cyan
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
    $OutputPath = "."
}
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$hasImportExcel = [bool](Get-Module -ListAvailable -Name ImportExcel)
if (($Format -in @('Excel', 'Both')) -and -not $hasImportExcel) {
    Write-Host "[WARN] 'ImportExcel' module is not installed. Defaulting to standard CSV export." -ForegroundColor Yellow
    if ($Format -eq 'Excel') { $Format = 'Csv' }
}

# -------------------------------------------------------------------------
# 2. RESOLVE SUBSCRIPTIONS ACROSS ALL SUPPLIED MANAGEMENT GROUPS
# -------------------------------------------------------------------------
Write-Host "`n[STEP 1/3] Resolving $($ManagementGroupId.Count) Management Group(s)..." -ForegroundColor Cyan

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

$allMgsCache        = $null
$allDiscoveredSubIds = [System.Collections.Generic.List[string]]::new()

foreach ($mgInput in $ManagementGroupId) {

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
        Write-Host "  [WARN] Management Group '$mgInput' was NOT found — skipping." -ForegroundColor Red
        continue
    }

    Write-Host "  [+] Matched: $($mg.DisplayName) (ID: $($mg.Name))" -ForegroundColor Green

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

    Write-Host "  [+] Found $($mgSubIds.Count) subscription(s) under '$($mg.DisplayName)':" -ForegroundColor Green
    $mgSubIds | ForEach-Object { Write-Host "      -> $_" -ForegroundColor DarkGray }

    foreach ($sid in $mgSubIds) { $allDiscoveredSubIds.Add($sid) }
}

$targetSubs = @($allDiscoveredSubIds | Select-Object -Unique)
if ($targetSubs.Count -eq 0) {
    Throw "[ERROR] No subscriptions found across any of the supplied Management Groups. Stopped."
}

Write-Host "`n[+] Combined unique subscription(s) across all $($ManagementGroupId.Count) Management Group(s): $($targetSubs.Count)" -ForegroundColor Cyan

$formattedKqlSubFilter = ($targetSubs | ForEach-Object { "'$_'" }) -join ", "

# -------------------------------------------------------------------------
# 3. EXTRACT VNET SUBNET DATA
# -------------------------------------------------------------------------
$subnetRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$hasArg = [bool](Get-Module -ListAvailable -Name Az.ResourceGraph)

if ($hasArg) {
    Write-Host "`n[STEP 2/3] Extracting Subnets via Azure Resource Graph (High-Speed)..." -ForegroundColor Cyan
    try {
        $kqlQuery = @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| where subscriptionId in ($formattedKqlSubFilter)
| mv-expand subnet = properties.subnets
| extend
    rawPrefix       = coalesce(tostring(subnet.properties.addressPrefix), tostring(subnet.properties.addressPrefixes[0])),
    allocatedIps    = coalesce(array_length(subnet.properties.ipConfigurations), 0)
| extend
    cidrMask        = toint(split(rawPrefix, '/')[1])
| extend
    totalUsableIps  = iff(isnotnull(cidrMask) and cidrMask >= 8 and cidrMask <= 30 and not(rawPrefix contains ':'), toint(pow(2, 32 - cidrMask) - 5), -1)
| extend
    availableIps    = iff(totalUsableIps >= 0, tostring(max_of(0, totalUsableIps - allocatedIps)), 'Dynamic / IPv6')
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
) on subscriptionId
| project
    SubnetName              = tostring(subnet.name),
    Region                  = location,
    ZoneRedundancyScope     = iff(isnotempty(zones), strcat('Zonal: ', tostring(zones)), 'Regional'),
    AvailableIPAddressCount = availableIps,
    AddressPrefix           = coalesce(tostring(subnet.properties.addressPrefix), strcat_array(subnet.properties.addressPrefixes, ', ')),
    ProvisioningState       = tostring(coalesce(subnet.properties.provisioningState, properties.provisioningState, 'Succeeded')),
    SubnetId                = tostring(coalesce(subnet.properties.resourceGuid, subnet.name)),
    VNetName                = name,
    TenantOrSubscriptionId  = tostring(coalesce(tenantId, subscriptionId)),
    EnableIPv6              = iff(tostring(subnet.properties.addressPrefix) contains ':' or tostring(subnet.properties.addressPrefixes) contains ':', 'true', 'false'),
    SubnetResourceId        = tostring(subnet.id),
    SubscriptionId          = subscriptionId,
    SubscriptionName        = coalesce(subscriptionName, subscriptionId),
    ResourceGroupName       = resourceGroup
| order by SubscriptionName asc, VNetName asc, SubnetName asc
"@

        $rawResults = Search-AzGraph -Subscription $targetSubs -Query $kqlQuery -First 5000
        Write-Host "[+] Retrieved $($rawResults.Count) Subnet(s) across target subscriptions." -ForegroundColor Green

        foreach ($row in $rawResults) {
            $subnetRecords.Add([PSCustomObject]@{
                SubnetName              = $row.SubnetName
                Region                  = $row.Region
                ZoneRedundancyScope     = $row.ZoneRedundancyScope
                AvailableIPAddressCount = $row.AvailableIPAddressCount
                AddressPrefix           = $row.AddressPrefix
                ProvisioningState       = $row.ProvisioningState
                SubnetId                = $row.SubnetId
                VNetName                = $row.VNetName
                TenantOrSubscriptionId  = $row.TenantOrSubscriptionId
                EnableIPv6              = $row.EnableIPv6
                SubnetResourceId        = $row.SubnetResourceId
                SubscriptionId          = $row.SubscriptionId
                SubscriptionName        = $row.SubscriptionName
                ResourceGroupName       = $row.ResourceGroupName
            })
        }
    }
    catch {
        Write-Host "[WARN] Azure Resource Graph error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "       Falling back to standard Az cmdlets (Get-AzVirtualNetwork)..." -ForegroundColor Yellow
        $hasArg = $false
    }
}

if (-not $hasArg) {
    Write-Host "`n[STEP 2/3] Extracting Subnets via Az cmdlets (Get-AzVirtualNetwork)..." -ForegroundColor Cyan
    $subs = Get-AzSubscription | Where-Object { $targetSubs -contains $_.Id }

    foreach ($sub in $subs) {
        Write-Host "  -> Scanning Subscription: $($sub.Name) ($($sub.Id))..." -ForegroundColor Gray
        $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue

        $vnets = Get-AzVirtualNetwork -ErrorAction SilentlyContinue
        if (-not $vnets) { continue }

        foreach ($vnet in $vnets) {
            $zoneScope = if ($vnet.Zones -and $vnet.Zones.Count -gt 0) { "Zonal: " + ($vnet.Zones -join ", ") } else { "Regional" }

            foreach ($sn in $vnet.Subnets) {
                $prefixStr = if ($sn.AddressPrefix) { $sn.AddressPrefix } elseif ($sn.AddressPrefixes) { $sn.AddressPrefixes -join ", " } else { "" }
                $isIpv6 = if ($prefixStr -match ':') { "true" } else { "false" }
                
                # Available IP Calculation
                $availCount = "Dynamic / IPv6"
                if ($prefixStr -and $prefixStr -match '/(\d+)$' -and -not ($prefixStr -match ':')) {
                    $mask = [int]$Matches[1]
                    if ($mask -ge 8 -and $mask -le 30) {
                        $usableTotal = [Math]::Pow(2, 32 - $mask) - 5
                        $allocated = if ($sn.IpConfigurations) { $sn.IpConfigurations.Count } else { 0 }
                        $availCount = [Math]::Max(0, [int]($usableTotal - $allocated)).ToString()
                    }
                }

                $subnetRecords.Add([PSCustomObject]@{
                    SubnetName              = $sn.Name
                    Region                  = $vnet.Location
                    ZoneRedundancyScope     = $zoneScope
                    AvailableIPAddressCount = $availCount
                    AddressPrefix           = $prefixStr
                    ProvisioningState       = if ($sn.ProvisioningState) { $sn.ProvisioningState } else { $vnet.ProvisioningState }
                    SubnetId                = if ($sn.ResourceNavigationLinks -or $sn.ServiceEndpoints) { $sn.Name } else { $sn.Name }
                    VNetName                = $vnet.Name
                    TenantOrSubscriptionId  = $currentContext.Tenant.Id
                    EnableIPv6              = $isIpv6
                    SubnetResourceId        = $sn.Id
                    SubscriptionId          = $sub.Id
                    SubscriptionName        = $sub.Name
                    ResourceGroupName       = $vnet.ResourceGroupName
                })
            }
        }
    }
}

# -------------------------------------------------------------------------
# 4. EXPORT REPORTS
# -------------------------------------------------------------------------
Write-Host "`n[STEP 3/3] Exporting Subnet Inventory..." -ForegroundColor Cyan

$mgLabel = ($ManagementGroupId -join "_and_")
$fileBase = Join-Path $OutputPath "VNet-Subnet-Details-$mgLabel"

if ($Format -in @('Csv', 'Both')) {
    $csvPath = "$fileBase.csv"
    $subnetRecords | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
    Write-Host "[+] Generated: $csvPath" -ForegroundColor Green
    Write-Host "    Total Subnets Exported: $($subnetRecords.Count)" -ForegroundColor DarkGray
}

if ($Format -in @('Excel', 'Both') -and $hasImportExcel) {
    $xlsxPath = "$fileBase.xlsx"
    $excelParams = @{
        BoldTopRow   = $true
        AutoSize     = $true
        AutoFilter   = $true
        FreezeTopRow = $true
    }
    $subnetRecords | Export-Excel -Path $xlsxPath -WorksheetName "VNetSubnets" @excelParams
    Write-Host "[+] Generated: $xlsxPath" -ForegroundColor Green
}

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " EXTRACTION COMPLETE" -ForegroundColor Green
Write-Host " Management Groups : $($ManagementGroupId -join ', ')"
Write-Host " Subscriptions     : $($targetSubs.Count)"
Write-Host " Total Subnets     : $($subnetRecords.Count)"
Write-Host " Output Directory  : $OutputPath"
Write-Host "========================================================" -ForegroundColor Green

if ($subnetRecords.Count -gt 0) {
    Write-Host "`nSample Data (First 3 Subnets):" -ForegroundColor Yellow
    $subnetRecords | Select-Object -First 3 SubnetName, VNetName, AddressPrefix, AvailableIPAddressCount, Region, SubscriptionName | Format-Table -AutoSize | Out-String | Write-Host
}
