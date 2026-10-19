# Azure Virtual Network (VNet) Subnet Audit & Inventory

This directory contains automation scripts and Azure Resource Graph (KQL) queries to extract detailed configuration, capacity, and security inventory for all Azure Virtual Network (VNet) Subnets within a specific Management Group.

---

## 1. Exact Column Headers & Description

The output report `VNet-Subnet-Details.csv` contains the 14 exact attributes requested:

| Column # | Column Header | Data Type | Description | Azure Property Source |
|:---:|:---|:---|:---|:---|
| **1** | `SubnetName` | String | Name of the Subnet | `subnet.name` |
| **2** | `Region` | String | Azure Location / Region | `location` |
| **3** | `ZoneRedundancyScope` | String | Availability Zone scope (e.g. `Zonal: [1,2,3]` or `Regional`) | `zones` / `properties.zoneRedundancy` |
| **4** | `AvailableIPAddressCount` | Number / String | Available, unallocated usable IP addresses (CIDR minus 5 Azure-reserved IPs minus allocated NICs) | Calculated from CIDR & `properties.ipConfigurations` |
| **5** | `AddressPrefix` | String | Subnet CIDR block(s) (e.g. `10.0.1.0/24`) | `subnet.properties.addressPrefix` |
| **6** | `ProvisioningState` | String | ARM Provisioning State (`Succeeded`, `Updating`, etc.) | `subnet.properties.provisioningState` |
| **7** | `SubnetId` | String | Subnet Identifier / Resource GUID | `subnet.properties.resourceGuid` or `subnet.name` |
| **8** | `VNetName` | String | Name of parent Virtual Network | `name` |
| **9** | `TenantOrSubscriptionId` | String | Azure Tenant ID or Subscription ID | `tenantId` / `subscriptionId` |
| **10** | `EnableIPv6` | Boolean | Whether IPv6 CIDR prefix is enabled (`true` / `false`) | Evaluates presence of IPv6 prefix |
| **11** | `SubnetResourceId` | String | Full ARM Resource ID of the subnet | `subnet.id` |
| **12** | `SubscriptionId` | String | Azure Subscription ID (GUID) | `subscriptionId` |
| **13** | `SubscriptionName` | String | Azure Subscription Display Name | Subscriptions container `name` |
| **14** | `ResourceGroupName` | String | Resource Group containing the VNet | `resourceGroup` |

---

## 2. ⚡ 1-Click Copy & Paste for Azure Cloud Shell (PowerShell)

Open **Azure Cloud Shell** (`>_` icon in top bar of Azure Portal), ensure **PowerShell** is selected, and **copy & paste this single code block directly into the terminal**:

> 🔒 **Pre-configured for Management Group `ac-1.1`** (You can change `$mgInput` on line 2 if needed):

```powershell
# ==============================================================================
# 1-CLICK VNET SUBNET INVENTORY SCRIPT (MANAGEMENT GROUP: ac-1.1)
# ==============================================================================
$mgInput = "ac-1.1"   # <-- Replace with your Management Group ID if needed

Write-Host "`n[1/3] Resolving Management Group '$mgInput'..." -ForegroundColor Cyan
$mg = Get-AzManagementGroup -GroupId $mgInput -Expand -Recurse -ErrorAction SilentlyContinue
if (-not $mg) {
    $allMgs = Get-AzManagementGroup -ErrorAction SilentlyContinue
    $matched = $allMgs | Where-Object { $_.Name -eq $mgInput -or $_.DisplayName -eq $mgInput } | Select-Object -First 1
    if ($matched) {
        $mg = Get-AzManagementGroup -GroupId $matched.Name -Expand -Recurse -ErrorAction SilentlyContinue
    }
}

if (-not $mg) {
    Throw "[ERROR] Management Group '$mgInput' was not found! Execution stopped."
}

Write-Host "[+] Matched Management Group: $($mg.DisplayName) (ID: $($mg.Name))" -ForegroundColor Green

# Recursively discover all subscription IDs under this Management Group
$discoveredSubIds = [System.Collections.Generic.List[string]]::new()
function Find-MgSubsRecursive($node) {
    if ($node.Children) {
        foreach ($c in $node.Children) {
            if ($c.Type -match 'subscriptions' -and $c.Name) {
                $discoveredSubIds.Add($c.Name)
            }
            if ($c.Children) {
                Find-MgSubsRecursive $c
            }
        }
    }
}
Find-MgSubsRecursive $mg

if ($discoveredSubIds.Count -eq 0) {
    $mgSubs = Get-AzManagementGroupSubscription -GroupName $mg.Name -ErrorAction SilentlyContinue
    if ($mgSubs) {
        foreach ($s in $mgSubs) {
            $sid = if ($s.SubscriptionId) { $s.SubscriptionId } elseif ($s.Name) { $s.Name } else { $s.Id }
            if ($sid) { $discoveredSubIds.Add($sid) }
        }
    }
}

$targetSubs = @($discoveredSubIds | Select-Object -Unique)
if ($targetSubs.Count -eq 0) {
    Throw "[ERROR] No subscriptions found under Management Group '$($mg.DisplayName)'. Stopped."
}

Write-Host "[+] Discovered $($targetSubs.Count) subscription(s) strictly under '$mgInput':" -ForegroundColor Green
$targetSubs | ForEach-Object { Write-Host "    -> Subscription ID: $_" -ForegroundColor DarkGray }

$formattedKqlSubFilter = ($targetSubs | ForEach-Object { "'$_'" }) -join ", "

Write-Host "`n[2/3] Extracting Subnet Details via Azure Resource Graph..." -ForegroundColor Cyan

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

$outputFile = "VNet-Subnet-Details-$mgInput.csv"
Search-AzGraph -Subscription $targetSubs -Query $kqlQuery -First 5000 | Export-Csv -Path $outputFile -NoTypeInformation -Encoding utf8

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " SUCCESS! Subnet inventory generated:" -ForegroundColor Green
Write-Host " File: $outputFile" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Green
Write-Host "`nTo download the file to your computer:" -ForegroundColor Cyan
Write-Host "  1. Click the 'Manage files' icon (↕) in Cloud Shell top toolbar."
Write-Host "  2. Click 'Download'."
Write-Host "  3. Type: $outputFile and click Download."
```

---

## 3. Azure Portal &rarr; Resource Graph Explorer (KQL Query)

If running directly in the Azure Portal GUI:
1. Search for **Resource Graph Explorer** in Azure Portal.
2. Under **Scope** at the top-left, select Management Group **`ac-1.1`** (or replace `'ac-1.1'` in the query).
3. Paste the KQL query below and click **Run Query**, then click **Download as CSV**:

```kql
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| mv-expand mg = properties.managementGroupAncestorsChain
| where mg.name =~ 'ac-1.1' or mg.displayName =~ 'ac-1.1'
| project subscriptionId, subscriptionName = name
| join kind=inner (
    resources
    | where type =~ 'microsoft.network/virtualnetworks'
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
    SubscriptionName        = subscriptionName,
    ResourceGroupName       = resourceGroup
| order by SubscriptionName asc, VNetName asc, SubnetName asc
```

---

## 4. Running the Standalone Script (`Export-VNetSubnetDetails.ps1`)

If running from your local PowerShell terminal or an automation runner:

```powershell
# Run with default Management Group 'ac-1.1':
.\Export-VNetSubnetDetails.ps1

# Run with a different Management Group:
.\Export-VNetSubnetDetails.ps1 -ManagementGroupId "your-other-mg"

# Export both CSV and formatted Excel (.xlsx):
.\Export-VNetSubnetDetails.ps1 -ManagementGroupId "ac-1.1" -OutputPath "C:\Reports" -Format Both
```
