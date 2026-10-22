# Azure Virtual Network (VNet) Audits & Inventory

This directory contains automation scripts and Azure Resource Graph (KQL) queries to extract detailed configuration, capacity, and security inventory for Azure Virtual Networks (VNets) and Subnets within a specific Management Group.

---

## 📑 Available Reports & Scripts

| Report Name | Scope | Script File | Output File | Attributes Extracted |
|---|---|---|---|---|
| **1. VNet Inventory** | VNet Level | [`Export-VNetInventory-ac-1.1.ps1`](./Export-VNetInventory-ac-1.1.ps1) | `VNet-Inventory-ac-1.1.csv` | `vnetname`, `vnetid`, `addressspace`, `provisioningstate`, `dnsservers`, `isdefault`, `azureregion`, `subscriptionid`, `subscriptionname` |
| **2. Subnet Details** | Subnet Level | [`Export-VNetSubnetDetails.ps1`](./Export-VNetSubnetDetails.ps1) | `VNet-Subnet-Details-ac-1.1.csv` | 14 Subnet & IP capacity attributes (Available IPs, IPv6, Subnet IDs, etc.) |

---

# Part 1: VNet Inventory Report (`Export-VNetInventory-ac-1.1.ps1`)

### Exact Column Headers (Row 1):
```csv
vnetname,vnetid,addressspace,provisioningstate,dnsservers,isdefault,azureregion,subscriptionid,subscriptionname
```

| Column # | Column Header | Data Type | Description | Azure Property Source |
|:---:|:---|:---|:---|:---|
| **1** | `vnetname` | String | Name of the Virtual Network | `name` |
| **2** | `vnetid` | String | Full ARM Resource ID of the VNet | `id` |
| **3** | `addressspace` | String | Configured CIDR address prefixes (comma-separated) | `properties.addressSpace.addressPrefixes` |
| **4** | `provisioningstate` | String | ARM Provisioning State (`Succeeded`, `Updating`, etc.) | `properties.provisioningState` |
| **5** | `dnsservers` | String | Custom DNS Servers or `Azure provided (Default)` | `properties.dhcpOptions.dnsServers` |
| **6** | `isdefault` | String / Boolean | `true` or `false` (Evaluates tags or default naming) | Tags `isDefault` / `Default` or naming |
| **7** | `azureregion` | String | Azure Location / Region (e.g. `eastus`, `westeurope`) | `location` |
| **8** | `subscriptionid` | String | Azure Subscription ID (GUID) | `subscriptionId` |
| **9** | `subscriptionname` | String | Azure Subscription Display Name | Subscriptions container `name` |

---

### ⚡ 1-Click Copy & Paste for Azure Cloud Shell: VNet Inventory

Open **Azure Cloud Shell** (`>_` icon in top bar of Azure Portal), ensure **PowerShell** is selected, and **copy & paste this block directly into the terminal**:

```powershell
# ==============================================================================
# 1-CLICK VNET INVENTORY EXTRACTION (MANAGEMENT GROUP: ac-1.1)
# ==============================================================================
$mgInput = "ac-1.1"   # <-- Pre-configured for ac-1.1

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

Write-Host "`n[2/3] Extracting Virtual Network inventory via Azure Resource Graph..." -ForegroundColor Cyan

$kqlQuery = @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| where subscriptionId in ($formattedKqlSubFilter)
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
) on subscriptionId
| project
    vnetname          = name,
    vnetid            = id,
    addressspace      = strcat_array(properties.addressSpace.addressPrefixes, ', '),
    provisioningstate = tostring(properties.provisioningState),
    dnsservers        = iff(isnotempty(properties.dhcpOptions.dnsServers), strcat_array(properties.dhcpOptions.dnsServers, ', '), 'Azure provided (Default)'),
    isdefault         = tostring(coalesce(tags.isDefault, tags.Default, iff(name =~ 'default', 'true', 'false'))),
    azureregion       = location,
    subscriptionid    = subscriptionId,
    subscriptionname  = coalesce(subscriptionName, subscriptionId)
| order by subscriptionname asc, vnetname asc
"@

$outputFile = "VNet-Inventory-$mgInput.csv"
Search-AzGraph -Subscription $targetSubs -Query $kqlQuery -First 5000 | Export-Csv -Path $outputFile -NoTypeInformation -Encoding utf8

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " SUCCESS! VNet Inventory generated:" -ForegroundColor Green
Write-Host " File: $outputFile" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Green
Write-Host "`nTo download the file to your computer:" -ForegroundColor Cyan
Write-Host "  1. Click the 'Manage files' icon (↕) in Cloud Shell top toolbar."
Write-Host "  2. Click 'Download'."
Write-Host "  3. Type: $outputFile and click Download."
```

---

# Part 2: Subnet Details Report (`Export-VNetSubnetDetails.ps1`)

For granular subnet-level IP capacity, IPv6, and configuration details:

### Exact Column Headers (Row 1):
```csv
SubnetName,Region,ZoneRedundancyScope,AvailableIPAddressCount,AddressPrefix,ProvisioningState,SubnetId,VNetName,TenantOrSubscriptionId,EnableIPv6,SubnetResourceId,SubscriptionId,SubscriptionName,ResourceGroupName
```

### Running Subnet Details Extraction:
```powershell
# Run subnet extraction for any Management Group:
.\Export-VNetSubnetDetails.ps1 -ManagementGroupId "your-management-group"

# Run for multiple Management Groups together:
.\Export-VNetSubnetDetails.ps1 -ManagementGroupId "ac-1.1","ac-1.2" -Format Both
```

---

## 3. How to Run via Standalone Script Files

You can pass **any** Management Group name or list of Management Groups at runtime — **nothing is hardcoded**:

```powershell
cd c:\Users\home\Downloads\exl\network_audit

# 1. Run VNet Inventory with your desired Management Group(s):
.\Export-VNetInventory.ps1 -ManagementGroupId "ac-1.1"
.\Export-VNetInventory.ps1 -ManagementGroupId "ac-1.1","ac-1.2"

# 2. Run and export both CSV and formatted Excel (.xlsx):
.\Export-VNetInventory.ps1 -ManagementGroupId "ac-1.1","ac-1.2" -OutputPath "C:\Reports" -Format Both

# 3. Run Subnet Details with your desired Management Group(s):
.\Export-VNetSubnetDetails.ps1 -ManagementGroupId "ac-1.1","ac-1.2" -Format Both
```
