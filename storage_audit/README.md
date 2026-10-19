# Azure Storage Security Audit Reports (AWS S3 Replication)

This repository contains scripts and queries to audit Azure Storage Account security configurations and export them into reports matching AWS S3 consolidated security and Block Public Access (BPA) tracking layouts.

---

## ⚡ 1-Click Copy & Paste for Azure Cloud Shell (PowerShell)

Open **Azure Cloud Shell** (`>_` icon in top bar of Azure Portal), ensure **PowerShell** is selected, and **copy & paste this single code block directly into the terminal**.

> 🔒 **Strict Scope Guarantee:** This script resolves your Management Group recursively to its exact child subscriptions and **hard-filters both the query engine and the KQL query**. It is physically impossible to scan or return resources from other subscriptions in the tenant.

```powershell
# ==============================================================================
# 1-CLICK AZURE CLOUD SHELL AUDIT SCRIPT (STRICT MANAGEMENT GROUP SCOPE)
# ==============================================================================

# 1. Prompt for Management Group ID or Name
$mgInput = Read-Host "Enter your Management Group ID or Display Name (or press Enter to list)"
if ([string]::IsNullOrWhiteSpace($mgInput)) {
    Write-Host "`nListing your accessible Management Groups..." -ForegroundColor Cyan
    Get-AzManagementGroup | Select-Object Name, DisplayName | Format-Table -AutoSize
    $mgInput = Read-Host "Enter the Management Group Name (ID) from the table above"
}

# 2. Resolve Management Group recursively
Write-Host "`n[1/4] Resolving Management Group '$mgInput'..." -ForegroundColor Cyan
$mg = Get-AzManagementGroup -GroupId $mgInput -Expand -Recurse -ErrorAction SilentlyContinue
if (-not $mg) {
    $allMgs = Get-AzManagementGroup -ErrorAction SilentlyContinue
    $matched = $allMgs | Where-Object { $_.Name -eq $mgInput -or $_.DisplayName -eq $mgInput } | Select-Object -First 1
    if ($matched) {
        $mg = Get-AzManagementGroup -GroupId $matched.Name -Expand -Recurse -ErrorAction SilentlyContinue
    }
}

if (-not $mg) {
    Throw "[ERROR] Management Group '$mgInput' was not found! Execution stopped to avoid scanning the entire tenant."
}

Write-Host "[+] Matched Management Group: $($mg.DisplayName) (ID: $($mg.Name))" -ForegroundColor Green

# 3. Recursively extract all Subscription IDs under this Management Group
$discoveredSubIds = [System.Collections.Generic.List[string]]::new()
function Find-MgSubscriptions($node) {
    if ($node.Children) {
        foreach ($c in $node.Children) {
            if ($c.Type -match 'subscriptions' -and $c.Name) {
                $discoveredSubIds.Add($c.Name)
            }
            if ($c.Children) {
                Find-MgSubscriptions $c
            }
        }
    }
}
Find-MgSubscriptions $mg

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
    Throw "[ERROR] No subscriptions found under Management Group '$($mg.DisplayName)'. Execution stopped."
}

Write-Host "[+] Found $($targetSubs.Count) subscription(s) strictly under this Management Group:" -ForegroundColor Green
$targetSubs | ForEach-Object { Write-Host "    -> Subscription ID: $_" -ForegroundColor DarkGray }

$formattedKqlSubFilter = ($targetSubs | ForEach-Object { "'$_'" }) -join ", "

# 4. Generate Report 1: Consolidated Storage Accounts
Write-Host "`n[2/4] Generating StorageAccount-consolidated.csv..." -ForegroundColor Cyan
Search-AzGraph -Subscription $targetSubs -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where subscriptionId in ($formattedKqlSubFilter)
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
) on subscriptionId
| project
    storageaccountname              = name,
    encryptionkeysource             = tostring(coalesce(properties.encryption.keySource, 'Microsoft.Storage')),
    infrastructureencryptionenabled = tostring(coalesce(properties.encryption.requireInfrastructureEncryption, false)),
    networkacldefaultaction         = tostring(coalesce(properties.networkAcls.defaultAction, 'Allow')),
    subscriptionname                = coalesce(subscriptionName, subscriptionId),
    subscriptionid                  = subscriptionId
| order by subscriptionname asc, storageaccountname asc
"@ -First 5000 | Export-Csv -Path "StorageAccount-consolidated.csv" -NoTypeInformation -Encoding utf8

# 5. Generate Report 2: BPA Subscription Summary
Write-Host "[3/4] Generating StorageAccount-bpa.csv (Subscription Summary)..." -ForegroundColor Cyan
Search-AzGraph -Subscription $targetSubs -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where subscriptionId in ($formattedKqlSubFilter)
| extend isPublicAllowed = coalesce(properties.allowBlobPublicAccess, false)
| summarize
    TotalAccounts = count(),
    PublicAllowedCount = countif(isPublicAllowed == true)
    by subscriptionId
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
) on subscriptionId
| project
    subscriptionname      = subscriptionName,
    subscriptionid        = subscriptionId,
    allowblobpublicaccess = iff(PublicAllowedCount > 0, strcat("true (", PublicAllowedCount, "/", TotalAccounts, " accounts allow public access)"), "false (Blocked on all accounts)")
| order by subscriptionname asc
"@ -First 5000 | Export-Csv -Path "StorageAccount-bpa.csv" -NoTypeInformation -Encoding utf8

# 6. Generate Report 2 Detailed: Per Storage Account BPA
Write-Host "[4/4] Generating StorageAccount-bpa-detailed.csv (Per Storage Account)..." -ForegroundColor Cyan
Search-AzGraph -Subscription $targetSubs -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where subscriptionId in ($formattedKqlSubFilter)
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
) on subscriptionId
| project
    storageaccountname    = name,
    subscriptionname      = coalesce(subscriptionName, subscriptionId),
    subscriptionid        = subscriptionId,
    allowblobpublicaccess = tostring(coalesce(properties.allowBlobPublicAccess, false))
| order by subscriptionname asc, storageaccountname asc
"@ -First 5000 | Export-Csv -Path "StorageAccount-bpa-detailed.csv" -NoTypeInformation -Encoding utf8

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " SUCCESS! Scanned ONLY subscriptions in '$($mg.DisplayName)'" -ForegroundColor Green
Write-Host " 3 files generated in Cloud Shell:" -ForegroundColor Green
Write-Host "  1. StorageAccount-consolidated.csv" -ForegroundColor Yellow
Write-Host "  2. StorageAccount-bpa.csv" -ForegroundColor Yellow
Write-Host "  3. StorageAccount-bpa-detailed.csv" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Green
Write-Host "`nTo download the files to your PC:" -ForegroundColor Cyan
Write-Host "  1. Click the 'Manage files' icon (the double up/down arrow ↕) in Cloud Shell top toolbar."
Write-Host "  2. Click 'Download'."
Write-Host "  3. Type the filename (e.g. StorageAccount-consolidated.csv) and click Download."
```

---

## 2. How to Download the Files to Your Computer

1. In the Azure Cloud Shell toolbar at the top, click the **Manage files** icon (`↕`).
2. Select **Download**.
3. Type the filename:
   - `StorageAccount-consolidated.csv`
   - `StorageAccount-bpa.csv`
   - `StorageAccount-bpa-detailed.csv`
4. Click **Download** to save directly to your local computer.

---

## 3. Exact Column Headers Mapping

### Report 1: `StorageAccount-consolidated.csv`
```csv
storageaccountname,encryptionkeysource,infrastructureencryptionenabled,networkacldefaultaction,subscriptionname,subscriptionid
```

| Excel Column | AWS Column (Original) | Azure Column (Exact Equivalent) | Azure Property Source | What It Pulls in Azure |
|:---:|:---|:---|:---|:---|
| **A** | `bucketname` | `storageaccountname` | `name` | Name of the Azure Storage Account |
| **B** | `ssealgorithm` | `encryptionkeysource` | `properties.encryption.keySource` | `Microsoft.Storage` (MMK) or `Microsoft.Keyvault` (CMK) |
| **C** | `bucketkeyenabled` | `infrastructureencryptionenabled` | `properties.encryption.requireInfrastructureEncryption` | `true` or `false` (Double encryption at hardware/service layers) |
| **D** | `bucket_policy_status` | `networkacldefaultaction` | `properties.networkAcls.defaultAction` | `Allow` (Open to all networks) or `Deny` (Firewall/VNet/Private restricted) |
| **E** | `accountname` | `subscriptionname` | Subscriptions container `name` | Azure Subscription Name |
| **F** | `accountid` | `subscriptionid` | `subscriptionId` | Azure Subscription GUID |

---

### Report 2: `StorageAccount-bpa.csv` (Block Public Access)
```csv
subscriptionname,subscriptionid,allowblobpublicaccess
```

| Excel Column | AWS Column (Original) | Azure Column (Exact Equivalent) | Azure Property Source | What It Pulls in Azure |
|:---:|:---|:---|:---|:---|
| **A** | `accountname` | `subscriptionname` | Subscriptions container `name` | Azure Subscription Name |
| **B** | `accountid` | `subscriptionid` | `subscriptionId` | Azure Subscription GUID |
| **C** | `publicaccessblockconfiguration` | `allowblobpublicaccess` | `properties.allowBlobPublicAccess` | `false` (Public access blocked) or `true` (Anonymous public access allowed) |

---

## 4. Azure Portal &rarr; Resource Graph Explorer (KQL Queries)

If using the Portal GUI directly, you can run these queries. They use `join kind=inner` with `managementGroupAncestorsChain` to guarantee that **only resources inside the specified Management Group are returned**, even if the portal scope is set to Tenant.

*Replace `'YOUR_MANAGEMENT_GROUP_ID'` with your Management Group ID or Display Name:*

### KQL Query 1: Consolidated Report (Hard-Filtered by Management Group)
```kql
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| mv-expand mg = properties.managementGroupAncestorsChain
| where mg.name =~ 'YOUR_MANAGEMENT_GROUP_ID' or mg.displayName =~ 'YOUR_MANAGEMENT_GROUP_ID'
| project subscriptionId, subscriptionName = name
| join kind=inner (
    resources
    | where type =~ 'microsoft.storage/storageaccounts'
) on subscriptionId
| project
    storageaccountname              = name,
    encryptionkeysource             = tostring(coalesce(properties.encryption.keySource, 'Microsoft.Storage')),
    infrastructureencryptionenabled = tostring(coalesce(properties.encryption.requireInfrastructureEncryption, false)),
    networkacldefaultaction         = tostring(coalesce(properties.networkAcls.defaultAction, 'Allow')),
    subscriptionname                = subscriptionName,
    subscriptionid                  = subscriptionId
| order by subscriptionname asc, storageaccountname asc
```

### KQL Query 2: Block Public Access Summary (Hard-Filtered by Management Group)
```kql
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| mv-expand mg = properties.managementGroupAncestorsChain
| where mg.name =~ 'YOUR_MANAGEMENT_GROUP_ID' or mg.displayName =~ 'YOUR_MANAGEMENT_GROUP_ID'
| project subscriptionId, subscriptionName = name
| join kind=inner (
    resources
    | where type =~ 'microsoft.storage/storageaccounts'
    | extend isPublicAllowed = coalesce(properties.allowBlobPublicAccess, false)
) on subscriptionId
| summarize
    TotalAccounts = count(),
    PublicAllowedCount = countif(isPublicAllowed == true)
    by subscriptionId, subscriptionName
| project
    subscriptionname      = subscriptionName,
    subscriptionid        = subscriptionId,
    allowblobpublicaccess = iff(PublicAllowedCount > 0, strcat("true (", PublicAllowedCount, "/", TotalAccounts, " accounts allow public access)"), "false (Blocked on all accounts)")
| order by subscriptionname asc
```

---

## 5. Running the Standalone Script (`Export-StorageAccountSecurityReports.ps1`)

If running from your computer or an automation pipeline:

```powershell
# Audit strictly for a specific Management Group:
.\Export-StorageAccountSecurityReports.ps1 -ManagementGroupId "YOUR_MANAGEMENT_GROUP_ID"

# Export to custom folder with both CSV and native formatted Excel (.xlsx):
.\Export-StorageAccountSecurityReports.ps1 -ManagementGroupId "YOUR_MANAGEMENT_GROUP_ID" -OutputPath "C:\Reports" -Format Both
```
