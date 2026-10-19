# Azure Storage Security Audit Reports (AWS S3 Replication)

This repository contains scripts and queries to audit Azure Storage Account security configurations and export them into reports matching AWS S3 consolidated security and Block Public Access (BPA) tracking layouts.

---

## ⚡ 1-Click Copy & Paste for Azure Cloud Shell (PowerShell)

Open **Azure Cloud Shell** (`>_` icon in top bar of Azure Portal), make sure **PowerShell** is selected, and **copy & paste this single code block directly into the terminal**:

```powershell
# ==============================================================================
# COPY & PASTE THIS ENTIRE SCRIPT DIRECTLY INTO AZURE CLOUD SHELL (POWERSHELL)
# ==============================================================================

# 1. Prompt for Management Group ID (or press Enter to see all your MGs)
$mgId = Read-Host "Enter your Management Group ID (or press Enter to list your MGs)"
if ([string]::IsNullOrWhiteSpace($mgId)) {
    Write-Host "`nListing your accessible Management Groups..." -ForegroundColor Cyan
    Get-AzManagementGroup | Select-Object Name, DisplayName | Format-Table -AutoSize
    $mgId = Read-Host "Enter the Management Group Name (ID) from the table above"
}

Write-Host "`n[1/3] Generating StorageAccount-consolidated.csv for MG: '$mgId'..." -ForegroundColor Cyan
Search-AzGraph -ManagementGroup $mgId -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
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

Write-Host "[2/3] Generating StorageAccount-bpa.csv (Subscription Summary)..." -ForegroundColor Cyan
Search-AzGraph -ManagementGroup $mgId -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
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

Write-Host "[3/3] Generating StorageAccount-bpa-detailed.csv (Per Storage Account)..." -ForegroundColor Cyan
Search-AzGraph -ManagementGroup $mgId -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
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
Write-Host " SUCCESS! 3 files generated in Cloud Shell:" -ForegroundColor Green
Write-Host "  1. StorageAccount-consolidated.csv" -ForegroundColor Yellow
Write-Host "  2. StorageAccount-bpa.csv" -ForegroundColor Yellow
Write-Host "  3. StorageAccount-bpa-detailed.csv" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Green
Write-Host "`nTo download the files to your PC:" -ForegroundColor Cyan
Write-Host "  1. Click the 'Manage files' icon (the double up/down arrow ↕) in the Cloud Shell top toolbar."
Write-Host "  2. Click 'Download'."
Write-Host "  3. Type the filename (e.g. StorageAccount-consolidated.csv) and click Download."
```

---

## 2. Individual Copy-Paste Commands (By File)

If you prefer to run them one by one, set your `$mgId` first:

```powershell
$mgId = "YOUR_MANAGEMENT_GROUP_ID"   # <-- Replace with your Management Group ID
```

### Command 1: Generate `StorageAccount-consolidated.csv`
```powershell
Search-AzGraph -ManagementGroup $mgId -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
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
```

### Command 2: Generate `StorageAccount-bpa.csv` (Subscription Summary)
```powershell
Search-AzGraph -ManagementGroup $mgId -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
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
```

### Command 3: Generate `StorageAccount-bpa-detailed.csv` (Per Storage Account)
```powershell
Search-AzGraph -ManagementGroup $mgId -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
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
```

---

## 3. How to Download the Files from Azure Cloud Shell to Your PC

1. In the Azure Cloud Shell toolbar at the top, click the **Manage files** icon (`↕`).
2. Select **Download**.
3. Type the filename:
   - `StorageAccount-consolidated.csv`
   - `StorageAccount-bpa.csv`
   - `StorageAccount-bpa-detailed.csv`
4. Click **Download** to save directly to your local computer.

---

## 4. Exact Column Headers Mapping

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

## 5. Azure Portal &rarr; Resource Graph Explorer (KQL Queries)

If using the Portal GUI directly:
1. Search for **Resource Graph Explorer** in Azure Portal.
2. Under **Scope** at the top left, select your **Management Group**.
3. Paste either query below and click **Run Query**, then click **Download as CSV**.

### KQL Query 1: Consolidated Report
```kql
resources
| where type =~ 'microsoft.storage/storageaccounts'
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
```

### KQL Query 2: Block Public Access Summary
```kql
resources
| where type =~ 'microsoft.storage/storageaccounts'
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
```

---

## 6. Standalone Script Usage (`Export-StorageAccountSecurityReports.ps1`)

If running locally with the PowerShell script:

```powershell
# Run with Management Group ID filter:
.\Export-StorageAccountSecurityReports.ps1 -ManagementGroupId "YOUR_MANAGEMENT_GROUP_ID"

# Export both CSV and formatted Excel (.xlsx):
.\Export-StorageAccountSecurityReports.ps1 -ManagementGroupId "YOUR_MANAGEMENT_GROUP_ID" -OutputPath "C:\Reports" -Format Both
```
