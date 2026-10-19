# Azure Storage Security Audit Reports (AWS S3 Replication)

This repository contains scripts and queries to audit Azure Storage Account security configurations and export them into reports matching AWS S3 consolidated security and Block Public Access (BPA) tracking layouts.

---

## 1. Exact Column Headers Mapping

### Report 1: `StorageAccount-consolidated`
**Excel / CSV Header Row (Row 1):**
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

### Report 2: `StorageAccount-bpa` (Block Public Access)
**Excel / CSV Header Row (Row 1):**
```csv
subscriptionname,subscriptionid,allowblobpublicaccess
```

> **Note on Architecture:** Unlike AWS S3 where Block Public Access is set at the AWS Account level, Azure configures `allowBlobPublicAccess` per Storage Account (or enforces it tenant-wide via Azure Policy). 
> Both options are covered below:
> 1. `StorageAccount-bpa.csv` matching the exact 3 columns at the subscription level.
> 2. `StorageAccount-bpa-detailed.csv` including `storageaccountname` for granular account-by-account tracking.

| Excel Column | AWS Column (Original) | Azure Column (Exact Equivalent) | Azure Property Source | What It Pulls in Azure |
|:---:|:---|:---|:---|:---|
| **A** | `accountname` | `subscriptionname` | Subscriptions container `name` | Azure Subscription Name |
| **B** | `accountid` | `subscriptionid` | `subscriptionId` | Azure Subscription GUID |
| **C** | `publicaccessblockconfiguration` | `allowblobpublicaccess` | `properties.allowBlobPublicAccess` | `false` (Public access blocked) or `true` (Anonymous public access allowed) |

---

## 2. Azure Portal Cloud Shell (PowerShell) — Quick One-Liners

If you are using the **PowerShell terminal inside Azure Portal (Cloud Shell)**, you do **not** need to install any modules or authenticate. 

Copy and paste these commands directly into your Cloud Shell prompt:

### Command 1: Generate `StorageAccount-consolidated.csv`
```powershell
Search-AzGraph -Query @"
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
Search-AzGraph -Query @"
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

### Command 3 (Optional): Generate `StorageAccount-bpa-detailed.csv` (Per Storage Account)
```powershell
Search-AzGraph -Query @"
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

### How to Download the Files from Azure Cloud Shell to Your PC:
1. In the Azure Cloud Shell top toolbar, click the **Manage files** icon (the double up/down arrow icon `↕`).
2. Click **Download**.
3. Type the filename:
   - `StorageAccount-consolidated.csv`
   - `StorageAccount-bpa.csv`
4. Click **Download** to save to your local machine.

---

## 3. Azure Portal &rarr; Resource Graph Explorer (KQL Queries)

You can also run these directly in the Azure Portal interface:
1. Search for **Resource Graph Explorer** in the Azure Portal top search bar.
2. Paste either query into the editor.
3. Click **Run Query**.
4. Click **Download as CSV** to get your spreadsheet immediately.

### KQL Query 1: Consolidated Storage Account Report
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

### KQL Query 2: Block Public Access (Subscription-Level Summary)
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

### KQL Query 2 (Detailed): Block Public Access Per Storage Account
```kql
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
```

---

## 4. Azure CLI (`az graph query`)

If running from Azure CLI:

```bash
# 1. Consolidated Report
az graph query -q "resources | where type =~ 'microsoft.storage/storageaccounts' | join kind=leftouter (resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, subscriptionName = name) on subscriptionId | project storageaccountname = name, encryptionkeysource = tostring(coalesce(properties.encryption.keySource, 'Microsoft.Storage')), infrastructureencryptionenabled = tostring(coalesce(properties.encryption.requireInfrastructureEncryption, false)), networkacldefaultaction = tostring(coalesce(properties.networkAcls.defaultAction, 'Allow')), subscriptionname = coalesce(subscriptionName, subscriptionId), subscriptionid = subscriptionId | order by subscriptionname asc, storageaccountname asc" --output table

# 2. BPA Subscription Report
az graph query -q "resources | where type =~ 'microsoft.storage/storageaccounts' | extend isPublicAllowed = coalesce(properties.allowBlobPublicAccess, false) | summarize TotalAccounts = count(), PublicAllowedCount = countif(isPublicAllowed == true) by subscriptionId | join kind=leftouter (resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, subscriptionName = name) on subscriptionId | project subscriptionname = subscriptionName, subscriptionid = subscriptionId, allowblobpublicaccess = iff(PublicAllowedCount > 0, strcat('true (', PublicAllowedCount, '/', TotalAccounts, ' accounts allow public access)'), 'false (Blocked on all accounts)') | order by subscriptionname asc" --output table
```

---

## 5. Full Standalone Automation Script (`Export-StorageAccountSecurityReports.ps1`)

If you want a full script that supports:
- Automatic fallback from Resource Graph to `Get-AzStorageAccount`
- Direct Excel `.xlsx` formatting with styled headers and autofit columns
- Filtering by specific subscription IDs

Run the script located in this folder:
```powershell
# Run with default CSV export
.\Export-StorageAccountSecurityReports.ps1

# Run with both CSV and native Excel (.xlsx) formatting
.\Export-StorageAccountSecurityReports.ps1 -OutputPath "C:\Reports" -Format Both
```
