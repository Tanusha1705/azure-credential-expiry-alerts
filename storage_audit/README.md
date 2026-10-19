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

## 2. Scoping to a Specific Management Group (Azure Cloud Shell PowerShell)

To run **only for a specific Management Group** instead of the entire tenant, simply pass the `-ManagementGroup` parameter to `Search-AzGraph`.

> **💡 How to find your Management Group ID:**
> In Cloud Shell, run:
> ```powershell
> Get-AzManagementGroup | Select-Object Name, DisplayName
> ```
> *(Note: Use the `Name` value, which is the Management Group ID/Code, e.g., `mg-production` or `mycompany-corp`)*.

---

### Quick One-Liners (Scoped to Management Group)

Set your Management Group ID once:
```powershell
$mgId = "YOUR_MANAGEMENT_GROUP_ID"   # <-- Replace with your actual Management Group ID
```

#### Command 1: Generate `StorageAccount-consolidated.csv`
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

#### Command 2: Generate `StorageAccount-bpa.csv` (Subscription Summary)
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

#### Command 3 (Optional): Generate `StorageAccount-bpa-detailed.csv` (Per Storage Account)
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

### How to Download the Files from Azure Cloud Shell to Your PC:
1. In the Azure Cloud Shell top toolbar, click the **Manage files** icon (`↕`).
2. Click **Download**.
3. Type the filename:
   - `StorageAccount-consolidated.csv`
   - `StorageAccount-bpa.csv`
4. Click **Download** to save directly to your local PC.

---

## 3. Azure Portal &rarr; Resource Graph Explorer (KQL Queries)

If using the Azure Portal UI directly:
1. Navigate to **Resource Graph Explorer**.
2. **Method A (GUI Scope Picker):** Click the **Scope** dropdown at the top-left (next to Directory), choose **Management Groups**, and select your Management Group. Then run standard queries.
3. **Method B (Hardcoded KQL Filter):** Use the queries below, which filter directly by Management Group inside the query itself without needing to touch the Scope picker!

### KQL Query 1: Consolidated Report (Scoped by Management Group in KQL)
```kql
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| mv-expand mg = properties.managementGroupAncestorsChain
| where mg.name =~ 'YOUR_MANAGEMENT_GROUP_ID' or mg.displayName =~ 'YOUR_MANAGEMENT_GROUP_NAME'
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

### KQL Query 2: Block Public Access Summary (Scoped by Management Group in KQL)
```kql
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| mv-expand mg = properties.managementGroupAncestorsChain
| where mg.name =~ 'YOUR_MANAGEMENT_GROUP_ID' or mg.displayName =~ 'YOUR_MANAGEMENT_GROUP_NAME'
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

## 4. Full Standalone Automation Script (`Export-StorageAccountSecurityReports.ps1`)

The script has a built-in `-ManagementGroupId` parameter:

```powershell
# Audit only a specific Management Group:
.\Export-StorageAccountSecurityReports.ps1 -ManagementGroupId "YOUR_MANAGEMENT_GROUP_ID"

# Audit specific Management Group and export both CSV and formatted Excel (.xlsx):
.\Export-StorageAccountSecurityReports.ps1 -ManagementGroupId "YOUR_MANAGEMENT_GROUP_ID" -OutputPath "C:\Reports" -Format Both
```

---

## 5. Azure CLI (`az graph query`)

If using Azure CLI with the `-m` (management group) flag:

```bash
# Set your MG ID
MG_ID="YOUR_MANAGEMENT_GROUP_ID"

# 1. Consolidated Report
az graph query -m "$MG_ID" -q "resources | where type =~ 'microsoft.storage/storageaccounts' | join kind=leftouter (resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId, subscriptionName = name) on subscriptionId | project storageaccountname = name, encryptionkeysource = tostring(coalesce(properties.encryption.keySource, 'Microsoft.Storage')), infrastructureencryptionenabled = tostring(coalesce(properties.encryption.requireInfrastructureEncryption, false)), networkacldefaultaction = tostring(coalesce(properties.networkAcls.defaultAction, 'Allow')), subscriptionname = coalesce(subscriptionName, subscriptionId), subscriptionid = subscriptionId | order by subscriptionname asc, storageaccountname asc" --output table
```
