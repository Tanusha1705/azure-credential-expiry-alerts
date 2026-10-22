# Azure Storage Security Audit Reports — AWS S3 Replication

This folder contains scripts to audit **Azure Storage Account** security configurations and export them into reports that mirror the layout of AWS S3 consolidated security and Block Public Access (BPA) tracking sheets.

---

## Table of Contents

1. [Resource Field Descriptions](#1-resource-field-descriptions)
2. [AWS vs Azure — Detailed Comparison](#2-aws-vs-azure--detailed-comparison)
3. [Report Schemas](#3-report-schemas)
4. [Microsoft Documentation References](#4-microsoft-documentation-references)
5. [1-Click Azure Cloud Shell Script](#5-1-click-azure-cloud-shell-script)
6. [How to Download Files](#6-how-to-download-files)
7. [KQL Queries (Resource Graph Explorer)](#7-kql-queries-resource-graph-explorer)
8. [Running the Standalone Script](#8-running-the-standalone-script)

---

## 1. Resource Field Descriptions

The following fields are collected for every Azure Storage Account. Each field maps to a specific security control that AWS tracks in its S3 audit reports.

---

### `storageaccountname`
- **What it is:** The globally unique name of the Azure Storage Account (equivalent to an S3 bucket name).
- **Source:** `resources.name` in Azure Resource Graph / `StorageAccountName` via Az PowerShell.
- **Format:** Lowercase string, 3–24 characters (e.g., `mystoragedemo001`).
- **Why it matters:** Identifies the specific storage resource being audited. Used as the primary key to match security posture per resource.

---

### `resourcegroup`
- **What it is:** The Azure Resource Group that contains the Storage Account.
- **Source:** `resources.resourceGroup` in Azure Resource Graph / `ResourceGroupName` via Az PowerShell.
- **Format:** String (e.g., `rg-prod-eastus`).
- **Why it matters:** Resource Groups are Azure's logical containers for resource management, RBAC, and cost tracking. This field helps teams identify which team/project owns a storage account and scope remediation efforts correctly. **There is no direct AWS equivalent** — in AWS, S3 buckets exist at the account level without a grouping layer analogous to Resource Groups.

---

### `encryptionkeysource`
- **What it is:** The source of the encryption key used to encrypt data at rest in the Storage Account.
- **Source:** `properties.encryption.keySource`.
- **Possible values:**

  | Value | Meaning |
  |---|---|
  | `Microsoft.Storage` | **Microsoft-Managed Keys (MMK)** — Azure manages key rotation automatically. Default setting. |
  | `Microsoft.Keyvault` | **Customer-Managed Keys (CMK)** — The customer controls the key lifecycle via Azure Key Vault. Required for most compliance frameworks (PCI-DSS, HIPAA, ISO 27001). |

- **Why it matters:** CMK gives you full control over encryption keys — including the ability to revoke access instantly (equivalent to deleting your data cryptographically). MMK is simpler but gives Microsoft more control.

---

### `infrastructureencryptionenabled`
- **What it is:** Whether **double encryption** (Infrastructure Encryption) is enabled — i.e., data is encrypted at both the software/service layer AND the hardware/infrastructure layer.
- **Source:** `properties.encryption.requireInfrastructureEncryption`.
- **Possible values:**

  | Value | Meaning |
  |---|---|
  | `true` | Data is encrypted **twice**: at the storage service layer (AES-256) AND at the underlying hardware level. Required for regulated industries. |
  | `false` | Data is encrypted once at the service layer only (default behavior). |

- **Why it matters:** Required for compliance in highly regulated environments (government, financial, healthcare). Once set at account creation, this **cannot be changed** — making it critical to audit.

---

### `networkacldefaultaction`
- **What it is:** The default network access rule for the Storage Account — what happens to traffic that does not match any specific allow-list rule.
- **Source:** `properties.networkAcls.defaultAction`.
- **Possible values:**

  | Value | Meaning | Risk Level |
  |---|---|---|
  | `Allow` | All public network traffic is **allowed by default**. Anyone with credentials can reach the endpoint from any network. | High |
  | `Deny` | All public traffic is **denied by default**. Only explicitly allowed VNets, IPs, or Private Endpoints can connect. | Secure |

- **Why it matters:** A value of `Allow` means the storage account is publicly reachable on the internet (though still auth-protected). Best practice is `Deny` with explicit allow-list entries. This is the primary network hardening control for Azure Storage.

---

### `allowblobpublicaccess`
- **What it is:** Whether **anonymous (unauthenticated) public read access** is permitted to blob containers and blobs within the storage account.
- **Source:** `properties.allowBlobPublicAccess`.
- **Possible values:**

  | Value | Meaning | Risk Level |
  |---|---|---|
  | `false` | Public anonymous access is **blocked** at the account level. No container or blob can be made public regardless of container-level settings. | Secure |
  | `true` | Public access is **allowed** at the account level. Individual containers can still be set to private, but the door is open. | High |

- **Why it matters:** This is the **single most critical data exposure control** for Azure Blob Storage. When `true`, a misconfigured container-level setting can result in public data exposure without any authentication. Microsoft now defaults this to `false` for new accounts (from Nov 2023).

---

### `subscriptionname`
- **What it is:** The human-readable name of the Azure Subscription containing the Storage Account.
- **Source:** `resourcecontainers` (subscription name lookup via join) / `Get-AzSubscription`.
- **Format:** String (e.g., `prod-connectivity-sub`).
- **Why it matters:** Used to group and filter audit results by business unit, environment, or account owner — analogous to AWS Account Name.

---

### `subscriptionid`
- **What it is:** The unique GUID identifier of the Azure Subscription.
- **Source:** `subscriptionId` (native field in Resource Graph).
- **Format:** UUID/GUID (e.g., `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
- **Why it matters:** The authoritative, immutable identifier for a subscription. Used for API calls, RBAC scoping, and cross-referencing billing/compliance data.

---

## 2. AWS vs Azure — Detailed Comparison

### Report 1: Consolidated Security Settings

| AWS S3 Column | AWS Meaning | Azure Column | Azure Meaning | Key Differences |
|---|---|---|---|---|
| `bucketname` | Globally unique name of the S3 bucket | `storageaccountname` | Globally unique name of the Azure Storage Account | Both are globally unique DNS names. S3 buckets exist at the AWS account level. Azure Storage Accounts exist within a Subscription > Resource Group hierarchy. |
| *(no equivalent)* | AWS accounts have no sub-grouping layer below the account | `resourcegroup` | Azure Resource Group containing the Storage Account | Azure-only concept. Resource Groups allow logical grouping for RBAC, billing, and lifecycle management. AWS uses tags and Organizations for looser grouping. |
| `ssealgorithm` | Encryption algorithm on the bucket: `AES256` (SSE-S3) or `aws:kms` (SSE-KMS) | `encryptionkeysource` | Key source: `Microsoft.Storage` (MMK) or `Microsoft.Keyvault` (CMK) | Both distinguish provider-managed vs customer-managed keys. AWS additionally supports SSE-C (customer-provided keys per request). Azure does not support per-request keys but offers automatic rotation policies in Key Vault. |
| `bucketkeyenabled` | Whether S3 Bucket Key is enabled to reduce KMS API call costs when using SSE-KMS | `infrastructureencryptionenabled` | Whether double-layer infrastructure encryption is enabled at the hardware level | Conceptually different: AWS Bucket Key is a **cost-optimization** feature. Azure Infrastructure Encryption is a **compliance/security** feature adding a second AES-256 encryption layer at hardware level. |
| `bucket_policy_status` | Whether the S3 bucket policy makes the bucket publicly accessible (`isPublic: true/false`) based on IAM policy analysis | `networkacldefaultaction` | Default network ACL action: `Allow` (open) or `Deny` (firewall-restricted) | Fundamentally different: AWS `bucket_policy_status` evaluates **identity/IAM policy** to determine public reachability. Azure `networkacldefaultaction` controls **network-layer** access (which IP ranges/VNets can reach the endpoint). Both are critical but measure different attack surfaces. |
| `accountname` | AWS Account Name (human-readable alias for the AWS account) | `subscriptionname` | Azure Subscription Name | Direct equivalent. Both are human-readable identifiers for the billing/organizational boundary. |
| `accountid` | AWS Account ID (12-digit unique identifier) | `subscriptionid` | Azure Subscription GUID | Direct equivalent. Both are unique, immutable identifiers for the cloud billing/organizational boundary. |

---

### Report 2: Block Public Access (BPA)

| AWS S3 Column | AWS Meaning | Azure Column | Azure Meaning | Key Differences |
|---|---|---|---|---|
| `accountname` | AWS Account Name | `subscriptionname` | Azure Subscription Name | Direct equivalent — human-readable billing scope name. |
| `accountid` | AWS Account ID | `subscriptionid` | Azure Subscription ID | Direct equivalent — unique immutable billing scope ID. |
| `publicaccessblockconfiguration` | AWS BPA — 4-flag block: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets` | `allowblobpublicaccess` | Single boolean: whether anonymous public blob access is permitted at the storage account level | **AWS has 4 granular flags; Azure has 1 master switch.** AWS BPA lets you block ACL-based public access while still allowing policy-based public access. Azure's single toggle is simpler but overrides all container-level settings when `false`. |

---

### Architectural Comparison: AWS S3 vs Azure Blob Storage

| Dimension | AWS S3 | Azure Blob Storage | Notes |
|---|---|---|---|
| **Resource hierarchy** | Organization > Management Account > Member Account > S3 Bucket | Management Group > Subscription > Resource Group > Storage Account > Container | Azure has an extra **Resource Group** layer not present in AWS |
| **Namespace** | Bucket names are globally unique across all AWS accounts | Storage Account names are globally unique across all Azure subscriptions | Both are DNS-resolvable globally |
| **Encryption at rest** | SSE-S3 (AES-256, AWS-managed), SSE-KMS (CMK), SSE-C (customer-provided per request) | MMK (Microsoft-managed AES-256), CMK via Azure Key Vault, optional Infrastructure Encryption (double-layer) | Azure supports double encryption (infra layer); AWS has no direct equivalent |
| **Public access control** | 4-flag Block Public Access config at account + bucket level | Single `allowBlobPublicAccess` toggle at account level + container-level public access setting | AWS is more granular; Azure's account-level toggle overrides container settings when `false` |
| **Network access control** | S3 Bucket Policy (resource-based IAM), VPC Endpoints, S3 Access Points | Network ACL default action (Allow/Deny) + IP rules + VNet Service Endpoints + Private Endpoints | Azure separates network access (ACL) from identity access (RBAC/SAS) more explicitly |
| **Audit tooling** | AWS Config, Security Hub, Macie, Access Analyzer | Azure Policy, Microsoft Defender for Storage, Azure Resource Graph | This script replicates the AWS audit layout using Azure Resource Graph (ARG) — equivalent to AWS Config aggregate queries |

---

## 3. Report Schemas

### Report 1: `StorageAccount-consolidated.csv` / `.xlsx`

```
storageaccountname | resourcegroup | encryptionkeysource | infrastructureencryptionenabled | networkacldefaultaction | subscriptionname | subscriptionid
```

| Col | AWS Source | Azure Source | Description |
|:---:|---|---|---|
| A | `bucketname` | `name` | Storage Account name |
| B | *(no equivalent)* | `resourceGroup` | Resource Group name |
| C | `ssealgorithm` | `properties.encryption.keySource` | `Microsoft.Storage` or `Microsoft.Keyvault` |
| D | `bucketkeyenabled` | `properties.encryption.requireInfrastructureEncryption` | `true` / `false` |
| E | `bucket_policy_status` | `properties.networkAcls.defaultAction` | `Allow` / `Deny` |
| F | `accountname` | Subscription container `name` | Subscription display name |
| G | `accountid` | `subscriptionId` | Subscription GUID |

---

### Report 2: `StorageAccount-bpa.csv` / `.xlsx` (Subscription Summary)

```
subscriptionname | subscriptionid | allowblobpublicaccess
```

| Col | AWS Source | Azure Source | Description |
|:---:|---|---|---|
| A | `accountname` | Subscription `name` | Subscription name |
| B | `accountid` | `subscriptionId` | Subscription GUID |
| C | `publicaccessblockconfiguration` | `properties.allowBlobPublicAccess` (aggregated) | Summary: `false (Blocked on all N accounts)` or `true (X of N allow public access)` |

---

### Report 2 Detailed: `StorageAccount-bpa-detailed.csv` / `.xlsx`

```
storageaccountname | resourcegroup | subscriptionname | subscriptionid | allowblobpublicaccess
```

| Col | Azure Source | Description |
|:---:|---|---|
| A | `name` | Storage Account name |
| B | `resourceGroup` | Resource Group name |
| C | Subscription `name` | Subscription display name |
| D | `subscriptionId` | Subscription GUID |
| E | `properties.allowBlobPublicAccess` | `true` / `false` per account |

---

## 4. Microsoft Documentation References

| Topic | Description | Link |
|---|---|---|
| Storage Account overview | What a Storage Account is, types, and capabilities | https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview |
| Encryption at rest (MMK vs CMK) | How Azure encrypts data at rest, MMK vs CMK, Key Vault integration | https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption |
| Customer-Managed Keys (CMK) | Setting up CMK with Azure Key Vault for Storage Accounts | https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-configure-key-vault |
| Infrastructure Encryption | Enabling the second hardware-level encryption layer | https://learn.microsoft.com/en-us/azure/storage/common/infrastructure-encryption-enable |
| Network ACLs (defaultAction) | Configuring firewall rules and virtual network rules | https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security |
| Allow Blob Public Access | Enabling/disabling anonymous public read access to blobs | https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure |
| Public access disabled by default | Microsoft announcement defaulting allowBlobPublicAccess to false | https://techcommunity.microsoft.com/t5/azure-storage-blog/azure-blob-storage-public-access-to-be-disabled-by-default/ba-p/3588356 |
| Resource Groups | What Azure Resource Groups are and best practices | https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal |
| Azure Subscriptions | What subscriptions are and how they relate to billing/management | https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/organize-subscriptions |
| Management Groups | How Management Groups organize subscriptions for governance | https://learn.microsoft.com/en-us/azure/governance/management-groups/overview |
| Azure Resource Graph (ARG) | What ARG is and how KQL queries work across subscriptions | https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview |
| Microsoft Defender for Storage | Cloud-native threat detection for Storage Accounts (equivalent to AWS Macie) | https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction |
| Azure Policy — Storage built-ins | Built-in Azure Policy definitions for Storage Account compliance | https://learn.microsoft.com/en-us/azure/storage/common/policy-reference |
| Private Endpoints for Storage | Connecting to Storage Accounts via private network only | https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints |

---

## 5. 1-Click Azure Cloud Shell Script

Open **Azure Cloud Shell** (`>_` icon in the Azure Portal top bar), select **PowerShell**, and paste the block below.

> **Strict Scope Guarantee:** The script resolves your Management Group recursively and hard-filters both the KQL query engine and the `Search-AzGraph` call. It is impossible to scan resources outside the target Management Group.

```powershell
# ==============================================================================
# 1-CLICK AZURE CLOUD SHELL AUDIT SCRIPT (STRICT MANAGEMENT GROUP SCOPE)
# ==============================================================================

# 1. Target Management Group
$mgInputs = @("ac-1.1", "ac-1.2")   # <-- Add or remove Management Group IDs here

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
    Throw "[ERROR] Management Group '$mgInput' was not found! Execution stopped."
}

Write-Host "[+] Matched: $($mg.DisplayName) (ID: $($mg.Name))" -ForegroundColor Green

# 3. Recursively extract Subscription IDs
$discoveredSubIds = [System.Collections.Generic.List[string]]::new()
function Find-MgSubscriptions($node) {
    if ($node.Children) {
        foreach ($c in $node.Children) {
            if ($c.Type -match 'subscriptions' -and $c.Name) { $discoveredSubIds.Add($c.Name) }
            if ($c.Children) { Find-MgSubscriptions $c }
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
if ($targetSubs.Count -eq 0) { Throw "[ERROR] No subscriptions found." }

Write-Host "[+] Found $($targetSubs.Count) subscription(s)" -ForegroundColor Green
$targetSubs | ForEach-Object { Write-Host "    -> $_" -ForegroundColor DarkGray }
$formattedKqlSubFilter = ($targetSubs | ForEach-Object { "'$_'" }) -join ", "

# 4. Report 1: Consolidated (with Resource Group)
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
    resourcegroup                   = resourceGroup,
    encryptionkeysource             = tostring(coalesce(properties.encryption.keySource, 'Microsoft.Storage')),
    infrastructureencryptionenabled = tostring(coalesce(properties.encryption.requireInfrastructureEncryption, false)),
    networkacldefaultaction         = tostring(coalesce(properties.networkAcls.defaultAction, 'Allow')),
    subscriptionname                = coalesce(subscriptionName, subscriptionId),
    subscriptionid                  = subscriptionId
| order by subscriptionname asc, storageaccountname asc
"@ -First 5000 | Export-Csv -Path "StorageAccount-consolidated.csv" -NoTypeInformation -Encoding utf8

# 5. Report 2: BPA Subscription Summary
Write-Host "[3/4] Generating StorageAccount-bpa.csv..." -ForegroundColor Cyan
Search-AzGraph -Subscription $targetSubs -Query @"
resources
| where type =~ 'microsoft.storage/storageaccounts'
| where subscriptionId in ($formattedKqlSubFilter)
| extend isPublicAllowed = coalesce(properties.allowBlobPublicAccess, false)
| summarize TotalAccounts = count(), PublicAllowedCount = countif(isPublicAllowed == true) by subscriptionId
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

# 6. Report 2 Detailed: Per-Account BPA (with Resource Group)
Write-Host "[4/4] Generating StorageAccount-bpa-detailed.csv..." -ForegroundColor Cyan
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
    resourcegroup         = resourceGroup,
    subscriptionname      = coalesce(subscriptionName, subscriptionId),
    subscriptionid        = subscriptionId,
    allowblobpublicaccess = tostring(coalesce(properties.allowBlobPublicAccess, false))
| order by subscriptionname asc, storageaccountname asc
"@ -First 5000 | Export-Csv -Path "StorageAccount-bpa-detailed.csv" -NoTypeInformation -Encoding utf8

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " SUCCESS! Scanned 0 Management Group(s) � 3 files generated:" -ForegroundColor Green
Write-Host "  1. StorageAccount-consolidated.csv" -ForegroundColor Yellow
Write-Host "  2. StorageAccount-bpa.csv" -ForegroundColor Yellow
Write-Host "  3. StorageAccount-bpa-detailed.csv" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Green
Write-Host "`nDownload: Click Manage files (up/down arrow) in Cloud Shell toolbar -> Download -> type filename." -ForegroundColor Cyan
```

---

## 6. How to Download Files

1. In the Azure Cloud Shell toolbar, click the **Manage files** icon (`↕`).
2. Select **Download**.
3. Type the filename:
   - `StorageAccount-consolidated.csv`
   - `StorageAccount-bpa.csv`
   - `StorageAccount-bpa-detailed.csv`
4. Click **Download**.

---

## 7. KQL Queries (Resource Graph Explorer)

In **Azure Portal → Resource Graph Explorer**. Replace `'YOUR_MANAGEMENT_GROUP_ID'` with your group ID or display name.

### Query 1 — Consolidated Report

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
    resourcegroup                   = resourceGroup,
    encryptionkeysource             = tostring(coalesce(properties.encryption.keySource, 'Microsoft.Storage')),
    infrastructureencryptionenabled = tostring(coalesce(properties.encryption.requireInfrastructureEncryption, false)),
    networkacldefaultaction         = tostring(coalesce(properties.networkAcls.defaultAction, 'Allow')),
    subscriptionname                = subscriptionName,
    subscriptionid                  = subscriptionId
| order by subscriptionname asc, storageaccountname asc
```

### Query 2 — BPA Summary

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
| summarize TotalAccounts = count(), PublicAllowedCount = countif(isPublicAllowed == true) by subscriptionId, subscriptionName
| project
    subscriptionname      = subscriptionName,
    subscriptionid        = subscriptionId,
    allowblobpublicaccess = iff(PublicAllowedCount > 0, strcat("true (", PublicAllowedCount, "/", TotalAccounts, " accounts allow public access)"), "false (Blocked on all accounts)")
| order by subscriptionname asc
```

---

## 8. Running the Standalone Script

```powershell
# Audit strictly for a specific Management Group:
.\Export-StorageAccountSecurityReports.ps1 -ManagementGroupId "YOUR_MANAGEMENT_GROUP_ID"

# Export to custom folder with both CSV and native formatted Excel (.xlsx):
.\Export-StorageAccountSecurityReports.ps1 -ManagementGroupId "YOUR_MANAGEMENT_GROUP_ID" -OutputPath "C:\Reports" -Format Both

# Target specific subscriptions directly (no Management Group):
.\Export-StorageAccountSecurityReports.ps1 -SubscriptionIds "sub-id-1","sub-id-2" -Format Both
```
