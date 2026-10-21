# Azure Credential & Certificate Expiry Alerts & Audit Suite

> **Two-Stage Solution for Microsoft Entra ID & Azure Workloads**  
> 1. 🧪 **Local Testing & Audit Script (`Test-TenantApplicationCertificates.ps1`):** Run locally on any admin workstation to discover ALL uploaded certificates across your tenant, export audit CSVs, and preview email notifications in your browser **without sending real emails**.  
> 2. ⚡ **Production Azure Automation Runbook (`script_v2.ps1`):** Deployed to your Azure Automation Account to run on a recurring schedule and deliver consolidated, color-coded HTML email alerts to application and workload owners before credentials expire.

> 🛡️ **Azure Storage Account Security Audits (AWS S3 Replication):**  
> Looking to audit Azure Storage Account security (encryption, BPA, network ACLs)? See the [`storage_audit/`](./storage_audit/README.md) directory for 1-click Azure Cloud Shell copy-paste scripts.

> 🌐 **Azure Virtual Network (VNet) Subnet Audits & Inventory:**  
> Looking to extract detailed VNet Subnet configuration, capacity, and IPv6 data across Management Groups? See the [`network_audit/`](./network_audit/README.md) directory for 1-click Azure Cloud Shell copy-paste scripts.

---

## 🔍 Monitored Workloads (5 Sources)

| # | Workload Surface | Target Resource | What is Monitored & Alerted |
|---|---|---|---|
| **1** | **Entra ID App Registrations** | Azure AD Applications | Uploaded Client/Federation Certificates (`KeyCredentials`) & Client Secrets |
| **2** | **Entra ID Enterprise Applications (NEW)** | Service Principals / SSO Apps | SAML Single Sign-On (SSO) Signing & Token Verification Certificates |
| **3** | **Azure App Service Certificates** | Azure App Service | SSL/TLS certificates attached to App Services |
| **4** | **Azure Key Vault Secrets** | Azure Key Vaults | Secrets with expiration dates (`Expires` attribute set) |
| **5** | **Azure Application Gateway** | Application Gateways | Directly uploaded SSL certificates (`PublicCertData` X.509) |

---

## 🧪 Stage 1: Local Testing & Validation (`Test-TenantApplicationCertificates.ps1`)

Before running automated alerts in an Automation Account, use [`Test-TenantApplicationCertificates.ps1`](./Test-TenantApplicationCertificates.ps1) to discover every certificate uploaded across your tenant, verify owner assignments, and preview the notification email format.

### 📦 Prerequisites for Local Testing

Open PowerShell 5.1 or PowerShell 7 (as Administrator or standard user) and install the lightweight Graph modules:

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Scope CurrentUser -Repository PSGallery -Force
```
*(Or pass `-AutoInstallModules` to the script to install automatically).*

### 🚀 Running the Local Test Script

#### Option A: Quick Interactive Browser Login (Recommended)
Pops a browser window to authenticate with your administrator account:
```powershell
.\Test-TenantApplicationCertificates.ps1
```

#### Option B: Retrieve ALL Certificates in the Tenant (Active, Upcoming & Expired)
Outputs every certificate in the tenant regardless of expiry date, exports to CSV, and generates an HTML browser preview:
```powershell
.\Test-TenantApplicationCertificates.ps1 -AllCertificates
```

#### Option C: Authenticate Unattended via App Registration (Client Secret)
```powershell
.\Test-TenantApplicationCertificates.ps1 `
    -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -ClientId "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
    -ClientSecret "YourSecretHere"
```

#### Option D: Custom Expiration Window (e.g. 60 or 90 Days)
```powershell
.\Test-TenantApplicationCertificates.ps1 -DaysUntilExpiration 60 -GenerateEmailPreview $true
```

#### Option E: Include Azure Infrastructure (App Services, Key Vaults, App Gateways)
```powershell
.\Test-TenantApplicationCertificates.ps1 -IncludeAzureResources
```

### 📊 Local Test Outputs

1. **Console Color Dashboard:**
   - Summary metric cards (Expired, Critical <=7d, Warning <=14d, Attention <=30d, Healthy >30d).
   - Formatted table showing Application Name, Certificate Friendly Name, Thumbprint, Start/End Dates, Days Remaining, and Resolved Owners.
   - Highlights orphaned applications (`<<No Owner - Orphaned>>`).
2. **CSV Audit Report:** Auto-generates a timestamped CSV (e.g. `TenantApplicationCertificates_20261021_211500.csv`) with full details for Excel analysis and reporting to management.
3. **Interactive HTML Email Preview:** Auto-generates and opens an HTML preview (`EmailAlert_Preview_*.html`) in your default web browser so you can inspect the exact formatting owners will receive.

---

## ⚡ Stage 2: Deploying to Azure Automation Account (`script_v2.ps1`)

Once local testing confirms all tenant certificates are detected, deploy [`script_v2.ps1`](./script_v2.ps1) to your Azure Automation Account to run daily and email owners automatically.

### 🔒 Confidential Placeholders & Replacement Guide

Replace the following placeholders in [`script_v2.ps1`](./script_v2.ps1) before publishing:

| Placeholder in Script | Where It Is Found | What to Replace It With | Example Value |
|---|---|---|---|
| `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | Line ~642 | **Azure Subscription ID** containing your shared Key Vault | `85eef697-53ef-4899-9885-070b3aaaa097` |
| `xxxx-keyvault-name` | Line ~644 | **Key Vault Name** where automation secrets are stored | `az03sskeyvaultinfra` |
| `xxxx-resource-group-name` | Line ~644 | **Resource Group Name** where the Key Vault resides | `az03-sharedservice-rg-automation-account` |
| `xxxx-clientId-secret` | Line ~646 | **Secret Name in Key Vault** containing the Client/App ID | `UC-Azure-SharedService-Automation-App-clientId` |
| `xxxx-tenantId-secret` | Line ~647 | **Secret Name in Key Vault** containing the Azure Tenant ID | `UC-Azure-SharedService-Automation-tenantID` |
| `xxxx-appSecret-secret` | Line ~648 | **Secret Name in Key Vault** containing the App Secret | `UC-Azure-SharedService-Automation-appSecret` |
| `xxxx-AutomationCredentialName` | Line ~651 | **Automation Account Credential Asset** name | `AppRegistrationExpiryAlert` |
| `xxxx-tenantID-variable` | Line ~654 | **Automation Variable** storing the Tenant ID string | `UC-Azure-SharedService-Automation-tenantID` |
| `xxxx-fallback-owner@yourdomain.com` | Line ~672 | **Fallback Owner Email** if no resource owner is found | `azurecloudinfra.team@yourdomain.com` |
| `xxxx-team-alerts@yourdomain.com` | Line ~880 | **Support Team Email** shown in the email footer | `azurecloudinfra.team@yourdomain.com` |
| `xxxx-lead-alerts@yourdomain.com` | Line ~881 | **Team Lead Email** shown in the email footer | `azurecloudinfra.lead@yourdomain.com` |
| `xxxx Cloud Infrastructure Team` | Line ~882 | **Team Signature Name** shown in the email footer | `Cloud Operations Team` |
| `xxxx-notification@yourdomain.com` | Line ~886 | **Sender Mailbox** used by Graph API to send alert emails | `azure.notification@yourdomain.com` |

---

## ⚙️ Azure Automation Account Configuration

### 1. 🔑 Credentials (`Automation Account -> Credentials`)
- **Credential Asset Name:** Matches `xxxx-AutomationCredentialName`
  - **Username:** Entra ID Application (Client) ID
  - **Password:** Entra ID Application Client Secret

### 2. 📝 Variables (`Automation Account -> Variables`)

| Variable Name | Type | Description |
|---|---|---|
| `GTAdminUsers` | String | Comma-separated emails of global administrators (included on CC) |
| `EmailCC_AppRegistrationExpiry` | String | Comma-separated emails to CC on every alert email |
| `EmailBCC_AppRegistrationExpiry` | String | Comma-separated emails to BCC on every alert email |
| `DefaultOwnerEmail` | String | Default owner address when resource owner lookup is blank |
| `xxxx-tenantID-variable` | String | Azure AD Tenant ID |

---

## 🛡️ Required Roles & Permissions

### Azure Role-Based Access Control (RBAC)
Grant the Automation Account **System-Assigned Managed Identity**:
- **Reader** role on all subscriptions to be monitored (for Resource Graph and App Gateway cert discovery).
- **Key Vault Secrets User** or **Key Vault Reader** on Key Vaults to discover secret expiration dates.

### Microsoft Graph Application API Permissions
Grant the App Registration used for Graph API:
- `Mail.Send` (Application) — to send alert notifications from the sender mailbox.
- `Application.Read.All` (Application) — to read Entra App Registration owners, secrets, and certificates.
- *Admin Consent must be granted for both permissions.*

---

## 📦 Required PowerShell Modules in Automation Account

Ensure these modules are imported into your Azure Automation Account:
- `Az.Accounts`
- `Az.Resources`
- `Az.ResourceGraph`
- `Az.KeyVault`
- `Az.Network`
- `Microsoft.Graph.Authentication`
- `Microsoft.Graph.Applications`

---

## 🚀 How to Deploy to Azure Automation

1. In Azure Portal, navigate to your **Automation Account** &rarr; **Runbooks**.
2. Click **Create a runbook**:
   - **Name:** `azure-credential-expiry-alerts`
   - **Runbook type:** PowerShell (7.2 or 5.1)
3. Paste the contents of [`script_v2.ps1`](./script_v2.ps1) (after updating your placeholders).
4. Click **Save** &rarr; **Test pane** to run a test execution.
5. Once validated, click **Publish**.
6. Navigate to **Schedules** &rarr; Link a recurring schedule (e.g., daily at 08:00 UTC).

---

## 🛠️ Key Improvements & Fixes in Version 2.1

- 🐛 **Fixed Admin-Only Owner Filter:** Previous versions contained `$isGTAdminUser` which inadvertently suppressed alerts for applications owned by regular users. Alerts now evaluate ALL tenant applications and email their respective owners.
- 🏢 **Added Enterprise Application SAML SSO Certs:** Discovers SAML Single Sign-On and token signing certificates uploaded directly to Enterprise Applications (Service Principals).
- ⚡ **10x Query Performance:** Pre-filters applications with credentials before performing owner lookups, eliminating redundant Graph API calls and preventing 429 throttling.
- 🔤 **Fixed PowerShell Syntax & Encoding Issues:** Resolved Unicode em-dash quote issues on Line 477, variable scope collision on `$($appName):`, and here-string formatting.
- 🧪 **Dedicated Local Testing Script:** Added [`Test-TenantApplicationCertificates.ps1`](./Test-TenantApplicationCertificates.ps1) with CSV export and browser HTML preview.
