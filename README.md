# Azure Credential & Certificate Expiry Alerts Runbook

> **Azure Automation Runbook (PowerShell 7.2 / 5.1)**  
> Monitors and alerts on upcoming and already-expired credentials and certificates across Microsoft Entra ID and Azure infrastructure workloads.

> 🛡️ **Azure Storage Account Security Audits (AWS S3 Replication):**  
> Looking to audit Azure Storage Account security (encryption, BPA, network ACLs)? See the [`storage_audit/`](./storage_audit/README.md) directory for 1-click Azure Cloud Shell copy-paste scripts.

---

## 📌 Overview

This runbook automatically discovers expiring and expired credentials across four critical Azure surfaces and sends consolidated, color-coded HTML email notifications to resource owners via Microsoft Graph API.

### 🔍 Monitored Workloads (4 Sources)

| Source | Target Resource | What is Monitored |
|---|---|---|
| **1. Entra ID App Registrations** | Azure AD Applications | Client Secrets and Certificates expiring or expired |
| **2. Azure App Service Certificates** | Azure App Service | SSL/TLS certificates attached to App Services |
| **3. Azure Key Vault Secrets** | Azure Key Vaults | Secrets with expiration dates (`Expires` attribute set) |
| **4. Azure Application Gateway** | Application Gateways | Directly uploaded SSL certificates (`PublicCertData` X.509) |

---

## 🔒 Confidential Placeholders & Replacement Guide

All sensitive infrastructure values in the script have been sanitized and replaced with `xxxx-` placeholders. Before running or deploying, replace the placeholders with your organization's actual values:

### 📋 Placeholders Table

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

The runbook relies on the following Azure Automation assets being configured:

### 1. 🔑 Credentials (`Automation Account -> Credentials`)
- **Credential Asset Name:** Matches `xxxx-AutomationCredentialName`
  - **Username:** Entra ID Application (Client) ID
  - **Password:** Entra ID Application Client Secret

### 2. 📝 Variables (`Automation Account -> Variables`)

| Variable Name | Type | Description |
|---|---|---|
| `GTAdminUsers` | String | Comma-separated emails of global administrators / team members |
| `EmailCC_AppRegistrationExpiry` | String | Comma-separated emails to CC on every alert email |
| `EmailBCC_AppRegistrationExpiry` | String | Comma-separated emails to BCC on every alert email |
| `DefaultOwnerEmail` | String | Default owner address when resource owner lookup is blank |
| `xxxx-tenantID-variable` | String | Azure AD Tenant ID |

---

## 🛡️ Required Roles & Permissions

### Azure Role-Based Access Control (RBAC)
Grant the Automation Account **Managed Identity**:
- **Reader** role on all subscriptions to be monitored (for Resource Graph and App Gateway cert discovery).
- **Key Vault Secrets User** or **Key Vault Reader** on Key Vaults to discover secret expiration dates.

### Microsoft Graph Application API Permissions
Grant the App Registration used for Graph API:
- `Mail.Send` (Application) — to send alert notifications from the sender mailbox.
- `Application.Read.All` (Application) — to read Entra App Registration owners, secrets, and certificates.
- *Admin Consent must be granted for both permissions.*

---

## 📦 Required PowerShell Modules

Ensure these modules are imported into your Azure Automation Account:
- `Az.Accounts`
- `Az.Resources`
- `Az.ResourceGraph`
- `Az.KeyVault`
- `Az.Network`
- `Microsoft.Graph.Authentication`

---

## 🚀 How to Deploy to Azure Automation

1. **Clone or Download** this repository.
2. In Azure Portal, navigate to your **Automation Account** &rarr; **Runbooks**.
3. Click **Create a runbook**:
   - **Name:** `azure-credential-expiry-alerts`
   - **Runbook type:** PowerShell (7.2 or 5.1)
4. Paste the contents of `script_v2.ps1` (after updating your placeholders).
5. Click **Save** &rarr; **Test pane** to run a test execution.
6. Once validated, click **Publish**.
7. Navigate to **Schedules** &rarr; Link a recurring schedule (e.g., daily at 08:00 UTC).

---

## 🎨 Alert Notification Features

- **Consolidated Notification:** Owners receive **one single email** summarizing all their expiring/expired assets across Entra, Key Vault, App Services, and Application Gateways.
- **Color-Coded Status:**
  - 🔴 **Red:** Already Expired (`0` days remaining)
  - 🔵 **Blue:** Expiring Very Soon (`<= 7` days)
  - 🟡 **Orange:** Expiring Soon (`<= 14` days)
- **Direct Renewal Guidance:** Each email includes exact step-by-step renewal and rotation instructions for the specific workload type.
