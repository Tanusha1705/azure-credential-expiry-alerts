<#
.SYNOPSIS
    Discovers expiring and active certificates across Microsoft Entra ID Enterprise Applications
    (SAML SSO Signing & Token Encryption) and Azure Infrastructure Workloads without Device Code Authentication.

.DESCRIPTION
    Audits certificates across your Microsoft Entra ID tenant and Azure subscriptions:
      1. Entra ID Enterprise Applications / Service Principals (SAML SSO Signing & Token Verification / Encryption)
      2. (Optional) Azure App Service Certificates (microsoft.web/certificates)
      3. (Optional) Azure Key Vault Secrets & Certificates (microsoft.keyvault/vaults)
      4. (Optional) Azure Application Gateway SSL Certificates (microsoft.network/applicationgateways)

    AUTHENTICATION DESIGN (NO DEVICE CODE AUTH):
      - Reuses active Azure context (Connect-AzAccount) and gets a Microsoft Graph bearer token seamlessly.
      - Supports interactive browser login (standard MSAL browser popup, never device code).
      - Supports Service Principal / App Registration authentication (-TenantId, -ClientId, -ClientSecret).
      - Supports Azure Automation Account Managed Identity (-UseManagedIdentity / auto-detected).
      - Operates via direct Microsoft Graph REST APIs so it works even if Microsoft.Graph modules are not installed!

.PARAMETER DaysUntilExpiration
    Threshold in days to flag certificates expiring soon. Default is 30 days.

.PARAMETER AllCertificates
    Switch to output ALL certificates regardless of expiration date (active, upcoming, or expired).

.PARAMETER IncludeAlreadyExpired
    Include certificates that have already expired. Default is $true.

.PARAMETER IncludeEnterpriseApps
    Include Enterprise Applications / Service Principals (SAML SSO certificates). Default is $true.

.PARAMETER IncludeAzureResources
    Switch to scan Azure Infrastructure (App Services, Key Vaults, and Application Gateways). Default is $false.

.PARAMETER TenantId
    Entra ID Tenant ID. Required for Client Secret authentication, optional for interactive.

.PARAMETER ClientId
    Application (Client) ID if authenticating via Service Principal / App Registration.

.PARAMETER ClientSecret
    Client Secret if authenticating via Service Principal / App Registration.

.PARAMETER UseManagedIdentity
    Authenticate using Azure Managed Identity (System-Assigned or User-Assigned) inside Azure Automation.

.PARAMETER ExportCsv
    Export results to a CSV file. Default is $true.

.PARAMETER CsvPath
    Custom path for the exported CSV file. Default is a timestamped file in the current directory.

.PARAMETER ExportExcel
    Export results to a formatted Excel file (.xlsx) if the ImportExcel module is available.

.PARAMETER FallbackOwnerEmail
    Default email address to assign when an application or resource has no owner configured.

.EXAMPLE
    # 1. Quick local test (uses your existing Azure login or standard browser popup):
    .\Export-EnterpriseAppAndInfraCertificates.ps1

.EXAMPLE
    # 2. View ALL certificates in Enterprise Apps regardless of expiration:
    .\Export-EnterpriseAppAndInfraCertificates.ps1 -AllCertificates

.EXAMPLE
    # 3. Include Azure Infrastructure (App Services, Key Vaults, App Gateways):
    .\Export-EnterpriseAppAndInfraCertificates.ps1 -IncludeAzureResources

.EXAMPLE
    # 4. Authenticate using App Registration / Client Secret (Headless / CI-CD):
    .\Export-EnterpriseAppAndInfraCertificates.ps1 -TenantId "xxx" -ClientId "yyy" -ClientSecret "zzz"

.EXAMPLE
    # 5. Run in Azure Automation Account with Managed Identity:
    .\Export-EnterpriseAppAndInfraCertificates.ps1 -UseManagedIdentity -IncludeAzureResources
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$DaysUntilExpiration = 30,

    [Parameter(Mandatory = $false)]
    [switch]$AllCertificates,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeAlreadyExpired = $true,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeEnterpriseApps = $true,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeAzureResources = $true,

    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [switch]$UseManagedIdentity,

    [Parameter(Mandatory = $false)]
    [bool]$ExportCsv = $true,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$ExportExcel,

    [Parameter(Mandatory = $false)]
    [string]$FallbackOwnerEmail = "azurecloudinfra.team@yourdomain.com"
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Entra ID Enterprise App & Infrastructure Certificate Audit" -ForegroundColor Cyan
Write-Host " Mode       : Zero Device-Auth (Local Test + Azure Automation Compatible)" -ForegroundColor Yellow
Write-Host " Threshold  : $($DaysUntilExpiration) Days $(if ($AllCertificates) { '(Flagging mode; ALL certificates will be output)' } else { '(Filtering to expiring items)' })" -ForegroundColor Gray
Write-Host " Timestamp  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "==========================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# 1. AUTHENTICATION ENGINE (NO DEVICE CODE AUTH)
# -------------------------------------------------------------------------
$graphAccessToken = $null
$effectiveTenantId = $TenantId

# Check if there is already an active Azure context (e.g. Azure Portal Cloud Shell or logged-in local PowerShell)
$currentAzContext = Get-AzContext -ErrorAction SilentlyContinue

# Detect Azure Automation environment (explicit switch or actual automation sandbox)
$isAzureAutomation = ($UseManagedIdentity -or ($env:AZUREPS_HOST_ENVIRONMENT -like "*AzureAutomation*") -or (Get-Command Get-AutomationVariable -ErrorAction SilentlyContinue))

Write-Host "`n[AUTH] Initializing authentication (Device Code Auth is DISABLED)..." -ForegroundColor Cyan

# Mode 1: Active Azure Session Detected (Azure Portal Cloud Shell or Local PowerShell)
if ($currentAzContext -and -not $ClientId -and -not $UseManagedIdentity) {
    $effectiveTenantId = $currentAzContext.Tenant.Id
    Write-Host "[+] Active Azure session detected in Portal / PowerShell: $($currentAzContext.Account.Id)" -ForegroundColor Green
    Write-Host "    Tenant ID: $effectiveTenantId" -ForegroundColor Gray

    # In Azure Cloud Shell, Get-AzContext defaults to container identity MSI@50342 which lacks Graph permissions.
    if ($currentAzContext.Account.Id -like "MSI@*") {
        Write-Host "[AUTH] Detected Azure Cloud Shell container identity ($($currentAzContext.Account.Id))." -ForegroundColor Yellow
        Write-Host "[AUTH] Attempting to acquire user Graph token via Azure CLI delegation..." -ForegroundColor Gray
        if (Get-Command az -ErrorAction SilentlyContinue) {
            try {
                $cliToken = az account get-access-token --resource-type ms-graph --query accessToken -o tsv 2>$null
                if ($cliToken -and $cliToken.Trim().Length -gt 20) {
                    $graphAccessToken = $cliToken.Trim()
                    Write-Host "[+] Successfully acquired Microsoft Graph token via Azure CLI in Cloud Shell." -ForegroundColor Green
                }
            }
            catch { }
        }
    }

    if (-not $graphAccessToken) {
        try {
            Write-Host "[AUTH] Acquiring Microsoft Graph token from active Azure Portal session..." -ForegroundColor Gray
            $tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue
            if (-not $tokenObj -or -not $tokenObj.Token) {
                $tokenObj = Get-AzAccessToken -ResourceTypeName MSGraph -ErrorAction SilentlyContinue
            }
            if ($tokenObj -and $tokenObj.Token) {
                $graphAccessToken = $tokenObj.Token
                Write-Host "[+] Successfully acquired Microsoft Graph token silently (Zero Prompts, No Device Auth)." -ForegroundColor Green
            }
        }
        catch {
            Write-Host "[WARN] Could not get Graph token silently from active session: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# Mode 2: Service Principal (ClientId + ClientSecret)
if (-not $graphAccessToken -and -not [string]::IsNullOrWhiteSpace($ClientId) -and -not [string]::IsNullOrWhiteSpace($ClientSecret)) {
    if ([string]::IsNullOrWhiteSpace($effectiveTenantId)) {
        Throw "[ERROR] -TenantId is required when authenticating with ClientId and ClientSecret."
    }
    Write-Host "[AUTH] Authenticating via Service Principal (Client Credentials) for App ID '$ClientId'..." -ForegroundColor Yellow
    
    $tokenUri = "https://login.microsoftonline.com/$effectiveTenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        $graphAccessToken = $tokenResponse.access_token
        Write-Host "[+] Successfully acquired Microsoft Graph token via Client Credentials." -ForegroundColor Green
    }
    catch {
        Throw "[ERROR] Failed to obtain access token with ClientSecret: $($_.Exception.Message)"
    }
}
# Mode 3: Azure Automation Managed Identity
elseif (-not $graphAccessToken -and $isAzureAutomation) {
    Write-Host "[AUTH] Detected Azure Automation environment. Connecting via Managed Identity..." -ForegroundColor Yellow
    try {
        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue
        $null = Connect-AzAccount -Identity -ErrorAction Stop
        $currentAzContext = Get-AzContext
        $effectiveTenantId = $currentAzContext.Tenant.Id
        Write-Host "[+] Connected to Azure via Managed Identity (Tenant: $effectiveTenantId)." -ForegroundColor Green

        # Acquire Microsoft Graph Access Token
        $tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
        $graphAccessToken = $tokenObj.Token
        Write-Host "[+] Acquired Microsoft Graph Access Token via Managed Identity." -ForegroundColor Green
    }
    catch {
        Throw "[ERROR] Managed Identity authentication failed: $($_.Exception.Message)"
    }
}
# Mode 4: Local Interactive Browser Login (Only if no active session found)
elseif (-not $graphAccessToken) {
    Write-Host "[AUTH] No active session found. Launching standard interactive browser sign-in..." -ForegroundColor Yellow
    $connectParams = @{ ErrorAction = 'Stop' }
    if (-not [string]::IsNullOrWhiteSpace($effectiveTenantId)) {
        $connectParams["TenantId"] = $effectiveTenantId
    }
    $null = Connect-AzAccount @connectParams
    $currentAzContext = Get-AzContext
    $effectiveTenantId = $currentAzContext.Tenant.Id
    Write-Host "[+] Using active Azure session: $($currentAzContext.Account.Id) (Tenant: $effectiveTenantId)" -ForegroundColor Green

    $tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop
    $graphAccessToken = $tokenObj.Token
    Write-Host "[+] Successfully acquired Microsoft Graph token from browser login." -ForegroundColor Green
}

# Connect Microsoft.Graph session if module is loaded and token is available
if ($graphAccessToken -and (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
    try {
        $secureToken = ConvertTo-SecureString $graphAccessToken -AsPlainText -Force
        Connect-MgGraph -AccessToken $secureToken -NoWelcome -ErrorAction SilentlyContinue
    }
    catch { }
}

# -------------------------------------------------------------------------
# 2. REST API HELPER (Graph Queries with Pagination & Resilience)
# -------------------------------------------------------------------------
function Invoke-GraphRestApi {
    param (
        [string]$Uri,
        [string]$AccessToken
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri

    # In Azure Cloud Shell (or whenever Az context is MSI@*), try az rest which uses pre-consented Azure CLI session
    $isCloudShellMsi = ($null -eq $AccessToken -or ($currentAzContext -and $currentAzContext.Account.Id -like "MSI@*"))
    if ($isCloudShellMsi -and (Get-Command az -ErrorAction SilentlyContinue)) {
        Write-Host "  [AUTH] Querying Microsoft Graph via Azure CLI (az rest) in Cloud Shell..." -ForegroundColor Gray
        while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
            try {
                $rawJson = az rest --method GET --uri "$nextUri" --output json 2>&1
                if ($LASTEXITCODE -eq 0 -and $rawJson) {
                    $jsonText = ($rawJson -join "`n").Trim()
                    $resp = $jsonText | ConvertFrom-Json
                    if ($resp.value) {
                        foreach ($item in $resp.value) { $results.Add($item) }
                    } else {
                        $results.Add($resp)
                    }
                    $nextUri = $resp.'@odata.nextLink'
                }
                else {
                    Write-Host "  [INFO] az rest did not return data; falling back to direct REST token call." -ForegroundColor DarkGray
                    break
                }
            }
            catch {
                break
            }
        }

        if ($results.Count -gt 0) {
            return $results
        }
    }

    $headers = @{
        "Authorization"    = "Bearer $AccessToken"
        "ConsistencyLevel" = "eventual"
        "Content-Type"     = "application/json"
    }

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        try {
            $resp = Invoke-RestMethod -Uri $nextUri -Headers $headers -Method Get -ErrorAction Stop
            if ($resp.value) {
                foreach ($item in $resp.value) { $results.Add($item) }
            } else {
                $results.Add($resp)
            }
            $nextUri = $resp.'@odata.nextLink'
        }
        catch {
            if ($_.Exception.Message -like "*401*" -or ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 401)) {
                Write-Host "`n[ERROR] Microsoft Graph API returned 401 (Unauthorized)!" -ForegroundColor Red
                if ($currentAzContext.Account.Id -like "MSI@*") {
                    Write-Host ">>> ROOT CAUSE: In Azure Cloud Shell, PowerShell runs under the internal container identity '$($currentAzContext.Account.Id)'." -ForegroundColor Yellow
                    Write-Host "    This container identity is only for storage mounting and has NO permissions to query Entra ID / Microsoft Graph." -ForegroundColor Yellow
                    Write-Host "`n>>> SOLUTIONS TO RUN SUCCESSFULLY:" -ForegroundColor Cyan
                    Write-Host "    1. RUN LOCALLY ON YOUR LAPTOP (Recommended for Local Testing):" -ForegroundColor White
                    Write-Host "       Open PowerShell on your Windows laptop (C:\Users\home\Downloads\exl) and run:" -ForegroundColor White
                    Write-Host "         .\Export-EnterpriseAppAndInfraCertificates.ps1" -ForegroundColor Green
                    Write-Host "       Your local PC will sign in as your real corporate user via standard browser SSO (No device code, No MSI!)." -ForegroundColor Gray
                    Write-Host "`n    2. OR PASS APP REGISTRATION CREDENTIALS (For Cloud Shell / Automation):" -ForegroundColor White
                    Write-Host "       Pass your App Registration Client ID and Secret (as configured in script_v2.ps1):" -ForegroundColor White
                    Write-Host "         .\Export-EnterpriseAppAndInfraCertificates.ps1 -TenantId '$effectiveTenantId' -ClientId '<ClientId>' -ClientSecret '<Secret>'" -ForegroundColor Green
                } else {
                    Write-Host "[WARN] Graph API query failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "[WARN] Graph API query failed on URI '$nextUri': $($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }
    }
    return $results
}

# Helper to format Thumbprint from byte array or base64 string
function Format-Thumbprint {
    param ($CustomKeyIdentifier, [string]$KeyId)

    if ($null -eq $CustomKeyIdentifier) { return $KeyId }
    try {
        if ($CustomKeyIdentifier -is [byte[]]) {
            return ($CustomKeyIdentifier | ForEach-Object { $_.ToString("X2") }) -join ""
        }
        if ($CustomKeyIdentifier -is [string]) {
            if ($CustomKeyIdentifier -match '^[0-9a-fA-F]{40}$') {
                return $CustomKeyIdentifier.ToUpper()
            }
            $bytes = [System.Convert]::FromBase64String($CustomKeyIdentifier)
            return ($bytes | ForEach-Object { $_.ToString("X2") }) -join ""
        }
    }
    catch {
        return $KeyId
    }
    return $KeyId
}

# Helper: Decode multi-format PublicCertData (DER Base64, PEM Base64, raw PEM)
function ConvertFrom-PublicCertData {
    param([string]$certData)

    if ([string]::IsNullOrWhiteSpace($certData)) { return $null }

    $clean = $certData.Trim()
    
    # Strategy 1: Direct Base64 to DER bytes -> X509Certificate2
    try {
        $bytes = [System.Convert]::FromBase64String($clean)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
        if ($cert -and $cert.Thumbprint) { return $cert }
    } catch { }

    # Strategy 2: Base64-encoded PEM string -> decode outer base64, extract PEM body, decode inner base64
    try {
        $decodedText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($clean))
        if ($decodedText -match "-----BEGIN CERTIFICATE-----") {
            $inner = ($decodedText -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
            $bytes = [System.Convert]::FromBase64String($inner)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
            if ($cert -and $cert.Thumbprint) { return $cert }
        }
    } catch { }

    # Strategy 3: Raw PEM string (not outer base64)
    try {
        if ($clean -match "-----BEGIN CERTIFICATE-----") {
            $inner = ($clean -replace "-----BEGIN CERTIFICATE-----","" -replace "-----END CERTIFICATE-----","" -replace "`r","" -replace "`n","" -replace " ","").Trim()
            $bytes = [System.Convert]::FromBase64String($inner)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
            if ($cert -and $cert.Thumbprint) { return $cert }
        }
    } catch { }

    # Strategy 4: Raw UTF8 bytes directly
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($clean)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
        if ($cert -and $cert.Thumbprint) { return $cert }
    } catch { }

    return $null
}

# -------------------------------------------------------------------------
# 3. DISCOVERY: ENTRA ID ENTERPRISE APPLICATIONS (SAML SSO & TOKEN ENCRYPTION)
# -------------------------------------------------------------------------
$allDiscoveredRecords = [System.Collections.Generic.List[PSCustomObject]]::new()

if ($IncludeEnterpriseApps) {
    Write-Host "`n[STEP 1/2] Scanning Entra ID Enterprise Applications / Service Principals..." -ForegroundColor Cyan

    $sps = @()
    if ($graphAccessToken) {
        $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName,keyCredentials,servicePrincipalType,accountEnabled&`$filter=servicePrincipalType ne 'ManagedIdentity'&`$top=999"
        $sps = Invoke-GraphRestApi -Uri $spUri -AccessToken $graphAccessToken
    }
    elseif (Get-Command Get-MgServicePrincipal -ErrorAction SilentlyContinue) {
        $sps = Get-MgServicePrincipal -All -Property "id", "appId", "displayName", "keyCredentials", "servicePrincipalType", "accountEnabled" |
            Where-Object { $_.ServicePrincipalType -ne 'ManagedIdentity' }
    }

    Write-Host "  -> Retrieved $($sps.Count) Enterprise Application(s) / Service Principal(s)." -ForegroundColor Gray

    $spsWithCerts = $sps | Where-Object { $null -ne $_.keyCredentials -and $_.keyCredentials.Count -gt 0 }
    Write-Host "  [+] Found $($spsWithCerts.Count) Enterprise Application(s) with uploaded certificate(s)." -ForegroundColor Yellow

    $spIndex = 0
    foreach ($sp in $spsWithCerts) {
        $spIndex++
        $spName  = $sp.displayName
        $spAppId = $sp.appId
        $spId    = $sp.id

        # Resolve Owners
        $ownerEmails = @()
        $ownerNames  = @()
        try {
            if ($graphAccessToken) {
                $ownerUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/owners?`$select=id,displayName,userPrincipalName,mail"
                $owners = Invoke-GraphRestApi -Uri $ownerUri -AccessToken $graphAccessToken
                foreach ($o in $owners) {
                    $email = if (-not [string]::IsNullOrWhiteSpace($o.mail)) { $o.mail } elseif (-not [string]::IsNullOrWhiteSpace($o.userPrincipalName)) { $o.userPrincipalName } else { $null }
                    if ($email) { $ownerEmails += $email }
                    if ($o.displayName) { $ownerNames += $o.displayName }
                }
            }
            elseif (Get-Command Get-MgServicePrincipalOwner -ErrorAction SilentlyContinue) {
                $mgOwners = Get-MgServicePrincipalOwner -ServicePrincipalId $spId -ErrorAction SilentlyContinue
                foreach ($o in $mgOwners) {
                    $mail = $o.AdditionalProperties.mail
                    $upn  = $o.AdditionalProperties.userPrincipalName
                    $dName = $o.AdditionalProperties.displayName
                    $email = if (-not [string]::IsNullOrWhiteSpace($mail)) { $mail } elseif (-not [string]::IsNullOrWhiteSpace($upn)) { $upn } else { $null }
                    if ($email) { $ownerEmails += $email }
                    if ($dName) { $ownerNames += $dName }
                }
            }
        }
        catch { }

        $ownerEmailString = if ($ownerEmails.Count -gt 0) { ($ownerEmails | Select-Object -Unique) -join ', ' } else { $FallbackOwnerEmail }
        $ownerNameString  = if ($ownerNames.Count -gt 0)  { ($ownerNames  | Select-Object -Unique) -join ', ' } else { "<<No Owner Configured>>" }
        $isOrphaned       = ($ownerEmailString -eq $FallbackOwnerEmail)

        foreach ($cert in $sp.keyCredentials) {
            $startDate = if ($cert.startDateTime) { [DateTime]$cert.startDateTime } else { $null }
            $endDate   = if ($cert.endDateTime)   { [DateTime]$cert.endDateTime }   else { $null }

            $daysRemaining = if ($endDate) { ($endDate - (Get-Date)).Days } else { 9999 }

            # Classify Certificate Usage
            $usage = if ($cert.usage) { $cert.usage } else { "Unknown" }
            $certFriendlyName = if (-not [string]::IsNullOrWhiteSpace($cert.displayName)) {
                $cert.displayName
            } elseif ($usage -eq "Sign") {
                "SAML SSO Signing Certificate"
            } elseif ($usage -eq "Verify") {
                "Token Verification / Encryption Certificate"
            } else {
                "Enterprise App Certificate ($usage)"
            }

            # Filter logic
            $include = $false
            if ($AllCertificates) {
                $include = $true
            }
            elseif ($IncludeAlreadyExpired) {
                if ($daysRemaining -le $DaysUntilExpiration) { $include = $true }
            }
            else {
                if ($daysRemaining -le $DaysUntilExpiration -and $daysRemaining -ge 0) { $include = $true }
            }

            # Expiry status
            $status = if ($daysRemaining -lt 0) {
                "EXPIRED"
            } elseif ($daysRemaining -le 14) {
                "EXPIRING URGENT (<= 14 Days)"
            } elseif ($daysRemaining -le 30) {
                "EXPIRING SOON (<= 30 Days)"
            } else {
                "HEALTHY / ACTIVE"
            }

            if ($include) {
                $thumb = Format-Thumbprint -CustomKeyIdentifier $cert.customKeyIdentifier -KeyId $cert.keyId

                $allDiscoveredRecords.Add([PSCustomObject]@{
                    WorkloadSource         = "Entra Enterprise Application"
                    ApplicationName        = $spName
                    ApplicationID          = $spAppId
                    ObjectID               = $spId
                    CredentialType         = "Certificate (SAML/SSO)"
                    CertificateName        = $certFriendlyName
                    Usage                  = $usage
                    Thumbprint             = $thumb
                    KeyId                  = $cert.keyId
                    StartDate              = if ($startDate) { $startDate.ToString("yyyy-MM-dd") } else { "N/A" }
                    EndDate                = if ($endDate)   { $endDate.ToString("yyyy-MM-dd") }   else { "N/A" }
                    DaysRemaining          = $daysRemaining
                    Status                 = $status
                    OwnerEmails            = $ownerEmailString
                    OwnerDisplayNames      = $ownerNameString
                    IsOrphaned             = $isOrphaned
                    ResourceGroup          = "N/A (Entra ID Tenant)"
                    SubscriptionId         = "N/A (Entra ID Tenant)"
                })
            }
        }
    }

    Write-Host "[+] Enterprise App cert discovery complete. Records matched: $($allDiscoveredRecords.Count)" -ForegroundColor Green
}

# -------------------------------------------------------------------------
# 4. (OPTIONAL) DISCOVERY: AZURE INFRASTRUCTURE CERTIFICATES
# -------------------------------------------------------------------------
if ($IncludeAzureResources) {
    Write-Host "`n[STEP 2/2] Scanning Azure Infrastructure (App Services, Key Vaults, App Gateways)..." -ForegroundColor Cyan

    $hasArg   = [bool](Get-Command Search-AzGraph -ErrorAction SilentlyContinue)
    $hasAzCli = [bool](Get-Command az -ErrorAction SilentlyContinue)

    if ($hasArg -or $hasAzCli) {
        # ---------------------------------------------------------------------
        # 1. App Service Certificates
        # ---------------------------------------------------------------------
        Write-Host "  -> Querying Azure App Service Certificates..." -ForegroundColor Gray
        $webCerts = @()
        if ($hasArg) {
            try {
                $argAppService = @"
                resources
                | where type =~ 'microsoft.web/certificates'
                | project name, id, resourceGroup, subscriptionId,
                          expirationDate = todatetime(properties.expirationDate),
                          thumbprint     = tostring(properties.thumbprint),
                          issuer         = tostring(properties.issuer),
                          ownerTag       = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
                $webCerts = Search-AzGraph -Query $argAppService -First 1000 -ErrorAction SilentlyContinue
            } catch { }
        }

        if ($webCerts) {
            foreach ($wc in $webCerts) {
                if ($wc.expirationDate) {
                    $expDate = [DateTime]$wc.expirationDate
                    $daysLeft = ($expDate - (Get-Date)).Days
                    $ownerVal = if (-not [string]::IsNullOrWhiteSpace($wc.ownerTag)) { $wc.ownerTag } else { $FallbackOwnerEmail }

                    $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }
                    $status = if ($daysLeft -lt 0) { "EXPIRED" } elseif ($daysLeft -le 14) { "EXPIRING URGENT (<= 14 Days)" } elseif ($daysLeft -le 30) { "EXPIRING SOON (<= 30 Days)" } else { "HEALTHY / ACTIVE" }

                    if ($include) {
                        $allDiscoveredRecords.Add([PSCustomObject]@{
                            WorkloadSource         = "Azure App Service Certificate"
                            ApplicationName        = $wc.name
                            ApplicationID          = $wc.id
                            ObjectID               = $wc.id
                            CredentialType         = "Certificate (App Service)"
                            CertificateName        = "$($wc.name) ($($wc.issuer))"
                            Usage                  = "SSL/TLS Server Authentication"
                            Thumbprint             = $wc.thumbprint
                            KeyId                  = "N/A"
                            StartDate              = "N/A"
                            EndDate                = $expDate.ToString("yyyy-MM-dd")
                            DaysRemaining          = $daysLeft
                            Status                 = $status
                            OwnerEmails            = $ownerVal
                            OwnerDisplayNames      = $ownerVal
                            IsOrphaned             = ($ownerVal -eq $FallbackOwnerEmail)
                            ResourceGroup          = $wc.resourceGroup
                            SubscriptionId         = $wc.subscriptionId
                        })
                    }
                }
            }
        }

        # ---------------------------------------------------------------------
        # 2. Application Gateway SSL Certificates (Directly Uploaded & KV-Linked)
        # ---------------------------------------------------------------------
        Write-Host "  -> Querying Azure Application Gateway SSL Certificates..." -ForegroundColor Gray
        $appGws = @()
        if ($hasArg) {
            try {
                $argAppGw = @"
                resources
                | where type =~ 'microsoft.network/applicationgateways'
                | project name, id, resourceGroup, subscriptionId,
                          sslCertificates = properties.sslCertificates,
                          httpListeners = properties.httpListeners,
                          trustedRootCertificates = properties.trustedRootCertificates,
                          ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
                $appGws = Search-AzGraph -Query $argAppGw -First 1000 -ErrorAction SilentlyContinue
            } catch { }
        }

        # Fallback to az CLI if ARG returned 0 or wasn't available
        if ((-not $appGws -or $appGws.Count -eq 0) -and $hasAzCli) {
            try {
                $rawAgwCli = az network application-gateway list -o json 2>$null
                if ($LASTEXITCODE -eq 0 -and $rawAgwCli) {
                    $cliGws = ($rawAgwCli -join "`n") | ConvertFrom-Json
                    if ($cliGws) {
                        $appGws = [System.Collections.Generic.List[PSObject]]::new()
                        foreach ($cg in $cliGws) {
                            $subIdFromId = if ($cg.id) { $cg.id.Split('/')[2] } else { "" }
                            $appGws.Add([PSCustomObject]@{
                                name                    = $cg.name
                                id                      = $cg.id
                                resourceGroup           = $cg.resourceGroup
                                subscriptionId          = $subIdFromId
                                sslCertificates         = $cg.sslCertificates
                                httpListeners           = $cg.httpListeners
                                trustedRootCertificates = $cg.trustedRootCertificates
                                ownerTag                = $null
                            })
                        }
                    }
                }
            } catch { }
        }

        Write-Host "     Found $($appGws.Count) Application Gateway(s) to inspect." -ForegroundColor Gray

        foreach ($ag in $appGws) {
            $agwName = $ag.name
            $agwRg   = $ag.resourceGroup
            $subId   = $ag.subscriptionId
            $ownerVal = if (-not [string]::IsNullOrWhiteSpace($ag.ownerTag)) { $ag.ownerTag } else { $FallbackOwnerEmail }

            # Retrieve full gateway object from ARM to access publicCertData and httpListeners
            $fullAgw = $null
            if (Get-Command Get-AzApplicationGateway -ErrorAction SilentlyContinue) {
                try {
                    $null = Set-AzContext -SubscriptionId $subId -ErrorAction SilentlyContinue
                    $fullAgw = Get-AzApplicationGateway -Name $agwName -ResourceGroupName $agwRg -ErrorAction SilentlyContinue
                } catch { }
            }

            if (-not $fullAgw -and $hasAzCli) {
                try {
                    $rawAgwJson = az network application-gateway show --subscription $subId -g $agwRg -n $agwName -o json 2>$null
                    if ($LASTEXITCODE -eq 0 -and $rawAgwJson) {
                        $fullAgw = ($rawAgwJson -join "`n") | ConvertFrom-Json
                    }
                } catch { }
            }

            # Extract sslCertificates from full gateway or ARG stub
            $sslCerts = $null
            if ($fullAgw) {
                if ($fullAgw.SslCertificates) { $sslCerts = $fullAgw.SslCertificates }
                elseif ($fullAgw.properties -and $fullAgw.properties.sslCertificates) { $sslCerts = $fullAgw.properties.sslCertificates }
                elseif ($fullAgw.sslCertificates) { $sslCerts = $fullAgw.sslCertificates }
            }
            if (-not $sslCerts) { $sslCerts = $ag.sslCertificates }

            if (-not $sslCerts -or $sslCerts.Count -eq 0) { continue }

            # Build HTTP Listener & Hostname Mapping
            $certListenerMap = @{}
            $listeners = if ($fullAgw.HttpListeners) { $fullAgw.HttpListeners }
                         elseif ($fullAgw.properties -and $fullAgw.properties.httpListeners) { $fullAgw.properties.httpListeners }
                         elseif ($fullAgw.httpListeners) { $fullAgw.httpListeners }
                         elseif ($ag.httpListeners) { $ag.httpListeners }
                         else { @() }

            foreach ($lst in $listeners) {
                $certRef = $null
                if ($lst.SslCertificate -and $lst.SslCertificate.Id) { $certRef = $lst.SslCertificate.Id }
                elseif ($lst.sslCertificate -and $lst.sslCertificate.id) { $certRef = $lst.sslCertificate.id }
                elseif ($lst.properties -and $lst.properties.sslCertificate -and $lst.properties.sslCertificate.id) { $certRef = $lst.properties.sslCertificate.id }

                if ($certRef) {
                    $cName = $certRef.Split('/')[-1]
                    $lstName = if ($lst.Name) { $lst.Name } elseif ($lst.name) { $lst.name } else { "Listener" }
                    $hostVal = if ($lst.HostName) { $lst.HostName }
                               elseif ($lst.hostName) { $lst.hostName }
                               elseif ($lst.properties -and $lst.properties.hostName) { $lst.properties.hostName }
                               elseif ($lst.HostNames) { $lst.HostNames -join ", " }
                               elseif ($lst.properties -and $lst.properties.hostNames) { $lst.properties.hostNames -join ", " }
                               else { "" }
                    
                    $listenerLabel = if ($hostVal) { "$lstName ($hostVal)" } else { $lstName }
                    if (-not $certListenerMap.ContainsKey($cName)) {
                        $certListenerMap[$cName] = [System.Collections.Generic.List[string]]::new()
                    }
                    $certListenerMap[$cName].Add($listenerLabel)
                }
            }

            foreach ($sslCert in $sslCerts) {
                $certName = if ($sslCert.Name) { $sslCert.Name } elseif ($sslCert.name) { $sslCert.name } else { "ssl-cert" }
                $certId   = if ($sslCert.Id) { $sslCert.Id } elseif ($sslCert.id) { $sslCert.id } else { "$($ag.id)/sslCertificates/$certName" }
                $listenersDesc = if ($certListenerMap.ContainsKey($certName)) { $certListenerMap[$certName] -join "; " } else { "Unattached / No Listener" }

                # Check KeyVaultSecretId
                $kvSecretId = $null
                if ($sslCert.KeyVaultSecretId) { $kvSecretId = $sslCert.KeyVaultSecretId }
                elseif ($sslCert.properties -and $sslCert.properties.keyVaultSecretId) { $kvSecretId = $sslCert.properties.keyVaultSecretId }
                elseif ($sslCert.keyVaultSecretId) { $kvSecretId = $sslCert.keyVaultSecretId }

                # Check PublicCertData / Data
                $publicData = $null
                if ($sslCert.PublicCertData) { $publicData = $sslCert.PublicCertData }
                elseif ($sslCert.properties -and $sslCert.properties.publicCertData) { $publicData = $sslCert.properties.publicCertData }
                elseif ($sslCert.publicCertData) { $publicData = $sslCert.publicCertData }
                elseif ($sslCert.Data) { $publicData = $sslCert.Data }
                elseif ($sslCert.properties -and $sslCert.properties.data) { $publicData = $sslCert.properties.data }
                elseif ($sslCert.data) { $publicData = $sslCert.data }

                # SCENARIO A: Directly Uploaded Certificate (Decoded via X.509)
                $x509 = ConvertFrom-PublicCertData -certData $publicData

                if ($x509) {
                    $expDate  = $x509.NotAfter
                    $daysLeft = ($expDate - (Get-Date)).Days
                    $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }
                    $status  = if ($daysLeft -lt 0) { "EXPIRED" } elseif ($daysLeft -le 14) { "EXPIRING URGENT (<= 14 Days)" } elseif ($daysLeft -le 30) { "EXPIRING SOON (<= 30 Days)" } else { "HEALTHY / ACTIVE" }

                    if ($include) {
                        $allDiscoveredRecords.Add([PSCustomObject]@{
                            WorkloadSource         = "Azure Application Gateway SSL"
                            ApplicationName        = "$agwName ($agwRg)"
                            ApplicationID          = $ag.id
                            ObjectID               = $certId
                            CredentialType         = "Certificate (Directly Uploaded to App Gateway)"
                            CertificateName        = "$certName | Subject: $($x509.Subject)"
                            Usage                  = "SSL/TLS Listener: $listenersDesc"
                            Thumbprint             = $x509.Thumbprint
                            KeyId                  = "N/A"
                            StartDate              = $x509.NotBefore.ToString("yyyy-MM-dd")
                            EndDate                = $expDate.ToString("yyyy-MM-dd")
                            DaysRemaining          = $daysLeft
                            Status                 = $status
                            OwnerEmails            = $ownerVal
                            OwnerDisplayNames      = $ownerVal
                            IsOrphaned             = ($ownerVal -eq $FallbackOwnerEmail)
                            ResourceGroup          = $agwRg
                            SubscriptionId         = $subId
                        })
                    }
                    $x509.Dispose()
                }
                elseif (-not [string]::IsNullOrWhiteSpace($kvSecretId)) {
                    # Key Vault linked App Gateway Certificate
                    $allDiscoveredRecords.Add([PSCustomObject]@{
                        WorkloadSource         = "Azure Application Gateway SSL (Key Vault)"
                        ApplicationName        = "$agwName ($agwRg)"
                        ApplicationID          = $ag.id
                        ObjectID               = $certId
                        CredentialType         = "Certificate (Key Vault Linked)"
                        CertificateName        = "$certName (KV Reference)"
                        Usage                  = "SSL/TLS Listener: $listenersDesc"
                        Thumbprint             = "KeyVault-Linked"
                        KeyId                  = $kvSecretId
                        StartDate              = "N/A"
                        EndDate                = "Managed in Key Vault"
                        DaysRemaining          = 9999
                        Status                 = "KEYVAULT LINKED"
                        OwnerEmails            = $ownerVal
                        OwnerDisplayNames      = $ownerVal
                        IsOrphaned             = ($ownerVal -eq $FallbackOwnerEmail)
                        ResourceGroup          = $agwRg
                        SubscriptionId         = $subId
                    })
                }
                else {
                    # Directly uploaded certificate exists on App Gateway but raw bytes not decoded
                    # Surface as directly uploaded record so it is NEVER silently missed
                    $allDiscoveredRecords.Add([PSCustomObject]@{
                        WorkloadSource         = "Azure Application Gateway SSL"
                        ApplicationName        = "$agwName ($agwRg)"
                        ApplicationID          = $ag.id
                        ObjectID               = $certId
                        CredentialType         = "Certificate (Directly Uploaded to App Gateway)"
                        CertificateName        = "$certName (Direct AppGW Upload)"
                        Usage                  = "SSL/TLS Listener: $listenersDesc"
                        Thumbprint             = "Directly-Uploaded"
                        KeyId                  = "N/A"
                        StartDate              = "N/A"
                        EndDate                = "Uploaded Directly to AppGW"
                        DaysRemaining          = 9999
                        Status                 = "DIRECTLY UPLOADED TO APPGW (Review Expiry)"
                        OwnerEmails            = $ownerVal
                        OwnerDisplayNames      = $ownerVal
                        IsOrphaned             = ($ownerVal -eq $FallbackOwnerEmail)
                        ResourceGroup          = $agwRg
                        SubscriptionId         = $subId
                    })
                }
            }
        }

        # ---------------------------------------------------------------------
        # 3. Key Vault Secrets & Certificates
        # ---------------------------------------------------------------------
        Write-Host "  -> Querying Azure Key Vault Secrets & Certificates..." -ForegroundColor Gray
        $kvs = @()
        if ($hasArg) {
            try {
                $argKeyVaults = @"
                resources
                | where type =~ 'microsoft.keyvault/vaults'
                | project name, id, resourceGroup, subscriptionId,
                          ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
                $kvs = Search-AzGraph -Query $argKeyVaults -First 500 -ErrorAction SilentlyContinue
            } catch { }
        }

        if ((-not $kvs -or $kvs.Count -eq 0) -and $hasAzCli) {
            try {
                $rawKvsCli = az keyvault list -o json 2>$null
                if ($LASTEXITCODE -eq 0 -and $rawKvsCli) {
                    $cliKvs = ($rawKvsCli -join "`n") | ConvertFrom-Json
                    if ($cliKvs) {
                        $kvs = [System.Collections.Generic.List[PSObject]]::new()
                        foreach ($ckv in $cliKvs) {
                            $subIdFromId = if ($ckv.id) { $ckv.id.Split('/')[2] } else { "" }
                            $kvs.Add([PSCustomObject]@{
                                name           = $ckv.name
                                id             = $ckv.id
                                resourceGroup  = $ckv.resourceGroup
                                subscriptionId = $subIdFromId
                                ownerTag       = $null
                            })
                        }
                    }
                }
            } catch { }
        }

        Write-Host "     Found $($kvs.Count) Key Vault(s) to inspect." -ForegroundColor Gray

        foreach ($kv in $kvs) {
            $ownerVal = if (-not [string]::IsNullOrWhiteSpace($kv.ownerTag)) { $kv.ownerTag } else { $FallbackOwnerEmail }
            $null = Set-AzContext -SubscriptionId $kv.subscriptionId -ErrorAction SilentlyContinue

            # 3a. Key Vault Certificates
            $kvCerts = $null
            if (Get-Command Get-AzKeyVaultCertificate -ErrorAction SilentlyContinue) {
                try {
                    $kvCerts = Get-AzKeyVaultCertificate -VaultName $kv.name -ErrorAction Stop
                } catch { }
            }
            if (-not $kvCerts -and $hasAzCli) {
                try {
                    $rawCliCerts = az keyvault certificate list --vault-name $kv.name -o json 2>$null
                    if ($LASTEXITCODE -eq 0 -and $rawCliCerts) {
                        $cliCerts = ($rawCliCerts -join "`n") | ConvertFrom-Json
                        if ($cliCerts) {
                            $kvCerts = @($cliCerts | ForEach-Object {
                                [PSCustomObject]@{
                                    Name       = $_.name
                                    Id         = $_.id
                                    Thumbprint = if ($_.x509ThumbprintHex) { $_.x509ThumbprintHex } else { "KV-Managed" }
                                    Expires    = if ($_.attributes -and $_.attributes.expires) { [DateTime]$_.attributes.expires } else { $null }
                                }
                            })
                        }
                    }
                } catch { }
            }

            if ($kvCerts) {
                foreach ($c in $kvCerts) {
                    $expDate = if ($c.Expires) { [DateTime]$c.Expires } elseif ($c.Attributes -and $c.Attributes.Expires) { [DateTime]$c.Attributes.Expires } else { $null }
                    if ($expDate) {
                        $daysLeft = ($expDate - (Get-Date)).Days
                        $include  = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }
                        $status   = if ($daysLeft -lt 0) { "EXPIRED" } elseif ($daysLeft -le 14) { "EXPIRING URGENT (<= 14 Days)" } elseif ($daysLeft -le 30) { "EXPIRING SOON (<= 30 Days)" } else { "HEALTHY / ACTIVE" }

                        if ($include) {
                            $allDiscoveredRecords.Add([PSCustomObject]@{
                                WorkloadSource         = "Azure Key Vault Certificate"
                                ApplicationName        = "$($kv.name) ($($kv.resourceGroup))"
                                ApplicationID          = $kv.id
                                ObjectID               = $c.Id
                                CredentialType         = "Certificate (Key Vault)"
                                CertificateName        = $c.Name
                                Usage                  = "Key Vault Certificate"
                                Thumbprint             = if ($c.Thumbprint) { $c.Thumbprint } else { "KV-Managed" }
                                KeyId                  = $c.Id
                                StartDate              = "N/A"
                                EndDate                = $expDate.ToString("yyyy-MM-dd")
                                DaysRemaining          = $daysLeft
                                Status                 = $status
                                OwnerEmails            = $ownerVal
                                OwnerDisplayNames      = $ownerVal
                                IsOrphaned             = ($ownerVal -eq $FallbackOwnerEmail)
                                ResourceGroup          = $kv.resourceGroup
                                SubscriptionId         = $kv.subscriptionId
                            })
                        }
                    }
                }
            }

            # 3b. Key Vault Secrets
            $secrets = $null
            if (Get-Command Get-AzKeyVaultSecret -ErrorAction SilentlyContinue) {
                try {
                    $secrets = Get-AzKeyVaultSecret -VaultName $kv.name -ErrorAction Stop
                } catch { }
            }
            if (-not $secrets -and $hasAzCli) {
                try {
                    $rawCliSecs = az keyvault secret list --vault-name $kv.name -o json 2>$null
                    if ($LASTEXITCODE -eq 0 -and $rawCliSecs) {
                        $cliSecs = ($rawCliSecs -join "`n") | ConvertFrom-Json
                        if ($cliSecs) {
                            $secrets = @($cliSecs | ForEach-Object {
                                [PSCustomObject]@{
                                    Name        = $_.name
                                    Id          = $_.id
                                    ContentType = $_.contentType
                                    Expires     = if ($_.attributes -and $_.attributes.expires) { [DateTime]$_.attributes.expires } else { $null }
                                }
                            })
                        }
                    }
                } catch { }
            }

            if ($secrets) {
                foreach ($sec in $secrets) {
                    if ($sec.Expires) {
                        $expDate  = [DateTime]$sec.Expires
                        $daysLeft = ($expDate - (Get-Date)).Days
                        $include  = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }
                        $status   = if ($daysLeft -lt 0) { "EXPIRED" } elseif ($daysLeft -le 14) { "EXPIRING URGENT (<= 14 Days)" } elseif ($daysLeft -le 30) { "EXPIRING SOON (<= 30 Days)" } else { "HEALTHY / ACTIVE" }

                        if ($include) {
                            $allDiscoveredRecords.Add([PSCustomObject]@{
                                WorkloadSource         = "Azure Key Vault Secret"
                                ApplicationName        = "$($kv.name) ($($kv.resourceGroup))"
                                ApplicationID          = $kv.id
                                ObjectID               = $sec.Id
                                CredentialType         = "Secret"
                                CertificateName        = $sec.Name
                                Usage                  = "Key Vault Secret"
                                Thumbprint             = "N/A"
                                KeyId                  = $sec.Id
                                StartDate              = "N/A"
                                EndDate                = $expDate.ToString("yyyy-MM-dd")
                                DaysRemaining          = $daysLeft
                                Status                 = $status
                                OwnerEmails            = $ownerVal
                                OwnerDisplayNames      = $ownerVal
                                IsOrphaned             = ($ownerVal -eq $FallbackOwnerEmail)
                                ResourceGroup          = $kv.resourceGroup
                                SubscriptionId         = $kv.subscriptionId
                            })
                        }
                    }
                }
            }
        }
    }
    else {
        Write-Host "  [INFO] Neither Az PowerShell nor Azure CLI (az) is available for infrastructure discovery." -ForegroundColor Yellow
    }
}

# -------------------------------------------------------------------------
# 5. DASHBOARD SUMMARY & REPORT EXPORTS
# -------------------------------------------------------------------------
Write-Host "`n==========================================================================" -ForegroundColor Green
Write-Host " AUDIT SUMMARY & DASHBOARD" -ForegroundColor Green
Write-Host " Total Matching Items Discovered: $($allDiscoveredRecords.Count)" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Green

if ($allDiscoveredRecords.Count -gt 0) {
    # Print breakdown by status
    $statusGroup = $allDiscoveredRecords | Group-Object Status
    foreach ($sg in $statusGroup) {
        $color = switch -Wildcard ($sg.Name) {
            "*EXPIRED*" { "Red" }
            "*URGENT*"  { "Yellow" }
            "*SOON*"    { "Magenta" }
            default     { "Green" }
        }
        Write-Host "  -> $($sg.Name.PadRight(30)) : $($sg.Count)" -ForegroundColor $color
    }

    # Print breakdown by source
    Write-Host "`nBreakdown by Workload Source:" -ForegroundColor Cyan
    $sourceGroup = $allDiscoveredRecords | Group-Object WorkloadSource
    foreach ($src in $sourceGroup) {
        Write-Host "  -> $($src.Name.PadRight(35)) : $($src.Count)" -ForegroundColor Gray
    }

    # Console Preview Table
    Write-Host "`nPreview (Top 10 Records):" -ForegroundColor Yellow
    $allDiscoveredRecords |
        Sort-Object DaysRemaining |
        Select-Object -First 10 ApplicationName, CredentialType, CertificateName, EndDate, DaysRemaining, Status, OwnerEmails |
        Format-Table -AutoSize | Out-String | Write-Host

    # Export to CSV
    if ($ExportCsv) {
        if ([string]::IsNullOrWhiteSpace($CsvPath)) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $CsvPath = Join-Path $PSScriptRoot "EnterpriseApp-and-Infra-Certificates-$timestamp.csv"
        }
        $allDiscoveredRecords | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8
        Write-Host "`n[+] Full Audit Exported to CSV: $CsvPath" -ForegroundColor Green
    }

    # Export to Excel
    if ($ExportExcel -and (Get-Command Export-Excel -ErrorAction SilentlyContinue)) {
        $xlsxPath = [System.IO.Path]::ChangeExtension($CsvPath, ".xlsx")
        $allDiscoveredRecords | Export-Excel -Path $xlsxPath -WorksheetName "Certificates" -AutoSize -AutoFilter -BoldTopRow -FreezeTopRow
        Write-Host "[+] Formatted Excel Exported: $xlsxPath" -ForegroundColor Green
    }
}
else {
    Write-Host "No expiring or matching certificates found with current filter settings." -ForegroundColor Green
}

# Return pipeline objects for Azure Automation Runbook consumption
return $allDiscoveredRecords
