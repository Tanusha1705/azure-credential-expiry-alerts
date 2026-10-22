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
    [switch]$IncludeAzureResources,

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

# Detect Azure Automation environment
$isAzureAutomation = ($UseManagedIdentity -or `
    $env:AZUREPS_HOST_ENVIRONMENT -like "*Automation*" -or `
    (Get-Command Get-AutomationVariable -ErrorAction SilentlyContinue) -or `
    $env:IDENTITY_HEADER)

Write-Host "`n[AUTH] Initializing authentication (Device Code Auth is DISABLED)..." -ForegroundColor Cyan

# Mode A: Service Principal (ClientId + ClientSecret)
if (-not [string]::IsNullOrWhiteSpace($ClientId) -and -not [string]::IsNullOrWhiteSpace($ClientSecret)) {
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
# Mode B: Azure Automation Managed Identity
elseif ($isAzureAutomation) {
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
# Mode C: Local Interactive / Reusing Active Az Context
else {
    # Check if user already has an active Azure context
    $currentAzContext = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $currentAzContext) {
        Write-Host "[AUTH] No active Azure session found. Launching standard interactive browser sign-in..." -ForegroundColor Yellow
        Write-Host "[INFO] A web browser window will open. Complete your standard corporate SSO sign-in." -ForegroundColor Gray
        
        $connectParams = @{ ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($effectiveTenantId)) {
            $connectParams["TenantId"] = $effectiveTenantId
        }
        $null = Connect-AzAccount @connectParams
        $currentAzContext = Get-AzContext
    }

    $effectiveTenantId = $currentAzContext.Tenant.Id
    Write-Host "[+] Using active Azure session: $($currentAzContext.Account.Id) (Tenant: $effectiveTenantId)" -ForegroundColor Green

    # Acquire Graph Token from active Az session without prompting!
    try {
        Write-Host "[AUTH] Acquiring Microsoft Graph token from active Az session..." -ForegroundColor Gray
        $tokenObj = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction SilentlyContinue
        if (-not $tokenObj -or -not $tokenObj.Token) {
            $tokenObj = Get-AzAccessToken -ResourceTypeName MSGraph -ErrorAction Stop
        }
        $graphAccessToken = $tokenObj.Token
        Write-Host "[+] Successfully acquired Microsoft Graph token from active Az context." -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Could not acquire Graph token from Az context. Checking Microsoft.Graph module..." -ForegroundColor Yellow
        if (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue) {
            Write-Host "[AUTH] Connecting to Microsoft Graph interactively (browser popup)..." -ForegroundColor Cyan
            Connect-MgGraph -Scopes "Application.Read.All", "User.Read.All" -NoWelcome -ErrorAction Stop
            $mgContext = Get-MgContext
            Write-Host "[+] Connected to Microsoft Graph via Connect-MgGraph." -ForegroundColor Green
        }
        else {
            Throw "[ERROR] Could not acquire Graph access token: $($_.Exception.Message)"
        }
    }
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
            Write-Host "[WARN] Graph API query failed on URI '$nextUri': $($_.Exception.Message)" -ForegroundColor Red
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

    $hasArg = [bool](Get-Command Search-AzGraph -ErrorAction SilentlyContinue)

    if ($hasArg) {
        # 1. App Service Certificates
        Write-Host "  -> Querying Azure App Service Certificates..." -ForegroundColor Gray
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
        catch {
            Write-Host "  [WARN] App Service Certificate scan encountered an issue: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # 2. Application Gateway SSL Certificates
        Write-Host "  -> Querying Azure Application Gateway SSL Certificates..." -ForegroundColor Gray
        try {
            $argAppGw = @"
            resources
            | where type =~ 'microsoft.network/applicationgateways'
            | project name, id, resourceGroup, subscriptionId,
                      ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
            $appGws = Search-AzGraph -Query $argAppGw -First 1000 -ErrorAction SilentlyContinue
            foreach ($ag in $appGws) {
                try {
                    $null = Set-AzContext -SubscriptionId $ag.subscriptionId -ErrorAction SilentlyContinue
                    $fullAgw = Get-AzApplicationGateway -Name $ag.name -ResourceGroupName $ag.resourceGroup -ErrorAction SilentlyContinue
                    if ($fullAgw.SslCertificates) {
                        foreach ($sslCert in $fullAgw.SslCertificates) {
                            $x509 = $null
                            try {
                                if ($sslCert.PublicCertData) {
                                    $certBytes = [System.Convert]::FromBase64String($sslCert.PublicCertData)
                                    $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                                } elseif ($sslCert.Data) {
                                    $certBytes = [System.Convert]::FromBase64String($sslCert.Data)
                                    $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                                }

                                if ($x509) {
                                    $expDate  = $x509.NotAfter
                                    $daysLeft = ($expDate - (Get-Date)).Days
                                    $ownerVal = if (-not [string]::IsNullOrWhiteSpace($ag.ownerTag)) { $ag.ownerTag } else { $FallbackOwnerEmail }

                                    $include = if ($AllCertificates) { $true } elseif ($IncludeAlreadyExpired) { $daysLeft -le $DaysUntilExpiration } else { $daysLeft -le $DaysUntilExpiration -and $daysLeft -ge 0 }
                                    $status  = if ($daysLeft -lt 0) { "EXPIRED" } elseif ($daysLeft -le 14) { "EXPIRING URGENT (<= 14 Days)" } elseif ($daysLeft -le 30) { "EXPIRING SOON (<= 30 Days)" } else { "HEALTHY / ACTIVE" }

                                    if ($include) {
                                        $allDiscoveredRecords.Add([PSCustomObject]@{
                                            WorkloadSource         = "Azure Application Gateway SSL"
                                            ApplicationName        = "$($ag.name) ($($ag.resourceGroup))"
                                            ApplicationID          = $ag.id
                                            ObjectID               = $sslCert.Id
                                            CredentialType         = "Certificate (App Gateway SSL)"
                                            CertificateName        = "$($sslCert.Name) | Subject: $($x509.Subject)"
                                            Usage                  = "SSL/TLS Listener"
                                            Thumbprint             = $x509.Thumbprint
                                            KeyId                  = "N/A"
                                            StartDate              = $x509.NotBefore.ToString("yyyy-MM-dd")
                                            EndDate                = $expDate.ToString("yyyy-MM-dd")
                                            DaysRemaining          = $daysLeft
                                            Status                 = $status
                                            OwnerEmails            = $ownerVal
                                            OwnerDisplayNames      = $ownerVal
                                            IsOrphaned             = ($ownerVal -eq $FallbackOwnerEmail)
                                            ResourceGroup          = $ag.resourceGroup
                                            SubscriptionId         = $ag.subscriptionId
                                        })
                                    }
                                    $x509.Dispose()
                                }
                            }
                            catch {
                                if ($x509) { try { $x509.Dispose() } catch {} }
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch {
            Write-Host "  [WARN] Application Gateway SSL Certificate scan encountered an issue: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # 3. Key Vault Secrets & Certificates
        Write-Host "  -> Querying Azure Key Vault Secrets & Certificates..." -ForegroundColor Gray
        try {
            $argKeyVaults = @"
            resources
            | where type =~ 'microsoft.keyvault/vaults'
            | project name, id, resourceGroup, subscriptionId,
                      ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))
"@
            $kvs = Search-AzGraph -Query $argKeyVaults -First 500 -ErrorAction SilentlyContinue
            foreach ($kv in $kvs) {
                try {
                    $null = Set-AzContext -SubscriptionId $kv.subscriptionId -ErrorAction SilentlyContinue
                    $ownerVal = if (-not [string]::IsNullOrWhiteSpace($kv.ownerTag)) { $kv.ownerTag } else { $FallbackOwnerEmail }

                    $secrets = Get-AzKeyVaultSecret -VaultName $kv.name -ErrorAction SilentlyContinue
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
                catch { }
            }
        }
        catch {
            Write-Host "  [WARN] Key Vault scan encountered an issue: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  [INFO] Az.ResourceGraph module not available; skipping infrastructure discovery." -ForegroundColor Yellow
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
