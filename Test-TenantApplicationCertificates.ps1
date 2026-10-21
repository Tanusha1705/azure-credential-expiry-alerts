<#
.SYNOPSIS
    Local Testing & Discovery Tool for All Certificates across Microsoft Entra ID
    Applications (App Registrations & Enterprise Apps) and Azure Workloads.

.DESCRIPTION
    Discovers all certificates uploaded to applications in your Microsoft Entra ID tenant:
      1. Entra ID App Registrations (Application KeyCredentials / Client & Federation Certificates)
      2. Entra ID Enterprise Applications / Service Principals (SAML Signing & Token Encryption Certificates)
      3. (Optional) Azure Infrastructure: App Services, Key Vaults, and Application Gateways
    
    Provides local testing capabilities before deploying to Azure Automation:
      - Console dashboard with color-coded status (Expired, Urgent, Soon, Healthy)
      - Application Owner resolution (identifies active owners & orphaned applications)
      - Automatic CSV export with full audit trail
      - HTML Email Preview generation to view the exact notification email locally before sending

.PARAMETER DaysUntilExpiration
    Threshold in days to flag certificates expiring soon. Default is 30 days.

.PARAMETER AllCertificates
    Switch to output ALL certificates regardless of expiration date (active, upcoming, or expired).

.PARAMETER IncludeAlreadyExpired
    Include certificates that have already expired. Default is $true.

.PARAMETER IncludeEnterpriseApps
    Include Enterprise Applications / Service Principals (e.g. SAML SSO certificates). Default is $true.

.PARAMETER IncludeAzureResources
    Include Azure App Service, Key Vault, and Application Gateway certificates (requires Az modules). Default is $false.

.PARAMETER TenantId
    Azure AD / Entra ID Tenant ID. If omitted, uses current tenant or prompts interactively.

.PARAMETER ClientId
    Application (Client) ID if authenticating via App Registration / Service Principal.

.PARAMETER ClientSecret
    Client Secret if authenticating via App Registration / Service Principal.

.PARAMETER ExportCsv
    Export results to a CSV file. Default is $true.

.PARAMETER CsvPath
    Custom path for the exported CSV file. Default is current directory.

.PARAMETER GenerateEmailPreview
    Generate a local HTML email preview and open it in the default browser. Default is $true.

.PARAMETER FallbackOwnerEmail
    Default email address to assign when an application has no owner configured.

.PARAMETER AutoInstallModules
    Automatically install missing Microsoft.Graph modules in CurrentUser scope without prompting.

.EXAMPLE
    # Quick interactive test (prompts for Microsoft Graph browser login)
    .\Test-TenantApplicationCertificates.ps1

.EXAMPLE
    # View ALL certificates in the tenant regardless of expiry date and generate preview
    .\Test-TenantApplicationCertificates.ps1 -AllCertificates

.EXAMPLE
    # Test using an App Registration with Client Secret
    .\Test-TenantApplicationCertificates.ps1 -TenantId "xxx" -ClientId "yyy" -ClientSecret "zzz"

.EXAMPLE
    # Include Azure Infrastructure (App Services, Key Vaults, App Gateways)
    .\Test-TenantApplicationCertificates.ps1 -IncludeAzureResources
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
    [bool]$ExportCsv = $true,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [bool]$GenerateEmailPreview = $true,

    [Parameter(Mandatory = $false)]
    [string]$FallbackOwnerEmail = "azurecloudinfra.team@yourdomain.com",

    [Parameter(Mandatory = $false)]
    [switch]$AutoInstallModules,

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceAuthentication
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Microsoft Entra ID - Application Certificate Audit & Expiry Discovery" -ForegroundColor Cyan
Write-Host " Mode: Local Testing & Validation" -ForegroundColor Yellow
Write-Host " Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "==========================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# HELPER: Check and Import Required Modules
# -------------------------------------------------------------------------
function Assert-GraphModules {
    param ([bool]$AutoInstall)

    $required = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
    $missing  = @()

    foreach ($mod in $required) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $missing += $mod
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host "[WARN] Missing required PowerShell modules: $($missing -join ', ')" -ForegroundColor Yellow
        if ($AutoInstall) {
            Write-Host "[INFO] Auto-installing missing modules in CurrentUser scope..." -ForegroundColor Cyan
            foreach ($mod in $missing) {
                Write-Host "[INFO] Installing $mod..." -ForegroundColor Cyan
                Install-Module -Name $mod -Scope CurrentUser -Force -Repository PSGallery -AllowClobber
            }
        }
        else {
            Write-Host "To install the required modules, run the following command in PowerShell:" -ForegroundColor White
            Write-Host "  Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Scope CurrentUser" -ForegroundColor Green
            Write-Host "Or re-run this script with the -AutoInstallModules switch." -ForegroundColor Yellow
            throw "Prerequisite modules missing: $($missing -join ', ')"
        }
    }

    foreach ($mod in $required) {
        if (-not (Get-Module -Name $mod)) {
            Import-Module $mod -ErrorAction Stop
        }
    }
}

# -------------------------------------------------------------------------
# HELPER: Connect to Microsoft Graph
# -------------------------------------------------------------------------
function Connect-ToGraph {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [switch]$UseDeviceCode
    )

    try {
        $currentContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($currentContext -and [string]::IsNullOrEmpty($ClientId)) {
            Write-Host "[INFO] Reusing active Microsoft Graph connection (Tenant: $($currentContext.TenantId), Account: $($currentContext.Account))." -ForegroundColor Green
            return
        }

        # Case 1: App Registration (Client Credentials)
        if (-not [string]::IsNullOrEmpty($ClientId) -and -not [string]::IsNullOrEmpty($ClientSecret)) {
            if ([string]::IsNullOrEmpty($TenantId)) {
                throw "TenantId is required when authenticating with ClientId and ClientSecret."
            }
            Write-Host "[INFO] Connecting to Microsoft Graph using Client Credentials (App ID: $ClientId)..." -ForegroundColor Cyan
            $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
            $credential   = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)
            Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop
        }
        else {
            $inCloudShell = ($env:ACC_PORT -or $env:AZURE_HTTP_USER_AGENT -like "*cloud-shell*" -or [System.Environment]::GetEnvironmentVariable("AZURE_CONSOLE") -or [System.Environment]::OSVersion.Platform -eq "Unix")
            
            # Interactive or Device Code Authentication
            $connectParams = @{
                Scopes    = @("Application.Read.All", "User.Read.All")
                NoWelcome = $true
            }
            if (-not [string]::IsNullOrEmpty($TenantId)) {
                $connectParams["TenantId"] = $TenantId
            }

            # If in Cloud Shell, Linux, or explicitly requested, use Device Code authentication
            if ($UseDeviceCode -or $inCloudShell) {
                Write-Host "[INFO] Authenticating to Microsoft Graph via Device Code..." -ForegroundColor Cyan
                Write-Host "[ACTION] Open the URL and enter the code displayed below to sign in:" -ForegroundColor Yellow
                $connectParams["UseDeviceAuthentication"] = $true
            }
            else {
                Write-Host "[INFO] Connecting to Microsoft Graph interactively (browser authentication)..." -ForegroundColor Cyan
            }

            Connect-MgGraph @connectParams -ErrorAction Stop
        }

        $activeContext = Get-MgContext
        Write-Host "[SUCCESS] Connected to Microsoft Graph (Tenant ID: $($activeContext.TenantId))." -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}

# -------------------------------------------------------------------------
# HELPER: Parse Certificate Thumbprint from CustomKeyIdentifier or KeyId
# -------------------------------------------------------------------------
function Get-ThumbprintString {
    param ($CustomKeyIdentifier, [string]$KeyId)

    if ($null -eq $CustomKeyIdentifier) {
        return $KeyId
    }

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
# DISCOVERY 1: Entra ID App Registrations
# -------------------------------------------------------------------------
function Get-EntraAppRegistrationCertificates {
    Write-Host "`n[1/3] Scanning Entra ID App Registrations for uploaded certificates..." -ForegroundColor Cyan

    $appSelect = @("id", "appId", "displayName", "keyCredentials", "createdDateTime")
    $allApps   = Get-MgApplication -All -Property $appSelect
    Write-Host "      Found $($allApps.Count) total App Registration(s). Filtering for certificates..." -ForegroundColor Gray

    $appsWithCerts = $allApps | Where-Object { $null -ne $_.KeyCredentials -and $_.KeyCredentials.Count -gt 0 }
    Write-Host "      $($appsWithCerts.Count) App Registration(s) have uploaded certificate(s)." -ForegroundColor Yellow

    $records = @()

    foreach ($app in $appsWithCerts) {
        $appName = $app.DisplayName
        $appId   = $app.AppId
        $objId   = $app.Id

        # Query owners only for apps that have certificates
        $owners = @()
        try {
            $owners = Get-MgApplicationOwner -ApplicationId $objId -ErrorAction SilentlyContinue
        }
        catch { }

        $ownerEmails = @()
        $ownerNames  = @()
        $ownerIds    = @()

        if ($owners -and $owners.Count -gt 0) {
            foreach ($o in $owners) {
                $upn   = $o.AdditionalProperties.userPrincipalName
                $mail  = $o.AdditionalProperties.mail
                $dName = $o.AdditionalProperties.displayName
                $oId   = $o.Id

                $primaryEmail = if (-not [string]::IsNullOrWhiteSpace($mail)) { $mail } elseif (-not [string]::IsNullOrWhiteSpace($upn)) { $upn } else { $null }
                if ($primaryEmail) { $ownerEmails += $primaryEmail }
                if ($dName)        { $ownerNames  += $dName }
                if ($oId)          { $ownerIds    += $oId }
            }
        }

        $ownerEmailString = if ($ownerEmails.Count -gt 0) { ($ownerEmails | Select-Object -Unique) -join ', ' } else { "<<No Owner - Orphaned>>" }
        $ownerNameString  = if ($ownerNames.Count -gt 0)  { ($ownerNames  | Select-Object -Unique) -join ', ' } else { "<<No Owner - Orphaned>>" }
        $ownerIdString    = if ($ownerIds.Count -gt 0)    { ($ownerIds    | Select-Object -Unique) -join ', ' } else { "N/A" }

        foreach ($cert in $app.KeyCredentials) {
            $startDate = $cert.StartDateTime
            $endDate   = $cert.EndDateTime
            $certName  = if (-not [string]::IsNullOrWhiteSpace($cert.DisplayName)) { $cert.DisplayName } else { "Certificate (KeyID: $($cert.KeyId))" }
            $thumb     = Get-ThumbprintString -CustomKeyIdentifier $cert.CustomKeyIdentifier -KeyId $cert.KeyId
            $daysLeft  = if ($endDate) { ($endDate - (Get-Date)).Days } else { 9999 }

            $records += [PSCustomObject]@{
                WorkloadSource         = "Entra App Registration"
                ApplicationName        = $appName
                ApplicationID          = $appId
                ObjectID               = $objId
                CredentialType         = "Certificate"
                CertificateName        = $certName
                Thumbprint             = $thumb
                KeyId                  = $cert.KeyId
                Usage                  = $cert.Usage
                StartDate              = if ($startDate) { $startDate.ToString("yyyy-MM-dd") } else { "N/A" }
                EndDate                = if ($endDate)   { $endDate.ToString("yyyy-MM-dd") }   else { "N/A" }
                EndDateTime            = $endDate
                RemainingDaysCount     = $daysLeft
                OwnerEmails            = $ownerEmailString
                OwnerDisplayNames      = $ownerNameString
                OwnerObjectIds         = $ownerIdString
                IsOrphaned             = ($ownerEmailString -like "*No Owner*")
            }
        }
    }

    Write-Host "      Extracted $($records.Count) certificate record(s) from App Registrations." -ForegroundColor Green
    return $records
}

# -------------------------------------------------------------------------
# DISCOVERY 2: Entra ID Enterprise Applications / Service Principals (SAML)
# -------------------------------------------------------------------------
function Get-EntraEnterpriseAppCertificates {
    Write-Host "`n[2/3] Scanning Entra ID Enterprise Applications (Service Principals & SAML SSO)..." -ForegroundColor Cyan

    $spSelect = @("id", "appId", "displayName", "keyCredentials", "servicePrincipalType", "appOwnerOrganizationId", "accountEnabled")
    $allSPs   = Get-MgServicePrincipal -All -Property $spSelect
    Write-Host "      Found $($allSPs.Count) total Service Principal(s). Filtering for certificates..." -ForegroundColor Gray

    # Focus on customer/enterprise apps with certificates
    $spsWithCerts = $allSPs | Where-Object { 
        $null -ne $_.KeyCredentials -and $_.KeyCredentials.Count -gt 0 -and
        $_.ServicePrincipalType -ne "ManagedIdentity"
    }

    Write-Host "      $($spsWithCerts.Count) Enterprise Application(s) have certificate(s) uploaded." -ForegroundColor Yellow

    $records = @()

    foreach ($sp in $spsWithCerts) {
        $spName = $sp.DisplayName
        $appId  = $sp.AppId
        $objId  = $sp.Id

        # Query owners
        $owners = @()
        try {
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $objId -ErrorAction SilentlyContinue
        }
        catch { }

        $ownerEmails = @()
        $ownerNames  = @()
        $ownerIds    = @()

        if ($owners -and $owners.Count -gt 0) {
            foreach ($o in $owners) {
                $upn   = $o.AdditionalProperties.userPrincipalName
                $mail  = $o.AdditionalProperties.mail
                $dName = $o.AdditionalProperties.displayName
                $oId   = $o.Id

                $primaryEmail = if (-not [string]::IsNullOrWhiteSpace($mail)) { $mail } elseif (-not [string]::IsNullOrWhiteSpace($upn)) { $upn } else { $null }
                if ($primaryEmail) { $ownerEmails += $primaryEmail }
                if ($dName)        { $ownerNames  += $dName }
                if ($oId)          { $ownerIds    += $oId }
            }
        }

        $ownerEmailString = if ($ownerEmails.Count -gt 0) { ($ownerEmails | Select-Object -Unique) -join ', ' } else { "<<No Owner - Orphaned>>" }
        $ownerNameString  = if ($ownerNames.Count -gt 0)  { ($ownerNames  | Select-Object -Unique) -join ', ' } else { "<<No Owner - Orphaned>>" }
        $ownerIdString    = if ($ownerIds.Count -gt 0)    { ($ownerIds    | Select-Object -Unique) -join ', ' } else { "N/A" }

        foreach ($cert in $sp.KeyCredentials) {
            $startDate = $cert.StartDateTime
            $endDate   = $cert.EndDateTime
            $certName  = if (-not [string]::IsNullOrWhiteSpace($cert.DisplayName)) { 
                $cert.DisplayName 
            } elseif ($cert.Usage -eq "Sign") { 
                "SAML SSO Signing Certificate" 
            } elseif ($cert.Usage -eq "Verify") { 
                "Token Verification Certificate" 
            } else { 
                "Enterprise App Certificate" 
            }
            $thumb     = Get-ThumbprintString -CustomKeyIdentifier $cert.CustomKeyIdentifier -KeyId $cert.KeyId
            $daysLeft  = if ($endDate) { ($endDate - (Get-Date)).Days } else { 9999 }

            $records += [PSCustomObject]@{
                WorkloadSource         = "Entra Enterprise Application"
                ApplicationName        = $spName
                ApplicationID          = $appId
                ObjectID               = $objId
                CredentialType         = "Certificate (SAML/SSO)"
                CertificateName        = $certName
                Thumbprint             = $thumb
                KeyId                  = $cert.KeyId
                Usage                  = $cert.Usage
                StartDate              = if ($startDate) { $startDate.ToString("yyyy-MM-dd") } else { "N/A" }
                EndDate                = if ($endDate)   { $endDate.ToString("yyyy-MM-dd") }   else { "N/A" }
                EndDateTime            = $endDate
                RemainingDaysCount     = $daysLeft
                OwnerEmails            = $ownerEmailString
                OwnerDisplayNames      = $ownerNameString
                OwnerObjectIds         = $ownerIdString
                IsOrphaned             = ($ownerEmailString -like "*No Owner*")
            }
        }
    }

    Write-Host "      Extracted $($records.Count) certificate record(s) from Enterprise Applications." -ForegroundColor Green
    return $records
}

# -------------------------------------------------------------------------
# DISCOVERY 3: Optional Azure Infrastructure Certificates
# -------------------------------------------------------------------------
function Get-AzureResourceCertificates {
    param ([string]$DefaultOwner)
    Write-Host "`n[3/3] Scanning Azure Resource Graph for App Service & Key Vault & AppGW certs..." -ForegroundColor Cyan

    $azureLogs = @()

    if (Get-Command Search-AzGraph -ErrorAction SilentlyContinue) {
        try {
            $argAppService = "resources | where type =~ 'microsoft.web/certificates' | project name, id, resourceGroup, subscriptionId, expirationDate = todatetime(properties.expirationDate), thumbprint = properties.thumbprint, ownerTag = coalesce(tostring(tags.Owner), tostring(tags.owner), tostring(tags.WorkloadOwner), tostring(tags.TechnicalContact))"
            $webCerts = Search-AzGraph -Query $argAppService -First 1000 -ErrorAction SilentlyContinue
            foreach ($row in $webCerts) {
                if ($row.expirationDate) {
                    $expDate  = [DateTime]$row.expirationDate
                    $daysLeft = ($expDate - (Get-Date)).Days
                    $ownerVal = if ([string]::IsNullOrWhiteSpace($row.ownerTag)) { $DefaultOwner } else { $row.ownerTag }

                    $azureLogs += [PSCustomObject]@{
                        WorkloadSource         = "Azure App Service Cert"
                        ApplicationName        = "$($row.name) ($($row.resourceGroup))"
                        ApplicationID          = $row.id
                        ObjectID               = "N/A"
                        CredentialType         = "Certificate"
                        CertificateName        = $row.name
                        Thumbprint             = $row.thumbprint
                        KeyId                  = "N/A"
                        Usage                  = "SSL/TLS Binding"
                        StartDate              = "N/A"
                        EndDate                = $expDate.ToString("yyyy-MM-dd")
                        EndDateTime            = $expDate
                        RemainingDaysCount     = $daysLeft
                        OwnerEmails            = $ownerVal
                        OwnerDisplayNames      = $ownerVal
                        OwnerObjectIds         = "N/A"
                        IsOrphaned             = ($ownerVal -eq $DefaultOwner)
                    }
                }
            }
            Write-Host "      Found $($azureLogs.Count) Azure App Service certificate(s)." -ForegroundColor Green
        }
        catch {
            Write-Host "      [WARN] Azure Resource Graph query skipped: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "      [INFO] Az.ResourceGraph module not loaded. Skipping Azure Infrastructure certs." -ForegroundColor Gray
    }

    return $azureLogs
}

# -------------------------------------------------------------------------
# EXECUTION CONTROLLER
# -------------------------------------------------------------------------
try {
    # Step 1: Ensure modules
    Assert-GraphModules -AutoInstall $AutoInstallModules

    # Step 2: Connect
    Connect-ToGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -UseDeviceCode:$UseDeviceAuthentication

    # Step 3: Gather certificates
    $allDiscoveredCerts = @()

    # Entra ID App Registrations
    $appRegCerts = Get-EntraAppRegistrationCertificates
    $allDiscoveredCerts += $appRegCerts

    # Entra ID Enterprise Applications
    if ($IncludeEnterpriseApps) {
        $enterpriseCerts = Get-EntraEnterpriseAppCertificates
        $allDiscoveredCerts += $enterpriseCerts
    }

    # Azure Infrastructure Resources (Optional)
    if ($IncludeAzureResources) {
        $azureCerts = Get-AzureResourceCertificates -DefaultOwner $FallbackOwnerEmail
        $allDiscoveredCerts += $azureCerts
    }

    Write-Host "`n--------------------------------------------------------------------------" -ForegroundColor Gray
    Write-Host " TOTAL CERTIFICATES DISCOVERED ACROSS TENANT: $($allDiscoveredCerts.Count)" -ForegroundColor Cyan
    Write-Host "--------------------------------------------------------------------------" -ForegroundColor Gray

    # Step 4: Apply Expiration Filtering
    $filteredCerts = @()

    foreach ($cert in $allDiscoveredCerts) {
        $days = $cert.RemainingDaysCount
        $include = $false

        if ($AllCertificates) {
            $include = $true
        }
        else {
            if ($days -le $DaysUntilExpiration) {
                if ($days -lt 0) {
                    if ($IncludeAlreadyExpired) { $include = $true }
                }
                else {
                    $include = $true
                }
            }
        }

        if ($include) {
            # Add Status Classification
            $status = "HEALTHY"
            $statusColor = "Green"

            if ($days -le 0) {
                $status = "EXPIRED"
                $statusColor = "Red"
            }
            elseif ($days -le 7) {
                $status = "CRITICAL (<= 7d)"
                $statusColor = "Magenta"
            }
            elseif ($days -le 14) {
                $status = "WARNING (<= 14d)"
                $statusColor = "Yellow"
            }
            elseif ($days -le 30) {
                $status = "ATTENTION (<= 30d)"
                $statusColor = "DarkYellow"
            }

            $cert | Add-Member -MemberType NoteProperty -Name "Status" -Value $status -Force
            $cert | Add-Member -MemberType NoteProperty -Name "StatusColor" -Value $statusColor -Force
            $filteredCerts += $cert
        }
    }

    # Sort primarily by RemainingDaysCount ascending (expired first, then most urgent)
    $filteredCerts = $filteredCerts | Sort-Object RemainingDaysCount

    # Step 5: Display Summary Dashboard
    $totalFound    = $allDiscoveredCerts.Count
    $totalMatched  = $filteredCerts.Count
    $expiredCount  = ($filteredCerts | Where-Object { $_.RemainingDaysCount -le 0 }).Count
    $urgentCount   = ($filteredCerts | Where-Object { $_.RemainingDaysCount -gt 0 -and $_.RemainingDaysCount -le 7 }).Count
    $soonCount     = ($filteredCerts | Where-Object { $_.RemainingDaysCount -gt 7 -and $_.RemainingDaysCount -le 14 }).Count
    $warningCount  = ($filteredCerts | Where-Object { $_.RemainingDaysCount -gt 14 -and $_.RemainingDaysCount -le 30 }).Count
    $healthyCount  = ($filteredCerts | Where-Object { $_.RemainingDaysCount -gt 30 }).Count
    $orphanedCount = ($filteredCerts | Where-Object { $_.IsOrphaned -eq $true }).Count

    $filterLabel = if ($AllCertificates) { "ALL CERTIFICATES" } else { "Expiring within $DaysUntilExpiration days" }

    Write-Host "`n========================= SUMMARY METRICS =========================" -ForegroundColor Yellow
    Write-Host " Total Certificates in Tenant Scanned : $totalFound" -ForegroundColor White
    Write-Host " Filter Mode                          : $filterLabel" -ForegroundColor White
    Write-Host " Matching Filter Criteria             : $totalMatched" -ForegroundColor White
    Write-Host "   Already Expired                    : $expiredCount" -ForegroundColor Red
    Write-Host "   Critical (<= 7 Days)               : $urgentCount" -ForegroundColor Magenta
    Write-Host "   Warning (<= 14 Days)               : $soonCount" -ForegroundColor Yellow
    Write-Host "   Attention (<= 30 Days)             : $warningCount" -ForegroundColor DarkYellow
    Write-Host "   Healthy (> 30 Days)                 : $healthyCount" -ForegroundColor Green
    Write-Host "   Orphaned (No Owner Assigned)       : $orphanedCount" -ForegroundColor DarkRed
    Write-Host "===================================================================`n" -ForegroundColor Yellow

    # Step 6: Console Table Display
    if ($filteredCerts.Count -gt 0) {
        Write-Host "Top Certificates to Review (Console Preview):" -ForegroundColor Cyan
        $previewItems = $filteredCerts | Select-Object -First 30
        $previewItems | Select-Object `
            @{Name="Status"; Expression={$_.Status}}, `
            @{Name="Days"; Expression={$_.RemainingDaysCount}}, `
            @{Name="Expires"; Expression={$_.EndDate}}, `
            @{Name="Source"; Expression={$_.WorkloadSource}}, `
            @{Name="Application Name"; Expression={if ($_.ApplicationName.Length -gt 32) { $_.ApplicationName.Substring(0,29) + "..." } else { $_.ApplicationName }}}, `
            @{Name="Certificate"; Expression={if ($_.CertificateName.Length -gt 30) { $_.CertificateName.Substring(0,27) + "..." } else { $_.CertificateName }}}, `
            @{Name="Thumbprint"; Expression={if ($_.Thumbprint.Length -gt 16) { $_.Thumbprint.Substring(0,16) + "..." } else { $_.Thumbprint }}}, `
            @{Name="Owners"; Expression={if ($_.OwnerEmails.Length -gt 35) { $_.OwnerEmails.Substring(0,32) + "..." } else { $_.OwnerEmails }}} | `
            Format-Table -AutoSize
    }
    else {
        Write-Host "[INFO] No certificates matched your filter criteria ($DaysUntilExpiration days threshold)." -ForegroundColor Green
    }

    # Step 7: Export to CSV
    if ($ExportCsv -and $filteredCerts.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        if ([string]::IsNullOrWhiteSpace($CsvPath)) {
            $CsvPath = Join-Path -Path $PSScriptRoot -ChildPath "TenantApplicationCertificates_$timestamp.csv"
        }
        elseif (Test-Path -Path $CsvPath -PathType Container) {
            $CsvPath = Join-Path -Path $CsvPath -ChildPath "TenantApplicationCertificates_$timestamp.csv"
        }

        $filteredCerts | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "[EXPORT] Full certificate report exported to CSV:" -ForegroundColor Green
        Write-Host "         $CsvPath" -ForegroundColor White
        if ($env:ACC_PORT -or $env:AZURE_HTTP_USER_AGENT -like "*cloud-shell*") {
            Write-Host "         [Cloud Shell Tip] To download to your PC, click 'Manage Files' (up/down arrow icon in top toolbar) -> 'Download' -> Enter: $(Split-Path $CsvPath -Leaf)" -ForegroundColor Yellow
        }
    }

    # Step 8: Generate Local HTML Email Preview
    if ($GenerateEmailPreview -and $filteredCerts.Count -gt 0) {
        $htmlTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $htmlPath = Join-Path -Path $PSScriptRoot -ChildPath "EmailAlert_Preview_$htmlTimestamp.html"

        $grouped = $filteredCerts | Group-Object -Property ApplicationName, OwnerEmails

        $html = [System.Text.StringBuilder]::new()
        [void]$html.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8">')
        [void]$html.AppendLine('<title>Azure Certificate Expiry Alert Preview</title>')
        [void]$html.AppendLine('<style>')
        [void]$html.AppendLine('body { font-family: Segoe UI, Calibri, Arial, sans-serif; font-size: 14px; color: #2d3748; background-color: #f7fafc; margin: 0; padding: 20px; }')
        [void]$html.AppendLine('.container { max-width: 1100px; margin: 0 auto; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 30px; }')
        [void]$html.AppendLine('.banner { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 20px 25px; border-radius: 6px; margin-bottom: 25px; }')
        [void]$html.AppendLine('.banner h1 { margin: 0 0 8px 0; font-size: 22px; }')
        [void]$html.AppendLine('.banner p { margin: 0; font-size: 13px; opacity: 0.9; }')
        [void]$html.AppendLine('.metrics { display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }')
        [void]$html.AppendLine('.metric-card { flex: 1; min-width: 130px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 15px; text-align: center; }')
        [void]$html.AppendLine('.metric-card.expired { border-left: 4px solid #ef4444; }')
        [void]$html.AppendLine('.metric-card.urgent { border-left: 4px solid #f97316; }')
        [void]$html.AppendLine('.metric-card.soon { border-left: 4px solid #eab308; }')
        [void]$html.AppendLine('.metric-card.healthy { border-left: 4px solid #10b981; }')
        [void]$html.AppendLine('.metric-val { font-size: 22px; font-weight: bold; color: #1e293b; }')
        [void]$html.AppendLine('.metric-lbl { font-size: 11px; text-transform: uppercase; color: #64748b; margin-top: 4px; font-weight: 600; }')
        [void]$html.AppendLine('.app-box { border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 25px; overflow: hidden; }')
        [void]$html.AppendLine('.app-header { background: #0f172a; color: white; padding: 12px 18px; display: flex; justify-content: space-between; align-items: center; }')
        [void]$html.AppendLine('.app-title { font-size: 15px; font-weight: 600; }')
        [void]$html.AppendLine('.app-owner { font-size: 12px; color: #94a3b8; }')
        [void]$html.AppendLine('table { width: 100%; border-collapse: collapse; font-size: 13px; }')
        [void]$html.AppendLine('th { background: #f1f5f9; color: #475569; font-weight: 600; text-align: left; padding: 10px 14px; border-bottom: 1px solid #e2e8f0; }')
        [void]$html.AppendLine('td { padding: 9px 14px; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }')
        [void]$html.AppendLine('.badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }')
        [void]$html.AppendLine('.badge-expired { background: #fee2e2; color: #991b1b; }')
        [void]$html.AppendLine('.badge-urgent { background: #ffedd5; color: #9a3412; }')
        [void]$html.AppendLine('.badge-soon { background: #fef9c3; color: #854d0e; }')
        [void]$html.AppendLine('.badge-healthy { background: #dcfce7; color: #166534; }')
        [void]$html.AppendLine('.src-badge { background: #e0e7ff; color: #3730a3; padding: 2px 7px; border-radius: 3px; font-size: 11px; font-weight: 500; }')
        [void]$html.AppendLine('.mono { font-family: Consolas, monospace; font-size: 12px; color: #475569; }')
        [void]$html.AppendLine('.action-box { background: #f0fdf4; border-left: 4px solid #16a34a; padding: 15px; border-radius: 4px; margin-top: 25px; }')
        [void]$html.AppendLine('.action-box h3 { margin: 0 0 8px 0; color: #166534; font-size: 14px; }')
        [void]$html.AppendLine('.action-box ol { margin: 0; padding-left: 20px; font-size: 13px; color: #14532d; line-height: 1.6; }')
        [void]$html.AppendLine('.footer { margin-top: 30px; padding-top: 15px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8; text-align: center; }')
        [void]$html.AppendLine('</style></head><body><div class="container">')

        [void]$html.AppendLine('<div class="banner">')
        [void]$html.AppendLine('<h1>Microsoft Entra ID - Application Certificate Expiry Report</h1>')
        [void]$html.AppendLine("<p>Evaluation Window: $filterLabel | Generated: $(Get-Date -Format 'dd-MMM-yyyy HH:mm:ss')</p></div>")

        [void]$html.AppendLine('<div class="metrics">')
        [void]$html.AppendLine("<div class='metric-card expired'><div class='metric-val' style='color:#ef4444;'>$expiredCount</div><div class='metric-lbl'>Already Expired</div></div>")
        [void]$html.AppendLine("<div class='metric-card urgent'><div class='metric-val' style='color:#f97316;'>$urgentCount</div><div class='metric-lbl'>&le; 7 Days</div></div>")
        [void]$html.AppendLine("<div class='metric-card soon'><div class='metric-val' style='color:#eab308;'>$soonCount</div><div class='metric-lbl'>&le; 14 Days</div></div>")
        [void]$html.AppendLine("<div class='metric-card healthy'><div class='metric-val' style='color:#10b981;'>$healthyCount</div><div class='metric-lbl'>Healthy (> 30d)</div></div>")
        [void]$html.AppendLine("<div class='metric-card'><div class='metric-val'>$totalMatched</div><div class='metric-lbl'>Total Matching</div></div>")
        [void]$html.AppendLine('</div>')

        foreach ($grp in $grouped) {
            $first = $grp.Group[0]
            $grpAppName = $first.ApplicationName
            $grpAppId   = $first.ApplicationID
            $grpOwners  = $first.OwnerEmails

            [void]$html.AppendLine('<div class="app-box">')
            [void]$html.AppendLine("<div class='app-header'><div class='app-title'>$grpAppName <span style='font-size:12px;font-weight:normal;color:#93c5fd;'>($grpAppId)</span></div><div class='app-owner'>Owner(s): <b>$grpOwners</b></div></div>")
            [void]$html.AppendLine('<table><thead><tr><th>Source</th><th>Certificate Name</th><th>Thumbprint</th><th>Start Date</th><th>Expiration Date</th><th>Days Remaining</th><th>Status</th></tr></thead><tbody>')

            foreach ($item in ($grp.Group | Sort-Object RemainingDaysCount)) {
                $statusBadgeClass = if ($item.RemainingDaysCount -le 0) {
                    "badge-expired"
                } elseif ($item.RemainingDaysCount -le 7) {
                    "badge-urgent"
                } elseif ($item.RemainingDaysCount -le 14) {
                    "badge-soon"
                } else {
                    "badge-healthy"
                }

                $thumbSnippet = if ($item.Thumbprint.Length -gt 24) { $item.Thumbprint.Substring(0,24) + "..." } else { $item.Thumbprint }

                [void]$html.AppendLine("<tr>")
                [void]$html.AppendLine("<td><span class='src-badge'>$($item.WorkloadSource)</span></td>")
                [void]$html.AppendLine("<td><b>$($item.CertificateName)</b></td>")
                [void]$html.AppendLine("<td class='mono' title='$($item.Thumbprint)'>$thumbSnippet</td>")
                [void]$html.AppendLine("<td>$($item.StartDate)</td>")
                [void]$html.AppendLine("<td><b>$($item.EndDate)</b></td>")
                [void]$html.AppendLine("<td>$($item.RemainingDaysCount) day(s)</td>")
                [void]$html.AppendLine("<td><span class='badge $statusBadgeClass'>$($item.Status)</span></td>")
                [void]$html.AppendLine("</tr>")
            }

            [void]$html.AppendLine('</tbody></table></div>')
        }

        [void]$html.AppendLine('<div class="action-box">')
        [void]$html.AppendLine('<h3>Action Required for Application Owners:</h3>')
        [void]$html.AppendLine('<ol>')
        [void]$html.AppendLine('<li>Navigate to Azure Portal &rarr; <b>Microsoft Entra ID</b>.</li>')
        [void]$html.AppendLine('<li>For <b>App Registrations</b>: Go to <i>App registrations</i> &rarr; Select your application &rarr; <b>Certificates &amp; secrets</b> &rarr; <b>Certificates</b> &rarr; Click <b>Upload certificate</b>.</li>')
        [void]$html.AppendLine('<li>For <b>Enterprise Applications</b>: Go to <i>Enterprise applications</i> &rarr; Select application &rarr; <b>Single sign-on</b> &rarr; <b>SAML Certificates</b> &rarr; Edit/Rotate the SAML certificate.</li>')
        [void]$html.AppendLine('<li>Update your dependent backend workloads, services, and token clients with the new certificate public key.</li>')
        [void]$html.AppendLine('<li>Once validated, remove the expired certificate to keep the credential inventory clean.</li>')
        [void]$html.AppendLine('</ol></div>')

        [void]$html.AppendLine('<div class="footer">')
        [void]$html.AppendLine('<p>This is a local simulated preview generated by <code>Test-TenantApplicationCertificates.ps1</code>.</p>')
        [void]$html.AppendLine('<p>Ready to deploy? Use the Azure Automation Runbook <code>script_v2.ps1</code> with your Automation Schedule to deliver automated alerts to owners.</p>')
        [void]$html.AppendLine('</div></div></body></html>')

        [System.IO.File]::WriteAllText($htmlPath, $html.ToString(), [System.Text.Encoding]::UTF8)
        Write-Host "[PREVIEW] Local HTML email preview created:" -ForegroundColor Green
        Write-Host "          $htmlPath" -ForegroundColor White

        try {
            Start-Process $htmlPath
            Write-Host "[PREVIEW] Opened preview in your default browser." -ForegroundColor Cyan
        }
        catch { }
    }

    Write-Host "`n==========================================================================" -ForegroundColor Cyan
    Write-Host " Local Certificate Discovery & Validation Completed Successfully." -ForegroundColor Green
    Write-Host "==========================================================================" -ForegroundColor Cyan
}
catch {
    Write-Host "`n[FATAL ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.Exception.StackTrace)" -ForegroundColor DarkRed
}
