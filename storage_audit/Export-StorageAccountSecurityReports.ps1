<#
.SYNOPSIS
    Exports Azure Storage Account security configurations replicating AWS S3 audit reports.
    Produces two exact Excel/CSV reports:
      1. StorageAccount-consolidated.csv (.xlsx)
         Headers: storageaccountname | encryptionkeysource | infrastructureencryptionenabled | networkacldefaultaction | subscriptionname | subscriptionid
      2. StorageAccount-bpa.csv (.xlsx)
         Headers: subscriptionname | subscriptionid | allowblobpublicaccess
         (Also generates a detailed per-account version: StorageAccount-bpa-detailed.csv)

.DESCRIPTION
    Replicates AWS S3 security tracking for Microsoft Azure:
    - S3 bucketname                   -> storageaccountname
    - S3 ssealgorithm                 -> encryptionkeysource (Microsoft.Storage / Microsoft.Keyvault)
    - S3 bucketkeyenabled             -> infrastructureencryptionenabled (Double encryption status)
    - S3 bucket_policy_status         -> networkacldefaultaction (Allow / Deny)
    - S3 accountname / accountid      -> subscriptionname / subscriptionid
    - S3 publicaccessblockconfig(BPA) -> allowblobpublicaccess

    Query Strategy:
    - High-performance Azure Resource Graph (ARG) by default (queries all subscriptions in seconds).
    - Automatic fallback to Az cmdlets (Get-AzStorageAccount) if ARG is unavailable.
    - Exports directly to CSV (native) and XLSX (if ImportExcel module is present).

.PARAMETER OutputPath
    Directory where reports will be saved. Default is the current script directory.

.PARAMETER Format
    Export format: 'Csv' (default), 'Excel', or 'Both'.

.PARAMETER SubscriptionIds
    Optional list of specific subscription IDs to audit. If omitted, queries all accessible subscriptions.

.EXAMPLE
    .\Export-StorageAccountSecurityReports.ps1

.EXAMPLE
    .\Export-StorageAccountSecurityReports.ps1 -OutputPath "C:\Reports" -Format Both
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Csv', 'Excel', 'Both')]
    [string]$Format = 'Csv',

    [Parameter(Mandatory = $false)]
    [string]$ManagementGroupId,

    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Azure Storage Account Security Audit & Reporting Script" -ForegroundColor Cyan
Write-Host " Replicating AWS S3 Consolidated & Block Public Access (BPA) Reports" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# 1. PRE-FLIGHT CHECKS & AUTHENTICATION
# -------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Throw "The 'Az.Accounts' PowerShell module is required. Please install it using: Install-Module -Name Az.Accounts -Scope CurrentUser"
}

$currentContext = Get-AzContext -ErrorAction SilentlyContinue
if (-not $currentContext) {
    Write-Host "[INFO] No active Azure context detected. Initiating interactive login..." -ForegroundColor Yellow
    Connect-AzAccount | Out-Null
    $currentContext = Get-AzContext
}

Write-Host "[+] Connected as: $($currentContext.Account.Id)" -ForegroundColor Green
Write-Host "[+] Tenant ID   : $($currentContext.Tenant.Id)" -ForegroundColor Green

if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Check if ImportExcel module is available if Excel format requested
$hasImportExcel = [bool](Get-Module -ListAvailable -Name ImportExcel)
if (($Format -in @('Excel', 'Both')) -and -not $hasImportExcel) {
    Write-Host "[WARN] 'ImportExcel' module is not installed. Defaulting to standard CSV exports." -ForegroundColor Yellow
    Write-Host "       To enable native .xlsx exports without MS Excel, run: Install-Module -Name ImportExcel -Scope CurrentUser" -ForegroundColor DarkGray
    if ($Format -eq 'Excel') { $Format = 'Csv' }
}

# -------------------------------------------------------------------------
# 2. DATA EXTRACTION
# -------------------------------------------------------------------------
$consolidatedList = [System.Collections.Generic.List[PSCustomObject]]::new()
$bpaList          = [System.Collections.Generic.List[PSCustomObject]]::new()
$bpaDetailedList  = [System.Collections.Generic.List[PSCustomObject]]::new()

$hasArg = [bool](Get-Module -ListAvailable -Name Az.ResourceGraph)

if ($hasArg) {
    Write-Host "`n[STEP 1/3] Extracting Storage Account data via Azure Resource Graph (High-Speed)..." -ForegroundColor Cyan
    try {
        # KQL Query to retrieve all storage accounts across all tenant subscriptions
        $kqlQuery = @"
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
    allowblobpublicaccess           = tostring(coalesce(properties.allowBlobPublicAccess, false)),
    subscriptionname                = coalesce(subscriptionName, subscriptionId),
    subscriptionid                  = subscriptionId
| order by subscriptionname asc, storageaccountname asc
"@
        $queryArgs = @{
            Query = $kqlQuery
            First = 5000
        }
        if ($ManagementGroupId) {
            $queryArgs['ManagementGroup'] = $ManagementGroupId
            Write-Host "[INFO] Scoping query strictly to Management Group: '$ManagementGroupId'" -ForegroundColor Yellow
        }
        elseif ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
            $queryArgs['Subscription'] = $SubscriptionIds
        }

        $rawResults = Search-AzGraph @queryArgs
        Write-Host "[+] Retrieved $($rawResults.Count) Storage Account(s) across subscriptions." -ForegroundColor Green

        foreach ($row in $rawResults) {
            # Report 1: Consolidated Object
            $consolidatedList.Add([PSCustomObject]@{
                storageaccountname              = $row.storageaccountname
                encryptionkeysource             = $row.encryptionkeysource
                infrastructureencryptionenabled = $row.infrastructureencryptionenabled
                networkacldefaultaction         = $row.networkacldefaultaction
                subscriptionname                = $row.subscriptionname
                subscriptionid                  = $row.subscriptionid
            })

            # Report 2 Detailed: Per Storage Account BPA
            $bpaDetailedList.Add([PSCustomObject]@{
                storageaccountname              = $row.storageaccountname
                subscriptionname                = $row.subscriptionname
                subscriptionid                  = $row.subscriptionid
                allowblobpublicaccess           = $row.allowblobpublicaccess
            })
        }

        # Report 2 Summary: Aggregate by Subscription (Exact AWS BPA equivalent matching row 1)
        $subGroups = $rawResults | Group-Object -Property subscriptionid
        foreach ($grp in $subGroups) {
            $subName = ($grp.Group | Select-Object -ExpandProperty subscriptionname -First 1)
            $totalCount = $grp.Group.Count
            $publicAllowedCount = ($grp.Group | Where-Object { $_.allowblobpublicaccess -eq 'true' }).Count

            $bpaStatus = if ($publicAllowedCount -eq 0) {
                "false (Blocked on all $totalCount accounts)"
            } else {
                "true ($publicAllowedCount of $totalCount accounts allow public access)"
            }

            $bpaList.Add([PSCustomObject]@{
                subscriptionname      = $subName
                subscriptionid        = $grp.Name
                allowblobpublicaccess = $bpaStatus
            })
        }
    }
    catch {
        Write-Host "[WARN] Azure Resource Graph query encountered an error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "       Falling back to standard Az cmdlets (Get-AzStorageAccount)..." -ForegroundColor Yellow
        $hasArg = $false
    }
}

if (-not $hasArg) {
    Write-Host "`n[STEP 1/3] Extracting Storage Account data via Az Cmdlets..." -ForegroundColor Cyan
    $subs = if ($ManagementGroupId) {
        Write-Host "  -> Discovering subscriptions under Management Group '$ManagementGroupId'..." -ForegroundColor Gray
        $mgSubs = Get-AzManagementGroupSubscription -GroupName $ManagementGroupId -ErrorAction SilentlyContinue
        if ($mgSubs) {
            Get-AzSubscription | Where-Object { $mgSubs.Id -contains $_.Id -or $mgSubs.SubscriptionId -contains $_.Id -or $mgSubs.Name -contains $_.Id }
        } else {
            Write-Host "  [WARN] Could not retrieve subscriptions via Get-AzManagementGroupSubscription. Querying all." -ForegroundColor Yellow
            Get-AzSubscription
        }
    }
    elseif ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
        Get-AzSubscription | Where-Object { $SubscriptionIds -contains $_.Id }
    } else {
        Get-AzSubscription
    }

    foreach ($sub in $subs) {
        Write-Host "  -> Scanning Subscription: $($sub.Name) ($($sub.Id))..." -ForegroundColor Gray
        $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue

        $accounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
        if (-not $accounts) { continue }

        $subPublicAllowedCount = 0

        foreach ($sa in $accounts) {
            $keySource = if ($sa.Encryption.KeySource) { $sa.Encryption.KeySource } else { "Microsoft.Storage" }
            $infraEnc = if ($null -ne $sa.Encryption.RequireInfrastructureEncryption) { $sa.Encryption.RequireInfrastructureEncryption.ToString().ToLower() } else { "false" }
            $netAction = if ($sa.NetworkRuleSet.DefaultAction) { $sa.NetworkRuleSet.DefaultAction } else { "Allow" }
            $bpa = if ($null -ne $sa.AllowBlobPublicAccess) { $sa.AllowBlobPublicAccess.ToString().ToLower() } else { "false" }

            if ($bpa -eq "true") { $subPublicAllowedCount++ }

            # Consolidated Report Item
            $consolidatedList.Add([PSCustomObject]@{
                storageaccountname              = $sa.StorageAccountName
                encryptionkeysource             = $keySource
                infrastructureencryptionenabled = $infraEnc
                networkacldefaultaction         = $netAction
                subscriptionname                = $sub.Name
                subscriptionid                  = $sub.Id
            })

            # BPA Detailed Report Item
            $bpaDetailedList.Add([PSCustomObject]@{
                storageaccountname              = $sa.StorageAccountName
                subscriptionname                = $sub.Name
                subscriptionid                  = $sub.Id
                allowblobpublicaccess           = $bpa
            })
        }

        $bpaStatus = if ($subPublicAllowedCount -eq 0) {
            "false (Blocked on all $($accounts.Count) accounts)"
        } else {
            "true ($subPublicAllowedCount of $($accounts.Count) accounts allow public access)"
        }

        $bpaList.Add([PSCustomObject]@{
            subscriptionname      = $sub.Name
            subscriptionid        = $sub.Id
            allowblobpublicaccess = $bpaStatus
        })
    }
}

# -------------------------------------------------------------------------
# 3. EXPORT REPORTS
# -------------------------------------------------------------------------
Write-Host "`n[STEP 2/3] Exporting reports matching exact column specifications..." -ForegroundColor Cyan

$file1Base = Join-Path $OutputPath "StorageAccount-consolidated"
$file2Base = Join-Path $OutputPath "StorageAccount-bpa"
$file2DetailedBase = Join-Path $OutputPath "StorageAccount-bpa-detailed"

# Export to CSV
if ($Format -in @('Csv', 'Both')) {
    $file1Csv = "$file1Base.csv"
    $file2Csv = "$file2Base.csv"
    $file2DetailedCsv = "$file2DetailedBase.csv"

    # Report 1
    $consolidatedList | Export-Csv -Path $file1Csv -NoTypeInformation -Encoding utf8
    Write-Host "[+] Generated: $file1Csv" -ForegroundColor Green
    Write-Host "    Columns: storageaccountname | encryptionkeysource | infrastructureencryptionenabled | networkacldefaultaction | subscriptionname | subscriptionid" -ForegroundColor DarkGray

    # Report 2 (Subscription Summary matching AWS BPA)
    $bpaList | Export-Csv -Path $file2Csv -NoTypeInformation -Encoding utf8
    Write-Host "[+] Generated: $file2Csv" -ForegroundColor Green
    Write-Host "    Columns: subscriptionname | subscriptionid | allowblobpublicaccess" -ForegroundColor DarkGray

    # Report 2 Detailed (Per-account granular BPA)
    $bpaDetailedList | Export-Csv -Path $file2DetailedCsv -NoTypeInformation -Encoding utf8
    Write-Host "[+] Generated: $file2DetailedCsv" -ForegroundColor Green
    Write-Host "    Columns: storageaccountname | subscriptionname | subscriptionid | allowblobpublicaccess" -ForegroundColor DarkGray
}

# Export to Excel (if requested and ImportExcel is installed)
if ($Format -in @('Excel', 'Both') -and $hasImportExcel) {
    $file1Xlsx = "$file1Base.xlsx"
    $file2Xlsx = "$file2Base.xlsx"
    $file2DetailedXlsx = "$file2DetailedBase.xlsx"

    $excelParams = @{
        BoldTopRow   = $true
        AutoSize     = $true
        AutoFilter   = $true
        FreezeTopRow = $true
    }

    $consolidatedList | Export-Excel -Path $file1Xlsx -WorksheetName "Consolidated" @excelParams
    Write-Host "[+] Generated: $file1Xlsx" -ForegroundColor Green

    $bpaList | Export-Excel -Path $file2Xlsx -WorksheetName "BPA-Summary" @excelParams
    Write-Host "[+] Generated: $file2Xlsx" -ForegroundColor Green

    $bpaDetailedList | Export-Excel -Path $file2DetailedXlsx -WorksheetName "BPA-PerAccount" @excelParams
    Write-Host "[+] Generated: $file2DetailedXlsx" -ForegroundColor Green
}

# -------------------------------------------------------------------------
# 4. SUMMARY DISPLAY
# -------------------------------------------------------------------------
Write-Host "`n[STEP 3/3] Execution Summary:" -ForegroundColor Cyan
Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray
Write-Host "Total Storage Accounts Scanned : $($consolidatedList.Count)"
Write-Host "Total Subscriptions Scanned    : $($bpaList.Count)"
Write-Host "Reports Directory              : $OutputPath"
Write-Host "-----------------------------------------------------------------" -ForegroundColor Gray

if ($consolidatedList.Count -gt 0) {
    Write-Host "`nSample Consolidated Output (First 3 Accounts):" -ForegroundColor Yellow
    $consolidatedList | Select-Object -First 3 | Format-Table -AutoSize | Out-String | Write-Host

    Write-Host "Sample BPA Output (Subscription Level):" -ForegroundColor Yellow
    $bpaList | Select-Object -First 3 | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host "[INFO] No storage accounts were found in the scanned subscriptions." -ForegroundColor Yellow
}

Write-Host "Audit export completed successfully!`n" -ForegroundColor Green
