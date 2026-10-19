<#
.SYNOPSIS
    Exports Azure Storage Account security configurations replicating AWS S3 audit reports
    strictly scoped to Management Group: 'ac-1.1'.

.DESCRIPTION
    Audits storage accounts within Management Group 'ac-1.1' and exports:
      1. StorageAccount-consolidated.csv (.xlsx)
         Headers: storageaccountname | encryptionkeysource | infrastructureencryptionenabled | networkacldefaultaction | subscriptionname | subscriptionid
      2. StorageAccount-bpa.csv (.xlsx)
         Headers: subscriptionname | subscriptionid | allowblobpublicaccess
      3. StorageAccount-bpa-detailed.csv (.xlsx)
         Headers: storageaccountname | subscriptionname | subscriptionid | allowblobpublicaccess

.PARAMETER OutputPath
    Directory where reports will be saved. Default is the current script directory.

.PARAMETER Format
    Export format: 'Csv' (default), 'Excel', or 'Both'.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Csv', 'Excel', 'Both')]
    [string]$Format = 'Csv'
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# ==============================================================================
# TARGET MANAGEMENT GROUP CONFIGURATION
# ==============================================================================
$TargetManagementGroupId = "ac-1.1"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Azure Storage Account Security Audit" -ForegroundColor Cyan
Write-Host " Target Scope : Management Group '$TargetManagementGroupId'" -ForegroundColor Yellow
Write-Host " Reports      : Consolidated Security & Block Public Access (BPA)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# 1. AUTHENTICATION & ENVIRONMENT CHECK
# -------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    Throw "The 'Az.Accounts' PowerShell module is required. Run: Install-Module -Name Az.Accounts -Scope CurrentUser"
}

$currentContext = Get-AzContext -ErrorAction SilentlyContinue
if (-not $currentContext) {
    Write-Host "[INFO] No active Azure context detected. Initiating interactive login..." -ForegroundColor Yellow
    Connect-AzAccount | Out-Null
    $currentContext = Get-AzContext
}

Write-Host "[+] Connected as : $($currentContext.Account.Id)" -ForegroundColor Green
Write-Host "[+] Tenant ID    : $($currentContext.Tenant.Id)" -ForegroundColor Green

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = "."
}
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$hasImportExcel = [bool](Get-Module -ListAvailable -Name ImportExcel)
if (($Format -in @('Excel', 'Both')) -and -not $hasImportExcel) {
    Write-Host "[WARN] 'ImportExcel' module is not installed. Defaulting to CSV exports." -ForegroundColor Yellow
    if ($Format -eq 'Excel') { $Format = 'Csv' }
}

# -------------------------------------------------------------------------
# 2. RESOLVE SUBSCRIPTIONS UNDER MANAGEMENT GROUP 'ac-1.1'
# -------------------------------------------------------------------------
Write-Host "`n[STEP 1/3] Resolving Management Group '$TargetManagementGroupId'..." -ForegroundColor Cyan

$mg = Get-AzManagementGroup -GroupId $TargetManagementGroupId -Expand -Recurse -ErrorAction SilentlyContinue
if (-not $mg) {
    # Check by DisplayName if not matched by ID
    $allMgs = Get-AzManagementGroup -ErrorAction SilentlyContinue
    $matched = $allMgs | Where-Object { $_.Name -eq $TargetManagementGroupId -or $_.DisplayName -eq $TargetManagementGroupId } | Select-Object -First 1
    if ($matched) {
        $mg = Get-AzManagementGroup -GroupId $matched.Name -Expand -Recurse -ErrorAction SilentlyContinue
    }
}

if (-not $mg) {
    Throw "[ERROR] Management Group '$TargetManagementGroupId' was not found in this tenant! Aborting to prevent full-tenant scanning."
}

Write-Host "[+] Matched Management Group: $($mg.DisplayName) (ID: $($mg.Name))" -ForegroundColor Green

# Recursively discover all subscription IDs under this Management Group
$discoveredSubIds = [System.Collections.Generic.List[string]]::new()
function Find-MgSubsRecursive($node) {
    if ($node.Children) {
        foreach ($c in $node.Children) {
            if ($c.Type -match 'subscriptions' -and $c.Name) {
                $discoveredSubIds.Add($c.Name)
            }
            if ($c.Children) {
                Find-MgSubsRecursive $c
            }
        }
    }
}
Find-MgSubsRecursive $mg

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
if ($targetSubs.Count -eq 0) {
    Throw "[ERROR] No subscriptions found under Management Group '$TargetManagementGroupId'. Aborting."
}

Write-Host "[+] Discovered $($targetSubs.Count) subscription(s) strictly inside '$TargetManagementGroupId':" -ForegroundColor Green
$targetSubs | ForEach-Object { Write-Host "    -> Subscription ID: $_" -ForegroundColor DarkGray }

$formattedKqlSubFilter = ($targetSubs | ForEach-Object { "'$_'" }) -join ", "

# -------------------------------------------------------------------------
# 3. EXTRACT DATA STRICTLY FOR TARGET SUBSCRIPTIONS
# -------------------------------------------------------------------------
$consolidatedList = [System.Collections.Generic.List[PSCustomObject]]::new()
$bpaList          = [System.Collections.Generic.List[PSCustomObject]]::new()
$bpaDetailedList  = [System.Collections.Generic.List[PSCustomObject]]::new()

$hasArg = [bool](Get-Module -ListAvailable -Name Az.ResourceGraph)

if ($hasArg) {
    Write-Host "`n[STEP 2/3] Querying Storage Accounts via Azure Resource Graph..." -ForegroundColor Cyan
    try {
        $kqlQuery = @"
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
    encryptionkeysource             = tostring(coalesce(properties.encryption.keySource, 'Microsoft.Storage')),
    infrastructureencryptionenabled = tostring(coalesce(properties.encryption.requireInfrastructureEncryption, false)),
    networkacldefaultaction         = tostring(coalesce(properties.networkAcls.defaultAction, 'Allow')),
    allowblobpublicaccess           = tostring(coalesce(properties.allowBlobPublicAccess, false)),
    subscriptionname                = coalesce(subscriptionName, subscriptionId),
    subscriptionid                  = subscriptionId
| order by subscriptionname asc, storageaccountname asc
"@
        $rawResults = Search-AzGraph -Subscription $targetSubs -Query $kqlQuery -First 5000
        Write-Host "[+] Retrieved $($rawResults.Count) Storage Account(s) under '$TargetManagementGroupId'." -ForegroundColor Green

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

        # Report 2 Summary: Aggregate by Subscription (Matching AWS account-level BPA)
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
        Write-Host "[WARN] Azure Resource Graph error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "       Falling back to standard Az cmdlets..." -ForegroundColor Yellow
        $hasArg = $false
    }
}

if (-not $hasArg) {
    Write-Host "`n[STEP 2/3] Querying Storage Accounts via Az cmdlets..." -ForegroundColor Cyan
    $subs = Get-AzSubscription | Where-Object { $targetSubs -contains $_.Id }

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

            $consolidatedList.Add([PSCustomObject]@{
                storageaccountname              = $sa.StorageAccountName
                encryptionkeysource             = $keySource
                infrastructureencryptionenabled = $infraEnc
                networkacldefaultaction         = $netAction
                subscriptionname                = $sub.Name
                subscriptionid                  = $sub.Id
            })

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
# 4. EXPORT REPORTS
# -------------------------------------------------------------------------
Write-Host "`n[STEP 3/3] Exporting reports..." -ForegroundColor Cyan

$file1Base         = Join-Path $OutputPath "StorageAccount-consolidated"
$file2Base         = Join-Path $OutputPath "StorageAccount-bpa"
$file2DetailedBase = Join-Path $OutputPath "StorageAccount-bpa-detailed"

if ($Format -in @('Csv', 'Both')) {
    $file1Csv         = "$file1Base.csv"
    $file2Csv         = "$file2Base.csv"
    $file2DetailedCsv = "$file2DetailedBase.csv"

    $consolidatedList | Export-Csv -Path $file1Csv -NoTypeInformation -Encoding utf8
    Write-Host "[+] Generated: $file1Csv" -ForegroundColor Green

    $bpaList | Export-Csv -Path $file2Csv -NoTypeInformation -Encoding utf8
    Write-Host "[+] Generated: $file2Csv" -ForegroundColor Green

    $bpaDetailedList | Export-Csv -Path $file2DetailedCsv -NoTypeInformation -Encoding utf8
    Write-Host "[+] Generated: $file2DetailedCsv" -ForegroundColor Green
}

if ($Format -in @('Excel', 'Both') -and $hasImportExcel) {
    $file1Xlsx         = "$file1Base.xlsx"
    $file2Xlsx         = "$file2Base.xlsx"
    $file2DetailedXlsx = "$file2DetailedBase.xlsx"

    $excelParams = @{ BoldTopRow = $true; AutoSize = $true; AutoFilter = $true; FreezeTopRow = $true }

    $consolidatedList | Export-Excel -Path $file1Xlsx -WorksheetName "Consolidated" @excelParams
    Write-Host "[+] Generated: $file1Xlsx" -ForegroundColor Green

    $bpaList | Export-Excel -Path $file2Xlsx -WorksheetName "BPA-Summary" @excelParams
    Write-Host "[+] Generated: $file2Xlsx" -ForegroundColor Green

    $bpaDetailedList | Export-Excel -Path $file2DetailedXlsx -WorksheetName "BPA-PerAccount" @excelParams
    Write-Host "[+] Generated: $file2DetailedXlsx" -ForegroundColor Green
}

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host " AUDIT COMPLETE FOR MANAGEMENT GROUP: '$TargetManagementGroupId'" -ForegroundColor Green
Write-Host " Total Storage Accounts : $($consolidatedList.Count)"
Write-Host " Total Subscriptions    : $($bpaList.Count)"
Write-Host " Reports Directory      : $OutputPath"
Write-Host "========================================================" -ForegroundColor Green
