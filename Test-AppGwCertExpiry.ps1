<#
.SYNOPSIS
    Test script to verify SSL certificate expiry date & time from a specific
    Azure Application Gateway and export the test results to CSV.

.DESCRIPTION
    Extracts directly uploaded SSL certificates from the target Application Gateway,
    parses the raw base64 PublicCertData using X509Certificate2Collection.Import(),
    displays the formatted test results in the console, and exports them to a CSV file.

.PARAMETER SubscriptionId
    Target Azure Subscription ID. Defaults to "242eb51a-ca35-493b-b2d7-941aa572c048".

.PARAMETER ResourceGroupName
    Target Resource Group name. Defaults to "MHA-Tech-Convet-AppGtway-NonProd-RG".

.PARAMETER AppGatewayName
    Target Application Gateway name. Defaults to "appgw-nonprod-convet-weu-01".

.PARAMETER CsvPath
    Optional custom CSV export path. Default: .\TestResult-AppGw-CertExpiry-<timestamp>.csv
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId = "242eb51a-ca35-493b-b2d7-941aa572c048",

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "MHA-Tech-Convet-AppGtway-NonProd-RG",

    [Parameter(Mandatory = $false)]
    [string]$AppGatewayName = "appgw-nonprod-convet-weu-01",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

# 1. Set subscription context
Write-Host "[+] Setting subscription context to: $SubscriptionId" -ForegroundColor Cyan
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

# 2. Fetch Application Gateway
Write-Host "[+] Fetching Application Gateway '$AppGatewayName' in RG '$ResourceGroupName'..." -ForegroundColor Cyan
$appgw = Get-AzApplicationGateway -ResourceGroupName $ResourceGroupName -Name $AppGatewayName

if (-not $appgw) {
    Write-Error "Application Gateway '$AppGatewayName' not found in Resource Group '$ResourceGroupName'."
    return
}

# 3. Build listener mapping (maps certificate name to HTTPS listener names/hostnames)
$listenerMap = @{}
foreach ($listener in $appgw.HttpListeners) {
    if ($listener.SslCertificate -and $listener.SslCertificate.Id) {
        $certNameFromId = $listener.SslCertificate.Id.Split('/')[-1]
        $hostInfo = if ($listener.HostName) { "$($listener.Name) ($($listener.HostName))" } else { $listener.Name }
        if (-not $listenerMap.ContainsKey($certNameFromId)) {
            $listenerMap[$certNameFromId] = [System.Collections.Generic.List[string]]::new()
        }
        $listenerMap[$certNameFromId].Add($hostInfo)
    }
}

# 4. Filter uploaded certificates (directly uploaded certs with PublicCertData)
$uploadedCerts = $appgw.SslCertificates | Where-Object { 
    [string]::IsNullOrEmpty($_.KeyVaultSecretId) -and -not [string]::IsNullOrEmpty($_.PublicCertData) 
}

Write-Host "[+] Found $($uploadedCerts.Count) uploaded SSL certificate(s) to evaluate." -ForegroundColor Green

$now = Get-Date

$results = foreach ($cert in $uploadedCerts) {
    try {
        $rawBytes = [System.Convert]::FromBase64String($cert.PublicCertData)

        # Use X509Certificate2Collection to support PKCS#7 / certificate chains
        $collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $collection.Import($rawBytes)

        # The first or leaf certificate in the bundle represents the endpoint certificate
        $leafCert = $collection[0]
        $notAfterLocal = $leafCert.NotAfter
        $notAfterUtc   = $notAfterLocal.ToUniversalTime()
        $daysRemaining = [int][Math]::Floor(($notAfterLocal - $now).TotalDays)

        $status = if ($notAfterLocal -lt $now) {
            "EXPIRED ($([Math]::Abs($daysRemaining)) days ago)"
        }
        elseif ($daysRemaining -le 7) {
            "EXPIRING URGENT ($daysRemaining days left)"
        }
        elseif ($daysRemaining -le 30) {
            "EXPIRING SOON ($daysRemaining days left)"
        }
        else {
            "ACTIVE ($daysRemaining days left)"
        }

        $listeners = if ($listenerMap.ContainsKey($cert.Name)) {
            $listenerMap[$cert.Name] -join "; "
        } else {
            "Unattached / No Listener"
        }

        [PSCustomObject]@{
            SubscriptionId      = $SubscriptionId
            ResourceGroupName   = $ResourceGroupName
            AppGatewayName      = $AppGatewayName
            CertificateName     = $cert.Name
            CommonName          = $leafCert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            Issuer              = $leafCert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
            Thumbprint          = $leafCert.Thumbprint
            ExpirationDateTime  = $notAfterLocal.ToString("yyyy-MM-dd HH:mm:ss")
            ExpirationDate_UTC  = $notAfterUtc.ToString("yyyy-MM-dd HH:mm:ss")
            DaysRemaining       = $daysRemaining
            Status              = $status
            AssociatedListeners = $listeners
        }
    }
    catch {
        Write-Warning "Failed to parse certificate '$($cert.Name)': $($_.Exception.Message)"
        [PSCustomObject]@{
            SubscriptionId      = $SubscriptionId
            ResourceGroupName   = $ResourceGroupName
            AppGatewayName      = $AppGatewayName
            CertificateName     = $cert.Name
            CommonName          = "DECODE_FAILED"
            Issuer              = "N/A"
            Thumbprint          = "N/A"
            ExpirationDateTime  = "N/A"
            ExpirationDate_UTC  = "N/A"
            DaysRemaining       = $null
            Status              = "ERROR: $($_.Exception.Message)"
            AssociatedListeners = "N/A"
        }
    }
}

# 5. Display results on console
Write-Host ""
Write-Host "============================= TEST RESULTS =============================" -ForegroundColor Yellow
$results | Sort-Object DaysRemaining | Format-Table -Property CertificateName, CommonName, ExpirationDateTime, DaysRemaining, Status, AssociatedListeners -AutoSize

# 6. Export results to CSV file
if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $baseDir   = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $CsvPath   = Join-Path $baseDir "TestResult-AppGw-CertExpiry-$timestamp.csv"
}

$results | Sort-Object DaysRemaining | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "[+] CSV test result exported successfully!" -ForegroundColor Green
Write-Host "    File Path: $CsvPath" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Yellow
Write-Host ""

return $results
