<#
    .SYNOPSIS
    Install forensics dependencies on the Windows server such as Windows Server 2016 to be used for forensics purposes
#>

# Sleep Time (in seconds)
Set-Variable SLEEP_TIME -Option Constant -Value 60

Write-Host "[*] Configuring TLS settings for downloading files..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Installation location for our binaries
$INSTALL_LOCATION = "C:\Users\Administrator\Desktop\opt"

# Get the current working directory 
$cwd = $(Get-Location | Select -ExpandProperty Path)

$SetupSettings = $null
if (Test-Path -Path ".\setup.secrets.env") {
    $SetupSettings = Get-Content -Path ".\setup.secrets.env" | ConvertFrom-Json
} else {
    Write-Host "[!] No setup.secrets.env file found"
}

Write-Host "[*] Checking if we need to install AzureAD module..."
if (-Not (Get-InstalledModule -Name AzureAd )) {
    Write-Host "[*] Installing 'AzureAD' module..."
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name AzureAd -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install Microsoft.Graph module..."
if (-Not (Get-InstalledModule -Name Microsoft.Graph )) {
    Write-Host "[*] Installing 'Microsoft.Graph' module..."
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name Microsoft.Graph -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install ExchangeOnlineManagement module..."
if (-Not (Get-InstalledModule -Name ExchangeOnlineManagement )) {
    Write-Host "[*] Installing 'ExchangeOnlineManagement' module..."
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name ExchangeOnlineManagement -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install Az module..."
if (-Not (Get-InstalledModule -Name Az )) {
    Write-Host "[*] Installing 'Az' module..."
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name Az -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install AzureADPreview module..."
if (-Not (Get-InstalledModule -Name AzureADPreview )) {
    Write-Host "[*] Installing 'AzureADPreview' module..."
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name AzureADPreview -Force -Confirm:$false
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION")) {
    Write-Host "[*] Creating new directory 'opt' in Desktop..."
    New-item -ItemType Directory -Path "C:\Users\Administrator\Desktop\opt"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\python")) {
    Write-Host "[*] Making directory python..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\python"
    
    Write-Host "[*] Downloading python..."
    $url="https://www.python.org/ftp/python/3.11.3/python-3.11.3-amd64.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\python\python.exe")

    Write-Host "[*] Installing python..."
    $command = "$INSTALL_LOCATION\python\python.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0"
    Invoke-Expression "& $command"

    Write-Host "[*] Sleeping for $SLEEP_TIME seconds until python is installed..."
    sleep "$SLEEP_TIME"

    #Write-Host "[*] Removing python.exe installer...."
    #Remove-Item -Path "$INSTALL_LOCATION\python\python.exe"
}


if (-Not (Test-Path -Path "$INSTALL_LOCATION\WMIExplorer")) {
    Write-Host "[*] Making directory WMIExplorer..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\WMIExplorer"

    Write-Host "[*] Downloading WMIExplorer..."
    $url =  "https://github.com/vinaypamnani/wmie2/releases/download/v2.0.0.2/WmiExplorer_2.0.0.2.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\WMIExplorer\WMIExplorer.zip")

    Write-Host "[*] Extracting WMIExplorer zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\WMIExplorer\WMIExplorer.zip" -DestinationPath "$INSTALL_LOCATION\WMIExplorer"

    Write-Host '[*] Removing WMIExplorer zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\WMIExplorer\WMIExplorer.zip"
}


if (-Not (Test-Path -Path "$INSTALL_LOCATION\wmi-parser")) {
    Write-Host "[*] Making directory wmi-parser..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\wmi-parser"

    Write-Host "[*] Downloading wmi-parser..."
    $url =  "https://github.com/woanware/wmi-parser/releases/download/v0.0.2/wmi-parser.v0.0.2.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\wmi-parser\wmi-parser.zip")

    Write-Host "[*] Extracting WMIExplorer zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\wmi-parser\wmi-parser.zip" -DestinationPath "$INSTALL_LOCATION\wmi-parser"

    Write-Host '[*] Removing wmi-parser zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\wmi-parser\wmi-parser.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\chainsaw")) {
    Write-Host "[*] Making directory chainsaw..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\chainsaw"

    Write-Host "[*] Downloading chainsaw..."
    $url =  "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.8.1/chainsaw_x86_64-pc-windows-msvc.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\chainsaw\chainsaw.zip")

    Write-Host "[*] Extracting chainsaw zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\chainsaw\chainsaw.zip" -DestinationPath "$INSTALL_LOCATION\chainsaw"

    Write-Host '[*] Removing chainsaw zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\chainsaw\chainsaw.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\sysinternals")) {
    Write-Host "[*] Making directory sysinternals..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\sysinternals"

    Write-Host "[*] Downloading sysinternals..."
    $url =  "https://download.sysinternals.com/files/SysinternalsSuite.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\sysinternals\sysinternals.zip")

    Write-Host "[*] Extracting sysinternals zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\sysinternals\sysinternals.zip" -DestinationPath "$INSTALL_LOCATION\sysinternals"

    Write-Host '[*] Removing sysinternals zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\sysinternals\sysinternals.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\ExtractUsnJrnl64")) {
    Write-Host "[*] Making directory ExtractUsnJrnl64..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\ExtractUsnJrnl64"

    Write-Host "[*] Downloading ExtractUsnJrnl64..."
    $url =  "https://github.com/jschicht/ExtractUsnJrnl/raw/master/ExtractUsnJrnl64.exe"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\ExtractUsnJrnl64\ExtractUsnJrnl64.exe")
}


if (-Not (Test-Path -Path "$INSTALL_LOCATION\UsnJrnl2Csv")) {
    Write-Host "[*] Making directory UsnJrnl2Csv..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\UsnJrnl2Csv"

    Write-Host "[*] Downloading UsnJrnl2Csv..."
    $url =  "https://github.com/jschicht/UsnJrnl2Csv/releases/download/v1.0.0.24/UsnJrnl2Csv_v1.0.0.24.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\UsnJrnl2Csv\UsnJrnl2Csv.zip")

    Write-Host "[*] Extracting UsnJrnl2Csv zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\UsnJrnl2Csv\UsnJrnl2Csv.zip" -DestinationPath "$INSTALL_LOCATION\UsnJrnl2Csv"

    Write-Host '[*] Removing UsnJrnl2Csv zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\UsnJrnl2Csv\UsnJrnl2Csv.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\TurnedOnTimesView")) {
    Write-Host "[*] Making directory TurnedOnTimesView..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\TurnedOnTimesView"

    Write-Host "[*] Downloading TurnedOnTimesView..."
    $url =  "https://www.nirsoft.net/utils/turnedontimesview.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\TurnedOnTimesView\TurnedOnTimesView.zip")

    Write-Host "[*] Extracting TurnedOnTimesView zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\TurnedOnTimesView\TurnedOnTimesView.zip" -DestinationPath "$INSTALL_LOCATION\TurnedOnTimesView"

    Write-Host '[*] Removing TurnedOnTimesView zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\TurnedOnTimesView\TurnedOnTimesView.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\chainsaw")) {
    Write-Host "[*] Making directory chainsaw..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\chainsaw"
    
    Write-Host "[*] Downloading chainsaw..."
    $url="https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.0/chainsaw_x86_64-pc-windows-msvc.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\chainsaw\chainsaw.zip")

    Write-Host "[*] Extracting chainsaw zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\chainsaw\chainsaw.zip" -DestinationPath "$INSTALL_LOCATION\chainsaw"

    Write-Host '[*] Removing chainsaw zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\chainsaw\chainsaw.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\velociraptor")) {
    Write-Host "[*] Making directory velociraptor..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\velociraptor"
    
    Write-Host "[*] Downloading velociraptor..."
    $url="https://github.com/Velocidex/velociraptor/releases/download/v0.7.1/velociraptor-v0.7.1-1-windows-amd64.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\velociraptor\velociraptor.exe")
}


if (-Not (Test-Path -Path "$INSTALL_LOCATION\kape")) {
    Write-Host "[*] Making directory kape..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\kape"
    
    Write-Host "[*] Downloading kape..."
    $url="https://github.com/manasmbellani/splunkfiles/raw/master/kp.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\kape\kape.zip")

    Write-Host "[*] Extracting kape zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\kape\kape.zip" -DestinationPath "$INSTALL_LOCATION\kape"

    Write-Host '[*] Removing kape zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\kape\kape.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\winpmem")) {
    Write-Host "[*] Making directory winpmem..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\winpmem"
    
    Write-Host "[*] Downloading winpmem x64..."
    $url="https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\winpmem\winpmem_mini_x64_rc2.exe")

    Write-Host "[*] Downloading winpmem x86..."
    $url="https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x86.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\winpmem\winpmem_mini_x86.exe")
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\Microsoft-Extractor-Suite")) {
    Write-Host "[*] Making directory Microsoft-Extractor-Suite..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\Microsoft-Extractor-Suite"
    
    Write-Host "[*] Downloading kape..."
    $url="https://github.com/invictus-ir/Microsoft-Extractor-Suite/archive/refs/heads/main.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\Microsoft-Extractor-Suite\Microsoft-Extractor-Suite.zip")

    Write-Host "[*] Extracting Microsoft-Extractor-Suite zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\Microsoft-Extractor-Suite\Microsoft-Extractor-Suite.zip" -DestinationPath "$INSTALL_LOCATION\Microsoft-Extractor-Suite"

    Write-Host '[*] Removing Microsoft-Extractor-Suite zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\Microsoft-Extractor-Suite\Microsoft-Extractor-Suite.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\Microsoft-Analyzer-Suite")) {
    Write-Host "[*] Making directory Microsoft-Analyzer-Suite..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\Microsoft-Analyzer-Suite"
    
    Write-Host "[*] Downloading Microsoft-Analyzer-Suite..."
    $url="https://github.com/evild3ad/Microsoft-Analyzer-Suite/archive/refs/heads/main.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\Microsoft-Extractor-Suite\Microsoft-Analyzer-Suite.zip")

    Write-Host "[*] Extracting Microsoft-Extractor-Suite zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\Microsoft-Extractor-Suite\Microsoft-Analyzer-Suite.zip" -DestinationPath "$INSTALL_LOCATION\Microsoft-Analyzer-Suite"

    Write-Host '[*] Removing Microsoft-Analyzer-Suite zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\Microsoft-Extractor-Suite\Microsoft-Analyzer-Suite.zip"
}
