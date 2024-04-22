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
    Expand-Archive -Path "$INSTALL_LOCATION\usnjrnl_rewind\chainsaw.zip" -DestinationPath "$INSTALL_LOCATION\chainsaw"

    Write-Host '[*] Removing chainsaw zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\chainsaw\chainsaw.zip"
}

