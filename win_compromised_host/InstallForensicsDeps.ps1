<#
    .SYNOPSIS
    Install forensics dependencies on the Windows server such as Windows Server 2016 to be used for forensics purposes
#>

# Sleep Time (in seconds)
Set-Variable SLEEP_TIME -Option Constant -Value 60

Write-Host "[*] Configuring TLS settings for downloading files..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Get the current working directory 
$cwd = $(Get-Location | Select -ExpandProperty Path)

$SetupSettings = $null
if (Test-Path -Path ".\setup.secrets.env") {
    $SetupSettings = Get-Content -Path ".\setup.secrets.env" | ConvertFrom-Json
} else {
    Write-Host "[!] No setup.secrets.env file found"
}

if (-Not (Test-Path -Path "C:\Users\Administrator\Desktop\opt")) {
    Write-Host "[*] Creating new directory 'opt' in Desktop..."
    New-item -ItemType Directory -Path "C:\Users\Administrator\Desktop\opt"
}

if (-Not (Test-Path -Path "C:\Users\Administrator\Desktop\opt\python")) {
    Write-Host "[*] Making directory python..."
    New-item -ItemType Directory -Path "C:\Users\Administrator\Desktop\opt\python"
    
    Write-Host "[*] Downloading python..."
    $url="https://www.python.org/ftp/python/3.11.3/python-3.11.3-amd64.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "C:\Users\Administrator\Desktop\opt\python\python.exe")

    Write-Host "[*] Installing python..."
    $command = "C:\Users\Administrator\Desktop\opt\python\python.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0"
    Invoke-Expression "& $command"

    Write-Host "[*] Sleeping for $SLEEP_TIME seconds until python is installed..."
    sleep "$SLEEP_TIME"

    Write-Host "[*] Removing python.exe installer...."
    #Remove-Item -Path "C:\Users\Administrator\Desktop\opt\python\python.exe"
}


if (-Not (Test-Path -Path "C:\Users\Administrator\Desktop\opt\WMIExplorer")) {
    Write-Host "[*] Making directory WMIExplorer..."
    New-item -ItemType Directory -Path "C:\Users\Administrator\Desktop\opt\WMIExplorer"

    Write-Host "[*] Downloading WMIExplorer..."
    $url =  "https://github.com/vinaypamnani/wmie2/releases/download/v2.0.0.2/WmiExplorer_2.0.0.2.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "C:\Users\Administrator\Desktop\opt\WMIExplorer\WMIExplorer.zip")

    Write-Host "[*] Extracting WMIExplorer zip file..."
    Expand-Archive -Path "C:\Users\Administrator\Desktop\opt\WMIExplorer\WMIExplorer.zip" -DestinationPath "C:\Users\Administrator\Desktop\opt\WMIExplorer"

    Write-Host '[*] Removing WMIExplorer zip file...'
    Remove-Item -Path "C:\Users\Administrator\Desktop\opt\WMIExplorer\WMIExplorer.zip"
}
