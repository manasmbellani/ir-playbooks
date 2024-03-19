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
