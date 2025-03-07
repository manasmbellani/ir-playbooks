<#
    .SYNOPSIS
    Install forensics dependencies on the Windows server such as Windows Server 2016 to be used for forensics purposes
    Run in Windows Powershell v5.1

    Additional Steps:
        * Install FTKImager.exe in C:\Users\azureuser\Desktop\opt\FTKImager
	* Upload DetectRaptorVQL.zip in detectraptor folder manually in Velociraptor GUI through 'Artifacts' icon 
    	* Install Microsoft Office 2007 using key in my-notes
     	* Install Dokan under 'C:\Users\azureuser\Desktop\opt\Dokan\DokanSetup.exe' manually
      	* Add token from ipinfo.io website under 'C:\Users\azureuser\Desktop\opt\Microsoft-Analyzer-Suite\Microsoft-Analyzer-Suite-main\Config.ps1'
        * Ensure that additional logging is setup as defined in README.md#scenario-setup especially for ADCS
        * If error of .net6 from EZ Tools, open one of the binaries and install .NET version via the dialog box shown
	* Configure Windows visual studio manually with C# and C++ desktop tools via $INSTALL_LOCATION\VisualStudio\vs_community.exe
	  (C# - .NET Desktop Development, C++ - Desktop Development with C++)
        
   	
#>

# Sleep Time (in seconds)
Set-Variable SLEEP_TIME -Option Constant -Value 60

Write-Host "[*] Configuring TLS settings for downloading files..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Installation location for our binaries
$INSTALL_LOCATION = "C:\Users\azureuser\Desktop\opt"

# Get the current working directory 
$cwd = $(Get-Location | Select -ExpandProperty Path)

$SetupSettings = $null
if (Test-Path -Path ".\setup.secrets.env") {
    $SetupSettings = Get-Content -Path ".\setup.secrets.env" | ConvertFrom-Json
} else {
    Write-Host "[!] No setup.secrets.env file found"
}

Write-Host "[*] Trust PSGallery for installation of new powershell modules..."
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

Write-Host "[*] Checking if we need to install AzureAD module..."
if (-Not (Get-InstalledModule -Name AzureAd )) {
    Write-Host "[*] Installing 'AzureAD' module..."
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name AzureAd -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install Hawk module..."
if (-Not (Get-InstalledModule -Name Hawk )) {
    Write-Host "[*] Installing 'Hawk' module..."
    Install-Module -Name RobustCloudCommand -Force -Confirm:$false -RequiredVersion 2.1.0
    Install-Module -Name Hawk -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install MsrcSecurityUpdates module..."
if (-Not (Get-InstalledModule -Name MsrcSecurityUpdates )) {
    Write-Host "[*] Installing 'MsrcSecurityUpdates' module..."
    Install-Module -Name MsrcSecurityUpdates -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install Microsoft.Graph module..."
if (-Not (Get-InstalledModule -Name Microsoft.Graph )) {
    Write-Host "[*] Installing 'Microsoft.Graph' module..."
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name Microsoft.Graph -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install ImportExcel module..."
if (-Not (Get-InstalledModule -Name ImportExcel )) {
    Write-Host "[*] Installing 'ImportExcel' module..."
    #Required for Microsoft-Analyzer-Suite to process Excel sheets without Microsoft Excel installed 
    Install-Module -Name ImportExcel -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install AzureADIncidentResponse module..."
if (-Not (Get-InstalledModule -Name AzureADIncidentResponse )) {
    Write-Host "[*] Updating PowerShellGet module..."
    ## Taken from: https://github.com/AzureAD/MSAL.PS/blob/master/README.md#install-from-the-powershell-gallery
    ## Update Nuget Package and PowerShellGet Module
    Install-PackageProvider NuGet -Scope CurrentUser -Force
    Install-Module PowerShellGet -Scope CurrentUser -Force -AllowClobber
    ## Remove old modules from existing session
    Remove-Module PowerShellGet,PackageManagement -Force -ErrorAction Ignore
    ## Import updated module
    Import-Module PowerShellGet -MinimumVersion 2.0 -Force
    Import-PackageProvider PowerShellGet -MinimumVersion 2.0 -Force
    
    Write-Host "[*] Installing 'AzureADIncidentResponse' module..."
    Install-Module -Name AzureADIncidentResponse -Force -Confirm:$false -AcceptLicense
}

Write-Host "[*] Checking if we need to install VMWare.PowerCLI module..."
if (-Not (Get-InstalledModule -Name VMWare.PowerCLI )) {
    Write-Host "[*] Installing 'VMWare.PowerCLI' module..."
    #Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name VMWare.PowerCLI -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install AADInternals module..."
if (-Not (Get-InstalledModule -Name AADInternals )) {
    Write-Host "[*] Installing 'AADInternals' module..."
    Install-Module -Name AADInternals -Force -Confirm:$false
}

Write-Host "[*] Checking if we need to install MSOnline module..."
if (-Not (Get-InstalledModule -Name MSOnline )) {
    Write-Host "[*] Installing 'MSOnline' module..."
    Install-Module -Name MSOnline -Force -Confirm:$false
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
    Install-Module -Name AzureADPreview -Force -Confirm:$false -AllowClobber
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION")) {
    Write-Host "[*] Creating new directory 'opt' in Desktop..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION"
}

If (-Not (Test-Path "$INSTALL_LOCATION\flag-disable-windows-defender")) {
    Write-Host "[*] Making flag-disable-windows-defender to state that Windows defender has been disabled..."
    New-Item -ItemType File -Path "$INSTALL_LOCATION\flag-disable-windows-defender"

    Write-Host "[*] Disabling Windows Defender Scanning Settings..."
    Set-MpPreference -DisableRealTimeMonitoring $true
    Set-MpPreference -DisableBehaviorMonitoring $true
    Set-MpPreference -DisableArchiveScanning $true
    Set-MpPreference -MAPSReporting Disabled
    Set-MpPreference -SubmitSamplesConsent 0
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\Notepad++")) {
    Write-Host "[*] Making directory Notepad++..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\Notepad++"
    
    Write-Host "[*] Downloading Notepad++..."
    $url="https://github.com/manasmbellani/splunkfiles/raw/master/npp.8.5.Installer.x64.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\Notepad++\npp.8.5.Installer.x64.exe")

    Write-Host "[*] Installing Notepad++..."
    $command = "$INSTALL_LOCATION\Notepad++\npp.8.5.Installer.x64.exe /S"
    Invoke-Expression "& $command"

    Write-Host "[*] Sleeping for $SLEEP_TIME seconds until Notepad++ is installed..."
    sleep "$SLEEP_TIME"
}

If (-Not (Test-Path "$INSTALL_LOCATION\flag-disable-windows-firewall")) {
    Write-Host "[*] Making flag to state that Windows firewall has been disabled..."
    New-Item -ItemType File -Path "$INSTALL_LOCATION\flag-disable-windows-firewall"

    Write-Host "[*] Disabling Windows Firewall Settings..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
}

If (-Not (Test-Path "$INSTALL_LOCATION\flag-enable-ssh")) {
    Write-Host "[*] Making flag-enable-ssh to state that SSH has been enabled..."
    New-Item -ItemType File -Path "$INSTALL_LOCATION\flag-enable-ssh"

    Write-Host "[*] Enabling SSH..."
    $command="dism /online /Add-Capability /CapabilityName:OpenSSH.Client~~~~0.0.1.0"
    Invoke-Expression "& $command"
}

If (-Not (Test-Path "$INSTALL_LOCATION\flag-powershell-logging")) {
    # Taken from: https://support.alertlogic.com/hc/en-us/articles/4410220960795-Enable-Windows-PowerShell-Logging
    Write-Host "[*] Making flag-powershell-logging to state that powershell logging has been configured..."
    New-Item -ItemType File -Path "$INSTALL_LOCATION\flag-powershell-logging"

    Write-Host "[*] Enabling Module Logging..."
    New-Item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell" -Force
    New-Item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
    New-Item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -PropertyType "String" -Force
    
    Write-Host "[*] Enabling Scriptblock Logging..."
    New-Item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value "1" -PropertyType "DWORD" -Force
}


if (-Not (Test-Path -Path "$INSTALL_LOCATION/DumpDelegatesandForwardingRules")) {
    Write-Host "[*] Making directory DumpDelegatesandForwardingRules..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\DumpDelegatesandForwardingRules"

    Write-Host "[*] Downloading script for dumping delegates and forwarding rules in the Microsoft 365 environment..."
    $url="https://github.com/OfficeDev/O365-InvestigationTooling/raw/master/DumpDelegatesandForwardingRules.ps1"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\DumpDelegatesandForwardingRules\DumpDelegatesandForwardingRules.ps1")
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

if (-Not (Test-Path -Path "$INSTALL_LOCATION\WINTri")) {
    Write-Host "[*] Making directory WINTri..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\WINTri"
    
    Write-Host "[*] Downloading WINTri..."
    $url="https://github.com/DCScoder/WINTri/raw/main/WINTri.ps1"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\WINTri\WINTri.ps1")
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\OpenHashTab")) {
    Write-Host "[*] Making directory OpenHashTab..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\OpenHashTab"
    
    Write-Host "[*] Downloading OpenHashTab..."
    $url="https://github.com/namazso/OpenHashTab/releases/download/v3.0.4/OpenHashTab_setup.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\OpenHashTab\OpenHashTab_setup.exe")

    Write-Host "[*] Installing OpenHashTab..."
    $command = "$INSTALL_LOCATION\OpenHashTab\OpenHashTab_setup.exe /SILENT /NORESTART /ALLUSERS" 
    Invoke-Expression "& $command"

    Write-Host "[*] Sleeping for $SLEEP_TIME seconds until python is installed..."
    sleep "$SLEEP_TIME"

    Write-Host "[*] Removing OpenHashTab installer...."
    Remove-Item -Path "$INSTALL_LOCATION\OpenHashTab\OpenHashTab_setup.exe"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\7zip")) {
    Write-Host "[*] Making directory 7zip..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\7zip"

    Write-Host "[*] Downloading 7zip .exe..."
    $url = "https://www.7-zip.org/a/7z2201-x64.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\7zip\7z2201-x64.exe")

    Write-Host "[*] Installing 7zip..."
    $command = "$INSTALL_LOCATION\7zip\7z2201-x64.exe /S"
    Invoke-Expression "& $command"

    Write-Host "[*] Sleeping for $SLEEP_TIME seconds until 7zip is installed..."
    sleep "$SLEEP_TIME"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\Git")) {
    Write-Host "[*] Making directory Git..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\Git"

    Write-Host "[*] Downloading git.exe..."
    Invoke-WebRequest "https://github.com/git-for-windows/git/releases/download/v2.34.1.windows.1/Git-2.34.1-64-bit.exe" -OutFile "$INSTALL_LOCATION\Git\git.exe"

    Write-Host "[*] Installing git.exe..."
    $cmd = "$INSTALL_LOCATION\Git\git.exe /SILENT /NORESTART"
    Invoke-Expression "& $cmd"

    Write-Host "[*] Adding Git bin's path to PATH environment var..."
    [Environment]::SetEnvironmentVariable("PATH", "$env:PATH;C:\Program Files\Git\cmd", "User")

}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\dc3dd")) {
    Write-Host "[*] Making directory dc3dd..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\dc3dd"

    Write-Host "[*] Downloading dc3dd-windows.zip..."
    $url =  "https://github.com/manasmbellani/splunkfiles/raw/master/dc3dd-windows.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\dc3dd\dc3dd-windows.zip")

    Write-Host "[*] Extracting dc3dd-windows .zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\dc3dd\dc3dd-windows.zip" -DestinationPath "$INSTALL_LOCATION\dc3dd"

    Write-Host '[*] Removing dc3dd-windows.zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\dc3dd\dc3dd-windows.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\PurpleKnight")) {
    Write-Host "[*] Making directory PurpleKnight..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\PurpleKnight"

    Write-Host "[*] Downloading PurpleKnight.zip..."
    $url =  "https://github.com/manasmbellani/splunkfiles/raw/refs/heads/master/PK-Community-v4.3.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\PurpleKnight\PurpleKnight.zip")

    Write-Host "[*] Extracting PurpleKnight .zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\PurpleKnight\PurpleKnight.zip" -DestinationPath "$INSTALL_LOCATION\PurpleKnight"

    Write-Host '[*] Removing PurpleKnight.zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\PurpleKnight\PurpleKnight.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\PingCastle")) {
    Write-Host "[*] Making directory PingCastle..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\PingCastle"

    Write-Host "[*] Downloading PingCastle.zip..."
    $url =  "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\PingCastle\PingCastle.zip")

    Write-Host "[*] Extracting PingCastle .zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\PingCastle\PingCastle.zip" -DestinationPath "$INSTALL_LOCATION\PingCastle"

    Write-Host '[*] Removing PingCastle.zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\PingCastle\PingCastle.zip"
}


if (-Not (Test-Path -Path "$INSTALL_LOCATION\azurehound")) {
    Write-Host "[*] Making directory azurehound..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\azurehound"

    Write-Host "[*] Downloading azurehound.zip..."
    $url =  "https://github.com/BloodHoundAD/AzureHound/releases/download/v2.1.9/azurehound-windows-amd64.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\azurehound\azurehound.zip")

    Write-Host "[*] Extracting azurehound .zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\azurehound\azurehound.zip" -DestinationPath "$INSTALL_LOCATION\azurehound"

    Write-Host '[*] Removing azurehound.zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\azurehound\azurehound.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\Get-AzureADPSPermissions")) {
    Write-Host "[*] Making directory Get-AzureADPSPermissions..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\Get-AzureADPSPermissions"

    Write-Host "[*] Downloading Get-AzureADPSPermissions.ps1..."
    $url =  "https://gist.github.com/psignoret/41793f8c6211d2df5051d77ca3728c09/raw/fe8d91a625d9cdae20f103e39a49bc6dd5d7bd84/Get-AzureADPSPermissions.ps1"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\Get-AzureADPSPermissions\Get-AzureADPSPermissions.ps1")
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

if (-Not (Test-Path -Path "$INSTALL_LOCATION\detectraptor")) {
    Write-Host "[*] Making directory detectraptor..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\detectraptor"
    
    Write-Host "[*] Downloading detectraptor..."
    $url="https://github.com/mgreen27/DetectRaptor/releases/download/DetectRaptor/DetectRaptorVQL.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\detectraptor\DetectRaptorVQL.zip")
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

    Write-Host "[*] Installing Microsoft-Extractor-Suite via powershell..."
    Install-Module Microsoft-Extractor-Suite
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

if (-Not (Test-Path -Path "$INSTALL_LOCATION\sigma")) {
    Write-Host "[*] Making directory sigma..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\sigma"
    
    Write-Host "[*] Downloading sigma..."
    $url="https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\sigma\sigma.zip")

    Write-Host "[*] Extracting sigma zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\sigma\sigma.zip" -DestinationPath "$INSTALL_LOCATION\sigma"

    Write-Host '[*] Removing sigma zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\sigma\sigma.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\esxitri")) {
    Write-Host "[*] Making directory esxitri..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\esxitri"

    Write-Host "[*] Downloading ESXiTri..."
    $url="https://raw.githubusercontent.com/manasmbellani/ESXiTri/main/ESXiTri.sh"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\esxitri\esxitri.sh")
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\TokenTactics")) {
    Write-Host "[*] Making directory TokenTactics..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\TokenTactics"
    
    Write-Host "[*] Downloading TokenTactics..."
    $url="https://github.com/rvrsh3ll/TokenTactics/archive/refs/heads/main.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\TokenTactics\TokenTactics.zip")

    Write-Host "[*] Extracting TokenTactics zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\TokenTactics\TokenTactics.zip" -DestinationPath "$INSTALL_LOCATION\TokenTactics"

    Write-Host '[*] Removing TokenTactics zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\TokenTactics\TokenTactics.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\LogFileParser")) {
    Write-Host "[*] Making directory LogFileParser..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\LogFileParser"
    
    Write-Host "[*] Downloading LogFileParser..."
    $url="https://github.com/jschicht/LogFileParser/releases/download/v2.0.0.51/LogFileParser_v2.0.0.51.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\LogFileParser\LogFileParser.zip")

    Write-Host "[*] Extracting LogFileParser zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\LogFileParser\LogFileParser.zip" -DestinationPath "$INSTALL_LOCATION\LogFileParser"

    Write-Host '[*] Removing LogFileParser zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\LogFileParser\LogFileParser.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\plaso")) {
    Write-Host "[*] Making directory plaso..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\plaso"
    
    Write-Host "[*] Downloading plaso..."
    $url="https://github.com/log2timeline/plaso/releases/download/20240308/plaso-20240308.tar.gz"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\plaso\plaso.tar.gz")

    Write-Host "[*] Extracting plaso tar.gz file via 7z..."
    $zipFilePath = "$INSTALL_LOCATION\plaso\plaso.tar.gz"
    $destinationPath = "$INSTALL_LOCATION\plaso"
    $command = """C:\Program Files\7-zip\7z.exe"" -o$destinationPath x $zipFilePath"
    Invoke-Expression "& $command"

    Write-Host "[*] Extracting plaso tar file via 7z..."
    $zipFilePath = "$INSTALL_LOCATION\plaso\plaso-*.tar"
    $destinationPath = "$INSTALL_LOCATION\plaso"
    $command = """C:\Program Files\7-zip\7z.exe"" -o$destinationPath x $zipFilePath"
    Invoke-Expression "& $command"

    Write-Host '[*] Removing plaso zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\plaso\plaso.tar.gz"
    Remove-Item -Path "$INSTALL_LOCATION\plaso\plaso-*.tar"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\encrypted-disk-detector")) {
    Write-Host "[*] Making directory encrypted-disk-detector..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\encrypted-disk-detector"
    
    Write-Host "[*] Downloading encrypted-disk-detector..."
    $url="https://github.com/manasmbellani/splunkfiles/raw/master/encrypted-disk-detector.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\encrypted-disk-detector\encrypted-disk-detector.exe")
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\FullEventLogView")) {
    Write-Host "[*] Making directory FullEventLogView..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\FullEventLogView"
    
    Write-Host "[*] Downloading FullEventLogView..."
    $url="https://github.com/manasmbellani/splunkfiles/raw/master/FullEventLogView.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\FullEventLogView\FullEventLogView.exe")
}

if (-Not (Test-Path "$INSTALL_LOCATION\sysmon-config")) {
    Write-Host "[*] Making directory sysmon-config..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\sysmon-config"
    
    Write-Host "[*] Downloading sysmon-config..."
    $url = "https://gist.github.com/manasmbellani/1baccb274e6deae15befd0a736ad8f36/raw/sample-sysmon-config.xml"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\sysmon-config\sample-sysmon-config.xml")
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\dotnet-install")) {
    Write-Host "[*] Making directory dotnet-install..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\dotnet-install"
    
    Write-Host "[*] Downloading dotnet-install.ps1..."
    $url="https://dot.net/v1/dotnet-install.ps1"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\dotnet-install\dotnet-install.ps1")

    Write-Host "[*] Installing dotnet 6..."
    cd "$INSTALL_LOCATION\dotnet-install"
    & .\dotnet-install.ps1 -Version 6.0    
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\EZTools")) {
    Write-Host "[*] Making directory EZTools..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\EZTools"
    
    Write-Host "[*] Downloading EZTools..."
    $url="https://f001.backblazeb2.com/file/EricZimmermanTools/Get-ZimmermanTools.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\EZTools\EZTools.zip")

    Write-Host "[*] Extracting EZTools zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\EZTools\EZTools.zip" -DestinationPath "$INSTALL_LOCATION\EZTools"

    Write-Host '[*] Removing EZTools zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\EZTools\EZTools.zip"

    Write-Host '[*] Downloading all Eric Zimmerman forensics tools...'
    cd "$INSTALL_LOCATION\EZTools"
    .\Get-ZimmermanTools.ps1 -Dest .
}

if ( -Not (Get-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced").GetValue("ShowSecondsInSystemClock")) { 
	Write-Host "[*] Setting ShowSecondsInSystemClock value to ensure that seconds are visible..." 
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Value "1" -PropertyType DWORD
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\WindowsEventsToCSVTimeline")) {
    Write-Host "[*] Making directory WindowsEventsToCSVTimeline..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\WindowsEventsToCSVTimeline"
    
    Write-Host "[*] Downloading WindowsEventsToCSVTimeline..."
    $url = "https://github.com/piesecurity/WindowsEventsToCSVTimeline/archive/refs/heads/master.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\WindowsEventsToCSVTimeline\WindowsEventsToCSVTimeline.zip")

    Write-Host "[*] Extracting WindowsEventsToCSVTimeline zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\WindowsEventsToCSVTimeline\WindowsEventsToCSVTimeline.zip" -DestinationPath "$INSTALL_LOCATION\WindowsEventsToCSVTimeline"

    Write-Host '[*] Removing WindowsEventsToCSVTimeline zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\WindowsEventsToCSVTimeline\WindowsEventsToCSVTimeline.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\hayabusa")) {
    Write-Host "[*] Making directory hayabusa..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\hayabusa"
    
    Write-Host "[*] Downloading hayabusa..."
    $url = "https://github.com/Yamato-Security/hayabusa/releases/download/v3.0.1/hayabusa-3.0.1-win-x64-live-response.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\hayabusa\hayabusa.zip")

    Write-Host "[*] Extracting hayabusa zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\hayabusa\hayabusa.zip" -DestinationPath "$INSTALL_LOCATION\hayabusa"

    Write-Host '[*] Removing hayabusa zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\hayabusa\hayabusa.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\crowdstrike-crt")) {
    Write-Host "[*] Making directory crowdstrike-crt..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\crowdstrike-crt"
    
    Write-Host "[*] Downloading crowdstrike-crt..."
    $url = "https://github.com/CrowdStrike/CRT/archive/refs/heads/main.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\crowdstrike-crt\crowdstrike-crt.zip")

    Write-Host "[*] Extracting crowdstrike-crt zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\crowdstrike-crt\crowdstrike-crt.zip" -DestinationPath "$INSTALL_LOCATION\crowdstrike-crt"

    Write-Host '[*] Removing crowdstrike-crt zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\crowdstrike-crt\crowdstrike-crt.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\processhacker")) {
    Write-Host "[*] Making directory processhacker..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\processhacker"
    
    Write-Host "[*] Downloading processhacker..."
    $url = "https://github.com/manasmbellani/splunkfiles/raw/refs/heads/master/processhacker-2.39-bin.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\processhacker\processhacker.zip")

    Write-Host "[*] Extracting processhacker zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\processhacker\processhacker.zip" -DestinationPath "$INSTALL_LOCATION\processhacker"

    Write-Host '[*] Removing processhacker zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\processhacker\processhacker.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\bmc-tools")) {
    Write-Host "[*] Making directory bmc-tools..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\bmc-tools"
    
    Write-Host "[*] Downloading bmc-tools..."
    $url = "https://github.com/ANSSI-FR/bmc-tools/archive/refs/heads/master.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\bmc-tools\bmc-tools.zip")

    Write-Host "[*] Extracting bmc-tools zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\bmc-tools\bmc-tools.zip" -DestinationPath "$INSTALL_LOCATION\bmc-tools"

    Write-Host '[*] Removing bmc-tools zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\bmc-tools\bmc-tools.zip"
}

if(-Not (Test-Path "$INSTALL_LOCATION\VisualStudio")) {
    Write-Host "[*] Making directory VisualStudio..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\VisualStudio"

    Write-Host "[*] Downloading VS Community Binary installer..."
    $url = "https://aka.ms/vs/17/release/vs_community.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\VisualStudio\vs_community.exe")
}

if(-Not (Test-Path "$INSTALL_LOCATION\mo2007")) {
    Write-Host "[*] Making directory mo2007..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\mo2007"

    Write-Host "[*] Downloading mo 2007 binary installer..."
    $url = "https://github.com/manasmbellani/splunkfiles/raw/master/mo2007.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\mo2007\mo2007.zip")
}

if(-Not (Test-Path "$INSTALL_LOCATION\Trawler")) {
    Write-Host "[*] Making directory Trawler..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\Trawler"

    Write-Host "[*] Downloading Trawler..."
    $url = "https://github.com/joeavanzato/Trawler/archive/refs/heads/main.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\Trawler\Trawler.zip")

    Write-Host "[*] Extracting Trawler zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\Trawler\Trawler.zip" -DestinationPath "$INSTALL_LOCATION\Trawler"

    Write-Host '[*] Removing Trawler zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\Trawler\Trawler.zip"
}

if(-Not (Test-Path "$INSTALL_LOCATION\PersistenceSniper")) {
    Write-Host "[*] Making directory PersistenceSniper..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\PersistenceSniper"

    Write-Host "[*] Downloading PersistenceSniper..."
    $url = "https://github.com/last-byte/PersistenceSniper/archive/refs/heads/main.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\PersistenceSniper\PersistenceSniper.zip")

    Write-Host "[*] Extracting PersistenceSniper zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\PersistenceSniper\PersistenceSniper.zip" -DestinationPath "$INSTALL_LOCATION\PersistenceSniper"

    Write-Host '[*] Removing PersistenceSniper zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\PersistenceSniper\PersistenceSniper.zip"
}

if(-Not (Test-Path "$INSTALL_LOCATION\MemProcFS")) {
    Write-Host "[*] Making directory MemProcFS..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\MemProcFS"

    Write-Host "[*] Downloading MemProcFS..."
    $url = "https://github.com/ufrisk/MemProcFS/releases/download/v5.13/MemProcFS_files_and_binaries_v5.13.3-win_x64-20241218.zip"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\MemProcFS\MemProcFS.zip")

    Write-Host "[*] Extracting MemProcFS zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\MemProcFS\MemProcFS.zip" -DestinationPath "$INSTALL_LOCATION\MemProcFS"

    Write-Host '[*] Removing MemProcFS zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\MemProcFS\MemProcFS.zip"
}

if(-Not (Test-Path "$INSTALL_LOCATION\FTKImager")) {
    Write-Host "[*] Making directory FTKImager..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\FTKImager"

    Write-Host "[*] Downloading FTKImager..."
    $url = "https://github.com/manasmbellani/splunkfiles/raw/refs/heads/master/AccessData_FTK_Imager_4.7.1.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\FTKImager\FTKImager.exe")
}

if(-Not (Test-Path "$INSTALL_LOCATION\Dokan")) {
    Write-Host "[*] Making directory Dokan..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\Dokan"

    Write-Host "[*] Downloading Dokan..."
    $url = "https://github.com/dokan-dev/dokany/releases/download/v2.2.0.1000/DokanSetup.exe"
    (New-Object System.Net.WebClient).DownloadFile($url, "$INSTALL_LOCATION\Dokan\DokanSetup.exe")
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\chainsawRepo")) {
    Write-Host "[*] Making directory chainsawRepo..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\chainsawRepo"

    Write-Host "[*] Downloading chainsawRepo..."
    $url =  "https://github.com/WithSecureLabs/chainsaw/archive/refs/heads/master.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\chainsawRepo\chainsawRepo.zip")

    Write-Host "[*] Extracting chainsawRepo zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\chainsawRepo\chainsawRepo.zip" -DestinationPath "$INSTALL_LOCATION\chainsawRepo"

    Write-Host '[*] Removing chainsawRepo zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\chainsawRepo\chainsawRepo.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\TakaJo")) {
    Write-Host "[*] Making directory TakaJo..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\TakaJo"

    Write-Host "[*] Downloading TakaJo..."
    $url =  "https://github.com/Yamato-Security/takajo/releases/download/v2.7.1/takajo-2.7.1-win-x64.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\TakaJo\TakaJo.zip")

    Write-Host "[*] Extracting TakaJo zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\TakaJo\TakaJo.zip" -DestinationPath "$INSTALL_LOCATION\TakaJo"

    Write-Host '[*] Removing TakaJo zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\TakaJo\TakaJo.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\macos-UnifiedLogs")) {
    Write-Host "[*] Making directory macos-UnifiedLogs..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\macos-UnifiedLogs"

    Write-Host "[*] Downloading macos-UnifiedLogs..."
    $url =  "https://github.com/mandiant/macos-UnifiedLogs/releases/download/v0.1.1/unifiedlog_iterator-v0.1.1-x86_64-pc-windows-msvc.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\macos-UnifiedLogs\macos-UnifiedLogs.zip")

    Write-Host "[*] Extracting macos-UnifiedLogs zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\macos-UnifiedLogs\macos-UnifiedLogs.zip" -DestinationPath "$INSTALL_LOCATION\macos-UnifiedLogs"

    Write-Host '[*] Removing macos-UnifiedLogs zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\macos-UnifiedLogs\macos-UnifiedLogs.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\RawCopy")) {
    Write-Host "[*] Making directory RawCopy..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\RawCopy"

    Write-Host "[*] Downloading RawCopy..."
    $url =  "https://github.com/jschicht/RawCopy/archive/refs/heads/master.zip"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\RawCopy\RawCopy.zip")

    Write-Host "[*] Extracting RawCopy zip file..."
    Expand-Archive -Path "$INSTALL_LOCATION\RawCopy\RawCopy.zip" -DestinationPath "$INSTALL_LOCATION\RawCopy"

    Write-Host '[*] Removing RawCopy zip file...'
    Remove-Item -Path "$INSTALL_LOCATION\RawCopy\RawCopy.zip"
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\Edit-Clipboard-Contents")) {
    Write-Host "[*] Making directory Edit-Clipboard-Contents..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\Edit-Clipboard-Contents"

    Write-Host "[*] Downloading Edit-Clipboard-Contents..."
    $url =  "https://github.com/ThioJoe/Edit-Clipboard-Contents/releases/download/v1.6.2/EditClipboardContents_1.6.2.exe"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\Edit-Clipboard-Contents\Edit-Clipboard-Contents.exe")
}

if (-Not (Test-Path -Path "$INSTALL_LOCATION\azcli")) {
    Write-Host "[*] Making directory azcli..."
    New-item -ItemType Directory -Path "$INSTALL_LOCATION\azcli"

    Write-Host "[*] Downloading azcli..."
    $url =  "https://aka.ms/installazurecliwindowsx64"
    (New-Object System.Net.WebClient).DownloadFile("$url", "$INSTALL_LOCATION\azcli\azcli.msi")

    Write-Host "[*] Installing azcli from .msi silently..."
    $command="msiexec.exe /I $INSTALL_LOCATION\azcli.msi /quiet"
    Invoke-Expression "& $command"

    Write-Host "[*] Installing azcli via powershell silently and remove .msi..."
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi
    Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'
    Remove-Item .\AzureCLI.msi

    Write-Host "[*] Sleeping for $SLEEP_TIME seconds for azcli to install..."
    sleep "$SLEEP_TIME"
}

If (-Not (Test-Path "$INSTALL_LOCATION\flag-certservice-audit")) {
    Write-Host "[*] Making flag-certservice-audit to state that audit logging has been configured for ADCS..."
    New-Item -ItemType File -Path "$INSTALL_LOCATION\flag-certservice-audit"

    Write-Host "[*] Enabling auditing for ADCS..."
    $command = '& certutil -setreg CA\AuditFilter 127'
    Invoke-Expression "$command"
    
    Write-Host "[*] Restarting certsvc service for auditing of ADCS to take effect..."
    $command = '& net stop certsvc'
    Invoke-Expression "$command"

    $command = '& net start certsvc'
    Invoke-Expression "$command"

    Write-Host "[*] Validating CA/AuditFilter setting..."
    certutil -getreg CA\AuditFilter
}
    
If (-Not (Test-Path "$INSTALL_LOCATION\flag-audit-config")) {
    Write-Host "[*] Making flag-audit-config to state that audit logging has been configured..."
    New-Item -ItemType File -Path "$INSTALL_LOCATION\flag-audit-config"

    Write-Host "[*] Enabling account logoon audit policy..."
    $command='& auditpol /set /category:"Account Logon" /success:enable /failure:enable'
    Invoke-Expression "$command"

    Write-Host "[*] Enabling DS Access audit policy..."
    $command='& auditpol /set /category:"DS Access" /success:enable /failure:enable'
    Invoke-Expression "$command"

    Write-Host "[*] Enabling Account Management audit policy..."
    $command='& auditpol /set /category:"Account Management" /success:enable /failure:enable'
    Invoke-Expression "$command"

    Write-Host "[*] Enabling Policy Change audit policy..."
    $command='& auditpol /set /category:"Policy Change" /success:enable /failure:enable'
    Invoke-Expression "$command"

    Write-Host "[*] Enabling Object Access (including ADCS if enabled) audit policy..."
    $command='& auditpol /set /category:"Object Access" /success:enable /failure:enable'
    Invoke-Expression "$command"

    Write-Host "[*] Enabling Logon/Logoff audit policy..."
    $command='& auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable'
    Invoke-Expression "$command"

    Write-Host "[*] Enabling System audit policy..."
    $command='& auditpol /set /category:"System" /success:enable /failure:enable'
    Invoke-Expression "$command"

    Write-Host "[*] Enabling Privilege Use policy..."
    $command='& auditpol /set /category:"Privilege Use" /success:enable /failure:enable'
    Invoke-Expression "$command"

    Write-Host "[*] Enable Process Creation Events policy..."
    $command='& auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable'
    Invoke-Expression "$command"

    Write-Host "[*] Showing all configured audit logging policies..."
    $command = '& auditpol /get /category:*'
    Invoke-Expression "$command"


    # Write-Host "[*] Showing all configured audit logging policies..."
    # $command = '& gpupdate /force'
    # Invoke-Expression "$command"
}

