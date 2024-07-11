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

### Detection of Active Directory Certificate Services Abuse - SAN Template Certificates (ESC1)

- Typically, Extended Key Usage (EKU) attributes are used to define how a Public-private key pair generate for a user  can be used.
- Compromise Type 1: If attacker steals Bob’s private key and certificate, and the certificate has an authentication EKU, the attacker can authenticate to the AD domain without knowing Bob’s password
- Compromise Type 2 (ESC1): If a template with an authentication EKU lets low-privilege users specify SANs, an attacker can authenticate as any user in the SAN (eg for a cert with user "Alice", attacker can specify a domain admin account e.g. ace@aceresponder.com)
- Pre-requistes for ESC1:
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
EventID = 4768
Channel = Security
Description = A Kerberos Authentication Ticket was requested
Certificate Information.Certificate Issuer Name = *
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

Can be a persistence mechanism for threat actors

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

### via various methods for created and deleted files

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

### Network Connections / Sockets

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

### Command Lines

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

Taken from [LetsDefend Log4J's RCE exercise](https://files-ld.s3.us-east-2.amazonaws.com/Alert-Reports/Log4j_RCE_Detected.pdf)

#### via chainsaw / sigma

Detects any unusual activity from loaded sigma rules. More examples available [here](https://github.com/WithSecureLabs/chainsaw?tab=readme-ov-file#command-examples-1)
```
C:\Users\Administrator\Desktop\opt\chainsaw\chainsaw\chainsaw.exe hunt C:\Windows\Temp\Logs -s C:\Users\Administrator\Desktop\opt\sigma\sigma-master -r C:\Users\Administrator\Desktop\opt\sigma\sigma-master\rules --mapping C:\Users\Administrator\Desktop\opt\chainsaw\chainsaw\mappings\sigma-event-logs-all.yml --csv --output C:\Windows\Temp\out.csv
```

### Identify Downloaded files

Certain actions such as LSA Dumping can also write files to this location

#### via Explorer

See following locations:
- C:\Windows\Temp
- C:\Users\$USER_ID\Desktop
- C:\Users\$USER_ID\Downloads
- C:\Users\$USER_ID\AppData\Local\Temp

#### via Sysmon Windows Event ID 11 / File Create Event

```
# 'TargetFileName' contains the path to the new file being written
Event ID = 11
Channel = Microsoft-Windows-Sysmon/Operational
Description = File Created
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

### Get File Handles opened by process

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

### Check for installed applications 

Look for any applications running as servers and that could be exploited

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

### Check various Installed Application Logs

- Can provide indications of any exploits especially for running servers such as TightVNC, Mail servers, etc.

#### via Program Files 

Common location for logs:
- Minecraft: `C:\Users\LetsDefend\Desktop\Minecraft Server 1.12.2\logs`

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

#### via volatility3 / printkey

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
