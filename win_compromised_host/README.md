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

## Containment

TBC

## Collection

### Live Collection

To collect live RAM, we can leverage the `Belkasoft RAM Capturer` available from download [here](https://belkasoft.com/ram-capturer) and initiate the appropriate x64 bin from a remote USB disk. The memory image is then stored on this remote disk too, say `F:`

Alternatively, we can also leverage `DumpIt.exe` provided by `Magnet Forensics` as part of its `Comae Toolkit` available [here](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/) to collect live RAM from the compromised host for analysis.
```
.\DumpIt.exe
```

## Analysis

This section covers a variety of techniques which can be used for both live and offline analysis.

In case of live analysis, we have ability to connect a USB stick to the contained instance with tools running on the USB stick. 

Note that majority of the steps described in `Offline / Disk Analysis` could be performed in `Live Analysis` as well by copying the binaries to the USB stick and attaching it to the compromised instance.

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

#### via volatility2 / malfind

```
source /opt/volatility2/venv/bin/activate
python2.7 /opt/volatility2/vol.py --profile=WinXPSP2x86 -f /root/TEST-WIN-INSTAN-20240315-062005.raw malfind
deactivate
```

#### via volatility2 / psxview

See [here](#via-volatility2--psxview)

#### via sysmon logs / Process Create (Event ID 1)

Check the parent process in Sysmon Logs for suspicious Process Create (Event ID 1) events such as `cmd.exe`, `powershell.exe`, `nc.exe`, etc. and look at unusual parent process such as `word.exe`, `.jar` files, etc.

Taken from [LetsDefend Log4J's RCE exercise](https://files-ld.s3.us-east-2.amazonaws.com/Alert-Reports/Log4j_RCE_Detected.pdf)

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

## Eradication

## Recovery
