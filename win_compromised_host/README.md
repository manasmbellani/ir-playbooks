# Windows - Compromised Host

## Containment

## Collection

### Pre-requisites

### Forensics Instance Setup

#### Windows

For the Forensics instance, we deploy a Windows instance and execute the [script](./InstallForensicsDeps.ps1) which will install all the necessary forensic tools discussed here. The script can also be modified to install most dependencies on a USB stick instead by editing the `INSTALL_LOCATION` variable.

Live memory images or disk images taken from the compromised instance can then be attached to the instance for analysis. Alternatively, USB sticks can be attached to the instance for live analysis.

#### Ubuntu
For the Forensics instance, we deploy an Ubuntu 22.04 instance and execute the [script](./install_forensics_deps.sh) which will install all the necessary forensic tools discussed here. Live memory images or disk images taken from the compromised instance can then be attached to this instance for analysis

### Containment

TBC

### Live Collection

To collect live RAM, we can leverage the `Belkasoft RAM Capturer` available from download [here](https://belkasoft.com/ram-capturer) and initiate the appropriate x64 bin from a remote USB disk. The memory image is then stored on this remote disk too, say `F:`

Alternatively, we can also leverage `DumpIt.exe` provided by `Magnet Forensics` as part of its `Comae Toolkit` available [here](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/) to collect live RAM from the compromised host for analysis.
```
.\DumpIt.exe
```

## Analysis

### Live Analysis

In case of live analysis, we have ability to connect a USB stick to the contained instance with tools running on the USB stick. 

#### WMI Event Consumers Analysis

To detect malicious event consumers, we can use `WMIExplorer` to examine the current machine's WMI Event Consumers

### Offline Analysis

#### Memory Analysis

In this section, we process the live `.raw` memory image file collected via tools such as `DumpIt` or `Belkasoft RAM Capturer` through tools like `volatility3`

#### Process Tree

We are able to review the live `.raw` RAM collected via any of the live collection methods using volatility3 with commands as follows via `volatility3` to list current processes:
```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/TEST-WIN-INSTAN-20240315-062005.raw windows.pslist.PsList windows.pslist.PsList
deactivate
```

We are also able to see the process from live `.raw` RAM as a tree like structure using `volatility3`:
```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/TEST-WIN-INSTAN-20240315-062005.raw windows.pslist.PsList windows.pstree.PsTree
deactivate
...
******* 1244    5220    PsExec.exe      0xcf830d644080  6       -       2       True    2024-03-15 06:19:57.000000      N/A     \Device\HarddiskVolume3\Users\manasbellani\Downloads\SysinternalsSuite\PsExec.exe   PsExec.exe  -s -i cmd.exe       C:\Users\manasbellani\Downloads\SysinternalsSuite\PsExec.exe
...
```

#### Disk Analysis


#### Google Chrome Notifications

If Google Chrome is in use and Notifications are enabled for website, then historical notifications are usually available in the `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Platform Notifications` as LevelDB Database. Extract the file and determine the clear-text notifications that a user may have received via `strings` or `xxd`. More info available [here](https://www.sans.org/blog/google-chrome-platform-notification-analysis/), [here](https://www.linkedin.com/pulse/investigating-abusive-push-notification-browsers-chrome-jimmy-remy/) and the structure of the LevelDB database is described [here](https://sansorg.egnyte.com/dl/QaoN3qdhig)

```
strings MANIFEST/*
strings *.ldb
```

## Eradication

## Recovery

## TODO
- Collection fast ir artifacts - https://github.com/OWNsecurity/fastir_artifacts
- Collection winpmem (rekall)
- Collection FTK Imager fisk image
- Collection dc3dd disk image
- Analysis Recreate OneDrive Folders OneDriveExplorer https://github.com/Beercow/OneDriveExplorer
- Analysis Evil WMI Event Consumers https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics/?utm_medium=Social&utm_source=LinkedIn&utm_campaign=DFIR%20CaseLeads%20Newsletter
- Analysis Volatility Memory Analysis for fun and profit https://www.linkedin.com/posts/kinjalpatel12_memory-analysis-for-fun-and-profitpdf-activity-7170390235028115456-p02R
- Analysis RDP Bitmap Cache Files `C:\Users\CyberJunkie\AppData\Local\Microsoft\Terminal Server Client\Cache`, https://github.com/ANSSI-FR/bmc-tools
- Analysis [Azure CLI Forensic](https://www.inversecos.com/2023/03/azure-command-line-forensics-host-based.html?m=1)
- Analysis Volatility dllist unusual DLLs (eg stucnet .aslr.dll?)
- Analysis KAPE
- Analysis get windows version winver
- Analysis get windows version systeminfo
- Analysis volatility find+dump injected code malfind
- Analysis volatility duplicate processes (eg lsass.exe/stuxnet), imageinfo
- Analysis collect windows logs
- Analysis OpenArk review tools
- Analysis check scheduled tasks
- Analysis Detect RDP Sessions
- Analysis check network connections
- Analysis Check powershell code execution
- Analysis Detect Bitlocker Encryption https://arcpointforensics.medium.com/bitlocker-detection-from-the-command-line-53b3a8df7c9e 
- Analysis PCAParse http://windowsir.blogspot.com/2024/02/pcaparse.html?m=1
- Analysis EDRSilencer Detection https://blog.p1k4chu.com/security-research/adversarial-tradecraft-research-and-detection/edr-silencer-embracing-the-silence
- Analysis MTCH threat hunt keywords
- Analysis FOR500 SANS
- Analysis/Collection - Detect SCCM attacks https://github.com/subat0mik/Misconfiguration-Manager/blob/main/README.md
