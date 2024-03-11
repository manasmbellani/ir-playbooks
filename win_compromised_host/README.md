# Windows - Compromised Host

## Containment

## Collection

### Live Collection

To collect live RAM, we can leverage the `Belkasoft RAM Capturer` available from download [here](https://belkasoft.com/ram-capturer) and initiate the appropriate x64 bin from a remote USB disk. The memory image is then stored on this remote disk too, say `F:`

Alternatively, we can also leverage `DumpIt.exe` provided by `Magnet Forensics` as part of its `Comae Toolkit` available [here](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/) to collect live RAM from the compromised host for analysis.
```
.\DumpIt.exe
```

## Analysis

### Live Analysis

We are able to review the live RAM collected via any of the live collection methods using volatility3 with commands as follows via `volatility` to list current process:
```
cd C:\Users\Administrator\Desktop\volatility3
source venv\Scripts\activate
python3 .\vol.py -f F:\20240310.mem windows.pslist.PsList
deactivate
```

## Eradication

## Recovery

## TODO
- Collection - fast ir artifacts - https://github.com/OWNsecurity/fastir_artifacts
- Analysis RDP Bitmap Cache Files `C:\Users\CyberJunkie\AppData\Local\Microsoft\Terminal Server Client\Cache`, https://github.com/ANSSI-FR/bmc-tools
- Analysis [Azure CLI Forensic](https://www.inversecos.com/2023/03/azure-command-line-forensics-host-based.html?m=1)
- Analysis KAPE
- Analysis checj scheduled tasks
- Analysis Detect RDP Sessions
- Analysis check network connections
- Analysis Check powershell code execution
- Analysis Detect Bitlocker Encryption https://arcpointforensics.medium.com/bitlocker-detection-from-the-command-line-53b3a8df7c9e 
- Analysis PCAParse http://windowsir.blogspot.com/2024/02/pcaparse.html?m=1
- Analysis EDRSilencer Detection https://blog.p1k4chu.com/security-research/adversarial-tradecraft-research-and-detection/edr-silencer-embracing-the-silence
- Analysis MTCH threat hunt keywords
- Analysis FOR500 SANS
