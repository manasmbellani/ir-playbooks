# TODO
- Containment GCP Firewall
- Collection fast ir artifacts - https://github.com/OWNsecurity/fastir_artifacts
- Collection winpmem (rekall)
- Collection dc3dd disk image
- Collection Encrypted Disk Detector to detect encrypted disks https://www.magnetforensics.com/resources/encrypted-disk-detector/, https://www.raedts.biz/forensics/should-you-pull-the-plug/
- collection kapefiles via velociraptor
- collection windows memory acquisition vis velociraptor
- Analysis Add processing of programs from prefetch folder for file path, execution counts etc
- Analysis Add shimcache windows execution artifact
- Analysis Add amcache database processing as it can also contain windows hash
- Analysis parse userassist registry key for parsing SHA hashes
- Analysis parse runMRU lists for windows file path executions 
- Analysis Add tips/tricks from guidance for incident responders https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf
- Analysis detect dhcp administrators group abuse priv esc https://x.com/directoryranger/status/1787223247169147306?s=46&t=WvGY79Umt5enRwgCbi4TQQ
- Analysis Detect hidden scheduled tasks via https://www.binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks/
- Analysis review results of Joshua pager's resources https://github.com/bouj33boy/Domain-Persistence-Detection-Triage-and-Recovery-SO-CON-2024
- Analysis Detect DPAPI Backup key detection which encrypts everything in DC  if not rebuilding DC https://www.dsinternals.com/en/dpapi-backup-key-theft-auditing/
- Analysis Detect Browser Theft via Windows Audit Logging https://security.googleblog.com/2024/04/detecting-browser-data-theft-using.html
- Analysis Detect DLL Hijacking via sysmon (Event ID 7 Image Loaded) logs where DLL is unsigned and loaded from unusual locations
- Analysis Detect managed (.NET running code) via process hacker (green) - injection of `clr.dll` and `clrjit.dll` DLLs (Sysmon Event ID 7)
- Analysis filtering events in events viewer via XML
```<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4907)]]
      and
      *[EventData[Data[@Name='ObjectName'] and (Data='C:\test.txt')]]
    </Select>
  </Query>
</QueryList>
```
- Analysis dump bitlocker keys from EntraID - https://x.com/nathanmcnulty/status/1785094215749476722?s=46&t=WvGY79Umt5enRwgCbi4TQQ
- Analysis add Windows artefacts from Qazeer https://notes.qazeer.io/dfir/windows/_artefacts_overview
- Analysis Detect varioys technuques from Samuel r's detections https://github.com/Sam0x90/CB-Threat-Hunting
- Analysis Detect Remote Logins via Windows Event Logs' 4624 (type 3 / type 10)
- Analysis Detect ROP Binary Attacks via Windows Defender Logs' `Microsoft-Windows-Security-Mitigations/UserMode` https://amr-git-dot.github.io/forensic%20investigation/EventLog_Analysis/#service-manipulation
- Analysis Detect Brute-force attacks via Windows Event Logs (4625)
- Analysis Detect service manipulation via Sysmon Event ID by looking for sc.exe invocation
- Analysis Detect office phishing via Sysmon Event ID 1 for child processes spawned from Word/Excel 
- Analysis techniques from Microsoft IR guide https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf
- Analysis add detection techniques from Jai Minton's cheatsheet https://www.jaiminton.com/cheatsheet/DFIR/#
- Analysis detect various techniques from red team notes - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials
- Analysis Detect SCCM site abuse
- Analysis Detect cred theft from LSASS via process creation (sysmon/1), process requested handle (windows/4663,4656), process handle (sysmom/10), process read memory (EDR)
- Analysis Detect NTDS Access via via process requested handle to NTDS.dit (Security/4656,4663), VSS service starts (System/7036), Shadow Copy Creation (Security/8222, Sysmon 11)
- Analysis Detect NTDS Access through lolbas via sysmon/1: https://lolbas-project.github.io/#ntds
- Analysis Detect Detect lolbas usage vis sysmon/1: https://lolbas-project.github.io/
- Analysis Detect DCSync Attack
- Analysis Detect Golden Ticket via Windows Event Logs - 4769 (TGS ticket) without 4768 (TGT requested), elevated perms detection via 4627 (Group membership), klist validation via Rebeus
- Analysis Detect Diamond tickets via windows event logs with unusual lifespan such as Kerberos ticket  10 years?
- Analysis detect silver tickets
- Analysis Detect ADCS theft Abuse via windows event logs for key operation access (security/5058, security/5061), key operation export (security/5059), cert backup (security/4876, security/4877), object access (security/4663 if sacl enabled)
- Analysis Parse NTDS.dit file via ntdsdissector - https://github.com/synacktiv/ntdissector
- Analysis Extract browser passwords from external path https://www.nirsoft.net/utils/chromepass.html
- Analysis Detect Windows File share events `eventid:5140` via chainsaw
- Analysis analyse srum and shimcache to build timelines via chainsaw
- Analysis Detect SID History Injection attack (see sigma) https://github.com/NVISOsecurity/sigma-public/blob/master/rules/windows/builtin/win_susp_add_sid_history.yml 
- Analysis USB Forensics
- Analysis ProxyNotShell Detection https://www.securonix.com/blog/proxynotshell-revisited/, https://www.logpoint.com/en/blog/proxynotshell-detecting-exploitation-of-zero-day-exchange-server-vulnerabilities/
- Analysis DFIR Cheatsheet by Jai Minton https://www.jaiminton.com/cheatsheet/DFIR/#disable-remote-printing-printnightmare-rce-mitigation
- Analysis hiberfil.sys, pagefile.sys https://www.hackingarticles.in/forensic-investigation-pagefile-sys/
- Analysis Look for interesting files created via sysmon eg for ElasticSearch:
```
_index:"*winlogbeat*" AND host.hostname:"alice-pc" AND event.code:11 AND NOT (winlog.event_data.TargetFilename: "C:\\ProgramData\\*" OR winlog.event_data.TargetFilename: "C:\\Users\\alice\\AppData\\Local\\Packages\\*" OR winlog.event_data.TargetFilename: "C:\\Windows\\Prefetch\\*" OR winlog.event_data.TargetFilename: "C:\\Windows\\System32\\*" OR winlog.event_data.TargetFilename: "D:\\CollectGuestLogsTemp\\*" OR winlog.event_data.TargetFilename:"C:\\Users\\alice\\AppData\\Local\\Microsoft\\*")
```
- Analysis add USB Forensics from LetsDefend
- Analysis Add BTFM checks https://github.com/tom0li/collection-document/blob/master/Blue%20Team%20Field%20Manual.pdf
- Analysis MPLogfile for analysis https://www.crowdstrike.com/blog/how-to-use-microsoft-protection-logging-for-forensic-investigations/
- Analysis Add techniques from practical windows forensics "O'Reilly"
- Analysis check if multiple trusts involved `(event.code:4624 OR event.code:4768 OR event.code:4769)` and observe domains returned
- Analysis dfir mitre tactics various forensics techniques https://ondrej-sramek.gitbook.io/security/forensics/untitled
- Analysis dfir mitre tactics registry keys detection https://s0cm0nkey.gitbook.io/s0cm0nkeys-security-reference-guide/dfir-digital-forensics-and-incident-response/windows-dfir-check-by-mitre-tactic
- Analysis UsnJrnl analysis via velociraptor https://docs.velociraptor.app/blog/2020/2020-11-13-the-windows-usn-journal-f0c55c9010e/
- Analysis Various tools for Forensic Analysis https://svch0st.medium.com/forensics-tools-by-windows-artefact-cheat-sheet-9517fd1d6e45
- Analysis Add detection for Safebreach-labs/EDRaser on github
- Analysis Recover deleted files via VSC, Magnet Axiom ("Windows Forensics Cookbook")
- Analysis Recover deleted files via volume shadow copy and mklink+vssadmin from disk images. "Windows Forensics Cookbook"
- Analysis recover deleted files via VSC, nirsoft's shadowcopyview
- Analysis recover deleted files via reclaime in Windows ReFS
- Analysis recover deleted files via photorec
- Analysis Recover deleted files via Autopsy (Embedded File Extractor) plugin
- Analysis Use plaso create windows timeline https://notes.qazeer.io/dfir/tools/plaso
- Analysis use mactime to create windows timeline
- Analysis Arsenal Image Mounter
- Analysis Reconstructing powershell scripts https://news.sophos.com/en-us/2022/03/29/reconstructing-powershell-scripts-from-multiple-windows-event-logs/
- Analysis Windows Event Log analysis via sysmon/powershell, also some interesting event types available monitoring https://amr-git-dot.github.io/forensic%20investigation/EventLog_Analysis/
- Analysis Sleuthkit disk analysis mmstat,mmls,fsstat,fls,mactime
- Analysis Recreate OneDrive Folders OneDriveExplorer https://github.com/Beercow/OneDriveExplorer
- Analysis Evil WMI Event Consumers , https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics/?utm_medium=Social&utm_source=LinkedIn&utm_campaign=DFIR%20CaseLeads%20Newsletter
- Analysis Volatility Memory Analysis for fun and profit https://www.linkedin.com/posts/kinjalpatel12_memory-analysis-for-fun-and-profitpdf-activity-7170390235028115456-p02R
- Analysis RDP Bitmap Cache Files `C:\Users\CyberJunkie\AppData\Local\Microsoft\Terminal Server Client\Cache`, https://github.com/ANSSI-FR/bmc-tools
- Analysis [Azure CLI Forensic](https://www.inversecos.com/2023/03/azure-command-line-forensics-host-based.html?m=1)
- Analysis Volatility dllist unusual DLLs (eg stucnet .aslr.dll?)
- Analysis get windows version winver
- Analysis get windows version systeminfo
- Analysis volatility find+dump injected code malfind
- Analysis volatility duplicate processes (eg lsass.exe/stuxnet), imageinfo
- Analysis collect windows logs
- Analysis OpenArk review tools
- Analysis check scheduled tasks via windows event logs: security 4698, task scheduler 106 - https://www.binarydefense.com/resources/blog/diving-into-hidden-scheduled-tasks/
- Analysis Detect RDP Sessions
- Analysis check network connections
- Analysis Check powershell code execution
- Analysis Detect Bitlocker Encryption https://arcpointforensics.medium.com/bitlocker-detection-from-the-command-line-53b3a8df7c9e 
- Analysis PCAParse http://windowsir.blogspot.com/2024/02/pcaparse.html?m=1
- Analysis EDRSilencer Detection https://blog.p1k4chu.com/security-research/adversarial-tradecraft-research-and-detection/edr-silencer-embracing-the-silence
- Analysis MTCH threat hunt keywords
- Analysis FOR500 SANS
- Analysi Coercer / NTLM Relay detection https://www.linkedin.com/pulse/petitpotam-dfscoerce-ntlm-relay-attack-detection-debashis-pal?utm_source=share&utm_medium=member_ios&utm_campaign=share_via
- Analysis/Collection - Detect SCCM attacks https://github.com/subat0mik/Misconfiguration-Manager/blob/main/README.md
- Recovery Enable Credential Guard to prevent lsass memory dumping leading to creds
- Recovery OsQuery
- Recovery LDAP Queries for offensive and Defensive Operations https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
