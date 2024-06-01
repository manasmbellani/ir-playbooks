# TODO

- Static Analysis yara rules via yara or powershell
```
$rules = Get-ChildItem C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\rules | Select-Object -Property Name
foreach ($rule in $rules) {C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\yara64.exe C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\rules\$($rule.Name) C:\Users\johndoe\Desktop\pid.3648.dmp}
```
- Static Analysis Analyse rust malware https://www.binarydefense.com/resources/blog/digging-through-rust-to-find-gold-extracting-secrets-from-rust-malware/
- Static Analysis Capture etw logging via etwinspector https://github.com/jsecurity101/ETWInspector
- Static Analysis decompilation via Dogbolt's Decompiler Explorer: https://dogbolt.org/?id=20529e0a-a2d1-4aa4-8932-3bcc7fb847c9#Hex-Rays=1321
- Static Analysis Decrypt sourcedefender encrypted files via sourcerestorer https://github.com/Lazza/SourceRestorer
- Static Analysis Analyse malicious OneNote documents https://github.com/knight0x07/OneNoteAnalyzer
- Static Analysis Use pdf bmp preview Images and office xml files to identify more samples in wild https://blog.virustotal.com/2024/05/tracking-threat-actors-using-images-and.html
- Dynamic Analysis Review custom logs in Splunk through Ingestion via splunk4dfir https://github.com/mf1d3l/Splunk4DFIR
- Dynamic Analysis Use SilkETW for malware detection e.g SeatBelt https://github.com/pathtofile/Sealighter
- Dynamic Analysis Observe the called APIs via API Monitor
- Dynamic Analysis Observe the called APIs via ProcMon
