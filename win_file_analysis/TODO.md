# TODO

- Static Analysis yara rules via yara or powershell
```
$rules = Get-ChildItem C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\rules | Select-Object -Property Name
foreach ($rule in $rules) {C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\yara64.exe C:\Users\johndoe\Desktop\yara-4.3.2-2150-win64\rules\$($rule.Name) C:\Users\johndoe\Desktop\pid.3648.dmp}
```
- Static Analysis strings
- Static Analysis decompilation via Dogbolt's Decompiler Explorer: https://dogbolt.org/?id=20529e0a-a2d1-4aa4-8932-3bcc7fb847c9#Hex-Rays=1321
- Dynamic Analysis Use SilkETW for malware detection e.g SeatBelt https://github.com/pathtofile/Sealighter
- Dynamic Analysis Observe the called APIs via API Monitor
- Dynamic Analysis Observe the called APIs via ProcMon
