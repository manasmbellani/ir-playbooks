# File Analysis

## Forensics Server Setup

### Ubuntu

Refer to the forensics servers setup [here](../gcp_compromised_pod/install_forensics_deps.sh) 

## Common

### Analyse the Clipboard Contents and Modify 

For Windows, see [here](../win_compromised_host/README.md#analyse-the-clipboard-contents-and-modify)

### Determine file type

#### via file

```
file $FILE_NAME
```

#### via trid

```
trid $FILE_NAME
```

### Network Analysis

#### via wireshark

```
wireshark
```

### Analyse interesting strings in binary 

#### via strings

```
strings bin.exe
strings -el bin.exe
strings -eL bin.exe
```

### Look for exif data / metadata

- Can be very useful for analysing `.lnk` files as well
  
#### via exiftool

```
exiftool img.jpeg
```

### Look for paths within binaries

#### via strings

Search using [strings](#via-strings) and look for `/home`, `/root`, `Users`, `Desktop`, `pdb` which can reveal the developer's name

See example for [rust](https://www.binarydefense.com/resources/blog/digging-through-rust-to-find-gold-extracting-secrets-from-rust-malware/)

### Look for embedded binaries

#### via binwalk

```
binwalk bin.exe
```

### Detect programming language

#### via strings / grep

Run `strings` as described [here](#via-strings) and look for keywords such as `rustc` 

### Decompile App

#### via IDA Pro

View > Show Disassembly

```
/opt/idafree-8.4/ida64
```

#### via binary ninja

Select View > Linear
Select Raw > Linear > Disassembly View
```
/opt/binaryninja/binaryninja/binaryninja bin.exe
```

#### via Ghidra

Window > Dissemble main 

```
ghidra
```

### Ransomware type detection

#### via ID Ransomware website

https://id-ransomware.malwarehunterteam.com/

#### via cryptosheriff

https://www.nomoreransom.org/crypto-sheriff.php?lang=en

#### via google search

can identify the ransomware type just by searching parts of README message on Google Search

#### via github search

can identify the ransomware type just by searching parts of README message on Github

### Determine Ransomware site links / victims

### via ransomlookup.io

Provides a screenshot of the Ransomware postings affecting various victims

https://www.ransomlook.io/

#### via ransomware.live

Provides a screenshot of the Ransomware postings affecting various victims

https://ransomware.live

#### via ransom watch

Provides links to ransomware links and posts

https://ransomwatch.telemetry.ltd/

Code based on: https://github.com/joshhighet/ransomwatch

#### via darkfeed.io / ransomwiki

https://darkfeed.io/ransomwiki/

#### via twitter / ransomwatcher

https://twitter.com/ransomwatcher
  
taken from: https://brandefense.io/top-ransomware-groups-and-monitoring-techniques/

#### via telegram / ransomwatch

https://t.me/ransomwatcher

#### via ransom.wiki

https://ransom.wiki

### Screenshot of Live Ransomware website

#### via Ransomware live

See [here](#via-ransomwarelive)

### Monitoring Ransomware sites / actors

#### via torbrowser_launcher

```
# Launch as default user
torbrowser-launcher
```

#### via onion browser / orbot mobile apps

Install `Onion Browser` and `Orbot` Mobile Apps

### Ransomware Decryption Tools

#### via github.com/ragnarok_decryptor

Decryption for rangarok ransomware

https://filebin.net/4jhdz2i306dpgvyh
https://github.com/manasmbellani/ragnarok_decrypter

#### via github/Cisco-Talos for tesladecrypt

Decryption for teslacrypt encrypted files

https://github.com/Cisco-Talos/TeslaDecrypt/releases/tag/1.0

#### via cryptosheriff

Provides links to various decryption tools for download

https://www.nomoreransom.org/en/decryption-tools.html

#### via Avast

Provides links to various decryption tools for download for different ransomware types

https://www.avast.com/ransomware-decryption-tools

#### via upguard

provides a list of various free websites which can be used for decryption for different ransomware types

https://www.upguard.com/blog/how-to-decrypt-ransomware

### Detect Malware signatures

#### via codebase-scanner

```
# codebase-scanner local ~/opt/ExtAnalysis/lab/samltracer
codebase-scanner local $FOLDER
```

#### via loki

```
# Scan files in /tmp/ directory
python3 /opt/loki/loki.py -p /tmp
```

#### via yara-x

```
# For scanning /tmp folder with Yara rules from /opt/signature-base
find /opt/signature-base -type f | xargs -I ARG /opt/yara-x/target/release/yr scan ARG /tmp
```

#### via yara

```
# For scanning /tmp folder with Yara rules from /opt/signature-base
find /opt/signature-base -type f | xargs -I ARG yara ARG /tmp/
```

### View file

#### via EZViewer

for .doc, .docx, .xls, .xlsx, .txt, .log, .rtf, .otd, .htm, .html, .mht, .csv, and .pdf.

```
C:\Users\Administrator\Desktop\opt\EZTools\net6\EZViewer\EZViewer.exe > Select file to open
```

## Windows .exe

## Macbook .app

## Linux .elf file

### Analyze system calls and identify IOCs

```
strace $BIN_NAME
```

https://dfir.ch/posts/strace/

## Microsoft Lnk file

### Get relative file path and absolute path pointed by .lnk files without opening file

#### via LECmd

```
cd C:\Users\Administrator\Desktop\opt\EZTools\net6
LECmd.exe -f $LNK_FILE
```

## Microsoft Office Files 

### Convert to Zip and search for interesting artifacts such as emails

- Look for unusual HTTP paths being called eg
```
# ignoring `http://openxml` paths as described  [here](https://www.4armed.com/blog/exploiting-xxe-with-excel/)
```

#### via grep / findstr

```
cp $FILENAME.docx $FILENAME.zip
unzip $FILENAME.zip
# In Windows, findstr /I /S *
grep -r -n -i -o -E "https?://" .
```

### Look for malicious macros in the files

#### via oleid

```
cd /opt/oletools
source venv/bin/activate
# eg oleid -a ~/samples/qakbot-malware-sample/qakbot.xlsx
oleid -a $SAMPLE_FILE
deactivate
```

https://github.com/decalage2/oletools/wiki/oleid

#### via olevba 

```
cd /opt/oletools
source venv/bin/activate
olevba ~/samples/qakbot-malware-sample/qakbot.xlsx
deactivate
```

https://github.com/decalage2/oletools/wiki/olevba

### Look for sector in a file

#### via olemap

```
cd /opt/oletools
source venv/bin/activate
# eg olemap -a ~/samples/qakbot-malware-sample/qakbot.xlsx
olemap -a $SAMPLE_FILE
deactivate
```

https://github.com/decalage2/oletools/wiki/olemap

#### via mraptor
```
cd /opt/oletools
source venv/bin/activate
# eg mraptor ~/samples/qakbot-malware-sample/qakbot.xlsx
mraptor $SAMPLE_FILE
deactivate
```

https://github.com/decalage2/oletools/wiki/mraptor

### Look for malicious DDE Links 

- Eg DDEAuto in files

#### via msodde

```
cd /opt/oletools
source venv/bin/activate
# eg msodde -a ~/samples/qakbot-malware-sample/qakbot.xlsx
msodde -a $SAMPLE_FILE
deactivate
```

https://github.com/decalage2/oletools/wiki/msodde

### Explore content & extract content of Office / OLE files


#### via oledump

- Easily identifies macros for you with letter 'm' or 'M'

```
cd /opt/oletools
source venv/bin/activate
# Lists all possible macros
python3 /opt/DidierStevensSuite/DidierStevensSuite/oledump.py ~/samples/qakbot-malware-sample/qakbot.xlsx
# Extract the macro
# Eg python3 /opt/DidierStevensSuite/DidierStevensSuite/oledump.py -v -s15 ~/samples/qakbot-malware-sample/qakbot.xlsx
python3 /opt/DidierStevensSuite/DidierStevensSuite/oledump.py -v -s$MACRO_ID $MALWARE_SAMPLE_FILE
deactivate
```

https://blog.didierstevens.com/programs/oledump-py/

#### via oledir

```
cd /opt/oletools
source venv/bin/activate
# eg msodde -a ~/samples/qakbot-malware-sample/qakbot.xlsx
oledir -a $SAMPLE_FILE
deactivate
```

https://github.com/decalage2/oletools/wiki/oledir

### Look for metadata for file

#### via olemeta

```
cd /opt/oletools
source venv/bin/activate
# eg olemeta -a ~/samples/qakbot-malware-sample/qakbot.xlsx
olemeta -a $SAMPLE_FILE
deactivate
```

https://github.com/decalage2/oletools/wiki/olemeta

#### via oletimes

- Returns creation and modification time for streams in the file

```
cd /opt/oletools
source venv/bin/activate
# eg oletimes ~/samples/qakbot-malware-sample/qakbot.xlsx
oletimes $SAMPLE_FILE
deactivate
```

https://github.com/decalage2/oletools/wiki/oletimes

### Look and extract flash objects in file

#### via pyxswf

```
cd /opt/oletools
source venv/bin/activate
# eg pyxswf ~/samples/qakbot-malware-sample/qakbot.xlsx
pyxswf $SAMPLE_FILE
# Extract flash object
pyxswf -x $SAMPLE_FILE
deactivate
```

https://github.com/decalage2/oletools/wiki/pyxswf

### Extract OLE objects from RTF files

```
cd /opt/oletools
source venv/bin/activate
# eg rtfobj ~/samples/qakbot-malware-sample/qakbot.xlsx
rtfobj $SAMPLE_FILE
# Extract OLE object from RTF file with the ID from command above
rtfobj -s $OBJ_ID $SAMPLE_FILE
deactivate
```
