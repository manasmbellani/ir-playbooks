# File Analysis

## Forensics Server Setup

### Ubuntu

Refer to the forensics servers setup [here](../gcp_compromised_pod/install_forensics_deps.sh) 

## Common

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

### Look for exif data

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

## Linux

## Microsoft Office Files 

### Convert to Zip and search for interesting artifacts such as emails

```
mv $FILENAME.docx $FILENAME.zip
unzip $FILENAME.zip
grep -r -n -i -o -E "https?://" .
```
