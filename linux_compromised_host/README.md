# Compromised Linux Instance

## Scenario

## Pre-requisites

## Scenario Setup

### Deploy auditd config 

We deploy best practice auditd configuration on a test linux instance for monitoring changes from [here](https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules) by copying this config to `/etc/audit/rules.d/audit.rules` 

We then run the following command to restart auditd and validate that it is applied:

```
systemctl restart auditd
auditctl -l
```

### Sample Disk DD Images

A number of sample disk images can be obtained from the links below:

- https://datasets.fbreitinger.de/datasets/
- https://dftt.sourceforge.net/test10/index.html
- https://cfreds.nist.gov/all/NIST/HackingCase
- https://github.com/BitCurator/bitcurator-access-webtools/blob/main/disk-images/mixed/charlie-work-usb-2009-12-11.E01

### Sample Volatility images

- https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples

## Containment

Containment of an instance depends on the technology in use which can be used for containment.

### Disable Network Adapters

See [here](../mac_compromised_host/README.md#apply-network-firewall)

### Disable from wired networks

Steps are the same as described [here](../win_compromised_host#disconnect-from-wired-networks)

### Disable Bluetooth Network

Check if bluetooth is running:
```
hcitool dev
service bluetooth status
systemctl status bluetooth.service
```

#### via service

```
service bluetooth stop
```

#### via systemctl

```
systemctl stop bluetooth.service
```

### Contain GCP Compute VM via GCP firewall 

The following set of commands can be used to create a network tag called `forensics-contain` which allow specific GCP inbound / outbound services but exclude all others. 
Once `forensics-contain` has been created, we apply the tag to the affected VM in GCP, and remove all other tags on the instance.
```
# Replace the FORENSICS_IP for the IP which should be excluded from containment rules e.g. "1.1.1.1/32"
FORENSICS_IP="..."

# Set the region and zone where the compute VM sits
gcloud config set compute/zone us-central1-c
gcloud config set compute/region us-central1

# Identify the network name in which the forensics instance is running e.g. assume it runs `default` 
gcloud compute instances describe forensics-instance --zone=us-central1-c \
  --format='value(networkInterfaces[0].network)'

# Allow DNS resolutions (this could be further restricted if the Nameservers are fixed)
gcloud compute firewall-rules create forensics-contain-allow-outbound-dns \
  --target-tags "forensics-contain" \
  --network "default" \
  --allow udp:53 \
  --priority 999 \
  --direction EGRESS \
  --destination-ranges="0.0.0.0/0" \
  --description="Allow outbound UDP DNS traffic"

# Allow outbound HTTP traffic to Forensics IP (e.g. to allow forensics agents to work)
gcloud compute firewall-rules create forensics-contain-allow-outbound-http-8000 \
  --target-tags "forensics-contain" \
  --network "default" \
  --allow tcp:8000 \
  --priority 999 \
  --direction EGRESS \
  --destination-ranges="$FORENSICS_IP" \
  --description="Allow outbound HTTP traffic on port 8000"

# Block all other traffic
gcloud compute firewall-rules create forensics-contain-deny-outbound-all \
  --target-tags "forensics-contain" \
  --network "default" \
  --priority 1000 \
  --rules all \
  --action deny \
  --direction EGRESS \
  --description="Deny all other outbound traffic"

# Allow inbound SSH from the Forensics instance for investigation
gcloud compute firewall-rules create forensics-contain-allow-inbound-ssh \
  --target-tags "forensics-contain" \
  --network "default" \
  --priority 999 \
  --allow tcp:22 \
  --source-ranges="$FORENSICS_IP" \
  --direction INGRESS \
  --description="Allow inbound SSH traffic"

# Block all other inbound connections
gcloud compute firewall-rules create forensics-contain-deny-inbound-all \
  --target-tags "forensics-contain" \
  --network "default" \
  --priority 1000 \
  --rules all \
  --action deny \
  --direction INGRESS \
  --description="Deny inbound traffic"
```

## Collection

### Memory Acquisition 

Refer steps [here](#taking-memory-image-live)

### Collect log rotate configuration

```
cat /etc/logrotate.conf
```

Taken from [here](https://linux.die.net/man/5/logrotate.conf)

### Taking disk image (Offline)

#### via dd

Check the mount points first via `mount`, `df` to identify the dev mount for disk to take image of is attached:
```
df -h
mount
cat /proc/mounts
```

Once the `/dev/sdxx` is identified, create a copy of the local disk image using `dd` for backup:

```
dd if=/dev/sdb1 of=/tmp/sdb1.raw bs=512

# Alternatively, specify a `count`if we want to have a limited image size
dd if=/dev/sdb1 of=/tmp/sdb1.raw bs=512 count=8192000
```

#### via dc3dd

```
dc3dd if=/dev/sda1 of=/tmp/image.dd hash=sha256 hlog=/tmp/hash.log log=/tmp/image.log
```

#### via ewfacquire / mmls

Follow steps here to acquire images via [ewfacquire](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount#ewf).

Further step-by-step instructions are documented by Hal Pomeranz [here](https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/89/mode/1up).
In case we come across `NO SUB SYSTEM TO MOUNT EWF FORMAT`, follow the steps described [here](https://www.wallofsheep.com/blogs/news/how-to-update-ewf-tools-on-kali-linux-eliminate-the-no-sub-system-to-mount-ewf-format-error)

Binaries available [here](https://github.com/alpine-sec/ewf-tools)

### Artifacts Collection

#### via uac

```
# To grab most useful data for IR 
./uac -p ir_triage /tmp
# To store the output in /tmp directory
./uac -p full /tmp
```

#### via lintri

```
# Check / or ~ directory for the .tar.gz file e.g. LINTri_kali-vm_20240719_084857.tar.gz
cd /opt/lintri
/bin/bash LINTri.sh
```

Taken from [here](https://github.com/DCScoder/LINTri)

#### via fastir_artifacts

To quickly contain main set of artifacts for analysis (similar to KAPE)

```
cd /opt/fastir_artifacts
source venv/bin/activate
python3 fastir_artifacts.py -o /tmp/fastirartefacts
deactivate
```

### Mounting image

#### via losetup

In the event that we have to mount the disk, we can use `losetup`:
```
# This will return $LOOP_DEV to mount
losetup --partscan --find --show /tmp/sdb1.raw
mkdir /mnt/disk
mount /dev/$LOOP_DEV /mnt/disk
```

### Taking memory image (Live)

#### via linpmem 

```
/usr/bin/linpmem -v  -m --format raw --output /tmp/mem.raw
```

#### via dumpitforlinux

this will create the memory image in the local folder:
```
cd /tmp
/opt/dumpit-linux/target/release/dumpitforlinux --raw
```

#### via LiME 

Steps for loading lime module in kernel module [here](https://www.otorio.com/resources/linux-memory-forensics-part-1-memory-acquisition/) for taking memory image in Linux

Taken from [here](https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/65/mode/1up)

#### via F-Response

paid tool.

Taken from [here](https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/65/mode/1up)

#### via avml / dwarf2json (volatility3)
If we have access to system, we can use `avml` utility from a USB disk (link [here](https://github.com/microsoft/avml)) to take an image of the instance:

```
cd /opt/avml
./avml memory.lime
```

Can also use FIFO to share data. 

```
mkfifo /tmp/myfifo
cat /tmp/myfifo | nc -w1 $REMOTE_HOST 9999 &
cd /opt/avml
./avml /tmp/myfifo
```

We can run the following command on volatility3 to locate the banner and see if we can locate the symbol file with the banner on [technarchy](https://isf-server.techanarchy.net/) OR on volatility3-symbols repository [here](https://github.com/Abyss-W4tcher/volatility3-symbols). The symbols file can be downloaded and saved to the folder `/opt/volatility3/volatility3/symbols/`

```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f memory.lime banners.Banners
deactivate
```

If we are building memory image for GKE Google COS Images (e.g. for Kubernetes / GKE), then we obtain a build ID from the machine image's name e.g. and download vmlinux to get the symbols for volatility. Taken from Spoftify's R&D here [here](https://engineering.atspotify.com/2023/06/analyzing-volatile-memory-on-a-google-kubernetes-engine-node/)

```
# where build_id=17800.147.54 if the machine image is `gke-1289-gke1000000-cos-109-17800-147-54-c-pre`
curl -s https://storage.googleapis.com/cos-tools/$build_id/vmlinux > /tmp/vmlinux
dwarf2json linux --elf /tmp/vmlinux > linux-$(uname -r).json
```


Otherwise, we can generate symbols using from a separate machine based on the same machine image on which we can install additional tools via the commands below. Assuming we are working with a compromised Ubuntu image (steps will vary for other server types), we first need to get the `vmlinux` file, and then use `dwarf2json` (link [here](https://github.com/volatilityfoundation/dwarf2json)) to generate the symbols file. 

```
# We follow steps for Ubuntu here: https://wiki.ubuntu.com/Debug%20Symbol%20Packages to download the debugging symbols OR use Microsoft CoPilot / ChatGPT
# Symbols are then downloaded to /usr/lib/debug/boot
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.list
apt-get -y update
apt-get -y install linux-image-$(uname -r)-dbgsym
find / -name vmlin\* -size +100M 2>/dev/null

# Next Generate the symbols file via `dwarf2json` and the `System-map` file located in `/boot` folder
# Steps taken from: 
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) --system-map /boot/System.map-$(uname -r) > linux-$(uname -r).json

# Move the generated file to the volatility3 symbols folder
mv linux-$(uname -r).json /opt/volatility3/volatility3/symbols/
```

### via avml / volatility2 

Take a memory image via `avml` and make a volatility2 profile by following steps in the article [here](https://beguier.eu/nicolas/articles/security-tips-3-volatility-linux-profiles.html#:~:text=A%20Linux%20Volatility%202%20profile,without%20starting%20a%20virtual%20machine.)

### Building a timeline

See [build a timeline](#build-a-timeline) section 


## Analysis

### Look for unusual web traffic 

#### via /var/log

```
cat /var/log/nginx/access.log
```

https://medium.com/@adammesser_51095/cloud-digital-forensics-and-incident-response-elastic-kubernetes-service-takeover-leads-to-9553c5424df5

### Determine the default timezone

#### via /etc/localtime

```
strings -a /etc/localtime
# To get readable version of /etc/localtime
zdump /etc/localtime
```

### Determine system installation date

#### via lost+found file creation

```
# Generally indicates the time when linux was installed on the system
stat /lost+found
```

#### via /etc/ssh/ssh_host_rsa_key

```
# The date on this file indicates when system was first booted 
ls -lah /etc/ssh/ssh_host_rsa_key
```
Ref [here](https://archive.org/details/HalLinuxForensics/page/105/mode/1up)

### Look for the hostname for device

#### via hostname

```
hostname
```

### Look for distro/release number

```
cat /etc/*-release
```

### Look for network IP addresses, DHCP Leases

```
cat /etc/hosts
cat /var/lib/NetworkManager
cat /var/lib/dhclient
cat /var/lib/dhcp

```

### Look for unusual missing packages

- `tmate` can leave indicators that there are outdated binaries. https://dfir.ch/posts/tmate_as_a_backdoor/

#### via /var/log

```
cat /var/log/unattended-upgrades/unattended-upgrades-dpkg.log
```

### Look for unusual commands / processes / command lines executed

- Interesting processes to look for: 
```
# Indicators of files being downloaded
curl
wget

# Unusual Connectivity based commands that sysadmins or threat actors may perform
# taken from: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_susp_c2_commands.yml
nc
netcat
ncat
ssh
socat
wireshark
rawshark
rdesktop
nmap
vnc
tigervnc

# Interesting processes being executed
base64
cargo
python
python3
bash
go
```

#### via auditd logs / ausearch / execve syscall

```
ausearch -sc execve
```

### Look for unusual services

Such as:
```
# Indicates a cloudflared tunnel eg https://x.com/malmoeb/status/1736995855482118314?s=46&t=WvGY79Umt5enRwgCbi4TQQ
cloudflared
# Indicates ngrok tunnel for privoting
ngrok
```

#### via /etc/system/systemd services

```
ls -l /etc/system/systemd/*
```

#### via auditd logs / systemctl

```
cat /var/log/audit/audit.log | grep -i systemctl
```

#### via service

```
service --status-all
```

#### via systemctl

```
systemctl list-unit-files
```

### Look for unusual kernel modules or rootkits

#### via dmesg

```
# Will return values like "Starting modprobe@configfs.service - Load Kernel Module configfs..."
dmesg | grep -i module
```

#### via rkhunter

```
rkhunter --check
```

#### via volatility3 / check_modules

```
# Compare outputs with one from a nomral machine
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.check_modules.Check_modules
deactivate
```

#### via volatility3 / lsmod

```
# Compare outputs with one from a nomral machine
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.lsmod.Lsmod
deactivate
```

https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/82/mode/1up

#### via volatility3 / check_syscall

```
# Compare outputs with one from a nomral machine
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.check_syscall.Check_syscall
deactivate

# Identify unique lines
sort syscall-output-* | uniq -u
```

https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/82/mode/1up

### Look for unusual indicators in data 

Can identify interesting indicators such as email addresses, passwords, PCAPs, etc.  and their frequency.
Can also be applied for raw image files

#### via bulk_extractor / tshark / zgrep

```
mkdir $BULK_EXTRACTOR_OUT_FOLDER
bulk_extractor -o $BULK_EXTRACTOR_OUT_FOLDER $IMAGE_MEM
strings -a -t d $IMAGE_MEM >  | gzip  >$BULK_EXTRACTOR_OUT_FOLDER/strings.asc.gz
# Search for the keywords
# To look for the strings around the specified address, use daddr for xfs_db (XFS filesystem) as described here: https://archive.org/details/HalLinuxForensics/page/178/mode/1up
zgrep -Fi password $BULK_EXTRACTOR_OUT_FOLDER/strings.asc.gz
```

Checkout interesting files such as:
1 `url_histogram` which provides frequency of URL hits, and combine it with command for context of that URL: `zgrep -F -C3 "$string_to_search" $BULK_EXTRACTOR_OUT_FOLDER/strings.txt `
2 Parse `pcaps` via tshark as follows:
```
tshark -n -r packets.pcap -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport | sort | uniq -c
tshark -n -r packets.pcap "tcp.srcport == 443"
```

Taken from Hal Pomeranz's intro to linux course > Page 56 [here](https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/56/mode/1up)

### Look for unusual login attempts / logon attempts


#### via log files 

- `Failed` Login Attempts: `/var/log/btmp` (read with `lastb`)
- Who is currently logged in: `/var/run/utmp` (read with )
- History of `/var/log/utmp` which typically contains user logins and system reboots: `/var/log/wtmp` (read with `last`)
- `Lastlog` - last login for each user (read with `lastlog`)
- `auth.log` - captures SSH login successful and failed attempts

View using `last` for full details or `strings`: 

```
last -f /var/run/utmp
```

Taken from [here](https://askubuntu.com/questions/325491/how-to-properly-display-the-contents-of-the-utmp-wtmp-and-btmp-files)

#### via velociraptor / linux.detection.bruteforce

- Detects brute-force attempts to linux host
- Use artifact [linux.detection.bruteforce](https://docs.velociraptor.app/exchange/artifacts/pages/linux.detection.bruteforce/)

#### via velociraptor / freebsd.sys.utx

- Freebsd's utx files - similar to `/var/log/wtmp`. See [here](https://docs.velociraptor.app/exchange/artifacts/pages/freebsd.sys.utx/). Use artifact `https://docs.velociraptor.app/exchange/artifacts/pages/freebsd.sys.utx/`

#### via velociraptor / linux.events.sshbruteforce

- Velociraptor Artifact [linux.events.sshbruteforce](https://docs.velociraptor.app/artifact_references/pages/linux.events.sshbruteforce/)
- Detects successful and failed SSH attempts

### Look for unusual processes

#### via ps

```
# E.g. for things like
#   /bin/bash -i (known to be a possible reverse shell if '-i' is in use, requires further investigation)
#   https://x.com/CraigHRowland/status/1802850025443336414
ps aux 
```

### Look for file descriptors that are open for unusual process 

Can be indicative of reverse shell 
Identify the unusual process via ps above

#### via /proc/$PID/fd

```
0,1,2 can refer to stderr, stdout, stdin
ls -lah /proc/$PID/fd
```

Taken from here: https://x.com/CraigHRowland/status/1802850025443336414

### Get the firewall rules

#### via iptables

```
iptables -L -n
```

### How long a system has been up for?

#### via uptime

```
uptime
```

### Getting unusual installed packages

- Can find signs of persistence eg tmate tool used for instant terminal sharing: https://dfir.ch/posts/tmate_as_a_backdoor/

#### via /var/lib folder

Depends on the type of package manager in use e.g. RedHat OR yum OR dpkg
```
echo "select name,version,release from rpm" | sqlite3 /var/lib/dnf/history.sqlite
for i in /var/lib/yum/yumdb/*/* ; do basename $i | cut -d\- -f2- ; done
egrep '^(Package:|Version:)' /var/lib/dpkg/status | awk '{print $2}' | while read a ; do read b ; echo "$a-$b" ; done
```

Taken from [here](https://github.com/clausing/scripts/blob/master/linux-pkgs.sh)

#### via /var/log

```
# contains Commands run to install packages
cat /var/log/apt/history.log

# contains Stdout of commands run
cat /var/log/apt/term.log
```

https://medium.com/@adammesser_51095/cloud-digital-forensics-and-incident-response-elastic-kubernetes-service-takeover-leads-to-9553c5424df5

### Unusual Browsing History Artifacts

Look for suspicious domains

#### via ~
```
# For 
ls -l ~/.mozilla/config/firefox/*.default*
ls -l ~/.config/Chromium/Default
```

### Unusual deleted files

#### via ~/.local/share/Trash/

```
# Contains full path to the deleted file
# Files are stored in the files folder
ls -l ~/.local/share/Trash/files
cat ~/.local/share/Trash/info
```

Taken from [here](https://archive.org/details/HalLinuxForensics/page/151/mode/1up)

### Unusual Files recently opened

#### via ~/.viminfo

```
cat ~/.viminfo
```

#### via ~/.local/share/recently-used.xbel

```
# contains Timestamped history of files opened with GUI applications
cat  ~/.local/share/recently-used.xbel
```

### Files Recently Changed

Can be indicative of unusual activity from threat actor

#### via auditd logs / openat / syscall 257

```
# Detects both files created and opened
SYSCALL=257
```

#### via find

```
# In last 3 days
find -ctime -3
```

### Show Disk Details

#### via fsstat / dumpe2fs

Analyse the mounted disk including the type of attached filesystem via `fsstat` or `dumpe2fs` for (ext2/3/4 volumes): 

```
# View the output to see disk type eg. ext4
fsstat /dev/sdb1

# For ext 2/3/4 volumes
dumpe2fs /tmp/sdb1.raw
```

### Identify and Recover Deleted files from disk

#### via Sleuthkit / mmls / fsstat / istat / fls

First, examine the partitions of the raw disk via mmls

```
mmls 10-ntfs-disk.dd 
```

Then use `fsstat` command to get the files listing specifying the correct start sector from previous command to get useful like OEM, Volume Name, Version, File System Type, etc.

```
fsstat -f ntfs -o 0000096390 10-ntfs-disk.dd 
```

We use `fls` command to get the inode number about the file and all files listing in the image

```
fls -l -f ntfs -o 0000096390 10-ntfs-disk.dd 
```

We can now use `istat` command to get information about the file

```
istat -f ntfs -o 0000096390 10-ntfs-disk.dd  "0-128-1"
```

We get the file via `icat`

```
icat -f ntfs -o 0000096390 10-ntfs-disk.dd  "0-128-1" > /tmp/mft-file.raw
```

Examine the file structure
```
file /tmp/mft-file.raw
xxd /tmp/mft-file.raw
```

Taken from [here](https://www.therootuser.com/2017/11/recover-deleted-files-using-sleuthkit/) and [here](https://wiki.sleuthkit.org/index.php?title=Fls)

Note the relevant partition where data might be present.

#### via fls / icat

See [above](#via-sleuthkit--mmls--fsstat--istat--fls)

#### via dd / proc

Can be used to get deleted executables / binaries:
```
# Identify the specific process ID
cd /proc/10047/
# Identify from the header the initial address e.g. 0x56218f564000
# Also calculate the length and update count in the dd command below 
head -1 maps

# Ensure that dd command is appropriately updated for length
dd if=mem bs=1 skip=$((0x56218f564000)) count=1000 of=/tmp/exec2
```

#### via tsk_recover

- Supports following image types for linux:
```
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))
vmdk (Virtual Machine Disk (VmWare, Virtual Box))
vhd (Virtual Hard Drive (Microsoft))
```

```
tsk_recover $IMAGE $OUTPUT_DIR
```

https://sansorg.egnyte.com/dl/N7FBvRlAm4

#### via foremost

https://sansorg.egnyte.com/dl/N7FBvRlAm4

#### via photorec

- Will use a Linux UI for data recovery

https://sansorg.egnyte.com/dl/N7FBvRlAm4

### Scan for malware from disk

#### via velociraptor / DetectRaptorVQL

Load the latest [DetectRaptor VQL](https://github.com/mgreen27/DetectRaptor/tree/master) Zip artifact into Velociraptor and launch YaraProcessLinux Artifact which will search for malware based on YaraForge.

Consider also looking for WebShellYara Artifact which will search for webshells based on YaraForge

#### via fraken

We can scan for any malware on the system as well using Neo23x0's Yara signatures if the file is mounted e.g. on `/mnt/disk` via the steps above via `fraken`:
```
docker run -v /opt/signature-base:/opt/signature-base2 -v /mnt/disk:/data -ti fraken fraken -rules /opt/signature-base2 -folder /data
```
#### via volatility3 / yarascan

```
# Compare outputs with one from a nomral machine
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime yarascan.YaraScan
deactivate
```

### Users with privileged access

#### via sudoers

```
# Look for unusual sudoers account
cat /etc/sudoers
```

#### via passwd

Look for users with lower UID e.g. 0

```
cat /etc/passwd
```

### Look for unusual users / User accounts


#### via /etc/group / admin accounts

```
# Look for unusual Administrative accounts in wheel, sudo, root groups
cat /etc/group
# Look for UID=0
cat /etc/passwd
```

#### via cat / etc/passwd / service accounts

This could be a potential backdoor where service accounts (accounts < UID 1000) don't have `/usr/sbin/nologin`, `/bin/false` in `/etc/passwd` OR `*` in `/etc/shadow` set.

```
# View the user accounts which don't have `/bin/false` or `/usr/sbin/nologin` set
# Can also compare the results with those from a clean system
cat uac_results/[root]/etc/passwd
```

#### via passwd

See [here](#via-passwd)

### User's Group Membership

#### via group

```
cat /etc/group
```

### List process Tree

#### via ps

```
ps -auxwf
```

#### via volatility3 / pstree

```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.pstree.PsTree
deactivate
```

#### via volatility3 / lsof

```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.lsof.Lsof
deactivate
```

#### via volatility3 / pslist

```
python3 vol.py -f /root/forensics-instance.lime linux.pslist.PsList
```

#### via volatility3 / elfs

```
python3 vol.py -f /root/forensics-instance.lime linux.elf.Elfs --pid $PID
```

### Detect environment variables for process

#### via `proc` folder

Leaks various interesting artifacts such as Client IP, command in case of SSH

See `/proc/$PID/environ`

### Get executable binary for process

#### via `proc` folder

See `/proc/$PID/exe`

Also, seen in this article: https://x.com/CraigHRowland/status/1802850025443336414

### List unusual running processes

- Identify unusual processes and processes running from suspicious locations such as from `/tmp`, `/var/tmp`, `/dev/shm`
- Identify unusual processes which can be used for persistence eg tmate. https://dfir.ch/posts/tmate_as_a_backdoor/

#### via ps aux

```
ps aux
```

#### via volatility3 / pslist

List running processes `ps` using `volatility3`'s `pslist` command:
```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.pslist.PsList
deactivate
```

#### via volatility3 / psaux

Alternatively, we can also use `volatility3`'s `psaux` command:
```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.pslist.PsList
deactivate
```

### List commands executed

#### via volatility3 / bash

List bash commands run using `volatility3`'s `bash.Bash` command:
```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.bash.Bash
deactivate
```

#### via journalctl

Parse the journal files in `/var/log/journal`:

```
# Focus on SYSLOG_IDENTIFIER for event type and CMDLINE for command lines executed
journalctl --file  /var/log/journal/993ae8921ac5f23a34cd3a99b9ba8ce6/system.journal -o verbose
```

### Check for unusual scheduled tasks

System Timers allow users to schedule tasks similar to cron jobs

See [here](https://righteousit.com/2024/05/05/systemd-timers/) for more details

#### via auditd log / syscall 257 / SYSCALL=openat

```
"openat"
```

#### via cron log 

See [here](#via-cron-log)

#### via systemctl / system timer

```
systemctl list-timers -l --all
```

#### via system timer / local file locations

```
/usr/lib/systemd/system/*.{timer,service}
/etc/systemd/system
$HOME/.config/systemd
[/var]/run/systemd/transient/*.{timer,service}
[/var]/run/user/*/systemd/transient/*.{timer,service}
```

#### via various init.d/* files

```
find /etc/init* -type f
```

#### via various crontabs

```
find /var/spool/cron/crontabs -type f
find /etc/cron* -type f
find /etc/*cron* -type f
/var/spool/cron/atjobs
```

### Build a timeline

Review the key artifacts to explore [here](../win_compromised_host/README.md#build-a-timeline)

#### via fls / mactime

```
fls -r -m / /dev/sda1 | gzip > /tmp/bodyfile-root.gz
zcat /tmp/bodyfile-root.gz | mactime -d -y -p /etc/passwd -g /etc/group 2019-01-01 > /tmp/timeline.csv
```

Ref [here](https://archive.org/details/HalLinuxForensics/page/118/mode/1up) and [here](https://archive.org/details/HalLinuxForensics/page/120/mode/1up)

#### via journalctl

See [here](#via-journalctl)

#### via user directory's hidden files

Files such as `~/.zsh_history`, `~/.bash_history` can contain past commands run by user

in case of `/bin/zsh`, we also have `~/.zsh_sessions` folder which contain the `.history` file and `.session` file. 
Session file contains a command for readable timestamp for when the history file was created. 
Whereas `.history` file contains the specific commands that were opened. 

Taken from [here](https://x.com/malmoeb/status/1794973569287410103)

### List running network ports/services from memory

#### via /proc/net/tcp, /proc/net/udp

Very useful if backdoors have hidden themselves

```
# IP Addresses are provided in hex format with lowest bytes from left-to-right which can be 
# Use the inode from ls -lah /proc/$PID/fd to identify the process which is responsible for the network connections

# Look for TCP connections
cat /proc/net/tcp

# Look for UDP connections
cat /proc/net/udp
```

Taken from here: https://x.com/CraigHRowland/status/1802850038164451367

#### via volatility3 / sockstat

List bash commands run using `volatility3`'s `sockscan.Sockstat` command:
```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.sockstat.Sockstat
deactivate
```

### Check auditd logs, rules

#### via auditd logs

Check if `auditd` is enabled and the logs are being logged in `auditd`:

```
/var/log/audit/audit.log
/var/log/messages
/var/log/syslog
/etc/audit/audit.rules
```

### Get Auditd Logs for interesting indicators

#### via ausearch / aureport

```
# to get logs from today
ausearch --start today --format text

# To search for presence of certain keywords in command lines
ausearch -if /mnt/evidence/var/log/audit -c useradd

# To convert PROCTITLE values from hex-encoded value as shown in auditd logs
echo 2F7573722F736269.. | xxd -r -p | tr \\000 ' '; echo

# To search by various type (-m) of logs 
ausearch -m execve
```

Interesting log types: 

```
EXECVE - Executed commands (e.g. syscall execve)
PATH - file related actions (e.g. syscall openat)
USER AUTH, USER_LOGIN, USER_START ,USER_END, USER_LOGOUT — user interactive logins (SSH sessions also use CRYPTO_KEY_USER, CRYPTO_SESSION)
USER_CMD, PROCTITLE, PATH, CWD, SYSCALL — process execution and user activity
ADD_USER, ADD_GROUP — account admin activity
AVC -— SELinux messages
TTY, USER_TTY — keystroke logs (if enabled)
LOGIN, USER_ACCT, USER_START, USER_END, CRED_ACQ, CRED_DISP, CRED_REFR — related to scheduled task start/stop
SYSTEM_BOOT, SYSTEM_RUNLEVEL, KERN _MODULE, NETFILTER_CFG
DAEMON_START, SERVICE_START, CFG_CHANGE — system boot and startup messages
```

#### via grep

Search the log records for interesting syscall numbers [here](https://filippo.io/linux-syscall-table/) such as `execve (59)`, `openat (257)`.

Use `grep` to search based on AuditID field (timestamp:ID) merged together as described [here](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files#sec-Understanding_Audit_Log_Files).

### Check various installed application logs

Review logs for various apps to detect attacks like log4j similar to described in Windows [here](../win_compromised_host/README.md#check-various-installed-application-logs)

#### via journalctl

```
sudo journalctl -u spring-boot-application
```
  

#### via cron logs

Check via cron scheduled task executions

```
cat /var/log/cron.log
grep -r -n -i --color cron /var/log/syslog
```

#### via cron

```
find /var/spool/cron/crontabs -type f
find /etc/cron* -type f
find /etc/*cron* -type f
```

Taken from [Hal Pomeranz's Linux DFIR Intro Course](https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/32/mode/1up) > Page 32

### Check SUID/SGID Bit set

This can be set if hackers are trying to create a backdoor

#### via uac

See the following files:
```
live_response/system/suid.txt
live_response/system/sgid.txt
```

### Check linux authentication attempts

#### via lastlog

```
lastlog
```

#### via auth.log

Check authentication attempts via `auth.log`:

```
/var/log/auth.log
```

### Check Linux Authentication attempts for CVE-2024-6387 (Regresshion)

#### via auth.log

```
# Unusual IP addresses making this attempt
# Example: ./auth.log.1:187:2024-06-29T07:49:02.498852+00:00 kali-vm sshd[9378]: fatal: Timeout before authentication for 140.246.97.188 port 52762
grep -r -n -i --color "timeout after authentication" /var/log/auth.log
# OR
# Excessive number of hits of the following
# Example: 2024-07-11T21:47:28.876206+00:00 kali-vm sshd[3341]: ssh_dispatch_run_fatal: Connection from 211.31.6.193 port 58642: message authentication code incorrect [preauth]
message authentication code incorrect [preauth]
```

https://www.splunk.com/en_us/blog/security/cve-2024-6387-regresshion-vulnerability.html

### Check Splunk UI Authentication Attempts

Assuming Splunk is running on the system, then login attempts to Splunk UI can be determined

#### via Splunk auth logs

```
/opt/splunk/var/log/splunk/audit.log
```

#### via Splunk _audit index Search

```
index=_audit sourcetype=audittrail user=* action=log*
```

### Look for Message of the Day (MOTD) Persistence

#### via ps / Parent Process ID 1

Since scripts in `update-motd.d` have to end for SSH shell to start, then any long running processes that from running a malicious script in `/etc/update-motd.d` would have a parent PID of 1 (default when a process's parent ends)

```
# Check where parent process ID is 1
ps -efj

# Alternatively, for a process tree
ps -auxwf
```

Taken from [here](https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/#10-boot-or-logon-initialization-scripts-motd)

### Monitor changes to authorized_keys file

#### via auditd

Reload auditd via `service auditd restart` and `auditctl -R` to 
```
echo "# Custom: Add monitoring for changes to authorized_keys file" >> /etc/audit/rules.d/audit.rules
echo "-a always -w /root/.ssh/authorized_keys -p wa -k root_keychange" >> /etc/audit/rules.d/audit.rules
echo "-a always -w /home/manasbellani/.ssh/authorized_keys -p wa -k user_keychange_mb" >> /etc/audit/rules.d/audit.rules
echo "-a always -w /home/ubuntu/.ssh/authorized_keys -p wa -k user_keychange_u" >> /etc/audit/rules.d/audit.rules
echo "-a always -w /root/.ssh/authorized_keys2 -p wa -k root_keychange" >> /etc/audit/rules.d/audit.rules
echo "-a always -w /home/manasbellani/.ssh/authorized_keys2 -p wa -k user_keychange_mb" >> /etc/audit/rules.d/audit.rules
echo "-a always -w /home/ubuntu/.ssh/authorized_keys2 -p wa -k user_keychange_u" >> /etc/audit/rules.d/audit.rules
```

Then, use `grep` to search for the key changes in audit log file

```
grep -r -n -i --color 'keychange' /var/log/audit.log
```

https://x.com/malmoeb/status/1867329453354860718 (`authorized_keys2`)

### Monitor for unusual changes to services

#### via auditd / ausearch

```
# Add the following to /etc/audit/rules.d/audit.rules file and restart auditd service
# sudo systemctl restart auditd
-w /etc/systemd/system/ -p wa -k service-config
-w /etc/init.d/ -p wa -k service-config
-w /usr/sbin/ -p x -k service-binaries
-w /var/log/ -p wa -k service-logs



sudo ausearch -k service-config
sudo ausearch -k service-binaries
sudo ausearch -k service-logs
```


### Look for ssh authorized keys

#### via find

As described [here](https://cyberkhalid.github.io/posts/ssh-persist/), SSH may have authorized keys which can be used for persistence

Locate the Authorized Keys:
```
find /home  -ipath "*authorized_keys*"
find /root  -ipath "*authorized_keys*"
```

Look for any suspicious `command` parameter in the `authorized_keys` file. See [here](https://serverfault.com/q/718317) for more details.

### Look for Message of the Day (MOTD) Scripts

#### via /etc/update-motd.d/ file

Scripts listed in these files executed as root on boot time and can be used for persistence

```
ls -l /etc/update-motd.d/
```

Typical file names:
```
00-header
91-release-upgrade
90-updates-available
98-reboot-required
```

https://pberba.github.io/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/#10-boot-or-logon-initialization-scripts-motd

### Detect timestomping

#### via tracker3 DB

This can detect times changed via the `touch` command. Check the `FileSystem.db` database for `<filename>` that needs to be checked for timestomping:

```
sqlite3 /home/<user>/.cache/tracker3/files/ .dump | grep <filename>

# Use this command for `date` 
date -d @$TIMESTAMP
```

More info [here](https://www.inversecos.com/2022/08/detecting-linux-anti-forensics.html?m=1)

#### via auditd

Assuming auditd is available, search the logs

```
grep -i touch /var/log/audit/audit.log
grep -i timedatectl /var/log/audit/audit.log
```

#### via stat

Weak detection, but could still give an indicator during timeline via `Birth` and `Change` fields, especially if `Access` and `Modify` timestamps are way-off

```
stat test.txt
```

https://www.inversecos.com/2022/08/detecting-linux-anti-forensics.html?m=1

### Check for unusual SSH connections

- Presence of `outgoing` SSH connections that looks unusual can indicate tmate persistence activity. https://dfir.ch/posts/tmate_as_a_backdoor/
  
#### via lsof 

```
lsof -p $PROCESS_ID | grep -i ":22"
```

### Check for unusual network activity

#### via /proc/net/unix

- Presence of `tmate` within the unix file indicates Unix networking activity related to tmate persistence https://dfir.ch/posts/tmate_as_a_backdoor/

```
cat /proc/net/unix | grep -i tmate
```

#### via lsof 

```
# Look for 'pack' type=RAW_SOCK
lsof -a -i4 -i6 -itcp
```

#### via /proc ... /fd

Look for `socket` based file descriptors to observe network activity.

```
ls -l /proc/$PID/fd | grep -i socket
```

#### via /proc ... /stack

Monitor the proc `stack` for network connectivity. Look for `sock_recvmsg` for network connectivity

```
watch -n 0.5 cat /proc/1338/stack
```

### Check for keylogging

#### via rkhunter

See [here](#via-rkhunter)

#### via volatility3 / tty_check

```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f ~/sample_images/gcp_ubuntu_instance2/memory.lime --profile=$PROFILE linux.tty_check.tty_check
deactivate
```

#### via volatility2 / tty_check

```
cd /opt/volatility2
source venv/bin/activate
python2 vol.py -f ~/sample_images/gcp_ubuntu_instance2/memory.lime --profile=$PROFILE linux.tty_check.tty_check
deactivate
```

### Check for packet sniffing

#### via ss

Look for very long BPF filters and linked to process ID that shouldn't have network activity

```
ss -0bp
```

### Build a wordlist for Extracting password encrypted files

#### via bulk_extractor

See [here](https://github.com/manasmbellani/ir-playbooks/blob/master/win_compromised_host/README.md#build-a-wordlist-for-extracting-password-encrypted-files) for more info.

## Eradication

## Recovery
