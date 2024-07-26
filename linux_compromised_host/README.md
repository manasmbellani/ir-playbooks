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

#### via fasir_artifacts

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

#### via LiME 

Taken from [here](https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/65/mode/1up)

#### via F-Response

paid tool.

Taken from [here](https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/65/mode/1up)

#### via avml / dwarf2json
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
./dwarf2json linux --elf /tmp/vmlinux > linux-$(uname -r).json
```


Otherwise, we can generate symbols using from a separate machine based on the same machine image on which we can install additional tools via the commands below. Assuming we are working with a compromised Ubuntu image (steps will vary for other server types), we first need to download the `vmlinux` file, and then use `dwarf2json` (link [here](https://github.com/volatilityfoundation/dwarf2json)) to generate the symbols file. 

```
# We follow steps for Ubuntu here: https://wiki.ubuntu.com/Debug%20Symbol%20Packages to download the debugging symbols,
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
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) --system-map /boot/System.map-$(uname -r) > linux-$(uname -r).json

# Move the generated file to the volatility3 symbols folder
mv linux-$(uname -r).json /opt/volatility3/volatility3/symbols/
```

## Analysis

### Look for interesting indicators in data 

#### via bulk_extractor

Can identify interesting indicators such as email addresses, PCAPs, etc.  and their frequency

```
mkdir $BULK_EXTRACTOR_OUT_FOLDER
bulk_extractor -o $BULK_EXTRACTOR_OUT_FOLDER $IMAGE_MEM
strings -a -t d $IMAGE_MEM >  | gzip  >$BULK_EXTRACTOR_OUT_FOLDER/strings.txt 
```

Checkout interesting files such as:
1 `url_histogram` which provides frequency of URL hits, and combine it with command for context of that URL: `zgrep -F -C3 "$string_to_search" $BULK_EXTRACTOR_OUT_FOLDER/strings.txt `
2 Parse `pcaps` via tshark as follows:
```
tshark -n -r packets.pcap -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport | sort | uniq -c
tshark -n -r packets.pcap "tcp.srcport == 443"
```

Taken from Hal Pomeranz's intro to linux course > Page 56 [here](https://archive.org/details/HalLinuxForensics/media-v3.0.2/PomeranzLinuxForensics/page/56/mode/1up)

### Look for login attempts

#### via log files 

- `Failed` Attempts: `/var/log/btmp`
- Who is currently logged in: `/var/run/utmp`
- History of `/var/log/utmp`: `/var/log/wtmp`

View using `last` for full details or `strings`: 

```
last -f /var/run/utmp
```

Taken from [here](https://askubuntu.com/questions/325491/how-to-properly-display-the-contents-of-the-utmp-wtmp-and-btmp-files)

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

### Getting installed packages

#### via /var/lib folder

Depends on the type of package manager in use e.g. RedHat OR yum OR dpkg
```
echo "select name,version,release from rpm" | sqlite3 /var/lib/dnf/history.sqlite
for i in /var/lib/yum/yumdb/*/* ; do basename $i | cut -d\- -f2- ; done
egrep '^(Package:|Version:)' /var/lib/dpkg/status | awk '{print $2}' | while read a ; do read b ; echo "$a-$b" ; done
```

Taken from [here](https://github.com/clausing/scripts/blob/master/linux-pkgs.sh)

### Files Recently Changed

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

### Scan for malware from disk

#### via fraken

We can scan for any malware on the system as well using Neo23x0's Yara signatures if the file is mounted e.g. on `/mnt/disk` via the steps above via `fraken`:
```
docker run -v /opt/signature-base:/opt/signature-base2 -v /mnt/disk:/data -ti fraken fraken -rules /opt/signature-base2 -folder /data
```

### Users with privileged access

#### via sudoers

```
cat /etc/sudoers
```

#### via passwd

Look for users with lower UID e.g. 0

```
cat /etc/passwd
```

### List Users

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

### List running processes

Identify unusual processes and processes running from suspicious locations such as from `/tmp`, `/var/tmp`, `/dev/shm`

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

### List System timer scheduled tasks

Timers allow users to schedule tasks similar to cron jobs

See [here](https://righteousit.com/2024/05/05/systemd-timers/) for more details

#### via systemctl

```
systemctl list-timers -l --all
```

#### via local file locations

```
/usr/lib/systemd/system/*.{timer,service}
/etc/systemd/system
$HOME/.config/systemd
[/var]/run/systemd/transient/*.{timer,service}
[/var]/run/user/*/systemd/transient/*.{timer,service}
```

### Build timeline

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

#### via volatility3 / sockscan

List bash commands run using `volatility3`'s `sockscan.Sockscan` command:
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

### Get Auditd Logs

#### via ausearch

```
# to get logs from today
ausearch --start today --format text
```

### Check various installed application logs

Review logs for various apps to detect attacks like log4j similar to described in Windows [here](../win_compromised_host/README.md#check-various-installed-application-logs)

#### via journalctl

```
sudo journalctl -u spring-boot-application
```
  
### Check cron scheduled tasks

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
```

Then, use `grep` to search for the key changes in audit log file

```
grep -r -n -i --color 'keychange' /var/log/audit.log
```

### Look for unlocked service accounts

This could be a potential backdoor where service accounts (accounts < UID 1000) don't have `/usr/sbin/nologin`, `/bin/false` in `/etc/passwd` OR `*` in `/etc/shadow` set.

#### via cat

```
# View the user accounts which don't have `/bin/false` or `/usr/sbin/nologin` set
# Can also compare the results with those from a clean system
cat uac_results/[root]/etc/passwd
```

### Look for ssh authorized keys

#### via find

As described [here](https://cyberkhalid.github.io/posts/ssh-persist/), SSH may have authorized keys which can be used for pentesting

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

### Check for network activity

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
