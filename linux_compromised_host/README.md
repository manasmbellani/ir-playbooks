# Compromised Linux Instance

## Scenario

## Pre-requisites

## Scenario Setup

## Containment

Containment of an instance depends on the technology in use which can be used for containment.

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

### Taking disk image (Offline)

#### via dd
Check the mount points first via `mount`, `df` to identify the dev mount for disk to take image of is attached:
```
df -h
mount
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

If we have access to system, we can use `avml` utility from a USB disk (link [here](https://github.com/microsoft/avml)) to take an image of the instance:
```
cd /opt/avml
./avml memory.lime
```

We can run the following command on volatility3 to locate the banner and see if we can locate the symbol file with the banner on [technarchy](https://isf-server.techanarchy.net/). The symbols file can be downloaded and saved to the folder `/opt/volatility3/volatility3/symbols/`

```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f memory.lime banners.Banners
deactivate
```

Alternatively, we can generate symbols using from a separate machine based on the same machine image on which we can install additional tools via the commands below. Assuming we are working with a compromised Ubuntu image (steps will vary for other server types), we first need to download the `vmlinux` file, and then use `dwar2json` (link [here](https://github.com/volatilityfoundation/dwarf2json)) to generate the symbols file. 

```
# We follow steps for Ubuntu here: https://wiki.ubuntu.com/Debug%20Symbol%20Packages to download the debugging symbols,
# Symbols are then downloaded to /usr/lib/debug/boot
echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.list
apt-get -y update
apt-get -y install linux-image-$(uname -r)-dbgsym

# Next Generate the symbols file via `dwarf2json` and the `System-map` file located in `/boot` folder
# Steps taken from: 
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) --system-map /boot/System.map-$(uname -r) > linux-$(uname -r).json

# Move the generated file to the volatility3 symbols folder
mv linux-$(uname -r).json /opt/volatility3/volatility3/symbols/
```

## Analysis

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

#### via fls / icat

For extracting deleted files, we list files using `fls` and use `icat` to extract the files and refer to link [here](https://wiki.sleuthkit.org/index.php?title=Fls) for more info on output file types:
```
fls /tmp/sdb1.raw
```

To extract a particular file, we use `inode` number displayed above to get the contents of the file via `icat` : 
```
icat -r /tmp/sdb1.raw $INODE_NUMBER > /tmp/$INODE_NUMBER.raw
file /tmp/$INODE_NUMBER.raw
ls -lah /tmp/$INODE_NUMBER.raw
```

We can get more details about the file as well using`$INODE_NUMBER` with `istat`:
```
istat /tmp/sdb1.raw $INODE_NUMBER
```

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

### Detect environment variables for process

#### via `proc` folder

Leaks various interesting artifacts such as Client IP, command in case of SSH

See `/proc/$PID/environ`

### Get executable binary for process

#### via `proc` folder

See `/proc/$PID/exe`

### List running processes

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

### List running network ports/services from memory

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

### Check cron scheduled tasks

#### via cron logs

Check cron scheduled tasks:

```
/var/log/cron.log
```


### Check linux authentication attempts

#### via auth.log

Check authentication attempts via `auth.log`:

```
/var/log/auth.log
```

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

### Look for ssh authorized keys

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
