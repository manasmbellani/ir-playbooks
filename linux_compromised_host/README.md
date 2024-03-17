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

### Taking disk image (Offline)

Create a copy of the local disk image using `dd` for backup:

```
dd if=/dev/sdb1 of=/tmp/sdb1.raw bs=512

# Alternatively, specify a `count`if we want to have a limited image size
dd if=/dev/sdb1 of=/tmp/sdb1.raw bs=512 count=8192000
```

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

### Offline Analysis

#### Show Disk Details
Analyse the mounted disk including the type of attached filesystem via `fsstat` or `dumpe2fs` for (ext2/3/4 volumes): 

```
# View the output to see disk type eg. ext4
fsstat /dev/sdb1

# For ext 2/3/4 volumes
dumpe2fs /tmp/sdb1.raw
```

#### Identify and Recover Deleted files from disk
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

#### Scan for malware on disk
We can scan for any malware on the system as well using Neo23x0's Yara signatures if the file is mounted e.g. on `/mnt/disk` via the steps above via `fraken`:
```
docker run -v /opt/signature-base:/opt/signature-base2 -v /mnt/disk:/data -ti fraken fraken -rules /opt/signature-base2 -folder /data
```

#### List running processes on memory

List running processes `ps` using `volatility3`'s `pslist` command:
```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.pslist.PsList
deactivate
```

Alternatively, we can also use `volatility3`'s `psaux` command:
```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.pslist.PsList
deactivate
```

#### List commands executed on memory

List bash commands run using `volatility3`'s `bash.Bash` command:
```
cd /opt/volatility3
source venv/bin/activate
python3 vol.py -f /root/forensics-instance.lime linux.bash.Bash
deactivate
```

## Eradication

## Recovery

## Automation

## Additional TODOs
- Collection - fast ir artifacts - https://github.com/OWNsecurity/fastir_artifacts
- Collection - Creating Disk image via dd / usb https://www.therootuser.com/2017/11/recover-deleted-files-using-sleuthkit/
- Collection - Capture linux memory for analysis https://cpuu.hashnode.dev/how-to-perform-memory-forensic-analysis-in-linux-using-volatility-3
- Collection dumpit-linux https://github.com/MagnetForensics/dumpit-linux
- Analysis OpenArk review tools https://github.com/BlackINT3/OpenArk
- Analysis - check for `memfd_create` in linux host processes. [Link](https://x.com/CraigHRowland/status/1629780744305295360?s=20)
- Analysis unix-like artifact collector
- Analysis disktype - provides detailed on partitions
- Analysis vgdisplay - For volume info
- Analysis mdadm - --examine detect Raid device (practical linux forensics)
- Analysis TheSleuthKit fls - steps to get deleted files 
