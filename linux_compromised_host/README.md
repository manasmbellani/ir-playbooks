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

## Analysis

Analyse the mounted disk including the type of attached filesystem via `fsstat` or `dumpe2fs` for (ext2/3/4 volumes): 

```
# View the output to see disk type eg. ext4
fsstat /dev/sdb1

# For ext 2/3/4 volumes
dumpe2fs /tmp/sdb1.raw
```

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

We can scan for any malware on the system as well using Neo23x0's Yara signatures if the file is mounted e.g. on `/mnt/disk` via the steps above via `fraken`:
```
docker run -v /opt/signature-base:/opt/signature-base2 -v /mnt/disk:/data -ti fraken fraken -rules /opt/signature-base2 -folder /data
```

## Eradication

## Recovery

## Automation

## Additional TODOs
- Collection - fast ir artifacts - https://github.com/OWNsecurity/fastir_artifacts
- Collection - Creating Disk image via dd / usb https://www.therootuser.com/2017/11/recover-deleted-files-using-sleuthkit/
- Collection - Capture linux memory for analysis https://cpuu.hashnode.dev/how-to-perform-memory-forensic-analysis-in-linux-using-volatility-3
- Collection dumpit-linux https://github.com/MagnetForensics/dumpit-linux
- Analysis OpenArk review tools
- Analysis - check for `memfd_create` in linux host processes. [Link](https://x.com/CraigHRowland/status/1629780744305295360?s=20)
- Analysis unix-like artifact collector
- Analysis disktype - provides detailed on partitions
- Analysis vgdisplay - For volume info
- Analysis mdadm - --examine detect Raid device (practical linux forensics)
- Analysis TheSleuthKit fls - steps to get deleted files 
