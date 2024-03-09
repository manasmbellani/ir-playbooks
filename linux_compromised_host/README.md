# Compromised Linux Instance

## Scenario

## Pre-requisites

## Scenario Setup

## Containment

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
- Collection - Creating Disk image via dd / usb https://www.therootuser.com/2017/11/recover-deleted-files-using-sleuthkit/
- Collection - Capture linux memory for analysis https://cpuu.hashnode.dev/how-to-perform-memory-forensic-analysis-in-linux-using-volatility-3
- Analysis - check for `memfd_create` in linux host processes. [Link](https://x.com/CraigHRowland/status/1629780744305295360?s=20)
- Analysis unix-like artifact collector
- Analysis disktype - provides detailed on partitions
- Analysis vgdisplay - For volume info
- Analysis mdadm - --examine detect Raid device (practical linux forensics)
- Analysis TheSleuthKit fls - steps to get deleted files 
