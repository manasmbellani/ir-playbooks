# Compromised Linux Instance

## Scenario

## Pre-requisites

## Scenario Setup

## Containment

## Collection

## Analysis

Analyse the mounted disk including the type of attached filesystem via `fsstat`: 

```
# View the output to see disk type eg. ext4
fsstat /dev/sdb1
```
## Eradication

## Recovery

## Automation

## Additional TODOs
- Collection - Creating Disk image via dd / usb https://www.therootuser.com/2017/11/recover-deleted-files-using-sleuthkit/
- Analysis - check for `memfd_create` in linux host processes. [Link](https://x.com/CraigHRowland/status/1629780744305295360?s=20)
- Analysis unix-like artifact collector
- Analysis disktype - provides detailed on partitions
- Analysis vgdisplay - For volume info
- Analysis mdadm - --examine detect Raid device (practical linux forensics)
- Analysis TheSleuthKit fls - steps to get deleted files 
