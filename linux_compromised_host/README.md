# Compromised Linux Instance

## Scenario

## Pre-requisites

## Scenario Setup

## Containment

## Eradication

## Analysis

Analyse the mounted disk including the type of attached filesystem via `fsstat`: 

```
fsstat /dev/sdb1
```

## Recovery

## Automation

## Additional TODOs

- Analysis - check for `memfd_create` in linux host processes. [Link](https://x.com/CraigHRowland/status/1629780744305295360?s=20)
- Analysis unix-like artifact collector
- Analysis disktype - provides detailed on partitions
- Analysis fsstat, vgdisplay - For volume info
