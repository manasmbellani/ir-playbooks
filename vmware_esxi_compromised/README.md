# VMWare ESXi - Compromised

## Pre-requisites

### Environment Setup

Follow the setup steps [here](https://www.wintips.org/how-to-install-vmware-esxi-on-virtualbox/) to install VMWare ESXi in Virtualbox for testing purposes

A version of VMWare ESXi is available for download [here](https://archive.org/details/ESXi6.7)

### Enable SSH

#### via ESXi UI

Set Manage > Services > TMSH-SSH to `Start` state

Taken from [here](https://www.serversaustralia.com.au/articles/virtualisation/vmware-esxi)

## Containment

## Collection

## Analysis

### Check Authentication Attempts

#### via /var/log/auth.log

Captures the IP and the username leveraged for connection to SSH

```
cat /var/log/auth.log
```

### Check shell commands executed

#### via /var/log/shell.log
```
cat /var/log/shell.log
``` 
