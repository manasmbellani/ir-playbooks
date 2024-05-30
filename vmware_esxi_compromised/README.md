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

### Collect Logs

Collect all logs from the following locations: 
- `/var/log`
- `find /var/run -ipath "*log*"`

More details about different VMWare log types defined [here](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.monitoring.doc/GUID-832A2618-6B11-4A28-9672-93296DA931D0.html)

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
