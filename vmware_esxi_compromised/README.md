# VMWare ESXi - Compromised

## Pre-requisites

### Environment Setup

Follow the setup steps [here](https://www.wintips.org/how-to-install-vmware-esxi-on-virtualbox/) to install VMWare ESXi in Virtualbox for testing purposes

A version of VMWare ESXi is available for download [here](https://archive.org/details/ESXi6.7)

Use [Putty](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) for SSH connectivity 

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

More details about different VMWare log types defined [here](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.monitoring.doc/GUID-832A2618-6B11-4A28-9672-93296DA931D0.html) and [here](https://pchawda.wordpress.com/2020/01/14/esxi-log-files-location-and-their-description/)

## Analysis

### Check kernel settings

#### via esxcli

Can show settings for `execInstalledOnly` and `secure boot` which are important as explained [here](https://www.truesec.com/hub/blog/secure-your-vmware-esxi-hosts-against-ransomware)
```
esxcli system settings kernel list
```

### Check if SSH was Enabled

#### via VMWare ESXI UI

Shown on the Host page

#### via VMWare ESXI UI / Manage 

Manage > Services > TMSH-SSH, is it running?

#### via esxi logs

Shown in `vobd.log` or `hostd.log` logs as `SSH Access has been enabled` and the time SSH connectivity was enabled

```
grep -r -n -i "SSH Access" /var/log 
```

### Check if authentication via domain

#### via logs

Login attempts appear as `DOMAIN\Administrator` OR `Administrator@corp.local` which contain domain name

### Check Authentication Attempts

#### via SSH / /var/log/auth.log

Captures the IP and the username leveraged for connection to SSH

```
cat /var/log/auth.log

grep -r -n -i E "authentication failure|session opened" /var/log
```

#### via web UI / /var/log/hostd.log

Shows the authentication attempts to the VMWare ESXI web browser e.g. `User root@192.168.56.101 logged in as <User-Agent>`
```
grep -r -n -i "logged in as" /var/log/hostd.log
```

### Check shell commands executed

#### via /var/log/shell.log
```
cat /var/log/shell.log
``` 

### Check running VMs

#### via esxcli

```
esxcli vm process list
```

### Check installed VIBs

For any unusual / malicious installed software packages

#### via esxcli

```
esxcli software vib list
```
