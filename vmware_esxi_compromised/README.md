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

### Connect via PowerCLI

```
powershell -ep bypass

# Ignore the SSL Certificate if using the default certificate
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

# Connect to ESXi Host
Connect-VIServer -Server $ESXI_SERVER -Protocol https -User root -Password $ESXI_PASSWORD
```

Taken from [here](https://www.ivobeerens.nl/2018/07/18/quick-tip-powercli-invalid-server-certificate-error/)

## Containment

### Reset password for the root account

#### via ESXI 

Via ESXI UI > Manage > Security & Users > Users > Select user to reset password for e.g. `root`

#### via esxcli

Assuming SSH is enabled,

```
# Auth as root
su -
passwd root
```

Taken from [here](https://knowledge.broadcom.com/external/article/318960/changing-an-esxiesx-host-root-password.html#:~:text=Log%20in%20to%20the%20ESXi,SSH%20or%20the%20physical%20console.&text=Enter%20the%20current%20root%20password%20when%20prompted.&text=Enter%20the%20new%20root%20password,a%20second%20time%20to%20verify.)

### Disconnect ESXI from connected directories (e.g. Active Directory)

#### via ESXI UI 

Via ESXI UI > Manage > Security & Users > Authentication > Change `Active Directory Enable` Setting

#### via SSH / likewise

```
/usr/lib/vmware/likewise/bin/domainjoin-cli leave
```
Taken from [here](https://mulcas.com/joining-an-esxi-host-to-a-windows-active-directory/)

#### via PowerCLI

```
Get-VMHost | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain "domain name" -User "username" -Password "password"
```

taken from [here](https://www.stigviewer.com/stig/vmware_vsphere_7.0_esxi/2023-02-21/finding/V-256402)

### Restrict network traffic from specific IP addresses

#### via ESXI UI / Firewall Rules

Via ESXI UI > Networking > Firewall Rules > SSH Server >  Edit Settings > Only Allow Connections from the following networks > Specify IP address ranges > 'OK'

### Disable SSH

Disable SSH Access by reversing the steps [here](#enable-ssh)

### Enable ExecInstalledOnly

Enable `ExecInstalledOnly` to only ensure that access is restricted

Taken from [here](https://www.crowdstrike.com/wp-content/uploads/2023/11/QRG-1.2-ESXi-Triage-Collection-and-Containment.pdf)

### Enable Lockdown mode (atleast Normal mode)

#### via ESXI UI

Via ESXI UI > Manage > Security & Users > Lockdown Mode > Select from Normal / Strict modes

Types:
- `Strict`: Users are restricted to logging in from vCenter server only
- `Normal`: Users may log in via DCUI and vCenter server

#### via DCUI UI 

https://knowledge.broadcom.com/external/article?legacyId=1008077

## Collection

### Collect VMs

#### via ssh / dd

First suspend the VM via VMWare ESXI UI or vSphere console

Assuming SSH has been enabled as per [above](#enable-ssh), we snapshot the VMs from `/vmfs/volumes/datastore1` folder.

Calculate the hashes via `sha256sum` utility first for each file and then `sha256sum` after.

Use `dd` and `ssh` to copy the file.

```
# Calculate sha256
ssh root@$VMWARE_IP "sha256sum /vmfs/volumes/datastore1/$VM_NAME/vmware.log"
ssh root@$VMWARE_IP "sha256sum /vmfs/volumes/datastore1/$VM_NAME/$VM_NAME.vmdk"
# Copy file
ssh root@$VMWARE_IP "dd if=/vmfs/volumes/datastore1/$VM_NAME/$VM_NAME.vmdk" | dd of=/tmp/$VM_NAME/$VM_NAME.vmdk
ssh root@$VMWARE_IP "dd if=/vmfs/volumes/datastore1/$VM_NAME/$VM_NAME.vmdk" | dd of=/tmp/$VM_NAME/$VM_NAME.vmdk
# Calculate sh256 hash again
ssh /tmp/$VM_NAME/vmware.log
ssh /tmp/$VM_NAME/$VM_NAME.vmdk
```

Now, take a copy of the image via `dd` and open the captured image in forensic tools like FTK Imager. Files from suspended VMs like `.vmss` can be analysed via forensic tools like volatility [here](https://github.com/volatilityfoundation/volatility/wiki/VMware-Snapshot-File)

```
dd if=/tmp/$VM_NAME/$VM_NAME.vmdk of=/tmp/$VM_NAME/$VM_NAME-copy.vmdk
```

Note: Remember to disable SSH again if it wasn't enabled in the first place. 

Taken from [here](https://www.sans.org/blog/how-to-digital-forensic-imaging-in-vmware-esxi/)

### Collect Logs

Collect all logs from the following locations: 
- `/var/log`
- `find /var/run -ipath "*log*"`

More details about different VMWare log types defined [here](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.monitoring.doc/GUID-832A2618-6B11-4A28-9672-93296DA931D0.html) and [here](https://pchawda.wordpress.com/2020/01/14/esxi-log-files-location-and-their-description/)

## Analysis

### Get VM's Hard disk

#### via powercli

```
Get-HardDisk -VM $VM_NAME | Format-List
```

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

#### via PowerCLI

```
Get-VM | Format-List
```

### Check installed VIBs

For any unusual / malicious installed software packages

#### via esxcli

```
esxcli software vib list
```
