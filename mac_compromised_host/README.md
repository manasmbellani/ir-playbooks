# MacOSX - Compromised Host

## Containment

### Disable network interfaces

#### via ifconfig

```
# List the network interfaces (can also use System Settings)
# Note the ones which have active IP address assigned (priortise these to disable) - don't touch loopback!
sudo ifconfig
sudo ifconfig en0 down
# Restoration via this command
# sudo ifconfig en0
```

### Disable from wired networks

Steps are the same as described [here](../win_compromised_host#disconnect-from-wired-networks)

### Apply Network Firewall

#### via pfctl

If testing only consider this to disable pfctl after 5 mins using crontab:
```
sudo su
crontab -e
# */5 * * * * /usr/bin/sudo /sbin/pfctl -d
```

Backup existing rules:
```
cp /etc/pf.conf /etc/pf.conf.bak
```

To apply the pfctl rules to block traffic except say port 53:
```
# /etc/pf.conf
# interfaces
ext_if="en0" 
# options
set block-policy drop
set skip on lo0
# filter rules
block in all
block out all
pass out quick on $ext_if proto tcp to any port 53 keep state
pass out quick on $ext_if proto udp to any port 53 keep state
```

Test the rules prior to applying them:
```
sudo /sbin/pfctl -n -v -f /etc/pf.conf
```

Apply the pf firewall rules:
```
sudo /sbin/pfctl -ef /etc/pf.conf
```

Disable the pf firewall rule:
```
sudo /sbin/pfctl -d 
```

More info on pf available [here](https://srobb.net/pf.html)

### Disable BlueTooth

#### via UI > System Settings

BlueTooth can be disabled via `System Settings` > `BlueTooth`

### Forget Wireless Networks

After performing the steps below, remember to disable the Wifi adapter

#### via networksetup

Remember to take screenshot of the saved wireless networks before removing them

```
# Identify the WIFI adapter
sudo networksetup -listallhardwareports
# List all the wireless networks
# Example:sudo networksetup -listpreferredwirelessnetworks en0
sudo networksetup -listpreferredwirelessnetworks $ADAPTER_NAME
# Disable the specific wifi network 
sudo networksetup -removepreferredwirelessnetwork en0 $WIFI
```

#### via UI > System Settings

Steps listed above can be performed via `System Settings` > `Network` >  `Wifi` 

## Collection

### Typical log locations

E.g To search via `grep`

```
/var/log
~/Library/Logs
/Library/Logs
/var/run
# View via `syslog` command eg `syslog -f *.asl`
/var/log/asl/*.asl
```

### Artifacts Collection

#### via uac

See [here](../linux_compromised_host/README.md#via-uac)

### Collection Scripts

#### via Crowdstrike's automactc

```
# git clone https://github.com/Crowdstrike/automactc /opt/automactc
cd /opt/automactc
automactc.py -m all -fmt json 
```


## Analysis

### Detect Last Logon Times

#### via `last`

```
last
```

### Look for Timezone

#### via /etc/localtime

```
cat /etc/localtime
```

#### via GlobalPreferences

```
plutil -p /Library/Preferences/.GlobalPreferences.plist
```

### Look for unusual deleted files

#### via ls / ~/.Trash

The deleted files are stored in `~/.Trash` folder

```
ls -lah ~/.Trash
```

### Look for malware 

#### via velocirpator / DetectRaptor

Load the latest [DetectRaptor VQL](https://github.com/mgreen27/DetectRaptor/tree/master) Zip artifact into Velociraptor and launch YaraProcessMacos Artifact which will search for malware based on YaraForge.

Consider also looking for WebShellYara Artifact which will search for webshells based on YaraForge

### Look for interesting indicators in data 

#### via bulk_extractor

See [here](../linux_compromised_host/README.md#look-for-interesting-indicators-in-data)

### Check various installed application logs

Can indicate various attacks occurring within and on the app as seen in Windows [here](../win_compromised_host/README.md#check-various-installed-application-logs)

#### via /Applications folder


### Launch Agents added

#### via common Launch Agent Paths

```
/System/Library/LaunchAgents
/Library/LaunchAgents
~/Library/LaunchAgents
```

Taken from [here](https://attack.mitre.org/techniques/T1543/001/)

#### via /var/log logs

Through file: `/var/log/com.apple.xpc.launchd/launchd.log`. Example:

```
/var/log/com.apple.xpc.launchd/launchd.log:4856:2024-06-10 16:40:10.879782 (gui/501 [100003]) <Notice>: Enabling service com.malicious.evil2.plist
```

### Files changed recently

#### via find

```
find . -ctime -1d
```

### Build a timeline 

Review the key artifacts to explore [here](../win_compromised_host/README.md#build-a-timeline)

## Recovery
