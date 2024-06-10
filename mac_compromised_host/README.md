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

### Collection Scripts

#### via Crowdstrike's automactc

```
# git clone https://github.com/Crowdstrike/automactc /opt/automactc
cd /opt/automactc
automactc.py -m all -fmt json 
```

## Analysis

### Files changed recently

#### via find

```
find . -ctime -1d
```

## Recovery
