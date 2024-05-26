# MacOSX - Compromised Host

## Containment

### Disable from wired networks

Steps are the same as described [here](win_compromised_host#disconnect-from-wired-networks)

### Disable BlueTooth

#### via UI > System Settings

BlueTooth can be disabled via `System Settings` > `BlueTooth`

### Forget Wireless Networks

After performing the steps below, remember to disable the Wifi adapter

#### via networksetup
```
# Identify the WIFI adapter
sudo networksetup -listallhardwareports
# List all the wireless networks
sudo networksetup -listpreferredwirelessnetworks en0
# Disable the specific wifi network 
sudo networksetup -removepreferredwirelessnetwork en0 $WIFI
```

#### via UI > System Settings

Steps listed above can be performed via `System Settings` > `Network` >  `Wifi` 

## Collection

## Analysis

## Recovery
