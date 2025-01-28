# Network Compromise

## Analysis

### Detect Unusually high HTTP traffic by destination ports

- Can easily detect nmap scanning traffic when looking at traffic volume to a destination IP by destination port
  
#### via destination port

### Detect unusually high DNS requests

- Can be indicative 

#### via wireshark for pcap

Filter for `dns` in wireshark 

### Detect unusual network user agent strings
- Look for various user agents which are known to be malicious eg for `certutil.exe` we see `Microsoft Crypto-API`: https://gist.github.com/GossiTheDog/77527a34cdecb0ad840910c0beb8ba41

#### via Wireshark


### Detect unusual network HTTP paths
- Look for suspicious HTTP Paths to which requests are made eg `/updater.ps1`. Useful when combined with user agent string analysis

#### via Wireshark
