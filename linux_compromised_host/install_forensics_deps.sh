#!/bin/bash
# Script to be run on Ubuntu 22.04 instance

echo "[*] Install basic dev tools..."
sudo apt-get -y install \
  net-tools
  
echo "[*] Install sleuthkit for utilities related to disk info..."
apt-get -y install sleuthkit
