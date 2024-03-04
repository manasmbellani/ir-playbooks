#!/bin/bash

echo "[*] Installing container-explorer..."
wget https://raw.githubusercontent.com/google/container-explorer/main/script/setup.sh -o /tmp/setup.sh
sudo bash /tmp/setup.sh install

echo "[*] Installing plaso-tools..."
sudo add-apt-repository -y universe
sudo add-apt-repository -y ppa:gift/stable
sudo apt-get -y update
sudo apt-get -y install plaso-tools
