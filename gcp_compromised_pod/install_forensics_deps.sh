#!/bin/bash

echo "[*] Installing container-explorer..."
wget https://raw.githubusercontent.com/google/container-explorer/main/script/setup.sh -o /tmp/setup.sh
sudo bash /tmp/setup.sh install
