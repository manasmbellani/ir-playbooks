#!/bin/bash
# Run code on Ubuntu 22.04 Jammy

echo "[*] Install basic deps..."
apt-get -y update && \
  apt-get -y install \
    wireshark
