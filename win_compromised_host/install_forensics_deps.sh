#!/bin/bash
# Script to be run on Ubuntu Linux 22.04 

echo "[*] Install basic deps..." 
apt-get -y update && \
  apt-get -y install python3 \
    python3-pip \
    python-setuptools \
    build-essential \
    git

echo "[*] Install basic python deps..." 
python3 -m pip install virtualenv

echo "[*] Install volatility2..."
apt-get -y install python2.7
git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility
cd /opt/volatility
python3 -m virtualenv venv
source venv/bin/activate
python2.7 setup.py install
deactivate
