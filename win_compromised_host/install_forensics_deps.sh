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

echo "[*] Installing volatility3..."
git clone https://github.com/volatilityfoundation/volatility3 /opt/volatility3
cd /opt/volatility3
python3 -m virtualenv venv
source venv/bin/activate
python3 setup.py install 
deactivate

echo "[*] Installing plyvel..."
mkdir /opt/plyvel
cd /opt/plyvel
python3 -m virtualenv venv
source venv/bin/activate
python3 -m pip install plyvel
deactivate

echo "[*] Installing uploadserver..."
mkdir /opt/uploadserver
cd /opt/uploadserver
python3 -m virtualenv venv
source venv/bin/activate
python3 -m pip install uploadserver
deactivate
