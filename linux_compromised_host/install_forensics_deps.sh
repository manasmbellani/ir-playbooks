#!/bin/bash
# Script to be run on Ubuntu 22.04 instance

echo "[*] Install basic dev tools..."
sudo apt-get -y install \
  net-tools \
  python3 \
  python3-pip \
  git \
  docker \
  wget \
  golang \
  python-setuptools \
  build-essential \
  unzip

echo "[*] Install basic python deps..." 
python3 -m pip install virtualenv
  
echo "[*] Install sleuthkit for utilities related to disk info..."
apt-get -y install sleuthkit

echo "[*] Installing fraken from turbinia..."
git clone https://github.com/google/turbinia /opt/turbinia
cd /opt/turbinia
docker pull us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest
docker tag us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest fraken:latest

echo "[*] Installing Neo23x0's yara signature base..."
git clone https://github.com/Neo23x0/signature-base.git /opt/signature-base && \
   cd /opt/signature-base && \
   find /opt/signature-base -type f -not -iname '*.yar' -not -iname '*.yara' -not -iname 'file-type-signatures.txt' -delete


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
python3 -m pip install capstone
python3 setup.py install 
deactivate

echo "[*] Installing AVML releases for linux memory capture..."
mkdir /opt/avml
cd /opt/avml
wget https://github.com/microsoft/avml/releases/download/v0.13.0/avml -O /opt/avml/avml
chmod +x /opt/avml/avml
wget https://github.com/microsoft/avml/releases/download/v0.13.0/avml-convert -O /opt/avml/avml-convert
chmod +x /opt/avml/avml-convert
wget https://github.com/microsoft/avml/releases/download/v0.13.0/avml-convert -O /opt/avml/avml-convert.exe

echo "[*] Downloading dwarf2json to create volatility symbol files..."
git clone https://github.com/volatilityfoundation/dwarf2json.git /opt/dwarf2json
cd /opt/dwarf2json
go build
chmod +x /opt/dwarf2json/dwarf2json

echo "[*] Cloning WMI_Forensics..."
git clone https://github.com/davidpany/WMI_Forensics /opt/WMI_Forensics
cd /opt/WMI_Forensics

echo "[*] Installing dc3dd..."
apt-get -y install dc3dd

echo "[*] Installing bulk-extractor..."
apt-get -y install bulk-extractor

