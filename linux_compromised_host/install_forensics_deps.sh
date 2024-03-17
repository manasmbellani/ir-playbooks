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
  golang
  
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

