#!/bin/bash
# Script to be run on Ubuntu 22.04 instance

echo "[*] Install basic dev tools..."
sudo apt-get -y install \
  net-tools \
  python3 \
  python3-pip \
  git \
  docker
  
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
