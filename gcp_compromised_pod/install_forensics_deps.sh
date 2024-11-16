#!/bin/bash
# Script to be run on Ubuntu 22.04 instance

echo "[*] Install basic dev tools..."
apt-get -y update && \
  apt-get -y install \
    net-tools \
    python3 \
    python3-pip \
    python-setuptools \
    python3-snappy \
    build-essential \
    git \
    unzip \
    binutils \
    xxd \
    sudo \
    wireshark \
    firefox \
    torbrowser-launcher \
    xrdp \
    dos2unix \
    jq

echo "[*] Enabling RDP service to start at beginning via xrdp..."
sudo systemctl enable xrdp --now
update-rc.d xrdp defaults

echo "[*] Adding bugfix for torbrowser-launcher..."
# Taken from: https://askubuntu.com/questions/1445050/updating-tor-screwed-up-my-client-download-error-404
sudo sed -i 's|self.language =.*|self.language = "ALL"|g' /usr/lib/python3/dist-packages/torbrowser_launcher/common.py

echo "[*] Installing pip's virtualenv for sandboxing python3 deps..."
python3 -m pip install virtualenv

echo "[*] Installing container-explorer..."
wget https://raw.githubusercontent.com/google/container-explorer/main/script/setup.sh -O /tmp/setup.sh
sudo bash /tmp/setup.sh install
rm /tmp/setup.sh

echo "[*] Installing plaso-tools..."
sudo add-apt-repository -y universe
sudo add-apt-repository -y ppa:gift/stable
sudo apt-get -y update
sudo apt-get -y install plaso-tools sqlite3

echo "[*] Setup docker-compose-plugin..."
sudo apt -y install apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu jammy stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt -y update
sudo apt-get -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin

echo "[*] Install timesketch..."
curl -sL https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh -o /tmp/deploy_timesketch.sh
chmod 755 /tmp/deploy_timesketch.sh
cd /opt
sudo /tmp/deploy_timesketch.sh
cd /opt/timesketch
sudo docker compose up -d
sudo docker compose down

echo "[*] Install dftimewolf..."
git clone https://github.com/log2timeline/dftimewolf.git /opt/dftimewolf
cd /opt/dftimewolf
python3 -m virtualenv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
deactivate

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
# Snappy is required for using avml generated binaries
python3 -m pip install setuptools
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

echo "[*] Installing bulk-extractor..."
apt-get -y install bulk-extractor

echo "[*] Installing avml..." 
mkdir /opt/avml
curl -sL https://github.com/microsoft/avml/releases/download/v0.14.0/avml -o /opt/avml/avml
chmod +x /opt/avml/avml

echo "[*] Installing dwarf2json..."
mkdir /opt/dwarf2json
curl -sL https://github.com/volatilityfoundation/dwarf2json/releases/download/v0.8.0/dwarf2json-linux-amd64 -o /opt/dwarf2json/dwarf2json
chmod +x /opt/dwarf2json/dwarf2json


