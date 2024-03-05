#!/bin/bash

echo "[*] Install basic dev tools..."
sudo apt-get -y install \
  net-tools

echo "[*] Install sleuthkit for utilities related to disk info..."
apt-get -y install sleuthkit

echo "[*] Installing container-explorer..."
wget https://raw.githubusercontent.com/google/container-explorer/main/script/setup.sh -o /tmp/setup.sh
sudo bash /tmp/setup.sh install

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
curl -s -O https://raw.githubusercontent.com/google/timesketch/master/contrib/deploy_timesketch.sh -o /tmp/deploy_timesketch.sh
chmod 755 /tmp/deploy_timesketch.sh
cd /opt
sudo /tmp/deploy_timesketch.sh
cd /opt/timesketch
sudo docker compose up -d



