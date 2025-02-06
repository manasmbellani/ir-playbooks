#!/bin/bash
# Script to be run on Ubuntu 22.04 instance

cwd=$(pwd)

echo "[*] Install basic dev tools..."
sudo apt-get -y install \
  net-tools \
  python3 \
  python3-pip \
  python2-dev \
  git \
  docker \
  wget \
  golang \
  python-setuptools \
  build-essential \
  unzip \
  curl \
  yara \
  exiftool \
  nmap \
  auditd \
  tshark \
  python3-virtualenv \
  docker.io \
  strace \
  wtmpdb

echo "[*] Install basic python deps..." 
python3 -m pip install virtualenv
  
echo "[*] Install sleuthkit for utilities related to disk info..."
apt-get -y install sleuthkit

echo "[*] Loading auditd rules and reloading rules..."
curl -sL https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -o /etc/audit/rules.d/audit.rules
# Apply the additional auditd rules
echo "# Custom: Add monitoring for changes to authorized_keys file" >> /etc/audit/rules.d/audit.rules
echo "-w /root/.ssh/authorized_keys -p wa -k root_keychange" >> /etc/audit/rules.d/audit.rules
echo "-w /home/manasbellani/.ssh/authorized_keys -p wa -k user_keychange_mb" >> /etc/audit/rules.d/audit.rules
echo "-w /home/ubuntu/.ssh/authorized_keys -p wa -k user_keychange_u" >> /etc/audit/rules.d/audit.rules
# Regenerate the audit.rules file
service auditd restart
# Reload audit.rules file 
auditctl -R /etc/audit/audit.rules


echo "[*] Installing fraken from turbinia..."
git clone https://github.com/google/turbinia /opt/turbinia
cd /opt/turbinia
docker pull us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest
docker tag us-docker.pkg.dev/osdfir-registry/turbinia/release/fraken:latest fraken:latest

echo "[*] Installing Neo23x0's yara signature base..."
git clone https://github.com/Neo23x0/signature-base.git /opt/signature-base && \
   cd /opt/signature-base && \
   find /opt/signature-base -type f -not -iname '*.yar' -not -iname '*.yara' -not -iname 'file-type-signatures.txt' -delete

echo "[*] Enabling RDP service to start at beginning via xrdp..."
echo "[*] Installing xrdp..."
sudo apt-get -y update && \
apt-get -y install \
  xfce4 \
  xfce4-goodies \
  xrdp
sudo systemctl enable xrdp --now
update-rc.d xrdp defaults

echo "[*] Install volatility2..."
apt-get -y install python2.7
git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility2
cd /opt/volatility2
python3 -m virtualenv venv
source venv/bin/activate
curl -s https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip.py
python2.7 /tmp/get-pip.py
rm /tmp/get-pip.py
python2.7 -m pip install distorm3 pycrypto openpyxl Pillow
python2.7 setup.py install
deactivate

echo "[*] Installing volatility3..."
git clone https://github.com/volatilityfoundation/volatility3 /opt/volatility3
cd /opt/volatility3
python3 -m virtualenv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
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
mv /opt/dwarf2json/dwarf2json /usr/bin/
cd $cwd

echo "[*] Downloading linpmem..."
curl -sL https://github.com/Velocidex/c-aff4/releases/download/v3.3.rc3/linpmem-v3.3-rc3.3-rc2 -o /usr/bin/linpmem
chmod +x /usr/bin/linpmem

echo "[*] Cloning WMI_Forensics..."
git clone https://github.com/davidpany/WMI_Forensics /opt/WMI_Forensics
cd /opt/WMI_Forensics

echo "[*] Installing dc3dd..."
apt-get -y install dc3dd

echo "[*] Installing bulk-extractor..."
apt-get -y install bulk-extractor

echo "[*] Installing binwalk..."
apt-get -y install binwalk

echo "[*] Installing rust, cargo..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash

echo "[*] Installing dumpit-linux and generating binary using rust..."
git clone https://github.com/MagnetForensics/dumpit-linux /opt/dumpit-linux
cd /opt/dumpit-linux
apt-get -y install pkg-config liblzma-dev
~/.cargo/bin/cargo build --release

echo "[*] Installing yara-x..."
git clone https://github.com/VirusTotal/yara-x /opt/yara-x
cd /opt/yara-x
~/.cargo/bin/cargo build --release

echo "[*] Installing Loki and signature base..."
git clone https://github.com/Neo23x0/Loki /opt/loki
cd /opt/loki
python3 -m virtualenv venv
source venv/bin/activate
python3 -m pip install colorama yara-python psutil rfc5424-logging-handler netaddr
python3 loki-upgrader.py
deactivate

echo "[*] Installing binary ninja disassembler..." 
mkdir /opt/binaryninja
cd /opt/binaryninja
curl -sL https://cdn.binary.ninja/installers/binaryninja_free_linux.zip -o /opt/binaryninja/binaryninja.zip
unzip /opt/binaryninja/binaryninja.zip

echo "[*] Installing IDA Pro..."
cd /tmp
curl -sL https://out7.hex-rays.com/files/idafree84_linux.run -o /tmp/idafree84_linux.run
chmod +x /tmp/idafree84_linux.run
/tmp/idafree84_linux.run
rm /tmp/idafree84_linux.run

echo "[*] Installing Ghidra via snap..."
apt-get -y install snapd
snap install ghidra

echo "[*] Installing fastir-artifacts..."
git clone https://github.com/OWNsecurity/fastir_artifacts /opt/fastir_artifacts
cd /opt/fastir_artifacts
python3 -m virtualenv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
deactivate

echo "[*] Installing trid..."
mkdir /opt/trid
curl -sL https://mark0.net/download/trid_linux_64.zip -o /opt/trid/trid.zip
cd /opt/trid
unzip trid.zip
chmod +x trid
mv trid /usr/bin
rm /opt/trid/trid.zip

echo "[*] Installing trid defs..."
curl -sL https://mark0.net/download/triddefs.zip -o /opt/trid/triddefs.zip
cd /opt/trid
unzip triddefs.zip
mv triddefs.trd /usr/bin
rm /opt/trid/triddefs.zip

echo "[*] Installing reflex..."
go install github.com/cespare/reflex@latest

echo "[*] Installing ewfmount..."
apt-get -y remove libewf && apt-get -y install ewf-tools

echo "[*] Installing plaso image via docker..."
docker pull log2timeline/plaso

echo "[*] Installing LinTri..."
git clone https://github.com/DCScoder/LINTri /opt/lintri

echo "[*] Installing unix artifacts collector (uac)..."
curl -sL https://github.com/tclahr/uac/releases/download/v2.9.1/uac-2.9.1.tar.gz -o /tmp/uac.tar.gz
cd /tmp
tar -xzvf uac.tar.gz
mv /tmp/uac-2.9.1 /opt/uac
cd $cwd

echo "[*] Installing bulk_extractor with required dependencies..."
# Some Steps taken from: https://medium.com/@randomdent/getting-started-with-bulk-extractor-on-ubuntu-20-04-lts-b7290b43f04a
git clone --recurse-submodules https://github.com/simsong/bulk_extractor.git /opt/bulk_extractor
cd /opt/bulk_extractor
apt-get -y update && apt-get -y install autoconf automake libssl-dev flex
cd etc/
/bin/bash CONFIGURE_UBUNTU22LTS.bash
cd ..
./bootstrap.sh
./configure
make
make install
cd $cwd

echo "[*] Installing sysinternalsebpf, sysmon for linux..."
apt-get -y install libjson-glib-1.0-0 libjson-glib-1.0-common
curl -sL https://github.com/microsoft/SysinternalsEBPF/releases/download/1.4.0.0/sysinternalsebpf_1.4.0_amd64.deb -o /tmp/sysinternalsebpf_1.4.0_amd64.deb
dpkg -i /tmp/sysinternalsebpf_1.4.0_amd64.deb
curl -sL https://github.com/microsoft/SysmonForLinux/releases/download/1.3.3.0/sysmonforlinux_1.3.3_amd64.deb -o /tmp/sysmonforlinux_1.3.3_amd64.deb
dpkg -i /tmp/sysmonforlinux_1.3.3_amd64.deb
rm /tmp/sysinternalsebpf_1.4.0_amd64.deb
rm /tmp/sysmonforlinux_1.3.3_amd64.deb


echo "[*] Installing oletools..."
mkdir /opt/oletools
cd /opt/oletools
python3 -m virtualenv venv
source venv/bin/activate
python3 -m pip install -U oletools[full]
deactivate

echo "[*] Installing DidierStevensSuite..."
mkdir /opt/DidierStevensSuite
cd /opt/DidierStevensSuite
curl -sL https://didierstevens.com/files/software/DidierStevensSuite.zip -o /tmp/DidierStevensSuite.zip
unzip /tmp/DidierStevensSuite.zip

echo "[*] Installing foremost for file recovery..."
apt-get -y install foremost

echo "[*] Installing photorec (testdisk) for file recovery..."
apt-get -y install testdisk

echo "[*] Installing CVE Prioritizer..."
git clone https://github.com/TURROKS/CVE_Prioritizer.git /opt/CVE_Prioritizer
cd /opt/CVE_Prioritizer
python3 -m virtualenv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
deactivate
