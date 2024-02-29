#!/bin/bash
# Based on https://grr-doc.readthedocs.io/en/latest/installing-grr-server/from-release-deb.html

echo "[*] Updating apt-get..."
apt-get -y update

echo "[*] Installing mysql-server and other deps..."
apt-get -y install \
    mysql-server \
    net-tools


# echo "[*] Updating my.cnf to change max_allowed_packet..."
cat <<EOF >> /etc/mysql/my.cnf
[mysqld]
max_allowed_packet=40M
log_bin_trust_function_creators=1
EOF

echo "[*] Setup GRR MySQL commands to execute..."
cat <<EOF > /tmp/grr-mysql-commands.txt
SET GLOBAL max_allowed_packet=41943040;
CREATE USER 'grr'@'localhost' IDENTIFIED BY 'password';
CREATE DATABASE grr;
GRANT ALL PRIVILEGES ON \*.* TO 'your_user'@'%';
FLUSH PRIVILEGES;
EOF

echo "[*] Setup MySQL commands to setup GRR..."
/usr/bin/mysql -u root < /tmp/grr-mysql-commands.txt

echo "[*] Restarting mysql server..."
service mysql restart

# echo "[*] Preparing mysql commands in file to setup fleetspeak..."
# cat <<EOF >> /tmp/fleetspeak.txt
# CREATE USER 'grr'@'localhost' IDENTIFIED BY 'password';
# CREATE DATABASE grr;
# GRANT ALL ON grr.* TO 'grr'@'localhost';
# CREATE USER 'fleetspeak'@'localhost' IDENTIFIED BY 'password';
# CREATE DATABASE fleetspeak;
# GRANT ALL ON fleetspeak.* TO 'fleetspeak'@'localhost';
# EOF

# echo "[*] Setup mysql server for fleetspeak server..."
# /usr/bin/mysql < /tmp/fleetspeak.txt

# echo "[*] Removing mysql commands file..."
# rm /tmp/fleetspeak.txt

echo "[*] Downloading the grr-server .deb 3.4.2.3 version of grr server..."
wget https://storage.googleapis.com/releases.grr-response.com/grr-server_3.4.2-3_amd64.deb

#echo "[*] Downloading the latest grr-server .deb version of grr server..."
#curl -s https://api.github.com/repos/google/grr/releases/latest \
#| grep "browser_download_url.*deb" \
#| cut -d : -f 2,3 \
#| tr -d \" \
#| wget -qi -

echo "[*] Installing grr server .deb..."
deb_file=$(ls -1 *.deb | head -n1)
apt-get install -y "./$deb_file"

echo "[*] Restarting grr server..."
sudo systemctl restart grr-server
