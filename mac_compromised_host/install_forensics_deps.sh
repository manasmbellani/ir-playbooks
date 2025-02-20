#!/bin/bash
# Script to install various dependencies on a macbook for forensics purposes

cwd=$(pwd)

mkdir ~/opt 2>/dev/null

echo "[*] Installing macos-UnifiedLogs for parsing unified logs..."

mkdir ~/opt/macos-UnifiedLogs
curl -sL https://github.com/mandiant/macos-UnifiedLogs/releases/download/v0.1.1/unifiedlog_iterator-v0.1.1-x86_64-apple-darwin.tar.gz -o ~/opt/macos-UnifiedLogs/unifiedlog_iterator.tar.gz
cd ~/opt/macos-UnifiedLogs/
tar xzvf ~/opt/macos-UnifiedLogs/unifiedlog_iterator.tar.gz
rm unifiedlog_iterator.tar.gz
mv *-apple-darwin unifiedlog_iterator
cd $cwd
