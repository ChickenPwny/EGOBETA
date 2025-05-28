#!/bin/bash

# Create a directory for static files
mkdir STATICFILES_DIRS

# Update packages
sudo apt update -y

# Install nmap
sudo apt-get install nmap -y

# Install Nuclei
echo "Installing Nuclei..."
curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | \
grep "browser_download_url.*nuclei-linux-amd64.zip" | \
cut -d '"' -f 4 | \
wget -qi -

# Unzip the downloaded file
unzip nuclei-linux-amd64.zip

# Move the binary to /usr/local/bin for global access
sudo mv nuclei /usr/local/bin/

# Clean up the zip file
rm nuclei-linux-amd64.zip

# Verify installation
nuclei -version