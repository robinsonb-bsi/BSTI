#!/bin/bash
# Author: Mitchell Kerns, Connor Fancy

# Function to check network connectivity
check_network_connection() {
    # Attempt to ping a reliable host
    if ! ping -c 1 google.com > /dev/null 2>&1; then
        echo "Network connection is not available. Please check your connection."
        exit 1
    fi
}

# Check for network connection
check_network_connection

# Update package lists
sudo apt-get update -y

# Install Docker and pull the pcredz Docker image
sudo apt-get install -y docker.io eyewitness
sudo docker pull snovvcrash/pcredz

# Edit Responder.conf
sudo sed -i 's/^SMB = On/SMB = OFF/' /etc/responder/Responder.conf
sudo sed -i 's/^HTTP = On/HTTP = OFF/' /etc/responder/Responder.conf

# Install SNMP MIB downloader and configure SNMP
sudo apt-get install -y snmp-mibs-downloader
sudo download-mibs
sudo sed -i '/^mibs :/s/^/#/' /etc/snmp/snmp.conf

# Update Metasploit
sudo apt install -y metasploit-framework

python3 -m pip install mitm6

echo "Setup complete."
