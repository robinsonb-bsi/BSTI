#!/bin/bash
# Author: Mitchell Kerns

sudo apt update -y

# Setup docker and pull the pcredz docker image
sudo apt install -y docker.io
sudo docker pull snovvcrash/pcredz

# Edit Responder.conf to 
sudo sed -i 's/^SMB = On/SMB = OFF/' /etc/responder/Responder.conf
sudo sed -i 's/^HTTP = On/HTTP = OFF/' /etc/responder/Responder.conf

#Install tool that helps translate SNMP output
sudo apt-get install snmp-mibs-downloader
sudo download-mibs
sudo sed -i '/^mibs :/s/^/#/' /etc/snmp/snmp.conf

# Update Metasploit
sudo apt install -y metasploit-framework
