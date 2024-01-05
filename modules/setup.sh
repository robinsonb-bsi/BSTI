#!/bin/bash

sudo apt update -y

# Setup docker and pull the pcredz docker image
sudo apt install docker.io
sudo docker pull snovvcrash/pcredz

# Edit Responder.conf to 
sudo sed -i 's/^SMB = On/SMB = OFF/' /etc/responder/Responder.conf
sudo sed -i 's/^HTTP = On/HTTP = OFF/' /etc/responder/Responder.conf

# Start term.py, enabling the option of opening a 
sudo python3 /root/term.py