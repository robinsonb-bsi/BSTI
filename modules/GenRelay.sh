#!/bin/bash

sudo crackmapexec smb $1 --gen-relay-list targets_$(date +%F).txt
sudo cat targets_$(date +%F).txt | sort | uniq | tee smb-not-signed.txt