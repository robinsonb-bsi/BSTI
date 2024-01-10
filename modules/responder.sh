#!/bin/bash
# ARGS
# INTERFACE "eg: eth0"
# ENDARGS
# Author: Connor Fancy

# Display a usage message if the number of arguments is incorrect
if [ $# -ne 1 ]; then
    echo "Usage: $0 <INTERFACE>"
    echo "Example: $0 eth0"
    exit 1
fi

INTERFACE=$1

# Check if the specified interface exists and is up
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "Error: Interface '$INTERFACE' does not exist or is down."
    exit 1
fi

# Execute the Responder command
sudo responder -I "$INTERFACE" -w -F -P