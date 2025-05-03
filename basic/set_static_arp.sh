#!/bin/bash

# Define ip's for the relevant hosts on ws LAN for instance here
WS3_IP="10.1.0.3"
R1_IP="10.1.0.1"

# find local ip address matching one of the target IPs
MY_IP=$(ip -o -4 addr show | awk -v r1="$R1_IP" -v ws3="$WS3_IP" '$4 ~ r1 || $4 ~ ws3 {split($4, a, "/"); print a[1]; exit}')

if [ "$MY_IP" = "$WS3_IP" ]; then
  ROLE="Workstation (ws3)"
  COUNTERPART_IP=$R1_IP
elif [ "$MY_IP" = "$R1_IP" ]; then
  ROLE="Router (r1)"
  COUNTERPART_IP=$WS3_IP
else
  echo "Error: Could not determine local role. Found IP '$MY_IP'." >&2
  echo "Run this script on the host with IP $WS3_IP or $R1_IP." >&2
  exit 1
fi

echo "Running on $ROLE ($MY_IP). Setting static ARP for $COUNTERPART_IP."

LOCAL_IF=$(ip route get $COUNTERPART_IP | awk '{print $3; exit}')
if [ -z "$LOCAL_IF" ]; then
  echo "Error: Could not determine local interface to reach $COUNTERPART_IP." >&2
  exit 1
fi

# Get counterpart MAC
COUNTERPART_MAC=$(arping -c 1 -I $LOCAL_IF $COUNTERPART_IP | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
if [ -z "$COUNTERPART_MAC" ]; then
  echo "Error: Could not get MAC address for $COUNTERPART_IP via $LOCAL_IF using arping." >&2
  echo "Ensure arping is installed and the counterpart is reachable." >&2
  exit 1
fi

# Set the static arp entry
echo "Executing: sudo arp -s $COUNTERPART_IP $COUNTERPART_MAC -i $LOCAL_IF"
sudo arp -s $COUNTERPART_IP $COUNTERPART_MAC -i $LOCAL_IF

echo "Verifying ARP entry:"
arp -n | grep "$COUNTERPART_IP" | grep "$LOCAL_IF"

echo "Static ARP entry set successfully."
exit 0