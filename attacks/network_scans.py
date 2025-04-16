from scapy.all import IP, ICMP, sr, conf, ARP, Ether, srp
import ipaddress
import sys
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

conf.verb = 0

def ping_sweep():
    try:
        network = input("What's the network to scan (ie: 10.1.0.0/24)? ").strip().lower();
        net = ipaddress.ip_network(network)
    
    except ValueError as e:
        print(f"Invalid network: {e}")
        return

    print(f"Scanning network {network} for live hosts...\n")
    for ip in net.hosts():
        pkt = IP(dst=str(ip)) / ICMP()
        ans, _ = sr(pkt, timeout=1, verbose=0)
        ans.summary( lambda s, r  : r.sprintf("{IP: %IP.src% is alive}") )
        
def arp_ping_sweep():
    try:
        network = input("What's the network to scan (ie: 10.1.0.0/24)? ").strip().lower();
        net = ipaddress.ip_network(network)
    
    except ValueError as e:
        print(f"Invalid network: {e}")
        return

    print(f"Scanning network {network} for live hosts...\n")
    targets = [str(ip) for ip in net.hosts()]
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
    ans, _ = srp(pkt, timeout=1, verbose=0)
    ans.summary(lambda s, r: r.sprintf("{ARP: %ARP.psrc% is alive with MAC %ARP.hwsrc%}"))
        
if __name__ == "__main__":
    print("What attack do you want to perform?\n")
    print("1. Ping Sweep\n")
    print("2. ARP Ping Sweep\n")
    

    choice = input("Enter your choice: ")
    if choice == '1':
        ping_sweep()

    elif choice == '2':
        arp_ping_sweep()

    else:
        print("Invalid choice.")
        sys.exit(1)
