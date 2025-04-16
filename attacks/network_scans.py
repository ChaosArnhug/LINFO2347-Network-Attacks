from scapy.all import IP, ICMP, sr, conf, ARP, Ether, srp, TCP
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
        network = input("What's the network to scan (ie: 10.1.0.0/24)? ").strip().lower()
        net = ipaddress.ip_network(network)
    
    except ValueError as e:
        print(f"Invalid network: {e}")
        return

    print(f"Scanning network {network} for live hosts...\n")
    targets = [str(ip) for ip in net.hosts()]
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
    ans, _ = srp(pkt, timeout=1, verbose=0)
    ans.summary(lambda s, r: r.sprintf("{ARP: %ARP.psrc% is alive with MAC %ARP.hwsrc%}"))

def tcp_syn_port_scan():
    try:
        ip = input("Enter the IP address to scan: ").strip()
        ports = input("Enter ports to scan (comma-separated): ").split(',')
        ports = [int(port.strip()) for port in ports]
        ipaddress.ip_address(ip)
        
    except ValueError as e:
        print(f"Error: {e}")
        return

    print(f"Scanning {ip} for open ports...\n")
    for port in ports:
        if not (1 <= port <= 65535):
            print(f"Port {port} is out of range. Skipping...")
            continue
        pkt = IP(dst=ip) / TCP(dport=port, flags='S')
        ans, _ = sr(pkt, timeout=1, verbose=0)
        for s, r in ans:
            if r.haslayer(TCP) and r[TCP].flags == 0x12:  # SYN-ACK
                print(f"Port {s[TCP].dport} is OPEN")

            #elif r.haslayer(TCP) and r[TCP].flags == 0x14:  # RST-ACK
                #print(f"Port {s[TCP].dport} is CLOSED")

def xmas_tree_scan():
    try:
        ip = input("Enter the IP address to scan: ").strip()
        ports = input("Enter ports to scan (comma-separated): ").split(',')
        ports = [int(port.strip()) for port in ports]
        ipaddress.ip_address(ip)

    except ValueError as e:
        print(f"Error: {e}")
        return

    print(f"Running Xmas Tree scan on {ip}...\n")

    for port in ports:
        if not (1 <= port <= 65535):
            print(f"Port {port} is out of range. Skipping...")
            continue

        pkt = IP(dst=ip) / TCP(dport=port, flags="FPU")
        ans, _ = sr(pkt, timeout=1, verbose=0)

        for s, r in ans:
            if r.haslayer(TCP) and r[TCP].flags == 0x14:  # RST
                print(f"Port {port} is CLOSED")
        
if __name__ == "__main__":
    print("What attack do you want to perform?\n")
    print("1. Ping Sweep\n")
    print("2. ARP Ping Sweep\n")
    print("3. TCP SYN Port Scan\n")
    print("4. Xmas Tree Scan\n")
    

    choice = input("Enter your choice: ")
    if choice == '1':
        ping_sweep()

    elif choice == '2':
        arp_ping_sweep()

    elif choice == '3':
        tcp_syn_port_scan()

    elif choice == '4':
        xmas_tree_scan()

    else:
        print("Invalid choice.")
        sys.exit(1)
