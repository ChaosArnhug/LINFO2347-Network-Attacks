from scapy.all import IP, ICMP, sr, sr1, conf, ARP, Ether, srp, TCP, UDP
import ipaddress
import sys
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

def get_ports():
    ports = input("Enter ports to scan (comma-separated, e.g., 22,80,443): ").split(',')
    return [int(port.strip()) for port in ports if port.strip().isdigit()]

def ping_sweep_hosts(network):
    net = ipaddress.ip_network(network)
    live_hosts = []
    print(f"\n[+] Scanning network {network} for live hosts (ICMP)...\n")
    for ip in net.hosts():
        pkt = IP(dst=str(ip)) / ICMP()
        ans, _ = sr(pkt, timeout=1, verbose=0)
        for _, r in ans:
            live_ip = r[IP].src
            print(f"{live_ip} is alive")
            live_hosts.append(live_ip)
    return live_hosts

def arp_ping_sweep_hosts(network):
    net = ipaddress.ip_network(network)
    targets = [str(ip) for ip in net.hosts()]
    live_hosts = []
    print(f"\n[+] Scanning network {network} for live hosts (ARP)...\n")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
    ans, _ = srp(pkt, timeout=1, verbose=0)
    for _, r in ans:
        live_ip = r[ARP].psrc
        print(f"{live_ip} is alive with MAC {r[ARP].hwsrc}")
        live_hosts.append(live_ip)
    return live_hosts

def tcp_syn_port_scan(ip, ports):
    print(f"\n[*] TCP SYN Scan on {ip}")
    for port in ports:
        pkt = IP(dst=ip) / TCP(dport=port, flags='S')
        ans, _ = sr(pkt, timeout=1, verbose=0)
        for _, r in ans:
            if r.haslayer(TCP) and r[TCP].flags == 0x12:
                print(f"    [OPEN] TCP Port {port}")

def xmas_tree_scan(ip, ports):
    print(f"\n[*] Xmas Tree Scan on {ip}")
    for port in ports:
        pkt = IP(dst=ip) / TCP(dport=port, flags="FPU")
        ans, _ = sr(pkt, timeout=1, verbose=0)
        if not ans:
            print(f"    [OPEN or FILTERED] TCP Port {port}")
        for _, r in ans:
            if r.haslayer(TCP) and r[TCP].flags == 0x14:
                print(f"    [CLOSED] TCP Port {port}")

def udp_scan(ip, ports):
    print(f"\n[*] UDP Scan on {ip}")
    for port in ports:
        pkt = IP(dst=ip) / UDP(dport=port)
        ans = sr(pkt, timeout=2, verbose=0)[0]
        if not ans:
            print(f"    [OPEN or FILTERED] UDP Port {port}")
        for _, r in ans:
            if r.haslayer(ICMP) and r[ICMP].type == 3 and r[ICMP].code == 3:
                print(f"    [CLOSED] UDP Port {port}")

def main():
    print("Choose network scan type:\n")
    print("1. ICMP Ping Sweep")
    print("2. ARP Ping Sweep")
    print("3. Exit\n")

    choice = input("Enter your choice: ").strip()
    if choice not in ['1', '2']:
        print("Exiting.")
        sys.exit(0)

    network = input("Enter network (e.g., 192.168.1.0/24): ").strip()
    try:
        ipaddress.ip_network(network)
    except ValueError as e:
        print(f"Invalid network: {e}")
        return

    ports = get_ports()
    if not ports:
        print("No valid ports provided. Exiting.")
        return

    if choice == '1':
        hosts = ping_sweep_hosts(network)
    elif choice == '2':
        hosts = arp_ping_sweep_hosts(network)

    if not hosts:
        print("No live hosts found.")
        return

    for host in hosts:
        tcp_syn_port_scan(host, ports)
        xmas_tree_scan(host, ports)
        udp_scan(host, ports)

if __name__ == "__main__":
    main()
