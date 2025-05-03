#!/usr/bin/env python3

import sys
import ipaddress
import logging
import time
import threading

from scapy.all import (
    IP, ICMP, TCP, UDP, ARP, Ether,
    sr, sr1, srp, srp1,
    conf
)

# Suppress Scapy warnings/verbose
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

DEFAULT_NET_WS   = "10.1.0.0/24"   # workstation LAN
DEFAULT_HOST_DMZ = "10.12.0.10"    # HTTP server in the DMZ
DEFAULT_PORTS    = "22,80,443"     # SSH, HTTP, HTTPS

SPINNER = ['|', '/', '-', '\\']
SPIN_SPEED = 0.1  # seconds between spinner frames

# global event to signal worker threads to stop
stop_event = threading.Event()

def _show_spinner_and_pct(i, total):
    """Displays a spinning cursor and the percentage completion.

    Internal helper function for showing progress during scans.

    :param i: int - The current index of the loop iteration.
    :param total: int - The total number of items to process.
    """
    frame = SPINNER[int(time.time() / SPIN_SPEED) % len(SPINNER)]
    pct = (i + 1) / total * 100
    sys.stdout.write(f"\r {frame}  {pct:5.1f}%")
    sys.stdout.flush()

def ping_sweep(stop_evt, net_str, timeout=0.1):
    """Performs an ICMP ping sweep on a given network range.

    Sends ICMP echo requests to each host in the specified network.
    Reports hosts that reply. Stops if the stop_evt is set.

    :param stop_evt: threading.Event - Event object to signal interruption.
    :param net_str: str - The network range in CIDR notation (e.g., "192.168.1.0/24").
    :param timeout: float - Time in seconds to wait for an ICMP reply (default: 0.1).
    """
    try:
        net = ipaddress.ip_network(net_str)
    except ValueError as e:
        print(f"→ Invalid network '{net_str}': {e}")
        return

    hosts = list(net.hosts())
    total = len(hosts)
    alive = []
    interrupted = False

    print(f"\n[*] ICMP Ping sweep on {net_str}")
    try:
        for i, ip in enumerate(hosts):
            if stop_evt.is_set():
                interrupted = True
                print("\nStopping ping sweep...")
                break
            _show_spinner_and_pct(i, total)
            pkt = IP(dst=str(ip)) / ICMP()
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp:
                alive.append(str(ip))
                sys.stdout.write('\r' + ' ' * 50 + '\r') # spinner
                print(f"  → {ip} is alive")
    finally:
        sys.stdout.write('\r' + ' ' * 50 + '\r') #spinner
        status = "Interrupted" if interrupted else "Terminated"
        print(f"[ICMP Ping sweep] {status}: {len(alive)} IP{'s' if len(alive)!=1 else ''} found")


def arp_ping_sweep(stop_evt, net_str, chunk_size=100):
    """Performs an ARP ping sweep on a given network range.

    Sends ARP requests to discover live hosts on the local network segment.
    Reports hosts that reply with their MAC addresses. Stops if the stop_evt is set.

    :param stop_evt: threading.Event - Event object to signal interruption.
    :param net_str: str - The network range in CIDR notation (e.g., "192.168.1.0/24").
    :param chunk_size: int - The number of hosts to probe in each ARP request batch (default: 100).
    """
    try:
        net = ipaddress.ip_network(net_str)
    except ValueError as e:
        print(f"→ Invalid network '{net_str}': {e}")
        return

    hosts = [str(ip) for ip in net.hosts()]
    total = len(hosts)
    alive = []
    interrupted = False

    print(f"\n[*] ARP Ping sweep on {net_str} (batch size: {chunk_size})")
    try:
        for idx in range(0, total, chunk_size):
            if stop_evt.is_set():
                interrupted = True
                print("\nStopping ARP sweep...")
                break
            batch = hosts[idx:idx+chunk_size]
            _show_spinner_and_pct(idx, total)
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=batch)
            # timeout=1 for ARP requests since it's all local 
            ans, _ = srp(pkt, timeout=1, verbose=0)
            for _, resp in ans:
                ip = resp.psrc
                mac = resp.hwsrc
                if (ip, mac) not in alive:
                    alive.append((ip, mac))
                    sys.stdout.write('\r' + ' ' * 60 + '\r') # spinner
                    print(f"  → {ip} is alive (MAC {mac})")
    finally:
        sys.stdout.write('\r' + ' ' * 60 + '\r') # spinner
        status = "Interrupted" if interrupted else "Terminated"
        print(f"[ARP Ping sweep] {status}: {len(alive)} IP{'s' if len(alive)!=1 else ''} found")


def tcp_syn_scan(stop_evt, tgt, ports, timeout=1):
    """Performs a TCP SYN scan on the target host and ports.

    Sends SYN packets and identifies open vs closed vs filtered ports.

    :param stop_evt: threading.Event - Event object to signal interruption.
    :param tgt: str - The target IP address to scan.
    :param ports: list - List of ports to scan (e.g., [22, 80, 443]).
    :param timeout: float - Time in seconds to wait for a response (default: 1).
    """
    try:
        ipaddress.ip_address(tgt)
    except ValueError as e:
        print(f"→ Invalid IP '{tgt}': {e}")
        return

    total = len(ports)
    interrupted = False
    print(f"\n[*] TCP SYN Scan on {tgt} ports {','.join(map(str, ports))}")
    try:
        for i, port in enumerate(ports):
            if stop_evt.is_set():
                interrupted = True
                print("\nStopping TCP SYN Scan...")
                break
            _show_spinner_and_pct(i, total)
            # send SYN
            pkt = IP(dst=tgt) / TCP(dport=port, flags='S')
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if stop_evt.is_set():
                interrupted = True
                break
            sys.stdout.write('\r' + ' ' * 50 + '\r')
            if resp is None:
                print(f"  → TCP port {port} FILTERED (no response)")
            elif resp.haslayer(TCP):
                tcp = resp.getlayer(TCP)
                if tcp.flags == 0x12:  # SYN-ACK
                    print(f"  → TCP port {port} OPEN")
                    # clean up with RST
                    sr(IP(dst=tgt)/TCP(dport=port, flags='R'), timeout=0.5, verbose=0)
                elif tcp.flags == 0x14:  # RST-ACK
                    print(f"  → TCP port {port} CLOSED")
            elif resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 3:
                print(f"  → TCP port {port} FILTERED (ICMP unreachable)")
    finally:
        sys.stdout.write('\r' + ' ' * 50 + '\r')
        status = "Interrupted" if interrupted else "Terminated"
        print(f"[TCP SYN Scan] {status}.")


def xmas_tree_scan(stop_evt, tgt, ports, timeout=1):
    """Performs a TCP Xmas Tree scan (FIN, PSH, URG flags).

    Open ports ignore, closed ports reply RST.

    :param stop_evt: threading.Event - Event object to signal interruption.
    :param tgt: str - The target IP address to scan.
    :param ports: list - List of ports to scan (e.g., [22, 80, 443]).
    :param timeout: float - Time in seconds to wait for a response (default: 1).
    """
    try:
        ipaddress.ip_address(tgt)
    except ValueError as e:
        print(f"→ Invalid IP '{tgt}': {e}")
        return

    total = len(ports)
    interrupted = False
    print(f"\n[*] Xmas Tree Scan on {tgt} ports {','.join(map(str, ports))}")
    try:
        for i, port in enumerate(ports):
            if stop_evt.is_set():
                interrupted = True
                print("\nStopping Xmas Tree Scan...")
                break
            _show_spinner_and_pct(i, total)
            pkt = IP(dst=tgt) / TCP(dport=port, flags='FPU')
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if stop_evt.is_set():
                interrupted = True
                break
            sys.stdout.write('\r' + ' ' * 50 + '\r')
            # no response = open|filtered
            if resp is None:
                print(f"  → TCP port {port} OPEN|FILTERED (no answer)")
            elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x14:
                print(f"  → TCP port {port} CLOSED")
            elif resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 3:
                print(f"  → TCP port {port} FILTERED (ICMP unreachable)")
    finally:
        sys.stdout.write('\r' + ' ' * 50 + '\r')
        status = "Interrupted" if interrupted else "Terminated"
        print(f"[Xmas Tree Scan] {status}.")


def udp_scan(stop_evt, tgt, ports, timeout=1):
    """Performs a UDP scan on the target host and ports.

    No reply => open|filtered; ICMP unreachable => closed.

    :param stop_evt: threading.Event - Event object to signal interruption.
    :param tgt: str - The target IP address to scan.
    :param ports: list - List of ports to scan (e.g., [53, 67, 123]).
    :param timeout: float - Time in seconds to wait for a response (default: 1).
    """
    try:
        ipaddress.ip_address(tgt)
    except ValueError as e:
        print(f"→ Invalid IP '{tgt}': {e}")
        return

    total = len(ports)
    interrupted = False
    print(f"\n[*] UDP Scan on {tgt} ports {','.join(map(str, ports))}")
    try:
        for i, port in enumerate(ports):
            if stop_evt.is_set():
                interrupted = True
                print("\nStopping UDP Scan...")
                break
            _show_spinner_and_pct(i, total)
            pkt = IP(dst=tgt) / UDP(dport=port)
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if stop_evt.is_set():
                interrupted = True
                break
            sys.stdout.write('\r' + ' ' * 50 + '\r')
            if resp is None:
                print(f"  → UDP port {port} OPEN|FILTERED (no answer)")
            elif resp.haslayer(ICMP) and resp.getlayer(ICMP).type == 3 and resp.getlayer(ICMP).code == 3:
                print(f"  → UDP port {port} CLOSED")
    finally:
        sys.stdout.write('\r' + ' ' * 50 + '\r')
        status = "Interrupted" if interrupted else "Terminated"
        print(f"[UDP Scan] {status}.")

def run_scan_in_thread(target_func, *args):
    """runs a given scan function in a separate daemon thread.

    Handles starting the thread & keyboard interrupts (Ctrl+C)
    with global stop_event and waits for the thread to finish

    :param target_func: function - The scan function to execute in the thread (e.g., ping_sweep).
    :param *args: tuple - Arguments to pass to the target_func (stop_evt is added automatically as the first arg).
    """
    global stop_event
    stop_event.clear() # ensure the event is clear before starting a new scan
    # pass stop_event as the first argument to the target function
    thread = threading.Thread(target=target_func, args=(stop_event,) + args, daemon=True)
    thread.start()
    try:
        # Wait for the thread to complete, but check frequently to remain responsive
        while thread.is_alive():
            thread.join(timeout=0.5) # Check every 0.5 seconds
    except KeyboardInterrupt:
        print("\n[Main] ^C detected! Signaling scan thread to stop...")
        stop_event.set()
        thread.join() # wait for the thread to finish
        print("[Main] Scan thread stopped.")

def main():
    """Main function to run the interactive command-line interface."""
    while True:
        print("\nSelect attack:")
        print(" 1. ICMP Ping Sweep")
        print(" 2. ARP Ping Sweep")
        print(" 3. TCP SYN Port Scan")
        print(" 4. Xmas Tree Scan")
        print(" 5. UDP Scan")
        print(" 6. Exit")
        choice = input("Choice: ").strip()

        try:
            if choice == '1':
                net = input(f"Network to ping-sweep [{DEFAULT_NET_WS}]: ").strip() or DEFAULT_NET_WS
                run_scan_in_thread(ping_sweep, net) # default timeout is 0.1 seconds
            elif choice == '2':
                net = input(f"Network to ARP-sweep [{DEFAULT_NET_WS}]: ").strip() or DEFAULT_NET_WS
                run_scan_in_thread(arp_ping_sweep, net, 100) # default chunk size is 100
            elif choice == '3':
                tgt = input(f"Target IP [{DEFAULT_HOST_DMZ}]: ").strip() or DEFAULT_HOST_DMZ
                ports_str = input(f"Ports [{DEFAULT_PORTS}]: ").strip() or DEFAULT_PORTS
                ports = [int(p) for p in ports_str.split(',')]
                run_scan_in_thread(tcp_syn_scan, tgt, ports)
            elif choice == '4':
                tgt = input(f"Target IP [{DEFAULT_HOST_DMZ}]: ").strip() or DEFAULT_HOST_DMZ
                ports_str = input(f"Ports [{DEFAULT_PORTS}]: ").strip() or DEFAULT_PORTS
                ports = [int(p) for p in ports_str.split(',')]
                run_scan_in_thread(xmas_tree_scan, tgt, ports)
            elif choice == '5':
                tgt = input(f"Target IP [{DEFAULT_HOST_DMZ}]: ").strip() or DEFAULT_HOST_DMZ
                ports_str = input(f"Ports [{DEFAULT_PORTS}]: ").strip() or DEFAULT_PORTS
                ports = [int(p) for p in ports_str.split(',')]
                run_scan_in_thread(udp_scan, tgt, ports)
            elif choice == '6':
                print("Exiting...")
                sys.exit(0)
            else:
                print("→ Invalid choice, try again.")
        except Exception as e:
             print(f"\n[Error] An unexpected error occurred: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[Main] Exiting due to ^C.")
        stop_event.set()
        # quickndirty way thread stops ^^
        time.sleep(0.5)
        sys.exit(0)