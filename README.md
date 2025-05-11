# LINFO2347: Network Attacks Project

This document provides an overview of the project structure, setup instructions, details about the implemented attacks, how to launch them, and the corresponding defenses using custom topologies. Additionally, it explains the functionality of the basic network protection.

---

## Project Structure

The project is organized into the following folders and files:

```
LINFO2347/
├── attacks/
│   ├── arp_poison.py          # ARP poisoning attack script
│   ├── network_scans.py       # Various network scanning attacks
│   ├── reflected_ddos.py      # DNS reflection attack script
│   ├── syn_flood.py           # SYN flooding attack script
├── basic_network_protection/
│   ├── topo.py                # Mininet topology for basic network protection
│   ├── basic_r1.nft           # Firewall rules for Router R1
│   ├── basic_r2.nft           # Firewall rules for Router R2
│   ├── basic_http.nft         # Firewall rules for HTTP server
│   ├── basic_dns.nft          # Firewall rules for DNS server
│   ├── basic_ntp.nft          # Firewall rules for NTP server
│   ├── basic_ftp.nft          # Firewall rules for FTP server
├── protections/
|   ├── arp_poison/            # Arp poison defense topology and rules
│   ├── xmas_scan/             # Xmas scan defense topology and rules
│   ├── syn_flood/             # SYN flood defense topology and rules
│   ├── reflected_ddos/        # DNS reflection defense topology and rules
|   ├── ping_sweep/            # Ping sweep defense topology and rules
├── README.md                  # Main documentation
├── statement.md               # Project statement
├── default_topo.py            # Default Mininet topology
```

---

## Setup Instructions

This project is designed to run on the VM provided in the course (V2) but we included instructions to run it on a fresh Debian 12 installation. The project uses Mininet for network simulation and `nftables` for firewall rules.

### Installing Required Tools (Debian 12)

Run the following commands to install the necessary tools if you are using a fresh Debian 12 installation:

```bash
sudo apt install tcpdump -y
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh
sudo apt install curl mininet python3-pip python3-setuptools apache2 dnsmasq openntpd vsftpd -y
sudo sed -i 's/^#port=/port=5353/' /etc/dnsmasq.conf
sudo sed -i 's/^port=.*/port=5353/' /etc/dnsmasq.conf
sudo systemctl restart dnsmasq
```

### Lauching the Topology

The project includes several topologies. Launching them include the application of the defenses mechanisms to the network and worstations.
All of them are based on the default topology given in the course with the default one being unmodified. 

1. **Default Topology**:
    Recommanded if you want to test the attacks in a defensless environment.
```bash
sudo python3 ./default_topo.py
```
2. **Basic Network Protection**:
```bash
sudo python3 ./basic_network_protection/topo.py
```
3. **Defense for Xmas Scan**:
```bash
sudo python3 ./protections/xmas_scan/xmas_topo.py
```
4. **Defense for Reflected DDoS**:
```bash
sudo python3 ./protections/reflected_ddos/reflected_topo.py
```
5. **Defense for ARP Poisoning**
```bash
sudo python3 ./protections/arp_poison/arp_poison_topo.py
```
6. **Defense for SYN Flood**:
```bash
sudo python3 ./protections/syn_flood/flood_topo.py
```
7. **Defense for Ping Sweep**:
```bash
sudo python3 ./protections/ping_sweep/sweep_topo.py
```

`NB`: It's recommended to pass the **-E** arg to sudo to preserve the environment variables (since we are dealing with mininet/python)`

---

## Basic Network Protection

The basic network protection ensures the topology mimics a secure enterprise network by implementing firewall rules using `nftables`. These rules enforce the following policies:

1. **Workstations (LAN)**:
   - Can send pings and initiate connections to any other host (workstations, DMZ servers, or the Internet).
   - Responses to their requests are allowed.
   - Cannot receive unsolicited pings or connections comming outside their LAN.

2. **DMZ Servers**:
   - Cannot initiate any connections or send pings.
   - Can only respond to incoming/established connections on specific ports (e.g., HTTP on port 80, DNS on port 5353, etc.) and ping requests.
   - Cannot forward traffic.

3. **Internet**:
   - Can only send pings or initiate connections to DMZ servers.
   - Cannot send pings or initiate connections to workstations.

These rules reduce the attack surface while maintaining normal network functionality.

### Launching the Basic Network Protection

Start the basic network protection topology and defense with the following command:
```bash
sudo python3 ./basic_network_protection/topo.py
```

---

## Attacks and Defenses

### 1. Network Scans (Xmas Scan)

#### Attack
The Xmas scan sends TCP packets with the **FIN**, **PSH**, and **URG** flags set. Open ports do not respond, while closed ports reply with a **RST**.

**Steps to Launch**:
1. Start the default topology:
```bash
sudo python3 ./default_topo.py
```
2. From the `internet` host, run the Xmas scan:
```bash
mininet> internet sudo -E python3 ~/Desktop/LINFO2347/attacks/network_scans.py
```
   Select option `4` (Xmas Tree Scan) and provide the target IP and ports.

*Note: The attack can be launched from any host, but the `internet` host is used for demonstration purposes.*

**Example Output**:

![xmas not protected](./screenshots/xmas_not_protected.png)

#### Defense
To improve the defenses against Xmas scans, add a rule on your hosts to drop packets with the **FIN**, **PSH**, and **URG** flags set:
```nft
tcp flags & (fin|psh|urg) == (fin|psh|urg) drop
```
**Launch the defense**:
```bash
sudo python3 ./protections/xmas_scan/xmas_topo.py
```
*Note: this will launch a new topology including the basic_network_protection and the added defenses.*

**Defense summary**:
| Attacker-Victim | How |
|------|-----|
| ws -> ws | ws and r1 nftable will drop the packets with the added rule |
| ws -> dmz | dmz, r1 and r2 will drop the packets with the added rule |
| ws -> internet | r1 and r2 will drop the packets with the added rule |
| dmz -> ws | dmz (attacker) cannot initiate connections + r1 and r2 will drop the packets with the added rule |
| dmz -> dmz | dmz (attacker) cannot initiate connections + dmz (victim), r1 and r2 will drop the packets with the added rule |
| dmz -> internet | dmz cannot initiate connections + r1 and r2 will drop the packets with the added rule |
| internet -> ws | r2 will drop the packets because invalid destination ip|
| internet -> dmz | dmz, r2 will drop the packets with the added rule |

---

### 2. DNS Reflection (DoS)

#### Attack
A DNS reflection attack uses a DNS server to amplify traffic towards a victim by sending spoofed DNS queries.

**Steps to Launch**:
1. Start the default topology:
```bash
sudo python3 ./default_topo.py
```
2. From the `internet` host, run the DNS reflection attack:
```bash
mininet> internet sudo -E python3 ~/Desktop/LINFO2347/attacks/reflected_ddos.py
```
*Note: The attack can be launched from any host, but the `internet` host is used for demonstration purposes.*

**Example Output**:

![dns ddos](./screenshots/dns_ddos_no_protection.png)
*Note: We can see the workstation being targetted by our own DNS server, with the UDP packets coming through both r2 and r1.*

#### Defense
To improve the defenses against DNS reflection attacks, add rules on `R2`to drop packets from the Internet claiming to originate from internal IP ranges:
```nft
iifname "r2-eth0" ip saddr 10.1.0.0/24 drop;
iifname "r2-eth0" ip saddr 10.12.0.0/24 drop;
```

**Launch the defense**:
```bash
sudo python3 ./protections/reflected_ddos/reflected_topo.py
```
*Note: this will launch a new topology including the basic_network_protection and the added defenses.*

**Example Output**:
![dns ddos](./screenshots/dns_ddos_full_protection.png)

**Defense summary**:
| Attacker-Victim | How |
|------|-----|
| ws -> ws | r1 will drop the dns response as it is not an established connection |
| ws -> dmz | dmz will drop the dns response as it doesn't respect the destination port rule (ie: response will not be on port 80 for http server)|
| ws -> internet | R2 will drop as it is not an established connection|
| dmz -> ws | dmz cannot initiate connections + r1 will drop the dns response as it is not an established connection  |
| dmz -> dmz | dmz (attacker) cannot initiate connections + dmz will drop the dns response as it doesn't respect the destination port rule (ie: response will not be on port 80 for http server) |
| dmz -> internet | dmz cannot initiate connections + R2 will drop the packets as it is not an established connection|
| internet -> ws | r2 will drop the packets with the added rule |
| internet -> dmz | r2 will drop the packets with the added rule |

---

### 3. ARP Poisoning (MITM)

#### Attack

ARP poisoning allows an attacker to intercept traffic between two devices by sending forged ARP packets.

**Steps to Launch**:
1. Start the default topology:
   ```bash
   sudo python3 ./default_topo.py
   ```
2. Open terminals for `ws2` (attacker) and `ws3` (victim):
   ```bash
   mininet> xterm ws2 ws3
   ```
3. On `ws2`, launch the ARP poisoning attack:
   ```bash
   ws2> sudo -E python3 ~/Desktop/LINFO2347/attacks/arp_poison.py
   ```
4. On `ws3`, try accessing a service (e.g., HTTP server):
   ```bash
   ws3> curl http://10.12.0.10
   ```
5. You can also use the `arp -n` command directly which lists the IP/MAC mapping (in the case of `ws3` initially, it should only have the router with the proper MAC address, not a spoofed one)
   ```bash
   mininet> ws3 arp -n
   Address                  HWtype  HWaddress           Flags Mask            Iface
   10.1.0.1                 ether   d2:e2:fe:98:25:e5   CM                    ws3-eth0
   ```

Screenshot of the attack:

![arp poison attack](./screenshots/arp_poison_atck_final.png)

A lot is going on on the screenshot but basically:
- We first `curl http://10.12.0.10` to test out
- Then we display ARP entries on `r1` and `ws3`. We can see that the arp tables contain the right MAC addresses.
- Now we start the attack from `ws2` and we can see that the `arp` tables of `r1` and the victim `ws3` is spoofed with `ws2`'s MAC address
- Traffic from `ws3` to, for instance a DMZ server (http) will pass through `ws2` as shown here with tcpdump:

![arp poison attack](./screenshots/arp_poison_atck_final2.png)


#### Defense

Defending against ARP poisoning requires static ARP entries:

1. On `r1`, set a static ARP entry for `ws3`:
   ```bash
   sudo arp -s 10.1.0.3 <ws3-mac-address> -i r1-eth0
   ```
2. On `ws3`, set a static ARP entry for `r1`:
   ```bash
   sudo arp -s 10.1.0.1 <r1-mac-address> -i ws3-eth0
   ```

But here we did it directly in the topology:

```bash
sudo -E python3 ~/Desktop/LINFO2347/protections/arp_poison/arp_poison_topo.py
```

![arp poison attack def](./screenshots/arp_poison_def_final.png)

Now, with the defense, the ARP table initial state is not empty, it contains the static entries from the Mininet topology.
And these entries do not change even after the attack is launched.

---

### 4. SYN Flooding (DoS)

#### Attack
A SYN flood attack overwhelms a target by sending numerous TCP connection requests without completing the handshake.

**Steps to Launch**:
1. Start the default topology:
```bash
sudo python3 ./default_topo.py
```
2. From `ws2`, launch the SYN flood attack:
```bash
ws2> sudo -E python3 ~/Desktop/LINFO2347/attacks/syn_flood.py
```
Provide the target IP, port, and number of requests.

*Note: The attack can be launched from any host, but the `ws2` host is used for demonstration purposes.*

**Example Output**:

![syn flood](./screenshots/syn_flood.png)

On `http` (target):

`watch -n 1 'ss -tan | grep "SYN-RECV" | wc -l'`

To monitor "every second" the SYN received

We can see that we reach ~255 occupied "temporary" unacked connections. Even though we send more packets (due to timeouts).

#### Defense

Only using nftables to defend against SYN flooding is not enough. The best way to defend against SYN flooding is to use a combination of `nftables` and other tcp stack protections. This means that the attacks will not be stopped but the impact will be reduced.

1. Rate limiter on your hosts for incoming SYN packets:
```nft
tcp flags syn ct state new limit rate 20/second burst 2 packets accept;
tcp flags syn ct state new drop;
```
2. Enable SYN cookies on your hosts:
```bash
sysctl -w net.ipv4.tcp_syncookies=1
```
3. Increase the maximum number of pending connections:
```bash
sysctl -w net.ipv4.tcp_max_syn_backlog=1024
```
4. Reduce the number of SYN-ACK retries:
```bash
sysctl -w net.ipv4.tcp_synack_retries=3
```
*Note: The rate limiter value can be adjusted based on the network's capacity and expected traffic. As we do not have a real network, the value may be too high or too low.*

**Launch the defense**:
```bash
sudo python3 ./protections/syn_flood/flood_topo.py
```
*Note: this will launch a new topology including the basic_network_protection and the added defenses.*

**Example Output**:

![syn flood](./screenshots/syn_flood_def.png)

On `http` (target):

`watch -n 1 'ss -tan | grep "SYN-RECV" | wc -l'`

To monitor "every second" the SYN received

We can see that we reach ~150 occupied "temporary" unacked connections (which is ~100 less than before). Even though we send more packets (due to timeouts).

So technically what's going on: well we are preventing mass new unacked connections attempts while keeping existing stable connections.

**Defense summary**:
| Attacker-Victim | How |
|------|-----|
| ws -> ws | ws rate limit drop the packets if too much SYN + tcp stacks protection |
| ws -> dmz | dmz rate limit drop the packets if too much SYN + tcp stacks protection |
| ws -> internet | Works but doesn't affect our network directly |
| dmz -> ws | dmz cannot initiate connections + r1 will drop the dns response as it is not an established connection |
| dmz -> dmz | dmz (attacker) cannot initiate connections + dmz (victim) rate limit drop the packets if too much SYN + tcp stacks protection|
| dmz -> internet | dmz cannot initiate connections |
| internet -> ws | r2 will drop the packets because invalid destination ip |
| internet -> dmz | dmz (victim) rate limit drop the packets if too much SYN + tcp stacks protection |

---

### 5. Ping Sweep

#### Attack
A ping sweep attack sends ICMP echo requests to multiple hosts to discover active devices on a network.

**Steps to Launch**:
1. Start the default topology:
```bash
sudo python3 ./default_topo.py
```
2. From the `internet` host, run the Xmas scan:
```bash
mininet> internet sudo -E python3 ~/Desktop/LINFO2347/attacks/network_scans.py
```
   Select option `1` (ICMP Ping Sweep) and provide the network to scan.

*Note: The attack can be launched from any host, but the `internet` host is used for demonstration purposes.*

**Example Output**:

![Ping sweep not protected](./screenshots/defensless_ping_sweep.jpg)

#### Defense
To improve the defenses against the ping sweep, add a rule on `r1` to prevent ICMP echo requests comming from the ws to other ip than those 
authorized in the DMZ (and internet). The basic configuration take care of the rest.
```nft
iifname "r1-eth0" ip saddr 10.1.0.0/24 ip protocol icmp icmp type echo-request ip daddr { 10.1.0.0/24, 10.12.0.10; 10.12.0.20, 10.12.0.30, 10.12.0.40, 10.2.0.0/24 } accept;
```
**Launch the defense**:
```bash
sudo python3 ./protections/ping_sweep/sweep_topo.py
```
*Note: this will launch a new topology including the basic_network_protection and the added defenses.*

**Defense summary**:
| Attacker-Victim | How |
|------|-----|
| ws -> ws | Works because of the project requirement |
| ws -> dmz | r1 will drop the packet pinging unauthorized ip with the added rule |
| ws -> internet | Works but doesn't affect our network directly |
| dmz -> ws | dmz cannot initiate connections + r1 will drop the dns response as it is not an established connection |
| dmz -> dmz | dmz (attacker) cannot initiate connections + r1 will drop the packet + r2 will drop the packets if pinging unauthorized ip |
| dmz -> internet | dmz cannot initiate connections + r1 will drop the packet + r2 will drop the packets as DMZ ip cannot go out else connection is already established |
| internet -> ws | r2 drop the packets|
| internet -> dmz | r2 will drop the packets if pinging unauthorized ip |

---
