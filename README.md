# LINFO2347: Network Attacks


## Setup

### Installing required material (from Debian 12)

```bash
sudo apt install tcpdump -y
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh
sudo systemctl status ssh

sudo nano /etc/ssh/sshd_config # with appropriate settings like password/less login
sudo systemctl restart ssh

sudo apt install curl mininet python3-pip python3-setuptools apache2 dnsmasq openntpd vsftpd -y
sudo sed -i 's/^#port=/port=5353/' /etc/dnsmasq.conf
sudo sed -i 's/^port=.*/port=5353/' /etc/dnsmasq.conf
sudo systemctl restart dnsmasq

#(to check everything is ok)
sudo systemctl status dnsmasq.service

# Note make sure dnsmasq is using port 5353 AND UNCOMENT the 'no-resolv' line #no-resolv (around line 70) in /etc/dnsmasq.conf
```

Then to start the `mininet`

```
sudo -E python3 ~/Desktop/LINFO2347/basic/topo_basic.py 
```

To clear:

```
sudo mn -c
```

## Attacks

### Network scans

After mininet is up and running:

```
mininet> ws2 python3 ~/Desktop/LINFO2347/attacks/network_scans.py

Select attack:
 1. ICMP Ping Sweep
 2. ARP Ping Sweep
 3. TCP SYN Port Scan
 4. Xmas Tree Scan
 5. UDP Scan
 6. Exit
Choice: 
```

If you choose 2 for instance:

```
Choice: 2
Network to ARP-sweep [10.1.0.0/24]: 

[*] ARP Ping sweep on 10.1.0.0/24 (batch size: 100)
  → 10.1.0.1 is alive (MAC de:17:94:f0:e5:b2)               
  → 10.1.0.3 is alive (MAC f2:2c:eb:66:29:93)               
[ARP Ping sweep] Terminated: 2 IPs found 
```

#### Defense

To defend see the `nftable` rule file in `/basic/network_scans.nft`. They can be activated in the topology directly in `/basic/topo_basic.py`

### DNS Reflection (DoS)

After mininet is up and running:

```
mininet> xterm internet
mininet> xterm ws2
```

From `ws2` (the victim) we want to capture the traffic and inspect the DoS occuring through the DNS:

```
root@vbox:~/Desktop/LINFO2347# tcpdump -i ws2-eth0 -n udp port 5353 -w /tmp/ws2-dns-reflect-capture.pcap
```

Now from `internet` we want to then launch the attack:

```
root@vbox:~/Desktop/LINFO2347# python3 ~/Desktop/LINFO2347/attacks/reflected_ddos.py
```


Optionally but you can check the DNS IN/OUT traffic to confirm/debug:

```
mininet> xterm dns
```

For incoming: 

```
tcpdump -i dns-eth0 -n 'udp and src host 10.1.0.2 and dst port 5353'
```

For outgoing:

```
tcpdump -i dns-eth0 -n 'udp and dst host 10.1.0.2 and src port 5353'
```

#### Defense

To defend see the `nftable` rule file in `/basic/basic_dmz.nft` `/basic/basic_r1.nft`. They can be activated in the topology directly in `/basic/topo_basic.py`

### ARP Poisoning (MITM)

For this attack we need `ws2` and `ws3`. 

We first start by opening 3 `xterm` terminals from the Mininet:

```
mininet> xterm ws2 ws2 ws3
```

On one `ws2` terminal we listen (MITM):
```
ws2> sudo tcpdump -i ws2-eth0 -n -X 'host 10.1.0.3 and not arp'
```

On the other `ws2` terminal we launch the attack
```
ws2> sudo -E python3 ~/Desktop/LINFO2347/attacks/arp_poison.py
```

Then on the victim we simply try to reach one of the service in the DMZ for instance the `http` server (`apache2`):
```
ws3> curl http://10.12.0.10
```

Before the attack:

![arp attack before](./screenshots/arp-attack-before.png)

After the attack:

![arp attack after](./screenshots/arp-attack-after.png)


### Defense

After spending quite a few hours on the question, we couldn't come up with `nftables` rules defending against our script. We could theoretically dumb down the attack/arp poisoning (by not targeting the router as well) but dual-sided poisoning is needed for a full MITM.

- Dynamic discovery + forged-but-accurate packets = can’t be told apart by simple IP/MAC rules.
- High-frequency flooding, rate limiting can't counter the attack
- Dual-sided poisoning means full MITM, not just cache pollution.


So the practical idea to defend against such nasty arp poisoning is to:

1. Either hardcode use static arp entries (albeit not simple ones because simple `ws` arp is not sufficent as explained earlier)

2. Use other tools than `nftables`, `nftables` are not appropriate to counter arp cache poison, it's more of a layer 3/layer 4 approach but with scapy we are at the lowest level possible forging layer 2 packets.

3. Hardcode MAC addresses and make all MAC addresses static (basically the idea would be to completely disable arp)

4. **Use ipv6 but this seems to be outside the scope of the project, but no one should be still using ipv4 arp**

### SYN Flooding

### Defense

To defend see the `nftable` rule file in `/basic/syn_flood.nft`. They can be activated in the topology directly in `/basic/topo_basic.py`