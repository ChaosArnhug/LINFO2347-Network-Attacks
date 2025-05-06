#!/usr/bin/env python3

import os
import argparse
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.examples.linuxrouter import LinuxRouter
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class TopoSecu(Topo):
    def build(self):
        # Routers
        r1 = self.addHost('r1', cls=LinuxRouter, ip=None)
        r2 = self.addHost('r2', cls=LinuxRouter, ip=None)
        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        # Links: LAN ↔ r1
        self.addLink(s1, r1, intfName2='r1-eth0', params2={'ip': '10.1.0.1/24'})
        # Links: DMZ ↔ r1
        self.addLink(s2, r1, intfName2='r1-eth12', params2={'ip': '10.12.0.1/24'})
        # Links: DMZ ↔ r2
        self.addLink(s2, r2, intfName2='r2-eth12', params2={'ip': '10.12.0.2/24'})
        # Internet host ↔ r2
        internet = self.addHost('internet', ip='10.2.0.2/24', defaultRoute='via 10.2.0.1')
        self.addLink(internet, r2, intfName2='r2-eth0', params2={'ip': '10.2.0.1/24'})
        # Internal hosts
        self.addHost('ws2', ip='10.1.0.2/24', defaultRoute='via 10.1.0.1')
        self.addHost('ws3', ip='10.1.0.3/24', defaultRoute='via 10.1.0.1')
        # DMZ servers
        for name, ip in [('http','10.12.0.10'), ('dns','10.12.0.20'), ('ntp','10.12.0.30'), ('ftp','10.12.0.40')]:
            self.addHost(name, ip=f"{ip}/24", defaultRoute='via 10.12.0.2')
        # Connect internal and DMZ hosts
        for h in ['ws2','ws3']:
            self.addLink(h, s1)
        for srv in ['http','dns','ntp','ftp']:
            self.addLink(srv, s2)

def add_routes(net):
    info(">>> Adding static routes\n")
    net['r1'].cmd("ip route add 10.2.0.0/24 via 10.12.0.2 dev r1-eth12")
    net['r2'].cmd("ip route add 10.1.0.0/24 via 10.12.0.1 dev r2-eth12")


def start_services(net):
    info(">>> Starting services on DMZ hosts\n")
    net['http'].cmd("/usr/sbin/apache2ctl -DFOREGROUND &")
    net['dns'].cmd("/usr/sbin/dnsmasq -k &")
    net['ntp'].cmd("/usr/sbin/ntpd -d &")
    net['ftp'].cmd("/usr/sbin/vsftpd &")
    for srv in ['http','ntp','ftp']:
        net[srv].cmd("/usr/sbin/sshd -D &")


def stop_services(net):
    info(">>> Stopping services\n")
    info(net['http'].cmd("killall apache2"))
    info(net['dns'].cmd("killall dnsmasq"))
    info(net['ntp'].cmd("killall ntpd"))
    info(net['ftp'].cmd("killall vsftpd"))


def apply_nftables_rules(net, hostnames, rules_path):
    fullpath = os.path.abspath(rules_path)
    for host in hostnames:
        info(f">>> Loading nftables from {fullpath} into {host}\n")
        out = net[host].cmd(f"nft flush ruleset; nft -f {fullpath} 2>&1")
        info(out)
        
def enable_syncookies(net, hostnames):
    info(f">>> Enabling SYN cookies on selected hosts\n")
    for host in hostnames:
        out = net[host].cmd("sysctl -w net.ipv4.tcp_syncookies=1")
        info(f"{host}: {out}")
        
def run():
    topo = TopoSecu()
    net = Mininet(topo=topo)
    setLogLevel('info')

    info(">>> Starting network\n")
    net.start()
    add_routes(net)
    start_services(net)

    enable_syncookies(net, ['http', 'dns', 'ftp', 'ntp', 'ws2', 'ws3'])

    # Apply rules
    apply_nftables_rules(net, ['r1'],   'basic_r1.nft')
    apply_nftables_rules(net, ['r2'],   'basic_r2.nft')
    apply_nftables_rules(net, ['http','dns','ftp','ntp'], 'basic_dmz.nft')

    CLI(net)
    stop_services(net)
    net.stop()


def ping_all():
    topo = TopoSecu()
    net = Mininet(topo=topo)
    setLogLevel('info')

    net.start()
    add_routes(net)
    start_services(net)

    enable_syncookies(net, ['http', 'dns', 'ftp', 'ntp', 'ws2', 'ws3'])
    
    apply_nftables_rules(net, ['r1'],   'basic_r1.nft')
    apply_nftables_rules(net, ['r2'],   'basic_r2.nft')
    apply_nftables_rules(net, ['http','dns','ftp','ntp'], 'basic_dmz.nft')

    net.pingAll()
    stop_services(net)
    net.stop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog="topo_basic.py",
        description="Mininet topology for the network attacks project of the course LINFO2347."
    )
    parser.add_argument("-p","--pingall", action="store_true",
                        help="Just pingall then exit")
    args = parser.parse_args()
    if args.pingall:
        ping_all()
    else:
        run()
