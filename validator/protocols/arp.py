import ipaddress
import time
from scapy.all import (
    Ether,
    Dot1Q,
    sendp,
    ARP,
    srp,
    conf
)

conf.use_pcap = True


class ARPTester:
    def __init__(self, iface, assigned_ip, gateway_ip):
        self.iface = iface
        self.assigned_ip = assigned_ip
        self.gateway_ip = gateway_ip

    def announce_ip(self, vlan_context):
        mac = vlan_context["mac"]
        vlan = vlan_context["vlan"]
        my_ip = vlan_context["ip"]

        grat = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / Dot1Q(vlan=vlan)
            / ARP(op=2, hwsrc=mac, psrc=my_ip, hwdst="00:00:00:00:00:00", pdst=my_ip)
        )

        sendp(grat, iface=self.iface, count=3, inter=0.2, verbose=0)
        time.sleep(0.1)

    
    def discover_peers(self, vlan_context, timeout=5):
       
        mac = vlan_context["mac"]
        vlan = vlan_context["vlan"]
        my_ip = vlan_context["dhcp_ip"]
        mask = vlan_context["subnet_mask"]

        # Build the network object
        network = ipaddress.IPv4Network(f"{my_ip}/{mask}", strict=False)

        # Skip network address, broadcast, and our own IP
        pkts = []
        for ip in network.hosts():
            ip = str(ip)
            if ip == my_ip:
                continue

            pkt = (
                Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                / Dot1Q(vlan=vlan)
                / ARP(op=1, hwsrc=mac, psrc=my_ip, pdst=ip)
            )
            pkts.append(pkt)
            if len(pkts) >= 64:
                break  # Limit to first 64  hosts for performance
        # Send and receive at L2 in one call
        ans, _ = srp(pkts, iface=self.iface, timeout=timeout, verbose=0)

        peers = {}
        for snd, rcv in ans:
            if ARP in rcv:
                ip = rcv[ARP].psrc
                mac = rcv[ARP].hwsrc
                peers[ip] = mac

        return peers
    
