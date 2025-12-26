import random
from scapy.all import Ether, Dot1Q, IP, ICMP

from validator.utils import RXSniffer

class ConnectivityTester:
    def __init__(self, iface):
        self.iface = iface
    

    def match_icmp_reply(self,pkt, src_ip):
        if not pkt.haslayer("ICMP"):
            return False
        print("RX:", pkt.summary())
        ip = pkt.getlayer("IP")
        icmp = pkt.getlayer("ICMP")

        return (
            ip.dst == src_ip and
            icmp.type == 0  # echo-reply
        )

    def ping(self, target, vlan_context, rx_sniffer:RXSniffer=None):
        """
        Ping using VLAN-tagged ICMP packets.
        
        Args:
            target: Target IP to ping
            vlan_context: dict with mac, vlan, ip, gateway_mac
        """
        try:
            icmp_id = random.randint(1, 65535)
            icmp_seq = 1
            
            pkt = (
                Ether(src=vlan_context["mac"], dst=vlan_context["gateway_mac"])
                / Dot1Q(vlan=vlan_context["vlan"])
                / IP(src=vlan_context["ip"], dst=target)
                / ICMP(type=8, code=0, id=icmp_id, seq=icmp_seq)
            )
            
            reply=rx_sniffer.send_and_wait(
                pkt,
                match_fn=lambda p: self.match_icmp_reply(p, vlan_context["ip"]),
                timeout=4.0
            )

            return reply is not None
        
        except Exception as e:
            print(f"Ping error: {e}")
            return False