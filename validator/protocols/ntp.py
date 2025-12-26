import random
import time
from scapy.all import Ether, Dot1Q, IP, UDP
from scapy.layers.ntp import NTPHeader

from validator.utils import RXSniffer

class NTPTester:
    def __init__(self, iface):
        self.iface = iface
    def match_ntp_reply(self, pkt, src_ip):
        if not pkt.haslayer("NTPHeader"):
            return False

        ip  = pkt.getlayer("IP")
        udp = pkt.getlayer("UDP")
        ntp = pkt.getlayer("NTPHeader")

        # Must be from port 123 (NTP server)
        if udp.sport != 123:
            return False

        print("RX:", pkt.summary())

        # Mode 4 = server reply
        return (
            ip.dst == src_ip and
            ntp.mode == 4
        )

    def test(self, ntp_server, vlan_context, rx_sniffer:RXSniffer=None):
        """
        Test NTP using VLAN-tagged packets.
        
        Args:
            ntp_server: NTP server IP
            vlan_context: dict with mac, vlan, ip, gateway_mac
        """
        try:
            # Build NTP request packet
            pkt = (
                Ether(src=vlan_context["mac"], dst=vlan_context["gateway_mac"])
                / Dot1Q(vlan=vlan_context["vlan"])
                / IP(src=vlan_context["ip"], dst=ntp_server)
                / UDP(sport=random.randint(49152, 65535), dport=123)
                / NTPHeader(mode=3, version=3)
            )
            
            reply=rx_sniffer.send_and_wait(
                pkt,
                match_fn=lambda p: self.match_ntp_reply(p, vlan_context["ip"]),
                timeout=4.0
            )
            if reply:
                self.print_ntp_reply(reply)
            return reply is not None
            
        except Exception as e:
            return f"FAIL: {e}"
        
    def _ntp_to_unix(self, ntp_ts):
        # NTP epoch starts in 1900, Unix in 1970
        return ntp_ts - 2208988800

    def print_ntp_reply(self, pkt):
        ntp = pkt.getlayer("NTPHeader")
        print("NTP Response:")
        print("  Mode:", ntp.mode)
        print("  Version:", ntp.version)
        print("  Stratum:", ntp.stratum)

        print("  Reference Time:", ntp.ref)
        print("  Origin Time:   ", ntp.orig)
        print("  Receive Time:  ", ntp.recv)
        print("  Transmit Time: ", ntp.sent)
        