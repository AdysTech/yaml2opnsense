import random
from scapy.all import Ether, Dot1Q, IP, UDP, BOOTP, DHCP, get_if_hwaddr, conf

from validator.utils import RXSniffer

conf.use_pcap = True


class DHCPTester:
    def __init__(self, iface):
        self.iface = iface

    def match_dhcp_reply(self, pkt, xid):
        """Match DHCP offer packets with our transaction ID."""
        if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
            return False

        bootp = pkt.getlayer(BOOTP)
        dhcp = pkt.getlayer(DHCP)

        # Check if it's a DHCP offer (message type 2) and matches our XID
        if bootp.op != 2 or bootp.xid != xid:  # op=2 is BOOTP reply
            return False

        # Check if it's a DHCP offer
        for opt in dhcp.options:
            if (
                isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] == 2
            ):  # 2 = OFFER
                print("RX:", pkt.summary())
                return True

        return False

    def discover(self, vlan, rx_sniffer: RXSniffer = None):
        """
        Send DHCP discover on VLAN and wait for offer.

        Args:
            vlan: VLAN ID to tag packets with
            rx_sniffer: RXSniffer instance for packet capture
        """
        mac = get_if_hwaddr(self.iface)
        xid = random.randint(1, 0xFFFFFFFF)

        dhcp_discover_req = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=mac)
            / Dot1Q(vlan=vlan)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(
                chaddr=bytes.fromhex(mac.replace(":", "")),
                xid=xid,
                flags=0x8000,
            )
            / DHCP(
                options=[
                    ("message-type", "discover"),
                    ("client_id", b"\x01" + bytes.fromhex(mac.replace(":", ""))),
                    "end",
                ]
            )
        )

        try:
            reply = rx_sniffer.send_and_wait(
                dhcp_discover_req,
                match_fn=lambda p: self.match_dhcp_reply(p, xid),
                timeout=10.0,
            )

        except PermissionError:
            print(
                " ERROR: DHCP testing requires root/sudo privileges for packet manipulation."
            )
            print("   Please run with: sudo python run.py --test <interface>")
            import sys

            sys.exit(1)

        if not reply:
            return None

        # Parse DHCP options from reply
        dhcp = reply[DHCP]
        opts = {
            "ip": reply[BOOTP].yiaddr,
            "mac": mac,
            "gateway_mac": reply[Ether].src,
        }

        for opt in dhcp.options:
            # skip "end", "pad", etc.
            if not isinstance(opt, tuple):
                continue
            if len(opt) < 2:
                continue

            key = opt[0]
            value = opt[1]
            if isinstance(key, str):
                opts[key] = value

        return opts
