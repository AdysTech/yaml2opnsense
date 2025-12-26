import subprocess
from scapy.all import (
    Ether,
    Dot1Q,
    get_if_hwaddr,
    sendp,
    ARP,
    AsyncSniffer
)


class ARPResponder:
    @staticmethod
    def run_subprocess(iface, vlan, ip):
        responder = ARPResponder(iface, vlan, ip)
        responder._enable_promisc()

        sniffer = AsyncSniffer(
            iface=iface,
            filter="arp",
            prn=responder._handle_arp,
            store=False,
        )
        sniffer.start()

        # Keep the subprocess alive forever
        try:
            sniffer.join()
        except KeyboardInterrupt:
            pass

    def __init__(self, iface, vlan, claimed_ip):
        self.iface = iface
        self.vlan = vlan
        self.claimed_ip = claimed_ip
        self.mac = get_if_hwaddr(iface)

        self._sniffer = None
        self._running = False

    def _enable_promisc(self):
        subprocess.run(["ip", "link", "set", self.iface, "promisc", "on"])

    def _handle_arp(self, pkt):
        # Only respond to ARP who-has for our claimed IP
        if ARP in pkt and pkt[ARP].op == 1:
            if pkt[ARP].pdst != self.claimed_ip:
                return
            print("ARP Request for claimed IP:", pkt.summary())
            # Build ARP reply
            reply = (
				Ether(src=self.mac, dst=pkt[Ether].src)
				/ Dot1Q(vlan=self.vlan)
				/ ARP(
					op=2,
					hwsrc=self.mac,
					psrc=self.claimed_ip,
					hwdst=pkt[ARP].hwsrc,
					pdst=pkt[ARP].psrc,
				)
			)
            sendp(reply, iface=self.iface, verbose=0)
