import random
from scapy.all import Ether, Dot1Q, IP, UDP, DNS, DNSQR

from validator.utils import RXSniffer

class DNSTester:
    def __init__(self, iface):
        self.iface = iface
    def match_dns_reply(self, pkt, src_ip, dns_id):
        if not pkt.haslayer("DNS"):
            return False

        dns = pkt.getlayer("DNS")
        ip  = pkt.getlayer("IP")
        udp = pkt.getlayer("UDP")

        # Must be a DNS response from port 53 to our IP
        if udp.sport != 53:
            return False

        print("RX:", pkt.summary())

        return (
            ip.dst == src_ip and
            dns.qr == 1 and          # response
            dns.id == dns_id         # matches our query
        )
    
    def test(self, dns_server, vlan_context, domain, rx_sniffer:RXSniffer=None):
        """
        Test DNS using VLAN-tagged packets.
        """

        try:
            # Pre-generate values
            mac = vlan_context["mac"]
            vlan = vlan_context["vlan"]
            src_ip = vlan_context["ip"]
            gateway_mac = vlan_context["gateway_mac"]

            sport = random.randint(49152, 65535)
            dns_id = random.randint(1, 65535)

            # Build packet once
            pkt = (
                Ether(src=mac, dst=gateway_mac)
                / Dot1Q(vlan=vlan)
                / IP(src=src_ip, dst=dns_server)
                / UDP(sport=sport, dport=53)
                / DNS(id=dns_id, rd=1, qd=DNSQR(qname=domain))
            )
            reply=rx_sniffer.send_and_wait(
                pkt,
                match_fn=lambda p: self.match_dns_reply(p, src_ip, dns_id),
                timeout=4.0
            )
            if reply:
                self.print_dns_reply(reply)
            return reply

        except Exception as e:
            print(f"DNS test exception: {e}")
            return None

    def test_ptr(self, dns_server, vlan_context, target_ip, rx_sniffer=None):
        try:
            mac = vlan_context["mac"]
            vlan = vlan_context["vlan"]
            src_ip = vlan_context["ip"]
            gateway_mac = vlan_context["gateway_mac"]

            sport = random.randint(49152, 65535)
            dns_id = random.randint(1, 65535)

            # Build reverse DNS name
            ptr_name = ".".join(reversed(target_ip.split("."))) + ".in-addr.arpa"

            pkt = (
                Ether(src=mac, dst=gateway_mac)
                / Dot1Q(vlan=vlan)
                / IP(src=src_ip, dst=dns_server)
                / UDP(sport=sport, dport=53)
                / DNS(id=dns_id, rd=1, qd=DNSQR(qname=ptr_name, qtype="PTR"))
            )

            reply = rx_sniffer.send_and_wait(
                pkt,
                match_fn=lambda p: self.match_dns_reply(p, src_ip, dns_id),
                timeout=4.0
            )

            if reply:
                self.print_dns_reply(reply)

            return reply

        except Exception as e:
            print(f"PTR test exception: {e}")
            return None


    def get_resolved_ips(self, reply):
        """
        Extract all A record IPs from a DNS reply.
        Returns list of IPs, or empty list if no A records found.
        """
        if not reply or not reply.haslayer("DNS"):
            return []
        
        dns = reply.getlayer("DNS")
        ips = []
        for i in range(dns.ancount):
            rr = dns.an[i]
            if rr.type == 1:  # A record
                ips.append(rr.rdata)
        return ips

    def get_resolved_fqdns(self, reply):
        """
        Extract all PTR record FQDNs from a DNS reply.
        Returns list of FQDNs, or empty list if no PTR records found.
        """
        if not reply or not reply.haslayer("DNS"):
            return []
        
        dns = reply.getlayer("DNS")
        fqdns = []
        for i in range(dns.ancount):
            rr = dns.an[i]
            if rr.type == 12:  # PTR record
                fqdn = rr.rdata
                if isinstance(fqdn, bytes):
                    fqdn = fqdn.decode('utf-8')
                # Remove trailing dot if present
                if fqdn.endswith('.'):
                    fqdn = fqdn[:-1]
                fqdns.append(fqdn)
        return fqdns
    
    def print_dns_reply(self, pkt):
        dns = pkt.getlayer("DNS")

        print("DNS Response:")
        print("  ID:", dns.id)
        print("  Questions:", dns.qdcount)
        print("  Answers:", dns.ancount)

        # Print each answer
        for i in range(dns.ancount):
            rr = dns.an[i]
            print(f"  Answer {i+1}:")
            print("    Name:", rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname)
            print("    Type:", rr.type)
            print("    TTL:", rr.ttl)

            # A record
            if rr.type == 1:
                print("    A:", rr.rdata)

            # AAAA record
            elif rr.type == 28:
                print("    AAAA:", rr.rdata)

            # CNAME
            elif rr.type == 5:
                print("    CNAME:", rr.rdata.decode() if isinstance(rr.rdata, bytes) else rr.rdata)

            else:
                print("    Raw rdata:", rr.rdata)