from multiprocessing import Process
from scapy.layers.dhcp import DHCPOptions
import ipaddress

from validator.models import VLANTestResult
from validator.protocols import DHCPTester, DNSTester, NTPTester, ConnectivityTester, ARPTester
from validator.utils import RXSniffer, ARPResponder


class VLANValidator:
    
    def __init__(self, iface):
        self.iface = iface
        self.dhcp = DHCPTester(iface)
        self.dns = DNSTester(iface)
        self.ntp = NTPTester(iface)
        self.conn = ConnectivityTester(iface)
        self.results = []  # Collect test results for summary table
    
    def print_summary(self):
        """Print a summary table of all VLAN test results."""
        if not self.results:
            return
        
        print("\n" + "=" * 80)
        print("VLAN VALIDATION SUMMARY")
        print("=" * 80)
        
        # Calculate column widths
        max_vlan_name = max(len(r.vlan_name) for r in self.results)
        name_width = max(10, max_vlan_name + 2)
        
        # Header
        header = f"{'VLAN':<6} | {'Name':<{name_width}} | {'DHCP':<10} | {'DNS':<10} | {'NTP':<10} | {'Connect':<10}"
        print(header)
        print("-" * len(header))
        
        # Rows
        for r in self.results:
            print(f"{r.vlan_id:<6} | {r.vlan_name:<{name_width}} | {r.dhcp:<10} | {r.dns:<10} | {r.ntp:<10} | {r.connectivity:<10}")
            if r.details:
                print(f"       | {'Details: ' + r.details}")
        
        print("=" * 80)
        
        # Summary stats
        total = len(self.results)
        passed = sum(1 for r in self.results if all(x in ['OK', 'DISABLED', 'N/A'] for x in [r.dhcp, r.dns, r.ntp, r.connectivity]))
        print(f"\nTotal VLANs: {total} | Passed: {passed} | Failed: {total - passed}")
        print()


    def validate_vlan(self, vlan):
        print(f"\n=== VLAN {vlan['id']} ({vlan['name']}) ===")
        
        result = VLANTestResult(
            vlan_id=vlan['id'],
            vlan_name=vlan['name'],
            dhcp="N/A",
            dns="N/A",
            ntp="N/A",
            connectivity="N/A"
        )

        dhcp_config = vlan.get("dhcp")
        
        # Check if DHCP is disabled
        if dhcp_config is False:
            print("DHCP: DISABLED (as configured)")
            result.dhcp = "DISABLED"
            self.results.append(result)
            # Skip DHCP-dependent tests
            return

        # Create RXSniffer 
        rx_sniffer = RXSniffer(self.iface)
        rx_sniffer.start()

        try:
            dhcp = self.dhcp.discover(vlan["id"], rx_sniffer=rx_sniffer)
            if not dhcp:
                print("DHCP: FAIL (no offer)")
                result.dhcp = "FAIL"
                result.details = "No DHCP offer received"
                self.results.append(result)
                return

            print(f"DHCP: OK → {dhcp}")
            result.dhcp = "OK"

            # Validate IP is within configured DHCP range
            assigned_ip = dhcp.get("ip")
            if assigned_ip and isinstance(dhcp_config, dict) and dhcp_config.get("range"):
                dhcp_range = dhcp_config["range"]
                start_ip = ipaddress.ip_address(dhcp_range[0])
                end_ip = ipaddress.ip_address(dhcp_range[1])
                assigned = ipaddress.ip_address(assigned_ip)
                
                if start_ip <= assigned <= end_ip:
                    print(f"IP Range: OK ({assigned_ip} within {dhcp_range[0]} - {dhcp_range[1]})")
                else:
                    print(f"IP Range: FAIL ({assigned_ip} NOT in range {dhcp_range[0]} - {dhcp_range[1]})")
                    result.dhcp = "FAIL"
                    result.details = f"IP {assigned_ip} out of range"
                    self.results.append(result)
                    return
                
                if vlan.get("gateway") != dhcp.get("router"):
                    print(f"Gateway Mismatch: FAIL (DHCP gateway {dhcp.get('router')} != configured {vlan.get('gateway')})")
                    result.dhcp = "FAIL"
                    result.details = "Gateway mismatch"
                    self.results.append(result)
                    return

            # Validate DHCP options
            configured_options = vlan.get("dhcp_options", {})
            if configured_options:
                # DHCPOptions already maps code (int) -> name (str), use it directly
                
                for opt_code, opt_value in configured_options.items():
                    opt_entry = DHCPOptions.get(int(opt_code)) 
                    opt_name = getattr(opt_entry, "name", opt_entry)
                    
                    # Get expected value (resolve "gateway" keyword)
                    if isinstance(opt_value, dict):
                        expected = opt_value.get("value")
                    else:
                        expected = opt_value
                        
                    if expected == "gateway":
                        expected = vlan.get("gateway")
                    
                    # Check if option is present in DHCP response
                    received = dhcp.get(opt_name)
                    if received:
                        if str(received) == str(expected):
                            print(f"DHCP Option {opt_code} ({opt_name}): OK ({received})")
                        else:
                            print(f"DHCP Option {opt_code} ({opt_name}): MISMATCH (got {received}, expected {expected})")
                    else:
                        print(f"DHCP Option {opt_code} ({opt_name}): MISSING (expected {expected})")
            
            arp = ARPTester(self.iface, assigned_ip, dhcp.get("router"))
            proc = Process(
                target=ARPResponder.run_subprocess,
                args=(self.iface, vlan["id"], assigned_ip)
            )
            proc.start()
                
            vlan_context = {
                "mac": dhcp["mac"],
                "vlan": vlan["id"],
                "dhcp_ip": assigned_ip,
                "ip":assigned_ip,
                "gateway_ip": dhcp.get("router"),
                "gateway_mac": dhcp["gateway_mac"],
                "subnet_mask": dhcp.get("subnet_mask"),
            }
            arp.announce_ip(vlan_context)
            
            # arp_peers = arp.discover_peers(vlan_context)            
            # print(f"Discovered {len(arp_peers)} ARP peers on VLAN {vlan['id']}")

            # DNS test
            if dhcp.get("name_server"):
                dns_server = dhcp["name_server"]
                print(f"\n--- DNS Tests ---")
                
                # Run connectivity_tests DNS lookups
                connectivity_tests = vlan.get("connectivity_tests", {})
                dns_tests_passed = 0
                dns_tests_total = 0
                
                if connectivity_tests:
                    # Test reverse lookup (PTR)
                    if "reverse_lookup" in connectivity_tests:
                        test = connectivity_tests["reverse_lookup"]
                        dns_tests_total += 1
                        print(f"Testing reverse lookup: {test['ip']} -> {test['fqdn']}")
                        reply = self.dns.test_ptr(dns_server, vlan_context, target_ip=test["ip"], rx_sniffer=rx_sniffer)
                        if reply:
                            resolved_fqdns = self.dns.get_resolved_fqdns(reply)
                            expected_fqdn = test.get("fqdn")
                            if expected_fqdn in resolved_fqdns:
                                print(f"  Reverse lookup ({test['ip']}): OK - {resolved_fqdns}")
                                dns_tests_passed += 1
                            else:
                                print(f"  Reverse lookup ({test['ip']}): FAIL - got {resolved_fqdns}, expected {expected_fqdn}")
                        else:
                            print(f"  Reverse lookup ({test['ip']}): FAIL - no response")
                    
                    # Test internal lookup (A record for internal host)
                    if "internal_lookup" in connectivity_tests:
                        test = connectivity_tests["internal_lookup"]
                        dns_tests_total += 1
                        
                        # Append search domain if hostname doesn't contain a dot
                        query_domain = test["host"]
                        if "." not in query_domain and dhcp.get("domain"):
                            domain = dhcp["domain"]
                            if isinstance(domain, bytes):
                                domain = domain.decode('utf-8')
                            query_domain = f"{query_domain}.{domain}"
                        
                        reply = self.dns.test(dns_server, vlan_context, domain=query_domain, rx_sniffer=rx_sniffer)
                        if reply:
                            resolved_ips = self.dns.get_resolved_ips(reply)
                            expected_ip = test.get("ip")
                            if expected_ip in resolved_ips:
                                print(f"  Internal lookup ({test['host']}): OK - {resolved_ips}")
                                dns_tests_passed += 1
                            else:
                                print(f"  Internal lookup ({test['host']}): FAIL - got {resolved_ips}, expected {expected_ip}")
                        else:
                            print(f"  Internal lookup ({test['host']}): FAIL - no response")
                    
                    # Test external lookup (A record for external host)
                    if "external_lookup" in connectivity_tests:
                        test = connectivity_tests["external_lookup"]
                        dns_tests_total += 1
                        reply = self.dns.test(dns_server, vlan_context, domain=test["host"], rx_sniffer=rx_sniffer)
                        if reply:
                            resolved_ips = self.dns.get_resolved_ips(reply)
                            expected_ip = test.get("ip")
                            if expected_ip in resolved_ips:
                                print(f"  External lookup ({test['host']}): OK - {resolved_ips}")
                                dns_tests_passed += 1
                            else:
                                print(f"  External lookup ({test['host']}): FAIL - got {resolved_ips}, expected {expected_ip}")
                        else:
                            print(f"  External lookup ({test['host']}): FAIL - no response")
                    
                    # Test overridden lookup (should resolve to internal IP via DNS override)
                    if "overridden_lookup" in connectivity_tests:
                        test = connectivity_tests["overridden_lookup"]
                        dns_tests_total += 1
                        reply = self.dns.test(dns_server, vlan_context, domain=test["host"], rx_sniffer=rx_sniffer)
                        if reply:
                            resolved_ips = self.dns.get_resolved_ips(reply)
                            expected_ip = test.get("ip")
                            if expected_ip in resolved_ips:
                                print(f"  Overridden lookup ({test['host']}): OK - {resolved_ips}")
                                dns_tests_passed += 1
                            else:
                                print(f"  Overridden lookup ({test['host']}): FAIL - got {resolved_ips}, expected {expected_ip}")
                        else:
                            print(f"  Overridden lookup ({test['host']}): FAIL - no response")
                
                # Set overall DNS result
                if dns_tests_total > 0:
                    result.dns = "OK" if dns_tests_passed == dns_tests_total else "FAIL"
                else:
                    result.dns = "N/A"

            # NTP test
            if dhcp.get("NTP_server"):
                ntp_result = self.ntp.test(dhcp["NTP_server"], vlan_context, rx_sniffer=rx_sniffer)
                print(f"NTP: {ntp_result}")
                result.ntp = "OK" if ntp_result else "FAIL"


            # Test internal network reachability based on private_network flag
            private_network = vlan.get("private_network", True)
            # Gateway connectivity test
            if dhcp.get("router"):
                gw = dhcp["router"]
                connectivity_result = self.conn.ping(gw, vlan_context, rx_sniffer=rx_sniffer)
                print(f"Gateway ping {gw}: {'OK' if connectivity_result else 'FAIL'}")
                if private_network:
                    # Should be able to reach internal peers
                    result.connectivity = "OK" if connectivity_result else "FAIL"
                else:
                    # Should NOT reach internal peers - test blocked
                    result.connectivity = "OK" if not connectivity_result else "FAIL"  # Inverted: blocking is success

            # if arp_peers:
            #     # Use first discovered peer for internal network test
            #     test_peer = arp_peers[0]
            #     ok = self.conn.ping(test_peer, vlan_context,rx_sniffer=rx_sniffer)
                
            #     if private_network:
            #         # Should be able to reach internal peers
            #         print(f"Internal network access ({test_peer}): {'OK' if ok else 'FAIL'} (private_network={private_network})")
            #         connectivity_tests.append(ok)
            #     else:
            #         # Should NOT reach internal peers - test blocked
            #         print(f"Internal network blocking ({test_peer}): {'OK (blocked)' if not ok else 'FAIL (leaked)'} (private_network={private_network})")
            #         connectivity_tests.append(not ok)  # Inverted: blocking is success
            # else:
            #     print(f"Internal network test: N/A (no peers discovered)")

            # Test external/internet reachability based on public_network flag
            # public_network = vlan.get("public_network", True)
            # test_external_ip = "8.8.8.8"
            # ok = self.conn.ping(test_external_ip, vlan_context)
            
            # if public_network:
            #     # Should reach internet
            #     print(f"Internet access: {'OK' if ok else 'FAIL'} (public_network={public_network})")
            #     connectivity_tests.append(ok)
            # else:
            #     # Should NOT reach internet - test blocked
            #     print(f"Internet blocking: {'OK (blocked)' if not ok else 'FAIL (leaked)'} (public_network={public_network})")
            #     connectivity_tests.append(not ok)  # Inverted: blocking is success
            
            # # Set overall connectivity result
            # if connectivity_tests:
            #     result.connectivity = "OK" if all(connectivity_tests) else "FAIL"
            
            self.results.append(result)
            
        except Exception as e:
            result.details = str(e)
            self.results.append(result)
            raise
        finally:
            if 'proc' in locals():
                proc.terminate()
                proc.join()
            if 'rx_sniffer' in locals():
                rx_sniffer.stop()