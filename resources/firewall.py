from core.client import OpnClient


def build_aliases(cfg):
    """
    Build firewall aliases from service definitions.
    Returns dict of alias_name -> alias_data.
    
    Supports both hostnames (resolved from static_leases) and IP addresses.
    """
    aliases = {}
    services = cfg.get("services", {})
    vlans = cfg.get("vlans", {})
    unmanaged = cfg.get("unmanaged_local_networks", [])
    
    # Build hostname-to-IP map from static_leases
    hostname_ip_map = {}
    for vlan_name, vlan in vlans.items():
        for lease_name, lease in vlan.get("static_leases", {}).items():
            hostname = lease.get("hostname")
            ip = vlan.get("gateway") if lease.get("ip") == "gateway" else lease.get("ip")
            if hostname and ip:
                hostname_ip_map[hostname] = ip

    for service_name, service_def in services.items():
        # Skip special sections
        if service_name in ["floating_rules"]:
            continue

        # Host aliases - resolve hostnames to IPs
        if "hosts" in service_def:
            hosts = service_def["hosts"]
            resolved_hosts = []
            
            for host in (hosts if isinstance(hosts, list) else [hosts]):
                # Try to resolve hostname to IP
                resolved_ip = hostname_ip_map.get(str(host))
                if resolved_ip:
                    resolved_hosts.append(resolved_ip)
                else:
                    # Not a known hostname, keep as-is (could be IP or external hostname)
                    resolved_hosts.append(str(host))
            
            content = "\n".join(resolved_hosts)
            
            aliases[f"{service_name}_hosts"] = {
                "name": f"{service_name}_hosts",
                "type": "host",
                "content": content,
                "descr": f"Host alias for {service_name}",
            }

        # Port aliases
        if "ports" in service_def:
            ports = service_def["ports"]
            content = "\n".join(str(p) for p in ports) if isinstance(ports, list) else str(ports)
            
            aliases[f"{service_name}_ports"] = {
                "name": f"{service_name}_ports",
                "type": "port",
                "content": content,
                "descr": f"Port alias for {service_name}",
            }

        # Special handling for local_private_networks
        if service_name == "local_private_networks":
            networks = []
            
            # Check if it has vlans list
            if isinstance(service_def, list):
                for item in service_def:
                    if isinstance(item, dict) and "vlans" in item:
                        # Add CIDRs from specified VLANs
                        for vlan_name in item["vlans"]:
                            vlan_def = vlans.get(vlan_name, {})
                            cidr = vlan_def.get("cidr")
                            if cidr:
                                networks.append(cidr)
                    elif item == "unmanaged_local_networks":
                        # Add unmanaged networks
                        networks.extend(unmanaged)
            
            if networks:
                content = "\n".join(networks)
                aliases["local_private_networks"] = {
                    "name": "local_private_networks",
                    "type": "network",
                    "content": content,
                    "descr": "All private local networks",
                }

    return aliases



def _search_aliases(client: OpnClient):
    try:
        data = client.post("/api/firewall/alias/searchItem")
        return data.get("rows", [])
    except Exception:
        return []


def _get_alias(client: OpnClient, uuid: str):
    return client.get(f"/api/firewall/alias/getItem/{uuid}").get("alias", {})

def build_floating_rules(cfg):
    """
    Build floating firewall rules from root floating_rules section.
    Returns list of rule definitions.
    """
    floating_rules_def = cfg.get("floating_rules", [])
    vlan_assignments = cfg.get("__vlan_assignments__", {})
    vlans = cfg.get("vlans", {})
    
    # Build VLAN ID to name mapping
    vlan_id_to_name = {}
    for vlan_name, vlan_def in vlans.items():
        vlan_id = vlan_def.get("id")
        if vlan_id:
            vlan_id_to_name[vlan_id] = vlan_name
    
    rules = []
    
    for rule_def in floating_rules_def:
        # Resolve VLANs to interface names
        vlan_refs = rule_def.get("vlans", [])
        interfaces = []
        
        for vlan_ref in vlan_refs:
            # Support both VLAN IDs (integers) and names (strings)
            if isinstance(vlan_ref, int):
                vlan_name = vlan_id_to_name.get(vlan_ref)
            else:
                vlan_name = vlan_ref
            
            if not vlan_name:
                continue
                
            # Get interface from assignments
            assignment = vlan_assignments.get(vlan_name, {})
            iface = assignment.get("interface")
            if iface:
                interfaces.append(iface)
        
        if not interfaces:
            continue
        
        # Parse source
        source = rule_def.get("source", "any")
        source_value = _parse_address(source)
        
        # Parse destination
        destination = rule_def.get("destination", "any")
        dest_value = _parse_address(destination)
        
        # Parse destination port
        dest_port = rule_def.get("destination_port", "")
        if dest_port:
            dest_port = _resolve_alias_reference(dest_port)
        
        # Normalize protocol to uppercase (OPNsense expects uppercase)
        protocol = rule_def.get("protocol", "any")
        if protocol.lower() != "any":
            protocol = protocol.upper()
        
        # Build rule
        rule = {
            "action": "pass",
            "interface": ",".join(interfaces),  # Multiple interfaces
            "direction": "in",
            "ipprotocol": "inet",
            "protocol": protocol,
            "source_net": source_value,
            "destination_net": dest_value,
            "quick": "1",
            "statetype": "keep",
            "enabled": "1",
            "description": rule_def.get("description", ""),
        }
        
        if dest_port:
            rule["destination_port"] = dest_port
        
        rules.append(rule)
    
    return rules


def _parse_address(addr):
    """
    Parse address field and return the value for OPNsense API.
    Examples:
      - "any" → "any"
      - "this_firewall" → "(self)"
      - "printers.hosts" → "printers_hosts"
      - "!local_private_networks.networks" → "!local_private_networks"
    """
    if addr == "any":
        return "any"
    
    if addr == "this_firewall":
        return "(self)"
    
    # Handle negation
    negated = False
    if addr.startswith("!"):
        negated = True
        addr = addr[1:]
    
    # Handle service alias reference (e.g., "printers.hosts")
    alias_name = _resolve_alias_reference(addr)
    
    if negated:
        alias_name = f"!{alias_name}"
    
    return alias_name


def _resolve_alias_reference(ref):
    """
    Resolve service reference like "printers.hosts" to alias name "printers_hosts".
    """
    if ".hosts" in ref:
        return ref.replace(".hosts", "_hosts")
    elif ".ports" in ref:
        return ref.replace(".ports", "_ports")
    elif ".networks" in ref:
        return ref.replace(".networks", "")
    return ref


def _set_alias(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/firewall/alias/setItem/{uuid}", {"alias": payload})


def _add_alias(client: OpnClient, payload: dict):
    return client.post("/api/firewall/alias/addItem", {"alias": payload})


def _search_rules(client: OpnClient):
    try:
        data = client.post("/api/firewall/filter/searchRule")
        return data.get("rows", [])
    except Exception:
        return []


def _get_rule(client: OpnClient, uuid: str):
    return client.get(f"/api/firewall/filter/getRule/{uuid}").get("rule", {})


def _set_rule(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/firewall/filter/setRule/{uuid}", {"rule": payload})


def _add_rule(client: OpnClient, payload: dict):
    return client.post("/api/firewall/filter/addRule", {"rule": payload})


def apply_firewall(cfg, client: OpnClient):
    """
    Apply firewall aliases + rules to OPNsense idempotently.
    Uses savepoint mechanism for safe changes.
    """
    changed = False

    # Build desired state 
    desired_aliases = build_aliases(cfg)
    desired_rules = build_floating_rules(cfg)

    # Create savepoint before making changes
    savepoint_response = client.post("/api/firewall/filter/savepoint")
    savepoint = savepoint_response.get("revision")

    try:
        # Sync aliases
        existing_aliases = _search_aliases(client)
        alias_index = {row.get("name"): row for row in existing_aliases}

        for alias_name, alias_data in desired_aliases.items():
            if alias_name in alias_index:
                # Alias exists; compare and update if needed
                uuid = alias_index[alias_name].get("uuid")
                current = alias_index[alias_name]
                if (
                    str(current.get("type", "")) != str(alias_data.get("type", "")) or
                    str(current.get("content", "")) != str(alias_data.get("content", ""))
                ):
                    _set_alias(client, uuid, alias_data)
                    changed = True
            else:
                # Add new alias
                _add_alias(client, alias_data)
                changed = True

        # Sync rules
        existing_rules = _search_rules(client)

        def make_key(rule):
            """Create unique key from rule fields for matching."""
            return (
                rule.get("interface", ""),
                rule.get("action", ""),
                rule.get("direction", ""),
                rule.get("ipprotocol", ""),
                rule.get("protocol", ""),
                rule.get("source_net", ""),
                rule.get("source_port", ""),
                rule.get("destination_net", ""),
                rule.get("destination_port", ""),
                rule.get("description", ""),
            )

        existing_index = {make_key(r): r for r in existing_rules}

        for rule_data in desired_rules:
            desired_key = make_key(rule_data)

            if desired_key in existing_index:
                # Rule already exists exactly
                continue

            # Otherwise create it
            _add_rule(client, rule_data)
            changed = True


        if changed:
            # Apply changes with rollback protection
            client.post(f"/api/firewall/filter/apply/{savepoint}")
            # Cancel rollback since changes succeeded
            client.post(f"/api/firewall/filter/cancelRollback/{savepoint}")

    except Exception as e:
        # On error, rollback will happen automatically after 60s
        raise RuntimeError(f"Firewall apply failed, will auto-rollback to savepoint {savepoint}: {e}")
