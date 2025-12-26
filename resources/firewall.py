from core.client import OpnClient


def build_zones(cfg):
    zones = {}
    for name, v in cfg["vlans"].items():
        zones[name] = {
            "name": name,
            "network": v["cidr"],
        }
    return zones
def resolve_service(cfg, service_name):
    svc = cfg["services"].get(service_name)
    if not svc:
        raise KeyError(f"Unknown service '{service_name}'")
    return svc["ip"], svc["ports"]

def build_firewall_rules(cfg):
    zones = build_zones(cfg)
    policies = cfg.get("policies", {})
    assignments = cfg.get("__vlan_assignments__", {})
    services = cfg.get("services", {})
    wan_iface = cfg.get("wan_interface")  # e.g. "opt2"

    rules = []

    for zone_name, policy in policies.items():
        src_alias = f"{zone_name}_net"

        # Interface for this zone
        zone_iface = assignments.get(zone_name, {}).get("interface")
        if not zone_iface:
            continue  # skip unassigned VLANs

        #
        # ALLOW RULES
        #
        for target in policy.get("allow", []):
            #
            # 1. Allow → Internet (WAN)
            #
            if target == "internet":
                rules.append({
                    "type": "pass",
                    "interface": zone_iface,
                    "direction": "in",
                    "ipprotocol": "inet",
                    "protocol": "any",
                    "quick": "yes",
                    "statetype": "keep state",
                    "src": src_alias,
                    "dst": wan_iface,  # WAN interface name, not "any"
                    "descr": f"{zone_name} → internet",
                })
                continue

            #
            # 2. Allow → Service (host + ports)
            #
            if target in services:
                svc = services[target]
                host_alias = f"{target}_host"
                ports = svc.get("ports", [])

                for port in ports:
                    rules.append({
                        "type": "pass",
                        "interface": zone_iface,
                        "direction": "in",
                        "ipprotocol": "inet",
                        "protocol": "any",
                        "quick": "yes",
                        "statetype": "keep state",
                        "src": src_alias,
                        "dst": host_alias,
                        "dst_port": str(port),
                        "descr": f"{zone_name} → {target}_{port}",
                    })
                continue

            #
            # 3. Allow → Another zone
            #
            if target in zones:
                dst_alias = f"{target}_net"
                rules.append({
                    "type": "pass",
                    "interface": zone_iface,
                    "direction": "in",
                    "ipprotocol": "inet",
                    "protocol": "any",
                    "quick": "yes",
                    "statetype": "keep state",
                    "src": src_alias,
                    "dst": dst_alias,
                    "descr": f"{zone_name} → {target}",
                })
                continue

        #
        # DENY RULES
        #
        for target in policy.get("deny", []):
            if target in zones:
                dst_alias = f"{target}_net"
                rules.append({
                    "type": "block",
                    "interface": zone_iface,
                    "direction": "in",
                    "ipprotocol": "inet",
                    "protocol": "any",
                    "quick": "yes",
                    "statetype": "keep state",
                    "src": src_alias,
                    "dst": dst_alias,
                    "descr": f"{zone_name} x {target}",
                })

        #
        # SPECIAL: deny_internet
        #
        if policy.get("deny_internet"):
            rules.append({
                "type": "block",
                "interface": zone_iface,
                "direction": "in",
                "ipprotocol": "inet",
                "protocol": "any",
                "quick": "yes",
                "statetype": "keep state",
                "src": src_alias,
                "dst": wan_iface,
                "descr": f"{zone_name} deny internet",
            })

    return rules



def build_aliases(cfg):
    aliases = {}

    #
    # 1. Service aliases (host + ports)
    #
    for name, svc in cfg.get("services", {}).items():
        ip = svc["ip"]
        ports = svc.get("ports", [])

        # Host alias
        aliases[f"{name}_host"] = {
            "name": f"{name}_host",
            "type": "host",
            "content": ip,
            "descr": f"Host alias for {name}",
        }

        # Port alias (only if ports exist)
        if ports:
            aliases[f"{name}_ports"] = {
                "name": f"{name}_ports",
                "type": "port",
                "content": "\n".join(str(p) for p in ports),
                "descr": f"Port alias for {name}",
            }

    #
    # 2. VLAN network aliases
    #
    for name, v in cfg["vlans"].items():
        aliases[f"{name}_net"] = {
            "name": f"{name}_net",
            "type": "network",
            "content": v["cidr"],
            "descr": f"Network alias for {name}",
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
    desired_rules = build_firewall_rules(cfg)

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
        # Build index of existing rules by their real matching fields
        existing_rules = _search_rules(client)

        def make_key(rule):
            return (
                rule.get("interface", ""),
                rule.get("type", ""),
                rule.get("source", ""),
                rule.get("source_port", ""),
                rule.get("destination", ""),
                rule.get("destination_port", ""),
                rule.get("protocol", ""),
                rule.get("direction", ""),
            )

        existing_index = {make_key(r): r for r in existing_rules}

        for rule_data in desired_rules:
            desired_key = (
                rule_data["interface"],
                rule_data.get("action", "pass"),
                rule_data.get("src", "any"),
                rule_data.get("src_port", ""),
                rule_data.get("dst", "any"),
                rule_data.get("dst_port", ""),
                "any",      # protocol
                "in",       # direction
            )

            if desired_key in existing_index:
                # Rule already exists exactly
                continue

            # Otherwise create it
            opn_rule = {
                "type": rule_data.get("action", "pass"),
                "interface": rule_data["interface"],
                "direction": "in",
                "ipprotocol": "inet",
                "protocol": "any",
                "quick": "yes",
                "statetype": "keep state",
                "source_net": rule_data.get("src", "any"),
                "destination_net": rule_data.get("dst", "any"),
                "description": rule_data.get("descr", ""),
            }

            if "dst_port" in rule_data:
                opn_rule["destination_port"] = str(rule_data["dst_port"])

            _add_rule(client, opn_rule)
            changed = True


        if changed:
            # Apply changes with rollback protection
            client.post(f"/api/firewall/filter/apply/{savepoint}")
            # Cancel rollback since changes succeeded
            client.post(f"/api/firewall/filter/cancelRollback/{savepoint}")

    except Exception as e:
        # On error, rollback will happen automatically after 60s
        raise RuntimeError(f"Firewall apply failed, will auto-rollback to savepoint {savepoint}: {e}")
