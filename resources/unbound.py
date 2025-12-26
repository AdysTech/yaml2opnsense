from core.client import OpnClient
import ipaddress


def cidr_to_reverse_zone(cidr: str) -> str | None:
    """
    Convert a CIDR to its reverse DNS zone (in-addr.arpa for IPv4).
    E.g., 192.168.20.0/24 -> 20.168.192.in-addr.arpa
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return None
    if net.version != 4:
        return None  # IPv6 reverse zones not implemented yet

    # Get the network address octets
    octets = str(net.network_address).split(".")
    prefix_len = net.prefixlen

    # Calculate which octets to include based on prefix length
    # /8 -> first octet, /16 -> first two octets, /24 -> first three octets
    if prefix_len >= 24:
        return f"{octets[2]}.{octets[1]}.{octets[0]}.in-addr.arpa"
    elif prefix_len >= 16:
        return f"{octets[1]}.{octets[0]}.in-addr.arpa"
    elif prefix_len >= 8:
        return f"{octets[0]}.in-addr.arpa"
    else:
        # For larger networks, just use the first octet
        return f"{octets[0]}.in-addr.arpa"


def build_dns_forwards(cfg):
    """
    Build DNS forward configurations for Unbound Query Forwarding.
    Creates forward zones for each VLAN:
    - Forward lookup: <vlan_name>.<domain> -> 127.0.0.1:53053
    - Reverse lookup: <reverse_zone>.in-addr.arpa -> 127.0.0.1:53053

    Also includes custom forwards from cfg["dns_forwards"] if present.
    Custom forwards support blank domains for catch-all forwarding.

    These tell Unbound to forward specific zone queries to dnsmasq (listening on 53053).
    """
    domain = cfg.get("__domain__")
    forwards = []
    
    # Add custom forwards first (e.g., for AdGuard, external DNS)
    custom_forwards = cfg.get("dns_forwards", [])
    for fwd in custom_forwards:
        forwards.append({
            "domain": fwd.get("domain", ""),
            "server": fwd["server"],
            "port": str(fwd.get("port", "53")),
            "description": fwd.get("description", ""),
        })
    
    # Add VLAN-based forwards
    if domain:
        
        # Forward lookup: domain -> 127.0.0.1:53053
        forwards.append(
            {
                "domain": f"{domain}",
                "server": "127.0.0.1",
                "port": "53053",
                "description": f"Forward zone for {domain} domain",
            }
        )
        
        for vlan_name, vlan in cfg["vlans"].items():
            cidr = vlan.get("cidr")
            if not cidr:
                continue

            # Reverse lookup: reverse_zone.in-addr.arpa -> 127.0.0.1:53053
            reverse_zone = cidr_to_reverse_zone(cidr)
            if reverse_zone:
                forwards.append(
                    {
                        "domain": reverse_zone,
                        "server": "127.0.0.1",
                        "port": "53053",
                        "description": f"Reverse zone for {vlan_name} VLAN ({cidr})",
                    }
                )

    return forwards


def _search_forwards(client: OpnClient):
    """Fetch all existing forward entries from Unbound."""
    try:
        data = client.post("/api/unbound/settings/search_forward", {})
        return data.get("rows", [])
    except Exception:
        return []


def _get_forward(client: OpnClient, uuid: str):
    """Get a specific forward entry by UUID."""
    return client.get(f"/api/unbound/settings/get_forward/{uuid}").get("forward", {})


def _set_forward(client: OpnClient, uuid: str, payload: dict):
    """Update an existing forward entry."""
    return client.post(f"/api/unbound/settings/set_forward/{uuid}", payload)


def _add_forward(client: OpnClient, payload: dict):
    """Add a new forward entry."""
    return client.post("/api/unbound/settings/add_forward", payload)


def apply_unbound_forwards(cfg, client: OpnClient):
    """
    Idempotently apply DNS forward configurations to Unbound.
    - Adds new forward zones
    - Updates existing forward zones when server/port differs
    - Triggers service reconfigure if any change

    Note: Does not remove forwards not in config (to avoid breaking user-added forwards).
    """
    desired_forwards = build_dns_forwards(cfg)
    if not desired_forwards:
        return

    changed = False
    existing_forwards = _search_forwards(client)
    # Index by domain, including blank domains
    forward_index = {row.get("domain", ""): row for row in existing_forwards}

    def _forward_equal(current: dict, desired: dict) -> bool:
        """Check if current forward matches desired configuration."""
        return (
            str(current.get("server", "")) == desired.get("server", "")
            and str(current.get("port", "")) == desired.get("port", "")
        )

    # Add/update forwards
    for forward in desired_forwards:
        domain = forward["domain"]

        payload = {
            "dot": {
                "enabled": "1",
                "domain": domain,
                "server": forward["server"],
                "port": forward["port"],
                "forward_tcp_upstream": "0",
                "forward_first": "0",
                "verify": "",
                "description": forward.get("description", ""),
            }
        }

        if domain in forward_index:
            current = forward_index[domain]
            if not _forward_equal(current, forward):
                uuid = current.get("uuid")
                _set_forward(client, uuid, payload)
                changed = True
        else:
            _add_forward(client, payload)
            changed = True

    if changed:
        client.post("/api/unbound/service/reconfigure")
