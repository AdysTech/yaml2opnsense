import yaml
import ipaddress
import re


def _validate_vlans(cfg: dict) -> None:
    """Validate `vlans` section in the loaded config.

    Rules:
    - `vlans` must exist and be a mapping with at least one entry
    - Each VLAN must have: `id` (int 1-4094), `cidr` (IPv4 CIDR), `gateway` (IPv4 inside CIDR)
    - Exactly one of `parent` (tagged) or `interface` (untagged) is required; not both
    - VLAN IDs must be unique
    - If `dhcp` is a dict with `range`: start/end must be IPv4 inside CIDR, start <= end, and not equal to network/broadcast
    - `dhcp_options` codes must be numeric and from {3, 6, 42, 66}; values may be a literal or the token 'gateway'
    - `static_leases` entries (if present) must include hostname, ip, mac; IP must be inside VLAN CIDR; MAC format AA:BB:CC:DD:EE:FF
    - CIDR networks should not overlap between VLANs (to avoid ambiguous routing/DHCP)
    """

    errors = []
    vlans = cfg.get("vlans")
    if not isinstance(vlans, dict) or not vlans:
        errors.append("'vlans' must be a non-empty mapping")
        if errors:
            raise ValueError("; "+"; ".join(errors))

    seen_ids = set()
    networks = {}

    for name, v in vlans.items():
        # id
        vid = v.get("id")
        if not isinstance(vid, int):
            errors.append(f"vlan '{name}': 'id' must be an integer")
        else:
            if not (1 <= vid <= 4094):
                errors.append(f"vlan '{name}': 'id' must be between 1 and 4094")
            elif vid in seen_ids:
                errors.append(f"vlan '{name}': duplicate 'id' {vid}")
            else:
                seen_ids.add(vid)

        # cidr
        cidr = v.get("cidr")
        net = None
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version != 4:
                errors.append(f"vlan '{name}': 'cidr' must be IPv4")
        except Exception:
            errors.append(f"vlan '{name}': invalid 'cidr' value")

        # gateway
        gw = v.get("gateway")
        try:
            gw_ip = ipaddress.ip_address(gw)
            if net and gw_ip not in net:
                errors.append(f"vlan '{name}': gateway {gw} not in {cidr}")
            if net and (gw_ip == net.network_address or gw_ip == net.broadcast_address):
                errors.append(f"vlan '{name}': gateway {gw} cannot be network/broadcast address")
        except Exception:
            errors.append(f"vlan '{name}': invalid 'gateway' IPv4 address")

        # parent/interface exclusivity
        has_parent = "parent" in v and isinstance(v.get("parent"), str) and v.get("parent").strip() != ""
        has_iface = "interface" in v and isinstance(v.get("interface"), str) and v.get("interface").strip() != ""
        if has_parent and has_iface:
            errors.append(f"vlan '{name}': specify only one of 'parent' (tagged) or 'interface' (untagged)")
        elif not has_parent and not has_iface:
            errors.append(f"vlan '{name}': must specify either 'parent' (tagged) or 'interface' (untagged)")

        # DHCP range validation (if present)
        dhcp_cfg = v.get("dhcp")
        if isinstance(dhcp_cfg, dict):
            rng = dhcp_cfg.get("range")
            if isinstance(rng, (list, tuple)) and len(rng) == 2:
                start, end = rng
                try:
                    s_ip = ipaddress.ip_address(str(start)) if start else None
                    e_ip = ipaddress.ip_address(str(end)) if end else None
                    if not (s_ip and e_ip):
                        errors.append(f"vlan '{name}': DHCP range must include start and end addresses")
                    elif net and (s_ip not in net or e_ip not in net):
                        errors.append(f"vlan '{name}': DHCP range {start}-{end} must be inside {cidr}")
                    elif int(s_ip) > int(e_ip):
                        errors.append(f"vlan '{name}': DHCP range start must be <= end")
                    elif net and (s_ip in (net.network_address, net.broadcast_address) or e_ip in (net.network_address, net.broadcast_address)):
                        errors.append(f"vlan '{name}': DHCP range cannot include network/broadcast address")
                except Exception:
                    errors.append(f"vlan '{name}': invalid DHCP range addresses")

        

        # Static leases validation (if present)
        leases = v.get("static_leases")
        if isinstance(leases, dict):
            for key, entry in leases.items():
                if not isinstance(entry, dict):
                    errors.append(f"vlan '{name}': static_leases entry '{key}' must be a mapping")
                    continue
                host = entry.get("hostname")
                ip = entry.get("ip")
                mac = entry.get("mac")
                if not host or not isinstance(host, str):
                    errors.append(f"vlan '{name}': static lease '{key}' missing valid 'hostname'")
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if net and ip_obj not in net:
                        errors.append(f"vlan '{name}': static lease '{key}' IP {ip} not in {cidr}")
                except Exception:
                    errors.append(f"vlan '{name}': static lease '{key}' has invalid 'ip'")
                if mac is not None and not re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", str(mac)):
                    errors.append(f"vlan '{name}': static lease '{key}' has invalid 'mac' (AA:BB:CC:DD:EE:FF)")

        if net:
            networks[name] = net

    # Check for overlapping CIDRs across VLANs
    names = list(networks.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = networks[names[i]], networks[names[j]]
            # Overlap if one network contains another's network address
            if (a.overlaps(b)):
                errors.append(f"vlans '{names[i]}' and '{names[j]}' have overlapping CIDRs ({a} vs {b})")

    if errors:
        raise ValueError("; "+"; ".join(errors))


def _validate_references(cfg: dict) -> None:
    """Validate references in config that depend on VLANs (e.g., free_radius_users)."""
    vlans = cfg.get("vlans", {})
    vlan_names = set(vlans.keys())

    raw_users = cfg.get("free_radius_users", [])
    errs = []
    if isinstance(raw_users, list):
        for idx, item in enumerate(raw_users):
            if not isinstance(item, dict) or len(item) != 1:
                errs.append(f"free_radius_users[{idx}]: each item must be a single-key mapping of vlan_name → [users]")
                continue
            vlan_name, entries = next(iter(item.items()))
            if vlan_name not in vlan_names:
                errs.append(f"free_radius_users[{idx}]: unknown VLAN '{vlan_name}'")
            if not isinstance(entries, list):
                errs.append(f"free_radius_users[{idx}]: value must be a list of user entries")
                continue
            for e in entries:
                if not isinstance(e, dict) or not e.get("mac"):
                    errs.append(f"free_radius_users[{idx}]: each user requires 'mac'")
    if errs:
        raise ValueError("; "+"; ".join(errs))

def load_config(path):
    with open(path, "r") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict) or len(raw) != 1:
        raise ValueError("Top-level YAML must have exactly one domain key")

    domain, cfg = next(iter(raw.items()))
    cfg["__domain__"] = domain
    # Validate core sections before proceeding
    _validate_vlans(cfg)
    _validate_references(cfg)
    return cfg