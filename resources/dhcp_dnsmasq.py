"""DHCP/DNSMasq configuration builder and applier for OPNsense."""
import ipaddress

from core.client import OpnClient


def expand_dhcp_options(vlan):
    """Expand DHCP options for a VLAN, replacing 'gateway' with the actual gateway IP."""
    opts = vlan.get("dhcp_options", {})
    gw = vlan["gateway"]
    result = []

    for code, value in opts.items():
        if value == "gateway":
            result.append(f"{code},{gw}")
        else:
            result.append(f"{code},{value}")

    return result


def build_dhcp_scopes(cfg):
    """Build DHCP scope definitions from VLAN configuration."""
    scopes = []
    for name, v in cfg["vlans"].items():
        dhcp_cfg = v.get("dhcp")
        if not dhcp_cfg:
            continue

        scope = {
            "interface": name,
            "range": dhcp_cfg["range"],
            "options": expand_dhcp_options(v),
        }
        scopes.append(scope)

    return scopes


def build_static_hosts(cfg):
    """Build static host entries from VLAN static leases."""
    domain = cfg["__domain__"]
    vlans = cfg["vlans"]
    hosts = []

    for v in vlans.values():
        leases = v.get("static_leases", {})
        for _, entry in leases.items():
            hosts.append({
                "host": entry["hostname"],
                "domain": entry.get("domain", domain),
                "ip": v.get("gateway") if entry.get("ip") == "gateway" else entry.get("ip"),
                "hwaddr": entry.get("mac", "").upper(),
                "descr": entry.get("description", ""),
                "tags": entry.get("tags", []),
            })

    return hosts


def build_vlan_networks(cfg):
    """Build a dictionary of VLAN name to IP network objects from CIDR definitions."""
    nets = {}
    for name, v in cfg["vlans"].items():
        cidr = v.get("cidr")
        if cidr:
            try:
                nets[name] = ipaddress.ip_network(cidr, strict=False)
            except Exception:
                continue
    return nets


def build_vlan_options(cfg):
    """
    Build DHCP options for VLANs.
    Skips options 3 (router) and 6 (dns-server) when they equal gateway,
    as these are automatically sent by dnsmasq when a DHCP range is created.

    Supports both simple and detailed DHCP option formats:
    - Simple: code: value
    - Detailed: code: {value: val, description: desc}
    """
    result = {}
    for name, v in cfg["vlans"].items():
        opts = v.get("dhcp_options", {})
        gw = v.get("gateway")
        items = []
        for code, entry in opts.items():
            code_int = int(code)

            # Handle both simple string and dict format
            if isinstance(entry, dict):
                value = entry.get("value", "")
                description = entry.get("description", "")
            else:
                value = entry
                description = ""

            # Skip options 3 (router) and 6 (dns-server) when value is "gateway"
            # These are automatically configured by dnsmasq for DHCP ranges
            if code_int in (3, 6) and value == "gateway":
                continue
            val = gw if value == "gateway" else value
            items.append({
                "option": str(code),
                "value": str(val),
                "type": "set",
                "description": str(description)
            })
        if items:
            result[name] = items
    return result


def derive_range_from_cidr(cidr: str, gateway: str | None = None):
    """Derive a DHCP range (start, end) from a CIDR, optionally excluding the gateway."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return None
    if net.version != 4:
        return None
    # No usable hosts on /31-/32
    if net.num_addresses < 4:
        return None
    first = int(net.network_address) + 1
    last = int(net.broadcast_address) - 1
    if gateway:
        try:
            gw_int = int(ipaddress.ip_address(gateway))
            if gw_int == first:
                first += 1
            elif gw_int == last:
                last -= 1
        except Exception:
            pass
    if first > last:
        return None
    return (str(ipaddress.ip_address(first)), str(ipaddress.ip_address(last)))


def _search_hosts(client: OpnClient):
    try:
        data = client.get("/api/dnsmasq/settings/search_host")
        return data.get("rows", [])
    except Exception:
        return []


def _get_host(client: OpnClient, uuid: str):
    return client.get(f"/api/dnsmasq/settings/get_host/{uuid}").get("host", {})


def _set_host(client: OpnClient, uuid: str, host_payload: dict):
    return client.post(f"/api/dnsmasq/settings/set_host/{uuid}", {"host": host_payload})


def _add_host(client: OpnClient, host_payload: dict):
    return client.post("/api/dnsmasq/settings/add_host", {"host": host_payload})


def _search_ranges(client: OpnClient):
    try:
        data = client.get("/api/dnsmasq/settings/search_range")
        return data.get("rows", [])
    except Exception:
        return []


def _get_range(client: OpnClient, uuid: str):
    return client.get(f"/api/dnsmasq/settings/get_range/{uuid}").get("range", {})


def _set_range(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/dnsmasq/settings/set_range/{uuid}", {"range": payload})


def _add_range(client: OpnClient, payload: dict):
    return client.post("/api/dnsmasq/settings/add_range", {"range": payload})


def _search_options(client: OpnClient):
    try:
        data = client.get("/api/dnsmasq/settings/search_option")
        return data.get("rows", [])
    except Exception:
        return []


def _get_option(client: OpnClient, uuid: str):
    return client.get(f"/api/dnsmasq/settings/get_option/{uuid}").get("option", {})


def _set_option(client: OpnClient, uuid: str, payload: dict):
    return client.post(f"/api/dnsmasq/settings/set_option/{uuid}", {"option": payload})


def _add_option(client: OpnClient, payload: dict):
    return client.post("/api/dnsmasq/settings/add_option", {"option": payload})


def _get_tag_list(client: OpnClient):
    try:
        data = client.get("/api/dnsmasq/settings/get_tag_list")
        tags = data.get("tags", {}).get("items", [])
        return {item["label"]: item["value"] for item in tags}
    except Exception:
        return {}


def _add_tag(client: OpnClient, tag_name: str):
    payload = {"tag": {"name": tag_name}}
    return client.post("/api/dnsmasq/settings/add_tag", payload)


def ensure_tags_exist(cfg, client: OpnClient) -> dict:
    """
    Ensure all tags referenced in the config exist in OPNsense.
    Returns a map of tag_label -> tag_uuid.
    """
    existing_tags = _get_tag_list(client)
    tag_map = existing_tags.copy()

    # Collect all unique tags from static_leases
    required_tags = set()
    for vlan in cfg["vlans"].values():
        for lease in vlan.get("static_leases", {}).values():
            tags = lease.get("tags", [])
            required_tags.update(tags)

        # Also collect tags from dhcp_tagged_options
        for tagged_opt in vlan.get("dhcp_tagged_options", []):
            tag = tagged_opt.get("tag")
            if tag:
                required_tags.add(tag)

    # Create missing tags
    for tag in required_tags:
        if tag not in tag_map:
            _add_tag(client, tag)
            # Refresh tag list to get the new UUID
            tag_map = _get_tag_list(client)

    return tag_map


def apply_dnsmasq_hosts(cfg, client: OpnClient, tag_map: dict) -> bool:
    """Synchronize static DNS/DHCP hosts with OPNsense. Returns True if changes were made."""
    changed = False
    desired_hosts = build_static_hosts(cfg)
    existing_hosts = _search_hosts(client)

    # Index by MAC address for reliable matching
    host_index = {}
    for host in existing_hosts:
        key = host.get("hwaddr", "").upper() if host.get("hwaddr", "") else host.get("ip", "")
        if key:
            host_index[key] = host

    def _host_equal(current: dict, desired: dict) -> bool:
        # Convert desired tags list to UUID string for comparison
        tags = desired.get("tags", [])
        tag_uuids = [tag_map.get(tag, "") for tag in tags if tag in tag_map]
        desired_set_tag = ",".join(filter(None, tag_uuids))

        return (
            current.get("ip", "") == str(desired.get("ip", "")) and
            str(current.get("hwaddr", "")).upper() == str(desired.get("hwaddr", "")).upper() and
            str(current.get("host", "")) == str(desired.get("host", "")) and
            str(current.get("domain", "")) == str(desired.get("domain", "")) and
            str(current.get("descr", "")) == str(desired.get("descr", "")) and
            str(current.get("set_tag", "")) == desired_set_tag
        )

    def _format_host_for_set(desired: dict) -> dict:
        # Convert tags list to comma-separated UUID string
        tags = desired.get("tags", [])
        tag_uuids = [tag_map.get(tag, "") for tag in tags if tag in tag_map]
        set_tag_value = ",".join(filter(None, tag_uuids))

        return {
            "host": desired.get("host", ""),
            "domain": desired.get("domain", ""),
            "local": "0",
            "ip": desired.get("ip", ""),
            "aliases": "",
            "cnames": "",
            "client_id": "*",
            "hwaddr": desired.get("hwaddr", ""),
            "lease_time": "",
            "set_tag": set_tag_value,
            "ignore": "0",
            "descr": desired.get("descr", ""),
            "comments": ""
        }

    for host in desired_hosts:
        key = host.get("hwaddr", "").upper() if host.get("hwaddr", "") else host.get("ip", "")
        # Match by MAC address only
        if key in host_index:
            current = host_index[key]
            if not _host_equal(current, host):
                _set_host(client, current.get("uuid"), _format_host_for_set(host))
                changed = True
        else:
            _add_host(client, _format_host_for_set(host))
            changed = True

    return changed


def apply_dnsmasq_ranges(cfg, client: OpnClient) -> bool:
    """Synchronize DHCP address ranges with OPNsense. Returns True if changes were made."""
    changed = False

    existing_ranges = _search_ranges(client)
    vlan_interface_assignment_map = cfg.get("__vlan_assignments__", {})

    for vlan_name, vlan in cfg["vlans"].items():
        iface = vlan_interface_assignment_map.get(vlan_name, {}).get("interface")
        if not iface:
            continue
        # Prefer explicit DHCP range from config; fall back to CIDR derivation
        dhcp_cfg = vlan.get("dhcp")
        if dhcp_cfg is False:
            # DHCP explicitly disabled; skip range management for this VLAN
            continue
        cidr = vlan.get("cidr")
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except Exception:
            net = None
        explicit_range = None
        if isinstance(dhcp_cfg, dict):
            rng = dhcp_cfg.get("range")
            if isinstance(rng, (list, tuple)) and len(rng) == 2:
                start = str(rng[0]) if rng[0] else ""
                end = str(rng[1]) if rng[1] else ""
                if start and end:
                    explicit_range = (start, end)
        if explicit_range:
            start_val, end_val = explicit_range
        else:
            derived = derive_range_from_cidr(cidr, vlan.get("gateway"))
            if not derived:
                continue
            start_val, end_val = derived
        matching_uuid = None
        exact_match = False
        iface_rows = [row for row in existing_ranges if row.get("interface") == iface]
        for row in iface_rows:
            current_start = row.get("start_addr") or row.get("start")
            current_end = row.get("end_addr") or row.get("end")
            try:
                cur_s = ipaddress.ip_address(current_start) if current_start else None
                cur_e = ipaddress.ip_address(current_end) if current_end else None
            except Exception:
                cur_s, cur_e = None, None
            if net and cur_s in net and cur_e in net:
                matching_uuid = row.get("uuid")
                if str(current_start) == start_val and str(current_end) == end_val:
                    exact_match = True
                break

        if matching_uuid:
            if not exact_match:
                payload = {"interface": iface, "start_addr": start_val, "end_addr": end_val}
                _set_range(client, matching_uuid, payload)
                changed = True
        else:
            payload = {"interface": iface, "start_addr": start_val, "end_addr": end_val}
            _add_range(client, payload)
            changed = True
    return changed


def apply_dnsmasq_options(cfg, client: OpnClient) -> bool:
    """Synchronize per-VLAN DHCP options with OPNsense. Returns True if changes were made."""
    changed = False
    vlan_options = build_vlan_options(cfg)
    existing_options = _search_options(client)
    opt_index = {}
    for row in existing_options:
        code = str(row.get("option") or row.get("option6") or "")
        iface = row.get("interface", "")
        tag = row.get("tag", "")
        # Only index non-tagged options (default options)
        if code and iface is not None and not tag:
            opt_index[(iface, code)] = row

    def _normalize_option_type(current_type) -> str:
        if isinstance(current_type, dict):
            if isinstance(current_type.get('set'), dict) and current_type['set'].get('selected'):
                return 'set'
            set_selected = current_type.get('match')
            if isinstance(set_selected, dict) and set_selected.get('selected'):
                return 'match'
            return 'basic'
        if not current_type:
            return 'basic'
        return str(current_type)

    for vlan_name, items in vlan_options.items():
        iface = cfg.get("__vlan_assignments__", {}).get(vlan_name, {}).get("interface")
        if not iface:
            continue
        for item in items:
            key = (iface, item["option"])
            desired_type = item.get("type", "set")
            desired_description = item.get("description", "")
            payload = {
                "interface": iface,
                "option": item["option"],
                "value": item["value"],
                "type": desired_type,
                "descr": desired_description
            }
            if key in opt_index:
                current_row = opt_index[key]
                uuid = current_row.get("uuid")
                # Use data already in search results instead of fetching again
                if (
                    str(current_row.get("value", "")) != str(item["value"]) or
                    _normalize_option_type(current_row.get("type")) != str(desired_type) or
                    str(current_row.get("descr", "")) != str(desired_description)
                ):
                    _set_option(client, uuid, payload)
                    changed = True
            else:
                _add_option(client, payload)
                changed = True

    return changed


def apply_dnsmasq_tagged_options(cfg, client: OpnClient, tag_map: dict) -> bool:
    """Apply DHCP options that are tagged for specific clients."""
    changed = False
    existing_options = _search_options(client)

    # Index existing options by (interface, option_code, tag)
    opt_index = {}
    for row in existing_options:
        code = str(row.get("option") or row.get("option6") or "")
        iface = row.get("interface", "")
        tag = str(row.get("tag", ""))
        if code and iface:
            opt_index[(iface, code, tag)] = row

    for vlan_name, vlan in cfg["vlans"].items():
        iface = cfg.get("__vlan_assignments__", {}).get(vlan_name, {}).get("interface")
        if not iface:
            continue

        tagged_options = vlan.get("dhcp_tagged_options", [])
        for tagged_opt in tagged_options:
            tag_label = tagged_opt.get("tag")
            if not tag_label or tag_label not in tag_map:
                continue

            tag_uuid = tag_map[tag_label]
            options = tagged_opt.get("options", [])

            for opt in options:
                # Handle both old dict format and new list format
                if isinstance(opt, dict):
                    code = str(opt.get("option", ""))
                    value = str(opt.get("value", ""))
                    description = str(opt.get("description", ""))
                    force = "1" if opt.get("force", False) else "0"
                else:
                    # Skip invalid entries
                    continue

                if not code:
                    continue

                payload = {
                    "interface": iface,
                    "type": "set",
                    "option": code,
                    "option6": "",
                    "tag": tag_uuid,
                    "set_tag": "",
                    "value": value,
                    "force": force,
                    "descr": description
                }

                key = (iface, code, tag_uuid)
                if key in opt_index:
                    current_row = opt_index[key]
                    uuid = current_row.get("uuid")
                    # Check if update needed
                    if (
                        str(current_row.get("value", "")) != value or
                        str(current_row.get("force", "0")) != force or
                        str(current_row.get("descr", "")) != description
                    ):
                        _set_option(client, uuid, payload)
                        changed = True
                else:
                    _add_option(client, payload)
                    changed = True

    return changed


def apply_dnsmasq(cfg, client: OpnClient):
    """Apply all DHCP/DNSMasq configuration: tags, hosts, ranges, and options."""
    changed = False

    # First, ensure all tags exist and get the tag map
    tag_map = ensure_tags_exist(cfg, client)

    if apply_dnsmasq_hosts(cfg, client, tag_map):
        changed = True
    if apply_dnsmasq_ranges(cfg, client):
        changed = True
    if apply_dnsmasq_options(cfg, client):
        changed = True
    if apply_dnsmasq_tagged_options(cfg, client, tag_map):
        changed = True

    if changed:
        client.post("/api/dnsmasq/service/reconfigure")
