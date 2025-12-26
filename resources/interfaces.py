import ipaddress
from core.client import OpnClient


def build_desired_interfaces(cfg):
    """
    Build two lists:
      - desired_vlans: VLANs that must be created (tagged)
      - untagged: physical interfaces that should NOT become VLANs
    """
    vlans = cfg["vlans"]

    desired_vlans = []
    untagged = []

    for name, v in vlans.items():
        # Tagged VLAN case
        if "parent" in v:
            item = {
                "name": name,
                "tag": v["id"],
                "parent": v["parent"],  # vtnet2, etc.
                "cidr": v["cidr"],
                "gateway": v["gateway"],
                "pcp": "0",
                "proto": "802.1q",
                "descr": name,
                "network": ipaddress.ip_network(v["cidr"], strict=False),
            }
            desired_vlans.append(item)
            continue

        # Untagged (native) network case
        if "interface" in v:
            untagged.append({
                "name": name,
                "device": v["interface"],  # physical interface (e.g., vtnet3)
                "cidr": v["cidr"],
                "gateway": v["gateway"],
                "network": ipaddress.ip_network(v["cidr"], strict=False),
            })
            continue

        raise ValueError(
            f"VLAN '{name}' must specify either 'parent' (tagged) or 'interface' (untagged)."
        )

    return desired_vlans, untagged


def _search_vlans(client: OpnClient):
    """Return list of VLAN rows from search endpoint."""
    resp = client.get("/api/interfaces/vlan_settings/search_item")
    return resp.get("rows", [])


def _get_vlan(client: OpnClient, uuid: str):
    """Fetch a single VLAN item."""
    return client.get(f"/api/interfaces/vlan_settings/get_item/{uuid}")


def _ensure_vlan(client: OpnClient, desired):
    """
    Ensure VLAN exists and matches desired fields. Idempotent.

    desired: {name, tag, parent, pcp, proto, descr}

    Returns one of: 'created', 'updated', 'unchanged'
    """
    rows = _search_vlans(client)

    def _selected_key(token_map):
        if isinstance(token_map, dict):
            for k, v in token_map.items():
                if isinstance(v, dict) and v.get("selected"):
                    return k
        return None

    # Find existing by (parent interface, tag)
    match = None
    for row in rows:
        uuid = row.get("uuid")
        if not uuid:
            continue
        item = _get_vlan(client, uuid)
        vlan = item.get("vlan", {})
        parent_selected = _selected_key(vlan.get("if"))
        if str(parent_selected) == str(desired["parent"]) and int(vlan.get("tag", 0)) == int(desired["tag"]):
            match = {"uuid": uuid, "vlan": vlan}
            break

    payload = {
        "vlan": {
            "if": desired["parent"],
            "tag": str(desired["tag"]),
            "pcp": str(desired.get("pcp", "0")),
            "proto": desired.get("proto", "802.1q"),
            "descr": desired.get("descr", desired["name"]),
        }
    }

    if match is None:
        client.post("/api/interfaces/vlan_settings/add_item", payload)
        return "created"

    # Update if any mutable field differs (except vlanif)
    current = match["vlan"]
    cur_pcp = _selected_key(current.get("pcp")) or "0"
    cur_proto = _selected_key(current.get("proto")) or "802.1q"
    cur_descr = str(current.get("descr", ""))
    needs_update = (
        str(cur_pcp) != payload["vlan"]["pcp"]
        or str(cur_proto) != payload["vlan"]["proto"]
        or str(cur_descr) != payload["vlan"]["descr"]
    )
    if needs_update:
        client.post(f"/api/interfaces/vlan_settings/set_item/{match['uuid']}", payload)
        return "updated"

    return "unchanged"


def apply_interfaces(cfg, client: OpnClient):
    desired_vlans, untagged = build_desired_interfaces(cfg)

    any_change = False
    created_names = []
    for vlan in desired_vlans:
        result = _ensure_vlan(client, vlan)
        if result == "created":
            created_names.append(vlan["name"])
            any_change = True
        elif result == "updated":
            any_change = True

    if any_change:
        client.post("/api/interfaces/vlan_settings/reconfigure")

    # Track untagged interfaces for future automation
    # (no action today — OPNsense lacks API for assignment/IP config)
    cfg["__untagged_interfaces__"] = untagged
    cfg["__created_vlans__"] = created_names


    # TODO: interface assignment and IPv4 configuration
    #
    # OPNsense does NOT currently expose stable MVC API endpoints for:
    #   1) Assigning interfaces (mapping vlanXX or physical NICs to optX)
    #   2) Enabling interfaces
    #   3) Setting IPv4 address, subnet, or description
    #
    # As a result:
    #   - Tagged VLANs created above must still be manually assigned in
    #     Interfaces → Assignments before they can be configured.
    #
    #   - Untagged interfaces (entries using `interface:` instead of `parent:`)
    #     must NOT be created as VLANs. They represent native networks bound
    #     directly to a physical NIC. These are collected in
    #     cfg["__untagged_interfaces__"] for future automation, but no action
    #     is taken today.
    #
    # When OPNsense exposes proper API endpoints (or if config.xml patching is
    # implemented), this block should:
    #   - Assign each VLAN device (vlanXX) to an optX slot
    #   - Assign each untagged physical interface to an optX slot
    #   - Enable the interface
    #   - Set IPv4 address = gateway
    #   - Set subnet = prefix from `cidr`
    #   - Apply interface configuration


def _find_vlanif(client: OpnClient, desired):
    """Locate the created vlan device name for a desired VLAN by (parent, tag)."""
    rows = _search_vlans(client)
    for row in rows:
        uuid = row.get("uuid")
        if not uuid:
            continue
        item = _get_vlan(client, uuid)
        vlan = item.get("vlan", {})
        # normalize parent match using selected token key
        parent_selected = None
        if isinstance(vlan.get("if"), dict):
            for k, v in vlan.get("if").items():
                if isinstance(v, dict) and v.get("selected"):
                    parent_selected = k
                    break
        if str(parent_selected) == str(desired["parent"]) and int(vlan.get("tag", 0)) == int(desired["tag"]):
            return vlan.get("vlanif")
    # Return whether we created any new VLANs so the caller can exit early
    return bool(created_names)


def _get_assigned_devices(client: OpnClient):
    """Return a set of device names that are currently assigned to interfaces (lan/wan/optX)."""
    try:
        rows= client.get("/api/interfaces/overview/interfaces_info").get("rows", [])
        results = []

        for iface in rows:
            addr4 = iface.get("addr4")
            if not addr4: 
                continue

            iface_ip = ipaddress.ip_interface(addr4)
            results.append({
                    "device": iface["device"],
                    "interface": iface["identifier"],
                    "description": iface.get("description"),
                    "gateway": iface["addr4"],
                    "is_physical": iface.get("is_physical", False),
                    "network": iface_ip.network,  # ← add calculated CIDR
                })

        return results
    
    except Exception:
        # Fallback: no overview info available
        return set()


def validate_vlan_assignments(cfg, client: OpnClient):
    """Validate that each desired tagged VLAN has been assigned to an optX interface.

    Returns a list of human-readable VLAN identifiers missing assignment.
    """
    desired_vlans, _untagged = build_desired_interfaces(cfg)
    # fetch full overview to inspect vlan parent/tag and current identifier (optX)
    assigned_networks = _get_assigned_devices(client)

    missing = []
    assignments = {}
    for vlan in desired_vlans:
        found = False 
        for a in assigned_networks: 
            if vlan["network"] == a["network"]: 
                found = True 
                break 
        if not found: 
            missing.append(f"vlan {vlan['name']} not assigned to optX")
        else:
            assignments[vlan["name"]] = {"device": a["device"], "interface": a["interface"],"network": a["network"]}

    for vlan in _untagged:
        for a in assigned_networks: 
            if vlan["network"] == a["network"]: 
                assignments[vlan["name"]] = {"device": a["device"], "interface": a["interface"],"network": a["network"]}
                break
            
    cfg["__missing_vlan_assignments__"] = missing
    cfg["__vlan_assignments__"] = assignments
    return missing
