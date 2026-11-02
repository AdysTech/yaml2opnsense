"""Firewall alias and rule configuration management for OPNsense.

Aliases (chunk 03, plans/03-aliases.md): YAML-defined `firewall.aliases`,
synced add/update + mark only — never deletes. Ownership is marked in the
description field with a " <provisioned>" suffix; content is compared
order-insensitively so steady state is a no-op.

Rules (chunk 04, not yet wired into the CLI): `build_floating_rules` and the
filter-rule API helpers below. The old savepoint-based `apply_firewall` was
superseded by the direct-mutate + reconfigure commit model (plans/README.md).
"""

import ipaddress
import re

from core.client import OpnClient


# ---------------------------------------------------------------------------
# Aliases (chunk 03)
# ---------------------------------------------------------------------------

# Ownership marker appended to the description of every alias we create/update.
PROVISIONED = " <provisioned>"

# YAML content key -> OPNsense alias type.
_TYPE_BY_KEY = {"hosts": "host", "ports": "port", "macs": "mac", "networks": "network"}

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_FQDN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$"
)
_PORT_RANGE_RE = re.compile(r"^(\d{1,5})-(\d{1,5})$")
_SERVICE_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


def _lease_index(cfg):
    """Build a hostname -> {"ip", "mac"} map from every VLAN's static_leases.

    A lease whose ip is the literal "gateway" resolves to its VLAN's gateway.
    """
    leases = {}
    for vlan in (cfg.get("vlans") or {}).values():
        gateway = vlan.get("gateway")
        for lease in (vlan.get("static_leases") or {}).values():
            hostname = lease.get("hostname")
            if not hostname:
                continue
            ip = lease.get("ip")
            if ip == "gateway":
                ip = gateway
            entry = leases.setdefault(str(hostname), {})
            if ip:
                entry["ip"] = ip
            if lease.get("mac"):
                entry["mac"] = lease["mac"]
    return leases


def _resolve_host(value, alias_name, leases):
    """Resolve a host item to an IP literal or an FQDN, else ValueError."""
    if value in leases:
        ip = leases[value].get("ip")
        if not ip:
            raise ValueError(f"alias {alias_name}: lease {value!r} has no IP")
        return str(ip)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if "." in value and _FQDN_RE.match(value):
        return value.lower()  # FQDNs are case-insensitive; keep comparison stable
    raise ValueError(
        f"alias {alias_name}: {value!r} is not an IP, FQDN, or static-lease hostname"
    )


def _resolve_mac(value, alias_name, leases):
    """Resolve a MAC item (literal or lease hostname), lowercased."""
    if value in leases:
        mac = leases[value].get("mac")
        if not mac:
            raise ValueError(f"alias {alias_name}: lease {value!r} has no MAC")
        return str(mac).lower()
    if _MAC_RE.match(value):
        return value.lower()
    raise ValueError(
        f"alias {alias_name}: {value!r} is not a MAC address or static-lease hostname"
    )


def _validate_port(value, alias_name):
    """Accept an int 1-65535, an a-b range, or a service name."""
    if value.isdigit():
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError(f"alias {alias_name}: port {value!r} out of range 1-65535")
        return str(port)
    m = _PORT_RANGE_RE.match(value)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        if not 1 <= lo < hi <= 65535:
            raise ValueError(f"alias {alias_name}: port range {value!r} is invalid")
        return f"{lo}-{hi}"
    if _SERVICE_RE.match(value):
        return value
    raise ValueError(
        f"alias {alias_name}: {value!r} is not a port, an a-b range, or a service name"
    )


def _normalize_network(value, alias_name):
    """CIDR -> canonical form; a bare IP is kept as-is (OPNsense reads it as /32)."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise ValueError(f"alias {alias_name}: {value!r} is not an IP or CIDR")


def _port_sort_key(port):
    """Deterministic order: plain ports by number, then ranges, then names."""
    m = _PORT_RANGE_RE.match(port)
    if m:
        return (1, int(m.group(1)), int(m.group(2)))
    if port.isdigit():
        return (0, int(port), 0)
    return (2, 0, port)


def _validate_items(alias_name, alias_type, raw_items, leases):
    """Validate, normalize, sort and de-dupe the items of one alias."""
    items = []
    for raw in raw_items:
        value = str(raw).strip()
        if not value:
            raise ValueError(f"alias {alias_name}: empty item")
        if alias_type == "host":
            items.append(_resolve_host(value, alias_name, leases))
        elif alias_type == "mac":
            items.append(_resolve_mac(value, alias_name, leases))
        elif alias_type == "port":
            items.append(_validate_port(value, alias_name))
        else:  # network
            items.append(_normalize_network(value, alias_name))

    if not items:
        raise ValueError(f"alias {alias_name}: needs at least one item")

    unique = set(items)
    if alias_type == "port":
        return sorted(unique, key=_port_sort_key)
    return sorted(unique)


def build_aliases(cfg, derived=None):
    """
    Build the desired alias set from `cfg["firewall"]["aliases"]`.

    Pure — no client calls. Returns {name: {"name", "type", "items", "description"}}
    where items are validated, normalized, sorted and de-duplicated, and the
    description already carries the PROVISIONED ownership marker.

    `derived` is an optional {alias_name: [ip, ...]} map injected by the caller
    (chunk 02 builds the WG_*_clients aliases from the wireguard section).
    """
    leases = _lease_index(cfg)
    aliases_cfg = ((cfg.get("firewall") or {}).get("aliases")) or {}
    aliases = {}

    for name, ips in (derived or {}).items():
        if name in aliases_cfg:
            raise ValueError(
                f"alias {name}: defined both in firewall.aliases and the derived set"
            )
        items = []
        for ip in ips:
            try:
                items.append(str(ipaddress.ip_address(str(ip))))
            except ValueError:
                raise ValueError(f"derived alias {name}: {ip!r} is not an IP")
        aliases[name] = {
            "name": name,
            "type": "host",
            "items": sorted(set(items)),
            "description": f"{name}{PROVISIONED}",
        }

    for name, entry in aliases_cfg.items():
        if not isinstance(entry, dict):
            raise ValueError(
                f"alias {name}: expected a mapping with one of {sorted(_TYPE_BY_KEY)}"
            )
        content_keys = [key for key in _TYPE_BY_KEY if key in entry]
        if len(content_keys) != 1:
            raise ValueError(
                f"alias {name}: exactly one of {sorted(_TYPE_BY_KEY)} required, "
                f"got {content_keys or 'none'}"
            )
        unknown = set(entry) - set(_TYPE_BY_KEY) - {"description"}
        if unknown:
            raise ValueError(f"alias {name}: unknown key(s) {sorted(unknown)}")

        alias_type = _TYPE_BY_KEY[content_keys[0]]
        raw_items = entry[content_keys[0]]
        items = _validate_items(
            name, alias_type,
            raw_items if isinstance(raw_items, list) else [raw_items],
            leases,
        )
        description = str(entry.get("description") or "").strip()
        aliases[name] = {
            "name": name,
            "type": alias_type,
            "items": items,
            "description": f"{description or name}{PROVISIONED}",
        }

    return aliases


def _search_aliases(client: OpnClient):
    """Fetch all existing alias rows."""
    try:
        data = client.post("/api/firewall/alias/search_item", {})
        return data.get("rows", [])
    except Exception:
        return []


def _get_alias(client: OpnClient, uuid: str):
    """Get a single alias row by UUID."""
    return client.get(f"/api/firewall/alias/get_item/{uuid}").get("alias", {})


def _resolve_alias(client: OpnClient, name: str):
    """Resolve an alias name to its UUID."""
    return client.get(f"/api/firewall/alias/get_alias_u_u_i_d/{name}")


def _set_alias(client: OpnClient, uuid: str, alias: dict):
    """Update an existing alias. `alias` is the bare row (no wrapper)."""
    return client.post(f"/api/firewall/alias/set_item/{uuid}", {"alias": alias})


def _add_alias(client: OpnClient, alias: dict):
    """Add a new alias."""
    return client.post("/api/firewall/alias/add_item", {"alias": alias})


def _payload(spec):
    """API row for a built alias — only the fields we own; no audit/meta echo-back."""
    return {
        "name": spec["name"],
        "type": spec["type"],
        "content": "\n".join(spec["items"]),
        "description": spec["description"],
    }


def _is_unmanaged_row(row):
    """System rows (external/internal, __-prefixed, automatic) are never managed."""
    if row.get("type") in ("external", "internal"):
        return True
    if str(row.get("name", "")).startswith("__"):
        return True
    if str(row.get("is_automatic", "")) in ("1", "true", "True"):
        return True
    return False


def _is_marked(row):
    """True when the row carries the <provisioned> ownership marker."""
    descr = row.get("description", row.get("descr", ""))
    return str(descr or "").endswith(PROVISIONED)


def _content_set(row):
    """Normalize a live row's newline-joined content into a comparable set.

    IPs -> dotted, CIDRs -> canonical, MACs/FQDNs -> lowercase, everything else
    (ports, ranges, service names, __lan_network) -> lowercase as-is.
    """
    items = set()
    for line in str(row.get("content", "")).splitlines():
        line = line.strip()
        if not line:
            continue
        if _MAC_RE.match(line):
            items.add(line.lower())
            continue
        try:
            items.add(str(ipaddress.ip_address(line)))
            continue
        except ValueError:
            pass
        try:
            items.add(str(ipaddress.ip_network(line, strict=False)))
            continue
        except ValueError:
            pass
        items.add(line.lower())
    return items


def apply_aliases(cfg, client: OpnClient, derived=None):
    """
    Idempotently apply `firewall.aliases` (plus any derived aliases) to OPNsense.

    Add/update + mark only — never deletes, never retypes (ValueError), and
    skips system rows. Content is compared as a set, so the same items in a
    different order is a no-op. Commits with `reconfigure` only when at least
    one alias was added or updated.
    """
    desired = build_aliases(cfg, derived)
    if not desired:
        return False

    alias_index = {row.get("name"): row for row in _search_aliases(client)}
    changed = False

    for spec in desired.values():
        name = spec["name"]
        row = alias_index.get(name)

        if row is None:
            _add_alias(client, _payload(spec))
            changed = True
            continue

        if _is_unmanaged_row(row):
            print(f"warning: alias {name} is system-managed, skipped")
            continue

        if row.get("type") != spec["type"]:
            raise ValueError(
                f"alias {name}: live type {str(row.get('type'))!r} does not match "
                f"desired {spec['type']!r} — refusing to retype; rename in YAML instead"
            )

        live = _content_set(row)
        want = set(spec["items"])
        if live == want and _is_marked(row):
            continue

        payload = _payload(spec)
        if live == want:
            # Adoption: content already matches — stamp the marker only,
            # and keep the live content verbatim.
            payload["content"] = str(row.get("content", ""))
        _set_alias(client, row.get("uuid"), payload)
        changed = True

    if changed:
        client.post("/api/firewall/alias/reconfigure")
    return changed


# ---------------------------------------------------------------------------
# Rules (chunk 04 — not yet wired into the CLI)
# ---------------------------------------------------------------------------

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


def _search_rules(client: OpnClient):
    """Fetch all existing filter rule rows."""
    try:
        data = client.post("/api/firewall/filter/search_rule", {})
        return data.get("rows", [])
    except Exception:
        return []


def _get_rule(client: OpnClient, uuid: str):
    """Get a single filter rule by UUID."""
    return client.get(f"/api/firewall/filter/get_rule/{uuid}").get("rule", {})


def _set_rule(client: OpnClient, uuid: str, rule: dict):
    """Update an existing filter rule. `rule` is the bare row (no wrapper)."""
    return client.post(f"/api/firewall/filter/set_rule/{uuid}", {"rule": rule})


def _add_rule(client: OpnClient, rule: dict):
    """Add a new filter rule."""
    return client.post("/api/firewall/filter/add_rule", {"rule": rule})
