# Copilot Instructions for yaml2opnsense

This file provides context and constraints for GitHub Copilot working in this repository.

---

## Project Purpose

`yaml2opnsense` is a declarative automation engine for OPNsense.  
It reads a single domain-rooted YAML file and configures OPNsense entirely via its REST API.

Resources managed:
- VLANs and interface assignments
- IPv4 addressing
- DHCP ranges, options, and static leases (via DNSMasq)
- Unbound DNS forwards and host overrides
- Firewall aliases and rules (derived from high-level policies)
- FreeRADIUS users for 802.1X / MAC-based authentication
- HAProxy load balancer frontends and backends

---

## Repo Structure

```
.
├── run.py                        # CLI entry point: python run.py <file.yaml> [--test eth0]
├── cli.py                        # Orchestrates all apply_* calls in dependency order
├── structure.yaml                # Canonical, fully-commented YAML schema (source of truth)
├── requirements.txt
├── core/
│   ├── client.py                 # OpnClient — wraps requests, handles auth + error checking
│   └── config_loader.py          # Loads + validates YAML; _validate_vlans enforces schema rules
├── resources/
│   ├── interfaces.py             # VLAN creation, IP assignment, preflight validation
│   ├── dhcp_dnsmasq.py           # DNSMasq static leases and DHCP configuration
│   ├── unbound.py                # DNS forwards and Unbound host overrides
│   ├── firewall.py               # Firewall aliases and policy-derived rules
│   ├── freeradius.py             # FreeRADIUS user management
│   └── haproxy.py                # HAProxy backend/frontend config + stale resource cleanup
├── validator/
│   ├── validator.py              # VLANValidator — orchestrates per-VLAN test suite
│   ├── models.py                 # Result models for test output
│   ├── protocols/                # Protocol-level test implementations (DHCP, DNS, ICMP, NTP, ARP)
│   └── utils/                   # Scapy helpers (sniffer, ARP responder)
└── yaml2opnsense-config/         # User YAML files (e.g., nammane.arpa.yaml) — private subrepo
```


1. `apply_interfaces` — VLANs must exist before anything else

---

## Running the Project

```bash
# Install dependencies
pip install -r requirements.txt

# Apply a config
python run.py yaml2opnsense-config/nammane.arpa.yaml

# Apply + run validation tests (requires sudo, needs a trunk-port NIC)
sudo python run.py yaml2opnsense-config/nammane.arpa.yaml --test eth0
```

Credentials are resolved from environment variables first, then from YAML:

| Variable             | YAML key              |
|----------------------|-----------------------|
| `OPNSENSE_HOST`      | `opnsense.host`       |
| `OPNSENSE_API_KEY`   | `opnsense.api_key`    |
| `OPNSENSE_API_SECRET`| `opnsense.api_secret` |

Store credentials in a `.env` file at the project root (loaded automatically via `python-dotenv`).

---

## YAML Schema

The canonical schema with all options and comments lives in `structure.yaml`.  
Always refer to it before generating or modifying YAML. Below is a structural summary.

```yaml
your.domain.name:            # Root key = network domain name

  opnsense:
    host: "http://..."       # OPNsense URL

  wan_interface: optX        # Physical WAN interface name

  dns_forwards:              # Custom Unbound forwarding rules
    - domain: ""             # Blank = catch-all
      server: "192.168.x.x"
      port: 53
      description: "..."

  host_overrides:            # Unbound A-record overrides
    - hostname: "svc.domain" # FQDN — split into hostname + domain automatically
      ip: "192.168.x.x"
      description: "..."

  connectivity_tests:        # Used by the validator for all VLANs
    reverse_lookup: { ip, fqdn }
    internal_lookup: { host, ip }
    external_lookup: { host, ip }
    overridden_lookup: { host, ip }

  vlans:
    <name>:
      id: 10                         # 1-4094, unique
      interface: vtnetX              # Untagged — use 'interface' OR 'parent', not both
      parent: vtnetX                 # Tagged parent interface
      cidr: 192.168.10.0/24
      gateway: 192.168.10.1
      dhcp: false                    # Disable DHCP server
      dhcp:                          # Or enable with a range
        range: [192.168.10.100, 192.168.10.200]
      private_network: true          # Allow access to other RFC1918 networks
      public_network: true           # Allow internet access
      dhcp_options:
        42: gateway                  # Simple: code: value or 'gateway' token
        66:
          value: "192.168.x.x"       # Complex: with description
          description: "TFTP server"
      static_leases:
        <hostname>:
          hostname: my-server
          ip: 192.168.10.5
          mac: "AA:BB:CC:DD:EE:FF"

  free_radius_users:
    - <vlan_name>:
        - mac: "AA:BB:CC:DD:EE:FF"
          description: "device-name"

  services:                          # Named aliases (IP + ports) for firewall rules
    <name>:
      ip: "192.168.x.x"
      ports: [53, 853]

  policies:                          # Zone-based firewall rules
    <source_vlan>:
      allow:
        - <service_or_vlan>
        - internet                   # Keyword: allow internet
      deny:
        - <vlan_name>
      deny_internet: true            # Keyword: block all internet

  haproxy:
    enabled: true
    bind_address: "192.168.x.x"
    stats:
      enabled: true
      uri: /haproxy_stats
      refresh: 10s
    backends:
      <name>:
        mode: http | tcp
        balance: roundrobin | leastconn | source
        health_check: { method, uri, port, check_interval }
        service: { port }
        options: [...]
        http_request: [{ action, name, value }]
        timeout_tunnel: 1h
        servers:
          - name: <hostname_from_static_leases>
    frontends:
      <name>:
        bind_port: 80
        mode: http | tcp
        ssl: true
        ssl_cert: "cert-name"
        default_backend: <backend_name>
        stats_enabled: true
```

---

## HAProxy Sync & Cleanup

HAProxy configuration is applied idempotently with **drift remediation** -- resources in OPNsense that no longer appear in the YAML are automatically deleted.

`apply_haproxy()` in `resources/haproxy.py` orchestrates a two-phase process:

### Phase 1: Sync (forward dependency order)

Leaf nodes are created first, then parents that reference them by UUID:

1. **Servers** -- leaf nodes (matched by name+backend). Returns `(changed, server_uuid_map)`.
   - Uses retry logic with fresh re-query when OPNsense search lags after create/update.
   - Servers are matched in UUID maps by `(address, port)` tuple since multiple backends can reference the same server IP.
2. **Healthchecks** -- independent leaf nodes (matched by name). Returns `(changed, healthcheck_uuid_map)`.
3. **Actions** -- http-request rules like set-header, del-header (matched by generated name). Returns `(changed, action_uuid_map_by_backend)`.
   - Action payload uses `type: "http-request"`, `http_request_action: <verb>`, `http_request_option: <args>` to match OPNsense's internal data model.
4. **Backends** -- reference servers, healthchecks, and actions by UUID. Returns `(changed, backend_uuid_map)`.
5. **Frontends** -- reference backends by UUID. Returns `(changed, frontend_uuid_map)`.
   - Builds certificate name → UUID map from frontend options for SSL binding.
   - Refreshes frontend list after changes to populate uuid map correctly.

### Phase 2: Cleanup (REVERSE dependency order)

When resources are removed from YAML, they are deleted from OPNsense in reverse dependency order to avoid foreign key violations:

1. **Frontends** -- `_cleanup_deleted_frontends()` deletes first, since they reference backends by UUID
2. **Backends** -- `_cleanup_deleted_backends()` deletes next, since they reference servers/actions/healthchecks by UUID
3. **Actions** -- `_cleanup_deleted_actions()` safe to delete after backends no longer reference them
4. **Healthchecks** -- `_cleanup_deleted_healthchecks()` independent, safe to delete after backends
5. **Servers** -- `_cleanup_deleted_servers()` matched by `(address, port)` tuple since multiple backends can share the same server IP

If any sync or cleanup phase reports changes, `postReconfigureHaproxy()` is called to apply the configuration to OPNsense.

### Key Implementation Details

- **Delete helpers**: `_delete_server`, `_delete_healthcheck`, `_delete_action`, `_delete_backend`, `_delete_frontend` wrap the OPNsense REST API delete endpoints (`/api/haproxy/settings/del*`)
- **Search helpers**: `_search_servers`, `_search_backends`, etc. query `/api/haproxy/settings/list*` and filter by resource type
- **Cleanup functions**: `_cleanup_deleted_*` compare existing OPNsense state (from search) against desired YAML state (from `build_haproxy_config()`) and remove stale entries
- **Null guards**: `if server is None: continue` in server iteration protects against blank entries in YAML server lists

### Apply Order (enforced in cli.py)

- **HTTP calls**: use `OpnClient.get()` / `OpnClient.post()` — never call `requests` directly in resource files
- **YAML parsing**: `PyYAML` via `core/config_loader.py`
- **Validation tests**: `scapy` for raw packet work, `dnspython` for DNS, `ntplib` for NTP
- **Style**: PEP-8, 2-space YAML indentation, no tabs, no trailing whitespace
- **Logic**: clear and deterministic; avoid unnecessary abstractions; prefer explicit over implicit
- **Error handling**: raise `ValueError` for config errors, `RuntimeError` for preflight failures

---

## Constraints — What NOT to Do

- Do not invent new top-level YAML keys not present in `structure.yaml`
- Do not change the YAML schema structure
- Do not generate VLAN IDs or IP ranges outside RFC1918 unless explicitly asked
- Do not generate passwords unless explicitly requested
- Do not reorder user-provided YAML unless asked
- Do not bypass the apply order defined in `cli.py`
- Do not call `requests` directly in resource files — use `OpnClient`
- Do not add features or refactor beyond what is directly requested
- Do not read or reference files under `yaml2opnsense-config/` — it is a private subrepo
