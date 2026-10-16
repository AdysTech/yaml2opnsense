# CLAUDE.md

`yaml2opnsense` is a declarative automation engine that configures an OPNsense firewall
entirely through its REST API, driven by one domain-rooted YAML file
(`yaml2opnsense-config/nammane.arpa.yaml`, private subrepo). It manages VLANs, IPv4,
DHCP (dnsmasq), DNS (Unbound), FreeRADIUS 802.1X users, and HAProxy load balancing.

- **Network context:** [NETWORK.md](NETWORK.md) — real VLAN segmentation, topology, and intent.
- **Schema (source of truth):** [structure.yaml](structure.yaml) — fully commented; read it before generating or modifying any YAML.
- **AI instructions:** [.github/copilot-instructions.md](.github/copilot-instructions.md) — detailed apply-order, HAProxy sync/cleanup mechanics, and constraints.

## Running

```bash
.venv/bin/pip install -r requirements.txt

# Apply config to OPNsense (idempotent)
.venv/bin/python run.py yaml2opnsense-config/nammane.arpa.yaml

# Apply + run per-VLAN protocol tests (DHCP/DNS/NTP/ICMP/ARP) — needs sudo and a trunk-port NIC
sudo .venv/bin/python run.py yaml2opnsense-config/nammane.arpa.yaml --test eth0
```

Credentials: `OPNSENSE_HOST` / `OPNSENSE_API_KEY` / `OPNSENSE_API_SECRET` from env (a
`.env` at the repo root is auto-loaded) or from the YAML's `opnsense:` block.
**Never print, commit, or echo credentials or the `.env` contents.**

## Architecture

`run.py` → `cli.apply(path, test_interface)` → in dependency order:

1. `apply_interfaces` — create tagged VLANs (802.1q), idempotent.
2. `validate_vlan_assignments` — **preflight**: aborts if a VLAN isn't assigned to an `optX` with IPv4 (manual step in OPNsense; no API for it yet).
3. `apply_dnsmasq` — static leases (match by MAC), ranges (match by interface+network), per-VLAN and tag-scoped options (match by interface+code+tag).
4. `apply_unbound` — auto-forwards domain + per-VLAN reverse zones to dnsmasq `127.0.0.1:53053`; host overrides.
5. `apply_freeradius` — MAC-based users, VLAN ID derived from `vlans.<name>.id`.
6. `apply_haproxy` — two-phase: sync leaf→parent (servers → healthchecks → actions → backends → frontends), then **reverse-order cleanup** of removed resources; `postReconfigureHaproxy()` if anything changed.

`validator/` (only with `--test`) — Scapy/dnspython/ntplib protocol tests per VLAN, keyed off `connectivity_tests` and the `private_network`/`public_network` flags.

## Conventions

- **All HTTP goes through `OpnClient`** (`core/client.py`) — never call `requests` directly in resource files.
- **Idempotent apply pattern:** search existing → match by a stable key → add or set only on diff; match keys differ per resource (see Architecture).
- **Error handling:** `ValueError` for config errors, `RuntimeError` for preflight/apply failures.
- **Firewall changes use savepoints:** `filter/savepoint` → apply → `cancelRollback`; on exception OPNsense auto-rolls back after ~60s.
- **Style:** PEP-8, 2-space YAML indentation, no tabs/trailing whitespace; explicit over implicit; avoid unrequested refactors.
- New code in `resources/` should follow the existing module shape: `build_*` (pure, from cfg) + `apply_*` (client calls) + small `_search_/_get_/_set_/_add_` API helpers.

## Known gaps / WIP (as of 2026-09)

- **Firewall is not wired in (code path only):** `resources/firewall.py` (`apply_firewall`: aliases + `floating_rules`) exists but `cli.py` never calls it — the comment at `cli.py:36` marks the intended position. The `policies` block in `structure.yaml` is **unimplemented**. **But the segmentation itself IS enforced** — the rules are configured manually in OPNsense and live; the `private_network`/`public_network` flags document that intent and drive the validator. Plan: export the manual rules and backfill code-driven rules from them. Extra routing rules (mDNS, device discovery, etc.) also live in OPNsense, unexpressed in the YAML — see NETWORK.md.
- `firewall.py` reads keys not in `structure.yaml`: `floating_rules`, `unmanaged_local_networks`, `services.hosts` (hostname→IP resolution from static leases), `local_private_networks` alias.
- Untagged `interface:` VLANs are validated and tracked (`cfg["__untagged_interfaces__"]`) but **not configured** — OPNsense lacks stable APIs for assignment/IP config (see TODO in `resources/interfaces.py`).
- **Future goals (not handled by the repo):** ACME client/certificate management (the `nammane.adystech.com` certs that terminate the HAProxy HTTPS frontend are managed manually in OPNsense today) and `udpbroadcastrelay` for cross-VLAN mDNS/SSDP — see "Future goals" in NETWORK.md.

## Constraints

- Do **not** modify `yaml2opnsense-config/` (private subrepo); read it only when the user explicitly asks (e.g., documenting the network).
- Do not invent top-level YAML keys absent from `structure.yaml`; do not reorder user YAML.
- Do not bypass the apply order in `cli.py` or the preflight check.
- Do not generate non-RFC1918 IPs or passwords unless explicitly asked.
- `.venv/` is local — never edit or search inside it.
