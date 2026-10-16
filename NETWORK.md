# Network — `nammane.home.arpa`

High-level VLAN segmentation for the home network managed by this project.
Single source of truth: `yaml2opnsense-config/nammane.arpa.yaml` (private subrepo).
This document is the human-readable explanation of *why* the network is shaped the way it is.

---

## Physical topology

- **OPNsense** is the core router/firewall for the whole domain (`vtnetX` NICs):
  - `opt2` — **WAN** (upstream link).
  - `vtnet1` — **untagged** LAN NIC, native `192.168.23.0/24`. OPNsense itself lives here at `192.168.23.1`.
  - `vtnet2` — **802.1q trunk** carrying all tagged VLANs to the UniFi switch.
- VLAN devices are created automatically by `apply_interfaces`, but **assigning a VLAN to an `optX` slot and setting its IPv4 address is still manual** in OPNsense (no stable API). `validate_vlan_assignments` preflight-checks that this was done and aborts otherwise.
- **VLAN placement is MAC-based (802.1X):** device MACs are registered as FreeRADIUS users, each with the VLAN ID of the segment it belongs to. The RADIUS server tells the switch which VLAN to place the port in — no per-SSID or static switch config.

```
            ┌─────────────── OPNsense (192.168.23.1) ───────────────┐
  WAN opt2  │                                                       │ vtnet1 (untagged)
 ┌─────────┐ │                                                       │  LAN 192.168.23.0/24
 │upstream │ │                                                       │  Proxmox hypervisors,
 └─────────┘ │                                                       │  tiny-ubuntu, OPNsense
             │  vtnet2 (802.1q trunk) ── UniFi switch (U7 Pro / AC Pro)
             │   ├─ 20  mgmt            192.168.20.0/24
             │   ├─ 21  servers         192.168.21.0/24
             │   ├─ 30  trusted_clients 192.168.30.0/24
             │   ├─ 40  iot_local       192.168.40.0/24
             │   ├─ 45  iot_jail        192.168.45.0/24
             │   ├─ 50  iot_cloud       192.168.50.0/24
             │   └─ 60  guest           192.168.60.0/24
             └───────────────────────────────────────────────────────┘
```

---

## VLAN map

| VLAN | ID | Subnet | Gateway | DHCP pool | Internet | Private | Purpose |
|------|----|--------|---------|-----------|:--------:|:-------:|---------|
| `lan` | 10 | 192.168.23.0/24 | .1 | .10–.50 | ✅ | ✅ | Core/home LAN: Proxmox hypervisors (`proxmox-ms-01`, `proxmox-tiny`, `proxmox-proart`), `tiny-ubuntu`; home of OPNsense and the adystech.com entry point |
| `mgmt` | 20 | 192.168.20.0/24 | .1 | .50–.200 | ✅ | ✅ | Network management: UniFi switch + APs (U7 Pro, AC Pro), Proxmox mgmt NICs, `ansible`, `unifi-os-server` (alias `unifi`), `sodola` |
| `servers` | 21 | 192.168.21.0/24 | .1 | .50–.200 | ✅ | ✅ | Self-hosted services: Docker Swarm nodes (`prox-docks`, `dock-gpu`, `dock-ms-01`), `truenas`, `adguard-home`, `plex`, `jellyfin`, `homeassistant`, `tftp-server`, `zb-gw03` (Zigbee), `raspi-prusa` |
| `trusted_clients` | 30 | 192.168.30.0/24 | .1 | .50–.200 | ✅ | ✅ | Authenticated personal devices (phones, laptops, TV, watch, Ecobee) via FreeRADIUS |
| `iot_local` | 40 | 192.168.40.0/24 | .1 | .10–.100 | ❌ | ✅ | Local-only smart home: Sonoff relays, Geeni/Taloya/HS300, printers, ESP heater, Prusa Core One + filament dryer |
| `iot_jail` | 45 | 192.168.45.0/24 | .1 | .10–.50 | ❌ | ❌ | Fully isolated segment (no internet, no cross-VLAN); reserved, currently unpopulated |
| `iot_cloud` | 50 | 192.168.50.0/24 | .1 | .10–.50 | ✅ | ❌ | Cloud-connected devices: porch/backyard cams, Eufy Lock, roborock, `essential-phone` — reach their clouds, but isolated from the rest of the LAN |
| `guest` | 60 | 192.168.60.0/24 | .1 | .2–.50 | ✅ | ❌ | Guest Wi-Fi: internet only |

Access intent per VLAN (from the `private_network` / `public_network` flags):

| VLAN | → other private networks | → Internet |
|------|:---:|:---:|
| `lan`, `mgmt`, `servers`, `trusted_clients` | ✅ | ✅ |
| `iot_local` | ✅ | ❌ |
| `iot_jail` | ❌ | ❌ |
| `iot_cloud`, `guest` | ❌ | ✅ |

> **Status:** the segmentation above **is enforced** — the rules are configured
> manually in OPNsense and currently live. The flags in the YAML express *intent*
> and drive the `--test` validator; the code-driven path (`policies` in
> `structure.yaml`, `apply_firewall()` in `resources/firewall.py`) is **WIP and not
> yet wired into `cli.py`**. Plan is to export the manual rules and backfill
> code-driven rules from them. Note also that additional routing rules (mDNS,
> device discovery, etc.) are configured in OPNsense and not fully expressed in
> this document or the YAML.

---

## Authentication & VLAN placement

- `free_radius_users` registers MAC-based users in OPNsense's FreeRADIUS server;
  the VLAN ID is derived from `vlans.<vlan_name>.id`.
- Currently registered populations: `trusted_clients` (personal devices),
  `iot_local` (smart home), `iot_cloud` (cloud IoT).
- Per-client differentiation within a VLAN uses **DHCP tags** (e.g. the
  `WgWindClient` tag on `ubuntu-22` forces Windscribe DNS `10.255.255.3` via a
  tagged option 6 with `force: true`).

## DHCP & DNS design

- **DHCP** is served by dnsmasq on OPNsense per-VLAN:
  - Static leases for all servers/devices (matched by MAC), with optional bare
    `aliases` that are auto-suffixed with the domain (`unifi` → `unifi.nammane.home.arpa`).
  - Options: `42: gateway` (NTP) expands to each VLAN's own gateway; `66` points
    `servers` VLAN at the TFTP server (`.6`) for PXE; client VLANs get option 6
    (DNS) = **AdGuard Home** `192.168.21.10`.
- **DNS** split-brain by design:
  - **Unbound** on OPNsense is the primary resolver. It forwards the whole
    `nammane.home.arpa` zone and every per-VLAN reverse zone to dnsmasq at
    `127.0.0.1:53053` (auto-generated by `apply_unbound`), plus any custom
    `dns_forwards`.
  - **dnsmasq** owns static leases, aliases and reverse (PTR) records.
  - **AdGuard Home** (`192.168.21.10`) is the client-facing sinkhole/filter
    resolver for all client VLANs.
- **Host overrides** (Unbound A-records) pin internal names: `nammane.adys` (MQTT,
  Tasmota), `*.docker` and `*.nammane.adystech.com` → HAProxy VIP `192.168.21.1`,
  Proxmox hostnames → `lan` VLAN IPs.

## Ingress chain — HAProxy → Traefik → services

All web/MQTT ingress to the self-hosted stack funnels through OPNsense's
HAProxy, which spreads it across the Docker Swarm nodes; **Traefik ingress runs
on every Swarm node** and routes to the actual service containers, discovered
via Swarm labels. Because Traefik is present on all nodes, HAProxy never needs
to know *where* a service is — it only needs a healthy node, and Traefik on
that node completes the route. This makes container placement and node
membership irrelevant to clients.

```
 client (any allowed VLAN)
   │  DNS: host overrides pin *.nammane.adystech.com / *.docker → 192.168.21.1
   ▼
 HAProxy on OPNsense — VIP 192.168.21.1 (the servers gateway)
   │  frontends:  http:80 · https:443 (SNI *.nammane) · mqtt:1883 · mqtt-ws:9001
   │  health: HEAD /ping on port 8081 (Traefik ping endpoint), 5s
   ▼
 Docker Swarm nodes (backend pools, all on :80 / :1883 / :9001)
   │  prox-docks  192.168.21.7
   │  dock-gpu    192.168.21.14
   │  dock-ms-01  192.168.21.15
   ▼
 Traefik (on every node) — routes to service containers by Swarm labels
   ▼
 service containers, wherever the scheduler put them
```

- **TLS** is terminated at the HAProxy frontend (cert `nammane.adystech.com`,
  SNI `*.nammane`); upstream to nodes is plain HTTP (`X-Forwarded-Proto`/`-Port`
  set explicitly). The certificate is issued/renewed by OPNsense's **ACME
  client** (two enabled entries: `*.adystech.com`, and `nammane.adystech.com`
  with SAN `*.nammane.adystech.com`) — this repo does **not** manage ACME yet.
- **Balance:** `leastconn` for the HTTP/HTTPS backends; `roundrobin` for MQTT
  and WebSocket. `Upgrade`/`Connection` headers are passed through so
  WebSocket upgrades work.
- **Long-lived connections:** MQTT/WebSocket tunnels get `timeout_tunnel: 1h`
  (MQTT clients hold `timeout_client: 4h`) — HTTP gets 300s.
- **Failover:** a node failing the `/ping:8081` check is dropped from the pool;
  the rest keep serving — the client just lands on another node's Traefik.
- Stats on `/haproxy_stats`; server names come from static leases, resolved by
  `resources/haproxy.py` at apply time.

## Other routing facts

- `unmanaged_local_networks: [192.168.23.0/24]` — feeds the `local_private_networks`
  firewall alias so rules can treat the LAN as a private destination set.
- Cross-VLAN discovery (mDNS `224.0.0.251:5353`, SSDP `239.255.255.250:1900`,
  WS-Discovery `3702`) is relayed **today by manual OPNsense routing rules**. The
  YAML TODO is to automate this with **`udpbroadcastrelay`** — the
  `SSDP_Broadcast` / `mDNS_Broadcast` / `discovery` service aliases are defined
  for that purpose, but no code exists for it yet.

## Future goals (not handled by the repo today)

1. **Firewall rules codification** — export the manually created, live
   OPNsense rules and turn them into the code-driven path: the `policies` block
   in `structure.yaml` plus `apply_firewall()` in `resources/firewall.py`
   (wired into `cli.py`).
2. **ACME client management** — declaratively manage OPNsense's ACME
   certificates (`*.adystech.com`, `nammane.adystech.com` + SAN
   `*.nammane.adystech.com`) that terminate the HAProxy HTTPS frontend.
3. **`udpbroadcastrelay`** — automate cross-VLAN mDNS/SSDP/WS-Discovery
   relaying (see above).
