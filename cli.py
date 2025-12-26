# cli.py
from core.config_loader import load_config
from core.client import OpnClient
from resources.interfaces import apply_interfaces, validate_vlan_assignments
from resources.dhcp_dnsmasq import apply_dnsmasq
from resources.unbound import apply_unbound_forwards
from resources.firewall import apply_firewall
from resources.freeradius import apply_freeradius


def apply(path, test_interface=None):
    cfg = load_config(path)
    client = OpnClient(cfg)

    # Order matters
    created = apply_interfaces(cfg, client)  # VLANs, IPs

    # If we just created VLANs, exit early with a reminder
    if created:
        names = cfg.get("__created_vlans__", [])
        msg_suffix = f" Newly created VLANs: {', '.join(names)}." if names else ""
        raise SystemExit(
            "VLANs were created. Please assign each new vlan device (vlanXX) to an optX interface and set IPv4 before continuing."
            + msg_suffix
        )

    # Preflight: ensure VLANs are assigned to optX before DHCP/firewall
    missing = validate_vlan_assignments(cfg, client)
    if missing:
        raise RuntimeError(
            "Unassigned VLAN interfaces detected. Assign vlan devices to optX and set IPv4 before DHCP/firewall. "
            + "; ".join(missing)
        )

    apply_dnsmasq(cfg, client)  # static leases, DHCP config as needed
    apply_unbound_forwards(cfg, client)  # DNS forwards for VLAN zones to dnsmasq
    apply_freeradius(cfg, client)  # FreeRADIUS users (MAC/username, VLAN)
    # apply_firewall(cfg, client)     # rules based on policies

    # Run validation tests if requested
    if test_interface:
        from validator.validator import VLANValidator

        validator = VLANValidator(test_interface)

        print("\n" + "=" * 60)
        print("Running VLAN validation tests")        
        print("=" * 60)

        for vlan_name, vlan_cfg in cfg["vlans"].items():
            vlan_test_cfg = {
                "id": vlan_cfg["id"],
                "name": vlan_name,
                "cidr": vlan_cfg.get("cidr"),
                "gateway": vlan_cfg.get("gateway"),
                "dhcp": vlan_cfg.get("dhcp"),
                "dhcp_options": vlan_cfg.get("dhcp_options"),
                "private_network": vlan_cfg.get("private_network"),
                "public_network": vlan_cfg.get("public_network"),
            }
            try:
                validator.validate_vlan(vlan_test_cfg)
            except Exception as e:
                print(f"\n❌ Validation failed for VLAN {vlan_name}: {e}")

        # Print summary table
        validator.print_summary()

        print("\n" + "=" * 60)
