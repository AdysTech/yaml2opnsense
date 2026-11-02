"""CLI entry point for applying YAML configuration to OPNsense."""
import sys

from validator.validator import VLANValidator

from core.config_loader import load_config
from core.client import OpnClient
from core.plan import RecordingClient, render_plan, has_mutations
from resources.interfaces import apply_interfaces, validate_vlan_assignments
from resources.dhcp_dnsmasq import apply_dnsmasq
from resources.unbound import apply_unbound
from resources.freeradius import apply_freeradius
from resources.haproxy import apply_haproxy
from resources.firewall import apply_aliases


def _run_pipeline(cfg, client):
    """Run the apply pipeline in dependency order against `client`.

    Returns the preflight block messages (empty list when not blocked).
    Works for a real OpnClient (apply) and a RecordingClient (plan/preview).
    """
    # Order matters
    apply_interfaces(cfg, client)  # VLANs, IPs

    # Preflight: ensure VLANs are assigned to optX before DHCP/firewall
    missing_assignments = validate_vlan_assignments(cfg, client)
    if missing_assignments:
        return missing_assignments

    apply_dnsmasq(cfg, client)  # static leases, DHCP config as needed
    apply_unbound(cfg, client)  # DNS forwards and host overrides
    apply_freeradius(cfg, client)  # FreeRADIUS users (MAC/username, VLAN) + clients (APs)
    apply_haproxy(cfg, client)      # HAProxy load balancer configuration
    apply_aliases(cfg, client)      # firewall aliases (add/update + mark only)
    # then apply_firewall rules (chunk 04 — filter rules based on the policies block)
    return []


def plan(path):
    """Read-only: show the delta between the YAML and the live box."""
    cfg = load_config(path)
    client = OpnClient(cfg)
    recorder = RecordingClient(client)

    print(f"Planning {path} against {client.base} (read-only) ...")
    blocked = _run_pipeline(cfg, recorder)
    print(render_plan(recorder.actions))

    if blocked:
        print("\nBLOCKED by preflight — no changes were made:")
        for message in blocked:
            print(f"  - {message}")
        print("Assign the VLANs to optX (with IPv4) in OPNsense, then re-run.")


def _confirm(message: str, auto_approve: bool) -> bool:
    """Prompt for interactive confirmation before mutating the box.

    Returns True to proceed. With `auto_approve` set, no prompt is shown.
    A non-interactive (non-TTY) stdin is treated as a refusal unless
    `auto_approve` was requested, so the box is never mutated by accident.
    """
    if auto_approve:
        return True
    if not sys.stdin.isatty():
        print("\nNot a terminal and --auto-approve was not given — nothing was applied.")
        print("Re-run with --auto-approve to skip this confirmation.")
        return False
    print()
    answer = input(message).strip().lower()
    return answer in ("y", "yes")


def apply(path, test_interface=None, auto_approve=False):
    """Apply configuration from a YAML file to an OPNsense instance.

    Runs a read-only preview pass first, prints the delta, and — unless
    `auto_approve` is set — asks for explicit confirmation before writing.
    """
    cfg = load_config(path)
    client = OpnClient(cfg)

    # Preview pass: compute the same delta apply would execute, without writing
    recorder = RecordingClient(client)
    blocked = _run_pipeline(cfg, recorder)
    print(render_plan(recorder.actions))

    if blocked:
        unassigned_vlan_msg = (
            "Unassigned VLAN interfaces detected. "
            "Assign vlan devices to optX and set IPv4 before DHCP/firewall. "
        )
        raise RuntimeError(unassigned_vlan_msg + "; ".join(blocked))

    if not has_mutations(recorder.actions):
        print("No changes to apply — the live configuration already matches the YAML.")
        return

    if not _confirm("Apply these changes? [y/N]: ", auto_approve):
        print("Aborted — no changes were applied.")
        return

    _run_pipeline(cfg, client)

    # Run validation tests if requested
    if test_interface:
        validator = VLANValidator(test_interface)

        print("\n" + "=" * 60)
        print("Running VLAN validation tests")
        print("=" * 60)

        # Get connectivity tests config
        connectivity_tests = cfg.get("connectivity_tests", {})

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
                "connectivity_tests": connectivity_tests,
            }
            try:
                validator.validate_vlan(vlan_test_cfg)
            except Exception as e:
                print(f"\n❌ Validation failed for VLAN {vlan_name}: {e}")

        # Print summary table
        validator.print_summary()

        print("\n" + "=" * 60)
