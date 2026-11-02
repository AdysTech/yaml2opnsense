"""CLI entry point for yaml2opnsense configuration application."""
import sys
from cli import apply, plan

USAGE = """\
usage: run.py [plan|apply] <nammane.arpa.yaml> [--test <iface>]

commands (default: apply)
  plan    read-only: show the delta against the live box, makes zero writes
  apply   show the delta, then execute it (skips work when already in sync)

options
  -h, --help        show this help
  --test <iface>    run per-VLAN protocol tests after apply (needs sudo, trunk-port NIC)
  --auto-approve    skip the interactive "apply? [y/N]" confirmation (apply only)
"""


def main():
    """Parse arguments and plan/apply the yaml2opnsense configuration."""
    args = sys.argv[1:]

    # Optional leading command: plan | apply (default apply)
    command = "apply"
    if args and args[0] in ("plan", "apply"):
        command = args[0]
        args = args[1:]

    if args and args[0] in ("-h", "--help", "help"):
        print(USAGE)
        return

    # Parse arguments
    path = "nammane.arpa.yaml"
    test_iface = None
    auto_approve = False
    i = 0
    while i < len(args):
        if args[i] == "--test":
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                test_iface = args[i + 1]
                i += 1
            else:
                print("\n --test requires interface name (e.g., --test eth0)")
                sys.exit(1)
        elif args[i] == "--auto-approve":
            auto_approve = True
        elif args[i] in ("-h", "--help", "help"):
            print(USAGE)
            return
        elif not args[i].startswith("--"):
            path = args[i]
        i += 1

    if command == "plan":
        plan(path)
    else:
        apply(path, test_interface=test_iface, auto_approve=auto_approve)


if __name__ == "__main__":
    main()
