import sys
from cli import apply

def main():
    # Parse arguments
    args = sys.argv[1:]
    path = "nammane.arpa.yaml"
    test_iface = None
    
    i = 0
    while i < len(args):
        if args[i] == "--test":
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                test_iface = args[i + 1]
                i += 1
            else:
                print("\n --test requires interface name (e.g., --test eth0)")
                sys.exit(1)        
        elif not args[i].startswith("--"):
            path = args[i]
        i += 1
    
    # Apply configuration (with optional testing)
    apply(path, test_interface=test_iface)

if __name__ == "__main__":
    main()
