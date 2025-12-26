# yaml2opnsense

`yaml2opnsense` is a declarative, model‑driven automation engine for OPNsense.  
It takes a single YAML source‑of‑truth file (e.g., `home.arpa.yaml`) and generates:

- VLANs and interface assignments  
- IPv4 addressing  
- DHCP ranges, options, and static leases  
- DNSMasq host entries  
- Firewall aliases  
- Firewall rules derived from high‑level policies  
- Service bindings (DNS, NTP, TFTP, etc.)
- FreeRADIUS users for 802.1X authentication

The goal is simple: **define your entire network in YAML, and let the engine configure OPNsense for you.**

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+
- An OPNsense instance
- API Key and Secret for your OPNsense user (see OPNsense docs on how to generate these)

### 2. Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd yaml2opnsense
    ```

2.  **Create a Python virtual environment:**
    ```bash
    python -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure API Credentials:**
    Create a `.env` file in the project root and add your OPNsense API credentials:
    ```ini
    OPNSENSE_API_KEY=your_api_key_here
    OPNSENSE_API_SECRET=your_api_secret_here
    ```

---

## ⚙️ Configuration

The entire network is defined in a single, domain-rooted YAML file. This file serves as the single source of truth for your network configuration.

**For a complete, commented guide to all available options, please see [structure.yaml](structure.yaml).**

Below is a high-level overview of the main configuration blocks.

### Key Configuration Sections

-   **`vlans`**: Define all your VLANs, including their ID, interface, CIDR, gateway, and DHCP settings. You can also control network access policies using `private_network` and `public_network` flags.
-   **`dhcp_options`**: Configure DHCP options for each VLAN. Both simple `code: value` and complex formats with descriptions are supported.
-   **`static_leases`**: Define DHCP static leases within each VLAN.
-   **`dns_forwards`**: Set up custom DNS forwarding rules, perfect for routing internal domains or integrating with local DNS resolvers like AdGuard Home. A blank domain (`""`) acts as a catch-all.
-   **`services`**: Create aliases for network services (an IP and a list of ports). These aliases can be used in firewall policies.
-   **`policies`**: Define high-level, zone-based firewall rules. The engine automatically generates the corresponding firewall rules on OPNsense based on `allow` and `deny` lists that reference other VLANs or service aliases.
-   **`free_radius_users`**: Manage MAC-based users for WPA2-Enterprise authentication. Users are automatically configured with the correct VLAN tunnel attributes.

---

## 🚀 Usage

### Basic Application
Apply your YAML configuration to OPNsense. The script will connect to the OPNsense API and apply all necessary changes idempotently.
```bash
python run.py nammane.arpa.yaml
```

### With Validation Testing
After applying the configuration, you can run a suite of network-level tests to validate that each VLAN is functioning as expected.
```bash
sudo python run.py nammane.arpa.yaml --test eth0
```
**Note:** The validation engine requires `sudo` for raw packet manipulation.

---

## 🔬 Validation Engine

The `--test` flag activates the validation engine, which performs a series of checks for each VLAN to ensure its health and compliance with the defined policies.

-   **DHCP**: Sends a DHCP discover packet on the tagged VLAN and verifies a valid offer is received.
-   **IP Range**: Ensures the assigned IP is within the configured DHCP range.
-   **Gateway**: Checks that the DHCP offer provides the correct gateway.
-   **DNS**: Tests DNS resolution using the nameservers provided by DHCP.
-   **NTP**: Verifies connectivity to the NTP server.
-   **Connectivity**:
    -   Pings the VLAN gateway.
    -   Tests `private_network` and `public_network` policies by attempting to ping an internal peer and an external IP (`8.8.8.8`).

### Interface Requirements for Validation

The validation engine relies on precise Layer-2 packet manipulation. The test interface (`eth0` in the example) **must** be connected to a trunk port that receives all tagged VLANs. For the tests to work reliably, the interface must support:

-   802.1Q VLAN tagging
-   Promiscuous mode
-   Raw packet injection (via Scapy)

If you encounter issues with the validation tests, it is often due to the network interface card (NIC) or its driver. It is highly recommended to **disable VLAN offloading** on the test interface:

```bash
# Disable RX/TX VLAN offloading
sudo ethtool -K eth0 rxvlan off txvlan off

# Enable promiscuous mode
sudo ip link set eth0 promisc on
```
This forces the NIC to pass raw, tagged frames to the OS, which is what Scapy requires to function correctly.
