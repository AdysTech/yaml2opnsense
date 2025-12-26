from dataclasses import dataclass

@dataclass
class VLANTestResult:
    vlan_id: int
    vlan_name: str
    dhcp: str  # OK, DISABLED, FAIL
    dns: str   # OK, FAIL, N/A
    ntp: str   # OK, FAIL, N/A
    connectivity: str  # OK, FAIL, N/A
    details: str = ""  # Additional details/error messages
