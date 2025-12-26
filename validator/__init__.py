"""
Validator package for testing OPNsense VLAN configurations.

Provides network-level validation of DHCP, DNS, NTP, and connectivity
after configuration is applied.
"""

from .validator import VLANValidator

__all__ = ['VLANValidator']
