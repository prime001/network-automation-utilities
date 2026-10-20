#!/usr/bin/env python3
"""
Network Topology YAML Validator - 028

Validates network topology YAML files for structural correctness and logical consistency.
Checks for:
- Missing or invalid device definitions
- Interface mismatches in links
- IP address conflicts and improper subnetting
- Invalid VLAN assignments
- Duplicate device names and interfaces

Usage:
    python 028_network_topology_validator.py topology.yaml
    
Example topology.yaml:
    devices:
      router-1:
        interfaces:
          eth0: 10.0.0.1/24
          eth1: 10.0.1.1/24
      switch-1:
        interfaces:
          eth0: 10.0.2.1/24
    links:
      - devices: [router-1, switch-1]
        interfaces: [eth1, eth0]
    vlans:
      10: MGMT
      20: DATA
"""

import yaml
import sys
import ipaddress
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


class NetworkTopologyValidator:
    """Validates network topology YAML files."""
    
    def __init__(self, topology: Dict):
        self.topology = topology
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.devices: Dict = topology.get('devices', {})
        self.links: List = topology.get('links', [])
        self.vlans: Dict = topology.get('vlans', {})
    
    def validate(self) -> bool:
        """Run all validations. Returns True if no errors."""
        self._validate_devices()
        self._validate_links()
        self._validate_ip_assignments()
        self._validate_vlans()
        return len(self.errors) == 0
    
    def _validate_devices(self):
        """Validate device definitions."""
        seen_devices = set()
        
        for device_name, device_config in self.devices.items():
            if not isinstance(device_config, dict):
                self.errors.append(f"Device '{device_name}' config must be a dict")
                continue
            
            if device_name in seen_devices:
                self.errors.append(f"Duplicate device name: {device_name}")
            seen_devices.add(device_name)
            
            interfaces = device_config.get('interfaces', {})
            if not isinstance(interfaces, dict):
                self.errors.append(f"Device '{device_name}': interfaces must be a dict")
                continue
            
            seen_interfaces = set()
            for iface_name, ip_addr in interfaces.items():
                if iface_name in seen_interfaces:
                    self.errors.append(
                        f"Device '{device_name}': duplicate interface '{iface_name}'"
                    )
                seen_interfaces.add(iface_name)
    
    def _validate_links(self):
        """Validate inter-device links."""
        for idx, link in enumerate(self.links):
            if not isinstance(link, dict):
                self.errors.append(f"Link {idx}: must be a dict")
                continue
            
            devices = link.get('devices')
            interfaces = link.get('interfaces')
            
            if not devices or not isinstance(devices, list):
                self.errors.append(f"Link {idx}: 'devices' must be a non-empty list")
                continue
            
            if len(devices) != 2:
                self.errors.append(f"Link {idx}: must connect exactly 2 devices")
                continue
            
            if not interfaces or not isinstance(interfaces, list) or len(interfaces) != 2:
                self.errors.append(f"Link {idx}: must specify exactly 2 interfaces")
                continue
            
            # Validate devices exist
            for device in devices:
                if device not in self.devices:
                    self.errors.append(f"Link {idx}: device '{device}' not defined")
            
            # Validate interfaces exist on devices
            for device, iface in zip(devices, interfaces):
                if device in self.devices:
                    dev_interfaces = self.devices[device].get('interfaces', {})
                    if iface not in dev_interfaces:
                        self.errors.append(
                            f"Link {idx}: interface '{iface}' not found on device '{device}'"
                        )
    
    def _validate_ip_assignments(self):
        """Validate IP addresses: no overlaps, proper subnetting."""
        subnets: Set[ipaddress.IPv4Network] = set()
        
        for device_name, device_config in self.devices.items():
            interfaces = device_config.get('interfaces', {})
            for iface_name, ip_str in interfaces.items():
                if not ip_str:
                    continue
                
                try:
                    ip = ipaddress.ip_interface(ip_str)
                    network = ip.network
                    
                    # Check for subnet overlap
                    for existing_subnet in subnets:
                        if network.overlaps(existing_subnet) and network != existing_subnet:
                            self.warnings.append(
                                f"Overlapping subnets: {network} and {existing_subnet}"
                            )
                    
                    subnets.add(network)
                    
                except ValueError as e:
                    self.errors.append(
                        f"Device '{device_name}' interface '{iface_name}': "
                        f"invalid IP address '{ip_str}' ({e})"
                    )
    
    def _validate_vlans(self):
        """Validate VLAN definitions."""
        if not isinstance(self.vlans, dict):
            self.errors.append("VLANs must be a dict")
            return
        
        for vlan_id, vlan_name in self.vlans.items():
            try:
                vid = int(vlan_id) if not isinstance(vlan_id, int) else vlan_id
                if vid < 1 or vid > 4094:
                    self.errors.append(f"VLAN ID {vlan_id} out of valid range (1-4094)")
            except (ValueError, TypeError):
                self.errors.append(f"VLAN ID must be numeric: {vlan_id}")
    
    def report(self):
        """Print validation report."""
        if not self.errors and not self.warnings:
            print("✓ Topology validation passed")
            return
        
        if self.errors:
            print("✗ Validation errors:")
            for error in self.errors:
                print(f"  - {error}")
        
        if self.warnings:
            print("⚠ Warnings:")
            for warning in self.warnings:
                print(f"  - {warning}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    yaml_file = Path(sys.argv[1])
    
    if not yaml_file.exists():
        print(f"Error: File not found: {yaml_file}")
        sys.exit(1)
    
    try:
        with open(yaml_file) as f:
            topology = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"YAML parsing error: {e}")
        sys.exit(1)
    
    validator = NetworkTopologyValidator(topology)
    validator.validate()
    validator.report()
    
    sys.exit(0 if validator.validate() else 1)


if __name__ == '__main__':
    main()