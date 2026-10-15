#!/usr/bin/env python3
"""
CSV Device Inventory Validator & Multi-Format Exporter
Validates device CSV data against network schema and exports to multiple formats.

Solves: Convert spreadsheet device inventory into structured data for automation
(Ansible, REST APIs, documentation) with built-in validation.

Input CSV: device_name, ip_address, device_type, site, os (required fields)
Output: inventory.ini, group_vars.yml, devices.json, validation report

Example CSV:
device_name,ip_address,device_type,site,os
router-dc1-01,10.0.0.1,router,dc1,ios
switch-dc1-01,10.0.1.1,switch,dc1,nxos
"""

import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict
from ipaddress import ip_address, AddressValueError


class DeviceInventoryValidator:
    """Validate and export network device CSV inventory."""
    
    DEVICE_TYPES = {'router', 'switch', 'firewall', 'load_balancer', 'wap', 'console_server'}
    MIN_IP = 0
    MAX_IP = 2**32 - 1
    
    def __init__(self, csv_file: str, output_dir: str = "."):
        self.csv_file = csv_file
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.devices = []
        self.errors = []
        self.groups = defaultdict(list)
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        try:
            ip_address(ip)
            return True
        except AddressValueError:
            return False
    
    def validate_device_type(self, dtype: str) -> bool:
        """Validate device type against known types."""
        return dtype.lower() in self.DEVICE_TYPES
    
    def read_and_validate(self) -> bool:
        """Read CSV and validate each row."""
        required = {'device_name', 'ip_address', 'device_type', 'site', 'os'}
        row_num = 0
        
        try:
            with open(self.csv_file, 'r') as f:
                reader = csv.DictReader(f)
                
                if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                    self.errors.append(f"Missing required columns: {required}")
                    return False
                
                for row in reader:
                    row_num += 1
                    
                    # Validate IP
                    if not self.validate_ip(row['ip_address']):
                        self.errors.append(f"Row {row_num}: Invalid IP '{row['ip_address']}'")
                        continue
                    
                    # Validate device type
                    if not self.validate_device_type(row['device_type']):
                        self.errors.append(
                            f"Row {row_num}: Unknown device_type '{row['device_type']}'. "
                            f"Valid: {self.DEVICE_TYPES}"
                        )
                        continue
                    
                    # Validate required non-empty fields
                    if not row['device_name'].strip():
                        self.errors.append(f"Row {row_num}: device_name cannot be empty")
                        continue
                    
                    if not row['site'].strip():
                        self.errors.append(f"Row {row_num}: site cannot be empty")
                        continue
                    
                    self.devices.append(row)
            
            return len(self.errors) == 0
        
        except FileNotFoundError:
            self.errors.append(f"File not found: {self.csv_file}")
            return False
        except csv.Error as e:
            self.errors.append(f"CSV parsing error: {e}")
            return False
    
    def organize_by_groups(self):
        """Organize devices into groups by site and device_type."""
        for device in self.devices:
            group = f"{device['site']}_{device['device_type']}"
            self.groups[group].append(device)
    
    def export_ini(self):
        """Export as Ansible inventory INI format."""
        ini_file = self.output_dir / "inventory.ini"
        with open(ini_file, 'w') as f:
            for group in sorted(self.groups.keys()):
                f.write(f"\n[{group}]\n")
                for device in self.groups[group]:
                    f.write(f"{device['device_name']} ")
                    f.write(f"ansible_host={device['ip_address']} ")
                    f.write(f"ansible_network_os={device['os']}\n")
        return str(ini_file)
    
    def export_yaml(self):
        """Export group_vars as YAML."""
        yaml_file = self.output_dir / "group_vars.yml"
        with open(yaml_file, 'w') as f:
            f.write("---\n")
            for group in sorted(self.groups.keys()):
                devices = self.groups[group]
                f.write(f"\n{group}:\n")
                f.write(f"  device_type: {devices[0]['device_type']}\n")
                f.write(f"  site: {devices[0]['site']}\n")
                f.write(f"  members:\n")
                for device in devices:
                    f.write(f"    - {device['device_name']}\n")
        return str(yaml_file)
    
    def export_json(self):
        """Export complete device data as JSON."""
        json_file = self.output_dir / "devices.json"
        data = {
            'metadata': {
                'source': self.csv_file,
                'total_devices': len(self.devices),
                'groups': list(self.groups.keys())
            },
            'devices': self.devices,
            'groups': {k: v for k, v in self.groups.items()}
        }
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)
        return str(json_file)
    
    def export_report(self):
        """Generate validation report."""
        report_file = self.output_dir / "validation_report.txt"
        with open(report_file, 'w') as f:
            f.write(f"Validation Report: {self.csv_file}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Valid Devices: {len(self.devices)}\n")
            f.write(f"Validation Errors: {len(self.errors)}\n\n")
            
            if self.errors:
                f.write("Errors:\n")
                for error in self.errors:
                    f.write(f"  • {error}\n")
            
            if self.devices:
                f.write(f"\nDevice Summary by Group:\n")
                for group in sorted(self.groups.keys()):
                    f.write(f"  {group}: {len(self.groups[group])} devices\n")
        
        return str(report_file)
    
    def process(self) -> Tuple[bool, List[str]]:
        """Process CSV: validate, organize, export."""
        if not self.read_and_validate():
            return False, self.errors
        
        self.organize_by_groups()
        outputs = [
            self.export_ini(),
            self.export_yaml(),
            self.export_json(),
            self.export_report()
        ]
        
        return True, outputs


if __name__ == "__main__":
    # Example: Create test CSV and process
    test_csv = "devices.csv"
    with open(test_csv, 'w') as f:
        f.write("device_name,ip_address,device_type,site,os\n")
        f.write("core-dc1-01,10.0.0.1,router,dc1,ios\n")
        f.write("core-dc1-02,10.0.0.2,router,dc1,ios\n")
        f.write("access-dc1-01,10.0.1.1,switch,dc1,nxos\n")
        f.write("fw-dc1-01,10.0.2.1,firewall,dc1,panos\n")
        f.write("invalid-ip,256.1.1.1,switch,dc1,nxos\n")
    
    validator = DeviceInventoryValidator(test_csv, output_dir="inventory_output")
    success, result = validator.process()
    
    if success:
        print(f"✓ Validation passed\n✓ Exported to:")
        for path in result:
            print(f"  {path}")
    else:
        print(f"✗ Validation failed with {len(result)} errors:")
        for error in result:
            print(f"  {error}")
        sys.exit(1)