#!/usr/bin/env python3
"""
Network Port Capacity Analyzer

Analyzes interface configurations and calculates port utilization metrics.
Helps identify bandwidth bottlenecks and plan capacity expansion.

Parses device configurations to extract interface speeds and allocated
bandwidth, then generates capacity utilization reports.

Usage:
    python 020_port_capacity_analyzer.py <config_file>

Example config format:
    interface GigabitEthernet0/0/1
    description WAN Link to ISP
    bandwidth 1000000
    ip address 10.0.0.1 255.255.255.0
    
    interface GigabitEthernet0/1/1
    description Link to Core Switch
    bandwidth 10000000
"""

import sys
import re
from pathlib import Path


class PortCapacityAnalyzer:
    """Analyzes interface capacity and bandwidth allocation."""
    
    # Common speed patterns in interface names
    SPEED_PATTERNS = {
        r'ten-?gig|10-?gig|10g': 10000,
        r'gig|1000base': 1000,
        r'fast-?eth|100base': 100,
        r'ethernet': 10,
    }
    
    def __init__(self, config_text):
        self.config = config_text
        self.interfaces = {}
        self._parse_config()
    
    def _parse_config(self):
        """Extract interface details from configuration."""
        lines = self.config.split('\n')
        current_iface = None
        
        for line in lines:
            stripped = line.strip()
            
            if not stripped or stripped.startswith('!'):
                continue
            
            # Match interface declaration
            iface_match = re.match(r'(?:interface|int)\s+(\S+)', stripped, re.I)
            if iface_match:
                current_iface = iface_match.group(1)
                self.interfaces[current_iface] = {
                    'description': '',
                    'bandwidth_kbps': 0,
                    'mtu': 1500,
                    'port_speed_mbps': self._infer_port_speed(current_iface),
                    'status': 'unknown'
                }
                continue
            
            # Parse interface configuration lines
            if current_iface:
                # Description
                desc_match = re.search(r'description\s+(.+)', stripped, re.I)
                if desc_match:
                    self.interfaces[current_iface]['description'] = desc_match.group(1)
                
                # Bandwidth (in kbps, convert to Mbps)
                bw_match = re.search(r'bandwidth\s+(\d+)', stripped, re.I)
                if bw_match:
                    kbps = int(bw_match.group(1))
                    self.interfaces[current_iface]['bandwidth_kbps'] = kbps
                
                # MTU
                mtu_match = re.search(r'mtu\s+(\d+)', stripped, re.I)
                if mtu_match:
                    self.interfaces[current_iface]['mtu'] = int(mtu_match.group(1))
                
                # Status (shutdown = down)
                if re.search(r'no\s+shutdown', stripped, re.I):
                    self.interfaces[current_iface]['status'] = 'up'
                elif re.search(r'^\s*shutdown', stripped, re.I):
                    self.interfaces[current_iface]['status'] = 'down'
    
    def _infer_port_speed(self, iface_name):
        """Infer port speed (Mbps) from interface name."""
        name_lower = iface_name.lower()
        
        for pattern, speed in self.SPEED_PATTERNS.items():
            if re.search(pattern, name_lower):
                return speed
        
        return 0
    
    def generate_report(self):
        """Generate capacity utilization report."""
        if not self.interfaces:
            return "No interfaces found in configuration."
        
        lines = [
            "Network Port Capacity Analysis",
            "=" * 80,
            ""
        ]
        
        total_capacity = 0
        total_allocated = 0
        
        # Sort interfaces by name
        for iface_name in sorted(self.interfaces.keys()):
            iface = self.interfaces[iface_name]
            port_speed = iface['port_speed_mbps']
            allocated_kbps = iface['bandwidth_kbps']
            allocated_mbps = allocated_kbps / 1000 if allocated_kbps else 0
            
            # Calculate utilization
            if port_speed > 0:
                utilization = (allocated_mbps / port_speed) * 100
                util_str = f"{utilization:6.1f}%"
            else:
                util_str = "Unknown"
            
            # Format output line
            speed_str = f"{port_speed:,}" if port_speed > 0 else "?"
            alloc_str = f"{allocated_mbps:,.0f}" if allocated_mbps > 0 else "0"
            
            lines.append(
                f"{iface_name:<20} | Speed: {speed_str:>7} Mbps | "
                f"Allocated: {alloc_str:>7} Mbps | Util: {util_str:>8}"
            )
            
            if iface['description']:
                lines.append(f"  └─ {iface['description']}")
            
            if iface['status'] != 'unknown':
                lines.append(f"  └─ Status: {iface['status']}")
            
            total_capacity += port_speed
            total_allocated += allocated_mbps
        
        # Summary
        lines.extend([
            "",
            "=" * 80,
            "Summary",
            "-" * 80
        ])
        
        if total_capacity > 0:
            overall_util = (total_allocated / total_capacity) * 100
            lines.append(f"Total Port Capacity:     {total_capacity:>10,.0f} Mbps")
            lines.append(f"Total Bandwidth Alloc:   {total_allocated:>10,.0f} Mbps")
            lines.append(f"Overall Utilization:     {overall_util:>10.1f}%")
            
            available = total_capacity - total_allocated
            lines.append(f"Available Bandwidth:     {available:>10,.0f} Mbps")
        
        return '\n'.join(lines)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    
    config_file = Path(sys.argv[1])
    
    if not config_file.exists():
        print(f"ERROR: Configuration file not found: {config_file}")
        sys.exit(1)
    
    try:
        config_text = config_file.read_text()
    except IOError as e:
        print(f"ERROR: Failed to read file: {e}")
        sys.exit(1)
    
    analyzer = PortCapacityAnalyzer(config_text)
    print(analyzer.generate_report())


if __name__ == '__main__':
    main()