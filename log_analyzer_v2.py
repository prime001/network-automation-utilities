#!/usr/bin/env python3
"""
Interface Status Analyzer - Detects flapping interfaces and calculates downtime.

Solves: Network engineers need to quickly identify problematic interfaces
that are flapping (going up/down repeatedly) or have been down for extended
periods, which indicates hardware failures or configuration issues.

Usage:
    analyzer = InterfaceAnalyzer(flap_threshold=3)
    analyzer.analyze_file('interface_logs.txt')
    print(analyzer.generate_report())
    flapping = analyzer.detect_flapping()
"""

import re
from datetime import datetime
from collections import defaultdict
from typing import Dict, Tuple


class InterfaceAnalyzer:
    """Analyze interface status logs to detect flapping and downtime."""
    
    def __init__(self, flap_threshold: int = 3):
        """
        Initialize analyzer.
        
        Args:
            flap_threshold: Number of state changes to flag as flapping
        """
        self.flap_threshold = flap_threshold
        self.interface_events = defaultdict(list)
    
    def parse_log_line(self, line: str) -> Dict:
        """
        Parse interface status log line.
        
        Expected format: YYYY-MM-DD HH:MM:SS Interface <name> <UP|DOWN>
        Example: 2026-05-20 14:30:45 Interface GigabitEthernet0/0 UP
        """
        pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+Interface\s+(\S+)\s+(UP|DOWN)'
        match = re.match(pattern, line, re.IGNORECASE)
        
        if match:
            timestamp_str, interface, state = match.groups()
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                return {
                    'timestamp': timestamp,
                    'interface': interface,
                    'state': state.upper()
                }
            except ValueError:
                pass
        return None
    
    def analyze_file(self, filename: str) -> None:
        """Parse interface log file."""
        try:
            with open(filename, 'r') as f:
                for line in f:
                    event = self.parse_log_line(line.strip())
                    if event:
                        self.interface_events[event['interface']].append(event)
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found")
    
    def detect_flapping(self) -> Dict[str, int]:
        """Detect interfaces with excessive state changes."""
        flapping = {}
        for interface, events in self.interface_events.items():
            if len(events) >= self.flap_threshold:
                flapping[interface] = len(events)
        return flapping
    
    def calculate_downtime(self, interface: str) -> Tuple[int, str]:
        """
        Calculate total downtime for an interface.
        
        Returns:
            Tuple of (total_seconds, formatted_string)
        """
        events = sorted(
            self.interface_events.get(interface, []),
            key=lambda x: x['timestamp']
        )
        total_down_seconds = 0
        last_down_time = None
        
        for event in events:
            if event['state'] == 'DOWN':
                last_down_time = event['timestamp']
            elif event['state'] == 'UP' and last_down_time:
                duration = (event['timestamp'] - last_down_time).total_seconds()
                total_down_seconds += int(duration)
                last_down_time = None
        
        hours = total_down_seconds // 3600
        minutes = (total_down_seconds % 3600) // 60
        seconds = total_down_seconds % 60
        formatted = f"{hours}h {minutes}m {seconds}s"
        
        return total_down_seconds, formatted
    
    def get_current_state(self, interface: str) -> str:
        """Get most recent state for an interface."""
        events = self.interface_events.get(interface, [])
        if events:
            return sorted(events, key=lambda x: x['timestamp'])[-1]['state']
        return 'UNKNOWN'
    
    def generate_report(self) -> str:
        """Generate comprehensive analysis report."""
        report = []
        report.append("=" * 70)
        report.append("INTERFACE STATUS ANALYSIS REPORT")
        report.append("=" * 70)
        
        if not self.interface_events:
            report.append("No interface events found.")
            return "\n".join(report)
        
        report.append(f"\nTotal interfaces: {len(self.interface_events)}\n")
        
        flapping = self.detect_flapping()
        report.append(f"FLAPPING INTERFACES (>{self.flap_threshold} changes):")
        report.append("-" * 70)
        if flapping:
            for iface in sorted(flapping.keys(), key=lambda x: flapping[x], reverse=True):
                current = self.get_current_state(iface)
                report.append(f"  {iface:25} {flapping[iface]:3} changes  [{current}]")
        else:
            report.append("  None detected")
        
        report.append("\nDOWNTIME SUMMARY:")
        report.append("-" * 70)
        down_list = []
        for iface in sorted(self.interface_events.keys()):
            total_sec, formatted = self.calculate_downtime(iface)
            if total_sec > 0:
                current = self.get_current_state(iface)
                down_list.append((iface, total_sec, formatted, current))
        
        if down_list:
            for iface, total_sec, formatted, current in sorted(
                down_list, key=lambda x: x[1], reverse=True
            ):
                report.append(f"  {iface:25} {formatted:20} [{current}]")
        else:
            report.append("  No downtime recorded")
        
        return "\n".join(report)


if __name__ == "__main__":
    sample_logs = """2026-05-20 10:00:00 Interface GigabitEthernet0/0 UP
2026-05-20 10:15:00 Interface GigabitEthernet0/0 DOWN
2026-05-20 10:16:00 Interface GigabitEthernet0/0 UP
2026-05-20 10:30:00 Interface GigabitEthernet0/0 DOWN
2026-05-20 10:31:00 Interface GigabitEthernet0/0 UP
2026-05-20 10:45:00 Interface GigabitEthernet0/0 DOWN
2026-05-20 11:00:00 Interface GigabitEthernet0/0 UP
2026-05-20 10:00:00 Interface GigabitEthernet0/1 UP
2026-05-20 11:30:00 Interface GigabitEthernet0/1 DOWN
2026-05-20 12:30:00 Interface GigabitEthernet0/1 UP
2026-05-20 10:00:00 Interface FastEthernet1/0 UP"""
    
    with open('/tmp/interface_status.log', 'w') as f:
        f.write(sample_logs)
    
    analyzer = InterfaceAnalyzer(flap_threshold=3)
    analyzer.analyze_file('/tmp/interface_status.log')
    print(analyzer.generate_report())
    
    print("\nFlapping interfaces:", analyzer.detect_flapping())
    print("\nGigabitEthernet0/0 downtime:", analyzer.calculate_downtime('GigabitEthernet0/0'))