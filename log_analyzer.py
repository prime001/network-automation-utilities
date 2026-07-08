#!/usr/bin/env python3
"""
Interface Flap and Error Analyzer
Analyzes network device interface logs to detect flaps, errors, and trends.

Real-world use case: Network operators need to quickly identify problematic
interfaces from syslog or device logs. This tool parses log data, detects
interface state changes (flaps), counts errors, and generates a summary
report to help troubleshoot connectivity issues.

Example log formats:
  Oct 10 10:15:22 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0/1, changed state to up
  Oct 10 10:15:25 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0/1, changed state to down
  Oct 10 10:20:01 router1 %INTF-4-ERRORS: Interface GigabitEthernet0/0/2 CRC errors
"""

import re
from collections import defaultdict
from typing import Dict, List, Tuple


class InterfaceLogAnalyzer:
    """Parses interface logs and detects flaps, errors, and state transitions."""

    # Common interface log patterns (Cisco IOS/IOS-XE format)
    PATTERNS = {
        'flap': re.compile(
            r'(?:LINK|LINEPROTO).*Interface\s+(\S+),?\s+changed state to\s+(\w+)',
            re.IGNORECASE
        ),
        'error': re.compile(
            r'(?:INTF|ERR|CRC|RUNTS|OVERRUN).*?(\S+)\s+(?:CRC|errors?|overrun|runts)',
            re.IGNORECASE
        ),
    }

    def __init__(self):
        """Initialize analyzer with empty state tracking."""
        self.flaps = defaultdict(list)  # interface -> [(timestamp, state)]
        self.errors = defaultdict(int)  # interface -> error_count
        self.interfaces = set()

    def parse_log_line(self, line: str) -> None:
        """Parse a single log line and extract interface events."""
        timestamp = self._extract_timestamp(line)
        
        # Check for flap events (state changes)
        match = self.PATTERNS['flap'].search(line)
        if match:
            interface, state = match.groups()
            self.interfaces.add(interface)
            self.flaps[interface].append((timestamp, state.lower()))
            return

        # Check for error events
        match = self.PATTERNS['error'].search(line)
        if match:
            interface = match.group(1)
            self.interfaces.add(interface)
            self.errors[interface] += 1

    def _extract_timestamp(self, line: str) -> str:
        """Extract timestamp from log line."""
        match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
        return match.group(1) if match else 'unknown'

    def detect_flaps(self, min_flaps: int = 2) -> Dict[str, List[Tuple[str, str]]]:
        """Identify interfaces with more than min_flaps state changes.
        
        Args:
            min_flaps: Minimum number of state changes to flag as problematic
            
        Returns:
            Dict mapping interface name to list of (timestamp, state) tuples
        """
        problematic = {}
        for iface, transitions in self.flaps.items():
            if len(transitions) >= min_flaps:
                problematic[iface] = transitions
        return problematic

    def get_error_summary(self) -> List[Tuple[str, int]]:
        """Return interfaces with errors, sorted by error count (descending)."""
        return sorted(self.errors.items(), key=lambda x: x[1], reverse=True)

    def generate_report(self) -> str:
        """Generate a human-readable analysis report."""
        report = []
        report.append("=" * 60)
        report.append("INTERFACE LOG ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"\nTotal interfaces seen: {len(self.interfaces)}")
        
        # Flap analysis
        flappy = self.detect_flaps(min_flaps=2)
        if flappy:
            report.append(f"\n[CRITICAL] Flapping Interfaces ({len(flappy)}):")
            for iface in sorted(flappy.keys()):
                transitions = flappy[iface]
                report.append(f"  {iface}: {len(transitions)} state changes")
                for ts, state in transitions[:3]:
                    report.append(f"    {ts} -> {state}")
                if len(transitions) > 3:
                    report.append(f"    ... and {len(transitions) - 3} more")
        else:
            report.append("\n[OK] No flapping interfaces detected")

        # Error analysis
        error_summary = self.get_error_summary()
        if error_summary:
            report.append(f"\n[WARNING] Interfaces with Errors ({len(error_summary)}):")
            for iface, count in error_summary[:10]:
                report.append(f"  {iface}: {count} errors")
        else:
            report.append("\n[OK] No errors detected")

        # Recommendations
        report.append("\n" + "-" * 60)
        report.append("REMEDIATION:")
        if flappy:
            report.append("• Check physical connections (cables, transceivers)")
            report.append("• Verify interface configuration (MTU, speed, duplex)")
            report.append("• Review for SFP/cable issues or incompatibilities")
        if error_summary:
            report.append("• Replace defective cables on high-error interfaces")
            report.append("• Verify interface config matches both link ends")
            report.append("• Check for signal issues on long-distance links")

        report.append("\n" + "=" * 60)
        return "\n".join(report)


def main():
    """Example: Process sample logs and generate report."""
    
    sample_logs = [
        "Oct 10 10:15:22 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0/1, changed state to up",
        "Oct 10 10:15:25 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0/1, changed state to down",
        "Oct 10 10:15:28 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0/1, changed state to up",
        "Oct 10 10:16:15 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0/1, changed state to down",
        "Oct 10 10:20:01 router1 %INTF-4-ERRORS: Interface GigabitEthernet0/0/2 CRC errors increased",
        "Oct 10 10:20:05 router1 %INTF-4-ERRORS: Interface GigabitEthernet0/0/2 overrun errors",
        "Oct 10 10:22:10 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0/3, changed state to up",
        "Oct 10 10:30:00 router1 %INTF-4-ERRORS: Interface GigabitEthernet0/0/2 CRC errors increased",
    ]

    analyzer = InterfaceLogAnalyzer()
    for log_line in sample_logs:
        analyzer.parse_log_line(log_line)

    print(analyzer.generate_report())

    flappy = analyzer.detect_flaps(min_flaps=2)
    if flappy:
        print("\nFlappy interfaces for alerting:")
        for iface in sorted(flappy.keys()):
            print(f"  {iface}")


if __name__ == "__main__":
    main()