```python
#!/usr/bin/env python3
"""
Interface Flap Detector - Identify and report interface state transitions from logs
Parses device logs for interface up/down events and identifies flapping interfaces.
Useful for troubleshooting intermittent connectivity issues and detecting hardware problems.
"""

import re
from datetime import datetime
from typing import Dict, List
from collections import defaultdict

def parse_syslog_lines(log_lines: List[str]) -> List[Dict]:
    """
    Parse syslog entries for interface state changes.
    Supports Cisco, Juniper, and Arista log formats.
    
    Args:
        log_lines: List of raw syslog lines
        
    Returns:
        List of dicts with interface, state, and timestamp
    """
    events = []
    
    # Pattern matching for different vendors
    patterns = [
        # Cisco: %LINK-3-UPDOWN: Interface GigabitEthernet0/0/0, changed state to up
        (r'Interface\s+(\S+),\s+changed state to\s+(\w+)', 'cisco'),
        # Juniper/Arista: iface ge-0/0/0 transitioned to up
        (r'iface\s+(\S+)\s+transitioned to\s+(\w+)', 'juniper'),
        # Generic: interface=eth0 state=up
        (r'interface=(\S+)\s+state=(\w+)', 'generic'),
    ]
    
    for line in log_lines:
        for pattern, vendor in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                groups = match.groups()
                timestamp = extract_timestamp(line) or datetime.now()
                events.append({
                    'interface': groups[0],
                    'state': groups[1].lower(),
                    'timestamp': timestamp,
                    'vendor': vendor,
                    'raw': line,
                })
                break
    
    return events

def extract_timestamp(log_line: str) -> datetime:
    """Extract timestamp from log line using common formats."""
    patterns = [
        (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', '%Y-%m-%dT%H:%M:%S'),
        (r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
    ]
    for pattern, fmt in patterns:
        match = re.search(pattern, log_line)
        if match:
            try:
                return datetime.strptime(match.group(1), fmt)
            except ValueError:
                pass
    return None

def detect_flaps(events: List[Dict], threshold_sec: int = 60) -> Dict[str, List]:
    """
    Detect interfaces that flap (rapid state changes).
    
    Args:
        events: Parsed log events from parse_syslog_lines()
        threshold_sec: Time window for detecting flaps (default 60 seconds)
        
    Returns:
        Dict mapping interface name to list of flap events with timing
    """
    flaps = defaultdict(list)
    
    # Group events by interface
    iface_events = defaultdict(list)
    for event in events:
        iface_events[event['interface']].append(event)
    
    # Detect flaps: state changes within threshold
    for iface, events_list in iface_events.items():
        sorted_events = sorted(events_list, key=lambda e: e['timestamp'])
        
        for i in range(len(sorted_events) - 1):
            current = sorted_events[i]
            next_event = sorted_events[i + 1]
            
            time_diff = (next_event['timestamp'] - current['timestamp']).total_seconds()
            
            # Record flap if state changed within threshold
            if time_diff <= threshold_sec and current['state'] != next_event['state']:
                flaps[iface].append({
                    'down_time': current['timestamp'],
                    'up_time': next_event['timestamp'],
                    'duration_sec': time_diff,
                })
    
    return flaps

def analyze_flaps(flaps: Dict[str, List]) -> Dict:
    """Generate statistics and severity assessment of flapping."""
    stats = {
        'interfaces_flapping': len(flaps),
        'total_flaps': sum(len(f) for f in flaps.values()),
        'worst_interface': None,
        'worst_count': 0,
        'average_flap_duration': 0.0,
    }
    
    total_duration = 0
    total_flap_count = 0
    
    for iface, flap_list in flaps.items():
        if len(flap_list) > stats['worst_count']:
            stats['worst_count'] = len(flap_list)
            stats['worst_interface'] = iface
        
        for flap in flap_list:
            total_duration += flap['duration_sec']
            total_flap_count += 1
    
    if total_flap_count > 0:
        stats['average_flap_duration'] = round(total_duration / total_flap_count, 2)
    
    return stats

def generate_report(flaps: Dict[str, List], stats: Dict, output_file: str = None) -> str:
    """
    Generate formatted flap detection report.
    
    Args:
        flaps: Output from detect_flaps()
        stats: Output from analyze_flaps()
        output_file: Optional filename to write report (else prints to stdout)
        
    Returns:
        Formatted report string
    """
    lines = [
        "=" * 70,
        "INTERFACE FLAP DETECTION REPORT",
        "=" * 70,
        f"Interfaces Flapping: {stats['interfaces_flapping']}",
        f"Total Flap Events: {stats['total_flaps']}",
        f"Worst Interface: {stats['worst_interface']} ({stats['worst_count']} flaps)",
        f"Average Flap Duration: {stats['average_flap_duration']}s",
        "",
        "DETAILED FLAP LOG:",
        "-" * 70,
    ]
    
    for iface, flap_list in sorted(flaps.items()):
        lines.append(f"\n{iface}: {len(flap_list)} flaps")
        for i, flap in enumerate(flap_list, 1):
            lines.append(
                f"  #{i}: DOWN {flap['down_time']} → UP {flap['up_time']} "
                f"({flap['duration_sec']}s downtime)"
            )
    
    lines.append("\n" + "=" * 70)
    report_text = "\n".join(lines)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report_text)
    
    return report_text

if __name__ == "__main__":
    # Example syslog data with interface flaps
    sample_logs = [
        "2026-01-20 12:30:00 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to down",
        "2026-01-20 12:30:15 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to up",
        "2026-01-20 12:30:30 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to down",
        "2026-01-20 12:30:45 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to up",
        "2026-01-20 12:31:00 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
        "2026-01-20 12:31:30 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up",
        "2026-01-20 12:32:00 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to up",
    ]
    
    print("Analyzing interface flaps from syslog...\n")
    
    events = parse_syslog_lines(sample_logs)
    print(f"Parsed {len(events)} interface state events\n")
    
    flaps = detect_flaps(events, threshold_sec=60)
    stats = analyze_flaps(flaps)
    
    report = generate_report(flaps, stats)
    print(report)
    
    # Save report to file: generate_report(flaps, stats, "flap_report.txt")
```