The user wants me to output the file content directly as text (no markdown fences) — this is for the NetAutoCommitter generator to capture. Let me output it as plain text:

#!/usr/bin/env python3
"""
030_vlan_checker.py - VLAN Consistency Checker

Parses VLAN configuration blocks from multiple switch outputs and flags
inconsistencies across the fleet: missing VLANs, name mismatches, and
VLANs confined to only one device (likely a misconfiguration).

Real-world use case: Before deploying a new VLAN or troubleshooting
inter-switch connectivity, verify all devices share the expected VLAN
database with consistent naming.

Supported input formats:
  - Cisco IOS 'show vlan brief' output
  - Cisco IOS running-config vlan stanzas

Usage:
    python 030_vlan_checker.py                  # built-in demo
    python 030_vlan_checker.py sw1.txt sw2.txt  # real switch outputs

Exit code: 0 if consistent, 1 if issues found (suitable for CI/CD checks).
"""

import re
import sys
from collections import defaultdict
from pathlib import Path


def parse_vlan_brief(text: str) -> dict:
    """
    Parse 'show vlan brief' output into {vlan_id: name}.
    Expected line format: '10   Management   active    Gi0/1, Gi0/2'
    """
    vlans = {}
    for line in text.splitlines():
        m = re.match(r'^\s*(\d{1,4})\s+([\w\-\.]+)\s+active', line)
        if m:
            vid = int(m.group(1))
            if 1 <= vid <= 4094:
                vlans[vid] = m.group(2)
    return vlans


def parse_running_config(text: str) -> dict:
    """
    Parse running-config vlan stanzas into {vlan_id: name}.

    Handles:
      vlan 10
       name Management
    """
    vlans = {}
    current_vlan = None
    for line in text.splitlines():
        vlan_start = re.match(r'^vlan (\d{1,4})\s*$', line.strip())
        if vlan_start:
            current_vlan = int(vlan_start.group(1))
            vlans[current_vlan] = f'VLAN{current_vlan:04d}'
        elif current_vlan is not None:
            name_match = re.match(r'^\s+name\s+(\S+)', line)
            if name_match:
                vlans[current_vlan] = name_match.group(1)
            elif line and not line.startswith(' '):
                current_vlan = None
    return vlans


def detect_format(text: str) -> str:
    if re.search(r'VLAN\s+Name\s+Status', text):
        return 'brief'
    if re.search(r'^vlan \d+', text, re.MULTILINE):
        return 'running'
    return 'brief'


def parse_device_vlans(text: str) -> dict:
    if detect_format(text) == 'running':
        return parse_running_config(text)
    return parse_vlan_brief(text)


def check_consistency(devices: dict) -> list:
    """
    Compare VLAN databases across all devices.
    Returns a list of human-readable issue strings.
    """
    issues = []
    vlan_presence = defaultdict(list)

    for device, vlans in devices.items():
        for vid in vlans:
            vlan_presence[vid].append(device)

    device_names = list(devices.keys())

    for vid in sorted(vlan_presence.keys()):
        present_on = vlan_presence[vid]
        missing_from = [d for d in device_names if d not in present_on]

        if missing_from:
            issues.append(
                f"VLAN {vid:>4}: missing on [{', '.join(missing_from)}]"
                f" — present on [{', '.join(present_on)}]"
            )

        names = {d: devices[d][vid] for d in present_on}
        unique_names = set(names.values())
        if len(unique_names) > 1:
            name_detail = ', '.join(f'{d}={n}' for d, n in sorted(names.items()))
            issues.append(f"VLAN {vid:>4}: name mismatch — {name_detail}")

    return issues


def print_summary(devices: dict) -> None:
    print("\n=== VLAN Database per Device ===")
    for device, vlans in devices.items():
        id_preview = ', '.join(str(v) for v in sorted(vlans)[:10])
        if len(vlans) > 10:
            id_preview += ', ...'
        print(f"  {device:<20} {len(vlans):>3} VLANs  [{id_preview}]")


DEMO_CONFIGS = {
    "core-sw1": """
VLAN Name                             Status    Ports
---- -------------------------------- --------- ----------------------------
1    default                          active    Gi0/1
10   Management                       active    Gi0/2
20   Servers                          active    Gi0/3
30   Voice                            active
40   Guest                            active
100  DMZ                              active
""",
    "core-sw2": """
VLAN Name                             Status    Ports
---- -------------------------------- --------- ----------------------------
1    default                          active
10   Management                       active
20   Server-Farm                      active
30   Voice                            active
50   Printers                         active
100  DMZ                              active
""",
    "access-sw1": """
VLAN Name                             Status    Ports
---- -------------------------------- --------- ----------------------------
1    default                          active    Fa0/1
10   Management                       active    Fa0/24
20   Servers                          active
30   Voice                            active
""",
}


def run_demo() -> None:
    print("=== VLAN Consistency Checker — Demo Mode ===")
    print(f"Devices: {', '.join(DEMO_CONFIGS)}\n")
    parsed = {name: parse_device_vlans(text) for name, text in DEMO_CONFIGS.items()}
    print_summary(parsed)
    issues = check_consistency(parsed)
    print(f"\n=== Issues Found: {len(issues)} ===")
    for issue in issues:
        print(f"  [!] {issue}")
    if not issues:
        print("  All VLANs consistent across devices.")


def main() -> None:
    if len(sys.argv) < 2:
        run_demo()
        return

    device_data = {}
    for path_str in sys.argv[1:]:
        p = Path(path_str)
        if not p.exists():
            print(f"[ERROR] File not found: {path_str}", file=sys.stderr)
            sys.exit(1)
        device_data[p.stem] = p.read_text()

    parsed = {name: parse_device_vlans(text) for name, text in device_data.items()}
    print_summary(parsed)
    issues = check_consistency(parsed)
    print(f"\n=== Issues Found: {len(issues)} ===")
    for issue in issues:
        print(f"  [!] {issue}")
    if not issues:
        print("  All VLANs consistent across devices.")

    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()