#!/usr/bin/env python3
"""
034_vlan_consistency_checker.py

Network Automation Utility: VLAN Consistency Checker

Parses Cisco IOS switch configuration files and identifies VLAN
inconsistencies across multiple switches in the same network segment.

Real-world problem solved:
  In multi-switch environments, VLANs drift out of sync — a VLAN exists
  on one switch but not another, allowed on a trunk but never defined,
  or carries different names on different devices. This tool catches
  those mismatches before they cause connectivity issues.

Usage:
  python 034_vlan_consistency_checker.py switch1.cfg switch2.cfg [...]

Example:
  python 034_vlan_consistency_checker.py core-sw1.cfg access-sw1.cfg access-sw2.cfg

Exit code 0 = clean, 1 = issues found, 2 = usage/file error.
"""

import re
import sys
from collections import defaultdict


def parse_vlans(config_text):
    """Return {vlan_id: name} for all 'vlan <id>' blocks in a Cisco IOS config."""
    vlans = {}
    lines = config_text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'^vlan (\d+)\s*$', line)
        if m:
            vid = int(m.group(1))
            name = ''
            if i + 1 < len(lines):
                nm = re.match(r'^\s+name (.+)$', lines[i + 1])
                if nm:
                    name = nm.group(1).strip()
            vlans[vid] = name
    return vlans


def expand_vlan_range(range_str):
    """Expand '10,20-22,30' into a set of integers."""
    vlans = set()
    for part in range_str.split(','):
        part = part.strip()
        if '-' in part:
            lo, hi = part.split('-', 1)
            vlans.update(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            vlans.add(int(part))
    return vlans


def parse_trunk_allowed_vlans(config_text):
    """Return set of all VLAN IDs referenced in 'switchport trunk allowed vlan' lines."""
    allowed = set()
    pattern = re.compile(
        r'switchport trunk allowed vlan(?:\s+add)?\s+([\d,\-]+)', re.MULTILINE
    )
    for m in pattern.finditer(config_text):
        allowed |= expand_vlan_range(m.group(1))
    return allowed


def load_switch(path):
    """Read a config file; return (hostname, defined_vlans, trunk_allowed_vlans)."""
    with open(path) as f:
        text = f.read()
    m = re.search(r'^hostname (.+)$', text, re.MULTILINE)
    hostname = m.group(1).strip() if m else path
    return hostname, parse_vlans(text), parse_trunk_allowed_vlans(text)


def check_consistency(switch_data):
    """
    Compare VLAN definitions and trunk membership across switches.

    switch_data: list of (hostname, defined_vlans_dict, trunk_allowed_set)
    Returns list of human-readable issue strings.
    """
    issues = []
    all_switches = {h for h, _, _ in switch_data}

    vlan_presence = defaultdict(set)
    vlan_names = defaultdict(dict)
    for hostname, defined, _ in switch_data:
        for vid, name in defined.items():
            vlan_presence[vid].add(hostname)
            if name:
                vlan_names[vid][hostname] = name

    for vid in sorted(vlan_presence):
        missing = all_switches - vlan_presence[vid]
        if missing:
            issues.append(
                f"VLAN {vid:4d}: defined on {sorted(vlan_presence[vid])} "
                f"but MISSING on {sorted(missing)}"
            )

    for vid, names in sorted(vlan_names.items()):
        if len(set(names.values())) > 1:
            detail = ', '.join(f"{h}={n!r}" for h, n in sorted(names.items()))
            issues.append(f"VLAN {vid:4d}: name mismatch — {detail}")

    for hostname, defined, trunk_allowed in switch_data:
        ghost = sorted(trunk_allowed - set(defined) - {1})
        if ghost:
            issues.append(
                f"{hostname}: trunk permits undefined VLANs: {ghost}"
            )

    return issues


def run_demo():
    """Built-in demo — two switches with deliberate mismatches."""
    SW1 = """
hostname core-sw1
vlan 10
 name MGMT
vlan 20
 name SERVERS
vlan 30
 name USERS
interface GigabitEthernet0/1
 switchport trunk allowed vlan 10,20,30
"""
    SW2 = """
hostname access-sw1
vlan 10
 name MGMT
vlan 20
 name SERVER
vlan 40
 name PRINTERS
interface GigabitEthernet0/1
 switchport trunk allowed vlan 10,20,30,40,99
"""
    print("=== Demo mode — no config files provided ===\n")
    data = []
    for text in (SW1, SW2):
        m = re.search(r'^hostname (.+)$', text, re.MULTILINE)
        hostname = m.group(1).strip() if m else 'unknown'
        defined = parse_vlans(text)
        trunk = parse_trunk_allowed_vlans(text)
        data.append((hostname, defined, trunk))
        print(f"  Loaded {hostname}: {len(defined)} VLANs, {len(trunk)} on trunks")

    print()
    report(data)


def report(switch_data):
    issues = check_consistency(switch_data)
    if not issues:
        print("OK — no VLAN inconsistencies detected.")
    else:
        print(f"Found {len(issues)} issue(s):\n")
        for issue in issues:
            print(f"  [WARN] {issue}")
    return len(issues)


def main():
    if len(sys.argv) < 2:
        run_demo()
        return

    switch_data = []
    for path in sys.argv[1:]:
        try:
            hostname, defined, trunk = load_switch(path)
            switch_data.append((hostname, defined, trunk))
            print(f"  Loaded {hostname}: {len(defined)} VLANs, {len(trunk)} on trunks")
        except FileNotFoundError:
            print(f"[ERROR] File not found: {path}", file=sys.stderr)
            sys.exit(2)

    print()
    issue_count = report(switch_data)
    sys.exit(0 if issue_count == 0 else 1)


if __name__ == '__main__':
    main()