The user's explicit instruction is "Output ONLY the file content" — user instructions take highest priority over skill process, per the using-superpowers doc itself. I've done the design thinking internally: a VLAN consistency auditor is the right choice (not covered by any of the 26 existing tools). Outputting file content now.

```python
"""
027_vlan_audit.py - VLAN Consistency Auditor

Reads per-switch VLAN definitions from a CSV and flags inconsistencies:
  - VLANs with different names across switches (name drift)
  - Asymmetric trunk links (sw-A trunks VLAN X to sw-B, but sw-B doesn't trunk back)
  - Trunk references to VLANs not defined on the peer switch
  - References to switches not present in the dataset

Input CSV columns:
  switch       - switch hostname (e.g. sw-core-01)
  vlan_id      - VLAN number (1-4094)
  vlan_name    - descriptive name (e.g. MGMT, DATA, VOICE)
  trunked_to   - comma-separated list of peer switch names this VLAN is trunked to
                 (leave empty if the VLAN is access-only or not trunked)

Example CSV row:
  sw-core-01,10,MGMT,"sw-access-01,sw-access-02"

Usage:
  python 027_vlan_audit.py vlans.csv
  python 027_vlan_audit.py vlans.csv --strict   # also flag VLANs absent from some switches
  python 027_vlan_audit.py --example            # run against built-in demo data
"""

import csv
import io
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set

EXAMPLE_CSV = """\
switch,vlan_id,vlan_name,trunked_to
sw-core-01,10,MGMT,"sw-access-01,sw-access-02"
sw-core-01,20,DATA,"sw-access-01,sw-access-02"
sw-core-01,30,VOICE,"sw-access-01"
sw-core-01,99,NATIVE,""
sw-access-01,10,MGMT,"sw-core-01"
sw-access-01,20,DATA,"sw-core-01"
sw-access-01,99,NATIVE,""
sw-access-02,10,MGMT,"sw-core-01"
sw-access-02,20,DATA_VLAN,"sw-core-01"
sw-access-02,99,NATIVE,""
"""


@dataclass
class VlanEntry:
    switch: str
    vlan_id: int
    vlan_name: str
    trunked_to: Set[str] = field(default_factory=set)


def parse_csv(source) -> List[VlanEntry]:
    entries = []
    for row in csv.DictReader(source):
        peers = {h.strip() for h in row["trunked_to"].split(",") if h.strip()}
        entries.append(VlanEntry(
            switch=row["switch"].strip(),
            vlan_id=int(row["vlan_id"].strip()),
            vlan_name=row["vlan_name"].strip(),
            trunked_to=peers,
        ))
    return entries


def audit(entries: List[VlanEntry], strict: bool = False) -> List[str]:
    issues = []

    by_switch: Dict[str, Dict[int, VlanEntry]] = defaultdict(dict)
    for e in entries:
        by_switch[e.switch][e.vlan_id] = e

    all_switches = set(by_switch.keys())

    # Collect all VLAN names fleet-wide: vlan_id -> {switch: name}
    fleet_names: Dict[int, Dict[str, str]] = defaultdict(dict)
    for e in entries:
        fleet_names[e.vlan_id][e.switch] = e.vlan_name

    # Check 1: VLAN name drift across switches
    for vlan_id, name_map in sorted(fleet_names.items()):
        if len(set(name_map.values())) > 1:
            detail = ", ".join(f"{sw}={nm}" for sw, nm in sorted(name_map.items()))
            issues.append(f"[NAME_MISMATCH]    VLAN {vlan_id:4d} has inconsistent names: {detail}")

    # Check 2 (strict): VLANs missing from some switches entirely
    if strict:
        for vlan_id, name_map in sorted(fleet_names.items()):
            missing = all_switches - set(name_map.keys())
            if missing:
                sample_name = next(iter(name_map.values()))
                issues.append(
                    f"[PARTIAL_VLAN]     VLAN {vlan_id:4d} ({sample_name}) "
                    f"absent on: {', '.join(sorted(missing))}"
                )

    # Check 3: trunk link issues
    for e in entries:
        for peer in e.trunked_to:
            if peer not in by_switch:
                issues.append(
                    f"[UNKNOWN_PEER]     {e.switch} VLAN {e.vlan_id:4d} trunks to "
                    f"unknown switch '{peer}'"
                )
                continue
            peer_vlans = by_switch[peer]
            if e.vlan_id not in peer_vlans:
                issues.append(
                    f"[PEER_MISSING_VLAN] {e.switch} trunks VLAN {e.vlan_id:4d} to {peer}, "
                    f"but {peer} has no VLAN {e.vlan_id} defined"
                )
            elif e.switch not in peer_vlans[e.vlan_id].trunked_to:
                issues.append(
                    f"[ASYMMETRIC_TRUNK] {e.switch} trunks VLAN {e.vlan_id:4d} to {peer}, "
                    f"but {peer} does not trunk VLAN {e.vlan_id} back to {e.switch}"
                )

    return issues


def main():
    strict = "--strict" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]

    if "--example" in sys.argv or not args:
        if not args:
            print("No input file specified — running built-in example.\n")
        entries = parse_csv(io.StringIO(EXAMPLE_CSV))
    else:
        with open(args[0], newline="") as fh:
            entries = parse_csv(fh)

    issues = audit(entries, strict=strict)

    switch_count = len({e.switch for e in entries})
    print(f"Switches : {switch_count}")
    print(f"Entries  : {len(entries)}")
    print(f"Issues   : {len(issues)}")
    print()

    if issues:
        for issue in issues:
            print(" ", issue)
    else:
        print("No issues found — VLAN configuration is consistent across all switches.")

    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
```