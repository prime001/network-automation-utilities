#!/usr/bin/env python3
"""
009_yaml_validator.py - Network YAML Configuration Validator

Validates YAML files used in network automation: Ansible inventories,
device config definitions, BGP policy files, VLAN schemas, and similar
structured data common in network engineering workflows.

Checks performed:
  - YAML syntax validity
  - IP address and prefix (CIDR) format correctness
  - VLAN ID range (1-4094)
  - BGP ASN range (1-4294967295, including 4-byte ASNs)
  - TCP/UDP port number range (1-65535)
  - Interface name patterns (IOS, EOS, Linux)
  - Duplicate hostname detection in inventory-style files

Usage:
  python 009_yaml_validator.py hosts.yml
  python 009_yaml_validator.py site-a.yml site-b.yml
  python 009_yaml_validator.py *.yml

Exit codes:
  0  all files passed
  1  one or more validation errors found
  2  usage error

Example YAML that would trigger errors:
  interfaces:
    - name: GigabitEthernet0/1
      ip: 300.1.1.1        # invalid IP
      vlan: 5000            # out of range
      bgp_asn: 0            # invalid ASN
"""

import ipaddress
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

VLAN_MIN, VLAN_MAX = 1, 4094
ASN_MIN, ASN_MAX = 1, 4294967295
PORT_MIN, PORT_MAX = 1, 65535

_INTF_PATTERNS = [
    r"^(GigabitEthernet|Gi)\d+([/\.]\d+)*$",
    r"^(TenGigabitEthernet|Te)\d+([/\.]\d+)*$",
    r"^(HundredGigE|Hu)\d+([/\.]\d+)*$",
    r"^(FastEthernet|Fa)\d+([/\.]\d+)*$",
    r"^(Ethernet|Et)\d+([/\.]\d+)*$",
    r"^(Loopback|Lo)\d+$",
    r"^(Port-channel|Po)\d+$",
    r"^(Tunnel|Tu)\d+$",
    r"^(Vlan|Vl)\d+$",
    r"^(Management|Mgmt|mgmt)\d*$",
    r"^eth\d+$",
    r"^bond\d+$",
    r"^(enp|ens|eno)\d+.*$",
]

_IP_KEY = re.compile(
    r"(^|_)(ip|address|addr|gateway|gw|neighbor|peer|src|dst|source|dest|destination|nexthop|next_hop)($|_)",
    re.I,
)
_PREFIX_KEY = re.compile(r"(^|_)(subnet|network|prefix|cidr|route|supernet)($|_)", re.I)
_VLAN_KEY = re.compile(r"(^|_)vlan(s|_id|_ids)?($|_)", re.I)
_ASN_KEY = re.compile(r"(^|_)(asn|as_number|as_num|local_as|remote_as|peer_as|bgp_as)($|_)", re.I)
_PORT_KEY = re.compile(r"(^|_)(port|dport|sport|src_port|dst_port)($|_)", re.I)
_INTF_KEY = re.compile(r"(^|_)(interface|iface|intf|int|uplink|downlink)($|_)", re.I)


def _check_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _check_prefix(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _check_interface(value: str) -> bool:
    return any(re.match(p, value, re.I) for p in _INTF_PATTERNS)


def _validate_scalar(key: str, value: Any, path: str) -> list[str]:
    errors = []
    if value is None:
        return errors

    if _IP_KEY.search(key) and isinstance(value, str):
        bare = value.split("/")[0]
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", bare) or ":" in bare:
            if "/" in value:
                if not _check_prefix(value):
                    errors.append(f"  {path}: invalid IP prefix '{value}'")
            elif not _check_ip(value):
                errors.append(f"  {path}: invalid IP address '{value}'")

    if _PREFIX_KEY.search(key) and isinstance(value, str) and "/" in value:
        if not _check_prefix(value):
            errors.append(f"  {path}: invalid network prefix '{value}'")

    if _VLAN_KEY.search(key) and isinstance(value, int):
        if not (VLAN_MIN <= value <= VLAN_MAX):
            errors.append(f"  {path}: VLAN {value} out of range ({VLAN_MIN}-{VLAN_MAX})")

    if _ASN_KEY.search(key) and isinstance(value, int):
        if not (ASN_MIN <= value <= ASN_MAX):
            errors.append(f"  {path}: ASN {value} out of valid range")

    if _PORT_KEY.search(key) and isinstance(value, int):
        if not (PORT_MIN <= value <= PORT_MAX):
            errors.append(f"  {path}: port {value} out of range ({PORT_MIN}-{PORT_MAX})")

    if _INTF_KEY.search(key) and isinstance(value, str):
        if re.match(r"^[A-Za-z]", value) and not _check_interface(value):
            errors.append(f"  {path}: unrecognized interface name '{value}'")

    return errors


def _walk(data: Any, path: str = "") -> list[str]:
    errors = []
    if isinstance(data, dict):
        for key, val in data.items():
            node = f"{path}.{key}" if path else str(key)
            errors.extend(_validate_scalar(str(key), val, node))
            errors.extend(_walk(val, node))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            errors.extend(_walk(item, f"{path}[{i}]"))
    return errors


def _check_duplicate_hostnames(data: Any) -> list[str]:
    """Flag duplicate 'hostname' or 'name' values at the top level list."""
    if not isinstance(data, list):
        return []
    seen: dict[str, int] = {}
    errors = []
    for i, item in enumerate(data):
        if isinstance(item, dict):
            for key in ("hostname", "name", "host"):
                if key in item and isinstance(item[key], str):
                    val = item[key]
                    if val in seen:
                        errors.append(f"  [{i}].{key}: duplicate '{val}' (first seen at [{seen[val]}])")
                    else:
                        seen[val] = i
    return errors


def validate_file(filepath: str) -> tuple[bool, list[str]]:
    p = Path(filepath)
    if not p.exists():
        return False, [f"  file not found: {filepath}"]
    if p.suffix.lower() not in (".yml", ".yaml"):
        return False, [f"  not a YAML file (expected .yml or .yaml): {filepath}"]

    try:
        text = p.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return False, [f"  YAML syntax error: {exc}"]
    except OSError as exc:
        return False, [f"  read error: {exc}"]

    if data is None:
        return True, ["  (empty file — no data to validate)"]

    errors = _walk(data)
    errors.extend(_check_duplicate_hostnames(data))
    return len(errors) == 0, errors


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)

    files = sys.argv[1:]
    total_issues = 0
    failed = 0

    for filepath in files:
        ok, issues = validate_file(filepath)
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {filepath}")
        for msg in issues:
            print(msg)
        if not ok:
            failed += 1
            total_issues += len(issues)

    print(f"\n{len(files)} file(s) checked — {total_issues} issue(s) in {failed} file(s).")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()