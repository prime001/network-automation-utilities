#!/usr/bin/env python3
"""
008_csv_to_inventory.py - CSV to Network Inventory Converter

Converts a device spreadsheet (CSV) into automation-ready inventory formats:
Ansible INI, Ansible YAML, Nornir YAML, or JSON.

Real-world use: network teams maintain device lists in spreadsheets; this
bridges the gap between those spreadsheets and automation frameworks without
manual reformatting.

Expected CSV headers (case-insensitive, all optional except hostname/ip_address):
    hostname     Device hostname
    ip_address   Management IP (validated)
    device_type  netmiko/nornir platform (e.g., cisco_ios, arista_eos)
    username     SSH username
    password     SSH password
    groups       Comma-separated group names (e.g., "core,datacenter")
    location     Physical site or datacenter
    os_version   OS version string

Usage:
    python3 008_csv_to_inventory.py devices.csv
    python3 008_csv_to_inventory.py devices.csv --format ansible-ini
    python3 008_csv_to_inventory.py devices.csv --format ansible-yaml
    python3 008_csv_to_inventory.py devices.csv --format nornir
    python3 008_csv_to_inventory.py devices.csv --format json
    python3 008_csv_to_inventory.py --demo        # built-in sample data
    cat devices.csv | python3 008_csv_to_inventory.py -   # stdin
"""

import csv
import ipaddress
import io
import json
import argparse
import sys
from collections import defaultdict

SAMPLE_CSV = """\
hostname,ip_address,device_type,username,password,groups,location,os_version
core-sw-01,192.168.1.1,cisco_ios,admin,cisco123,"core,datacenter",DC1,15.2(4)M7
dist-sw-01,192.168.1.2,cisco_nxos,admin,nxos456,"distribution,datacenter",DC1,9.3(5)
edge-rtr-01,10.0.0.1,cisco_ios,admin,cisco123,"edge,wan",DC1,16.9(3)
branch-fw-01,172.16.0.1,paloalto_panos,admin,pa123,"firewall,branch",Branch1,10.1.3
spine-01,192.168.2.1,arista_eos,admin,arista789,"spine,fabric",DC1,4.26.2F
leaf-01,192.168.2.10,arista_eos,admin,arista789,"leaf,fabric",DC1,4.26.2F
"""


def _valid_ip(addr):
    try:
        ipaddress.ip_address(addr.strip())
        return True
    except ValueError:
        return False


def parse_csv(source):
    """
    Parse CSV from a file path or '-' for stdin.
    Returns (devices, errors) where devices is a list of normalized dicts.
    """
    devices, errors = [], []

    fh = sys.stdin if source == "-" else open(source, newline="")
    reader = csv.DictReader(fh)
    if reader.fieldnames:
        reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]

    for lineno, row in enumerate(reader, start=2):
        row = {k.strip().lower(): (v.strip() if v else "") for k, v in row.items()}
        hostname = row.get("hostname", "")
        ip = row.get("ip_address", "")

        if not hostname:
            errors.append(f"row {lineno}: missing hostname — skipped")
            continue
        if not ip:
            errors.append(f"row {lineno}: {hostname} missing ip_address — skipped")
            continue
        if not _valid_ip(ip):
            errors.append(f"row {lineno}: {hostname} invalid ip_address '{ip}' — skipped")
            continue

        groups = [g.strip() for g in row.get("groups", "").split(",") if g.strip()]
        devices.append({
            "hostname":    hostname,
            "ip_address":  ip,
            "device_type": row.get("device_type", ""),
            "username":    row.get("username", ""),
            "password":    row.get("password", ""),
            "groups":      groups or ["ungrouped"],
            "location":    row.get("location", ""),
            "os_version":  row.get("os_version", ""),
        })

    if source != "-":
        fh.close()
    return devices, errors


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def fmt_ansible_ini(devices):
    groups = defaultdict(list)
    for d in devices:
        for g in d["groups"]:
            groups[g].append(d)

    lines = []
    for group, members in sorted(groups.items()):
        lines.append(f"[{group}]")
        for d in members:
            entry = d["hostname"]
            entry += f" ansible_host={d['ip_address']}"
            if d["username"]:
                entry += f" ansible_user={d['username']}"
            if d["device_type"]:
                entry += f" ansible_network_os={d['device_type']}"
            lines.append(entry)
        lines.append("")
    return "\n".join(lines)


def fmt_ansible_yaml(devices):
    groups = defaultdict(list)
    for d in devices:
        for g in d["groups"]:
            groups[g].append(d)

    lines = ["all:", "  children:"]
    for group, members in sorted(groups.items()):
        lines += [f"    {group}:", "      hosts:"]
        for d in members:
            lines.append(f"        {d['hostname']}:")
            lines.append(f"          ansible_host: {d['ip_address']}")
            if d["username"]:
                lines.append(f"          ansible_user: {d['username']}")
            if d["device_type"]:
                lines.append(f"          ansible_network_os: {d['device_type']}")
            if d["location"]:
                lines.append(f"          location: {d['location']}")
    return "\n".join(lines)


def fmt_nornir(devices):
    lines = ["---"]
    for d in devices:
        lines.append(f"{d['hostname']}:")
        lines.append(f"  hostname: {d['ip_address']}")
        if d["username"]:
            lines.append(f"  username: {d['username']}")
        if d["password"]:
            lines.append(f"  password: {d['password']}")
        if d["device_type"]:
            lines.append(f"  platform: {d['device_type']}")
        lines.append("  groups:")
        for g in d["groups"]:
            lines.append(f"    - {g}")
        extras = {k: d[k] for k in ("location", "os_version") if d[k]}
        if extras:
            lines.append("  data:")
            for k, v in extras.items():
                lines.append(f"    {k}: {v}")
    return "\n".join(lines)


def fmt_json(devices):
    return json.dumps({"devices": devices}, indent=2)


FORMATTERS = {
    "ansible-ini":  fmt_ansible_ini,
    "ansible-yaml": fmt_ansible_yaml,
    "nornir":       fmt_nornir,
    "json":         fmt_json,
}


def _parse_sample():
    reader = csv.DictReader(io.StringIO(SAMPLE_CSV))
    devices = []
    for row in reader:
        row = {k.strip().lower(): v.strip() for k, v in row.items()}
        groups = [g.strip() for g in row.get("groups", "").split(",") if g.strip()]
        devices.append({
            "hostname":    row["hostname"],    "ip_address":  row["ip_address"],
            "device_type": row.get("device_type", ""),
            "username":    row.get("username", ""),
            "password":    row.get("password", ""),
            "groups":      groups or ["ungrouped"],
            "location":    row.get("location", ""),
            "os_version":  row.get("os_version", ""),
        })
    return devices


def main():
    parser = argparse.ArgumentParser(
        description="Convert a CSV device spreadsheet to automation inventory formats."
    )
    parser.add_argument("csvfile", nargs="?", help="CSV file (or - for stdin)")
    parser.add_argument(
        "--format", choices=FORMATTERS, default="json",
        metavar="|".join(FORMATTERS), help="Output format (default: json)"
    )
    parser.add_argument("--demo", action="store_true",
                        help="Run built-in sample data and print all formats")
    args = parser.parse_args()

    if args.demo:
        devices = _parse_sample()
        for name, fn in FORMATTERS.items():
            print(f"\n{'='*60}\nFORMAT: {name}\n{'='*60}")
            print(fn(devices))
        return

    if not args.csvfile:
        parser.print_help()
        sys.exit(1)

    devices, errors = parse_csv(args.csvfile)
    for err in errors:
        print(f"WARNING: {err}", file=sys.stderr)
    if not devices:
        print("ERROR: no valid devices parsed.", file=sys.stderr)
        sys.exit(1)

    print(FORMATTERS[args.format](devices))


if __name__ == "__main__":
    main()