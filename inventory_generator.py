#!/usr/bin/env python3
"""
subnet_inventory.py — Network Subnet Inventory Generator

Reads a list of CIDR prefixes (one per line) from a file or stdin,
validates each entry, detects overlapping allocations, computes per-prefix
capacity statistics, and emits a structured inventory in table, JSON, or
CSV format.

Real-world use cases:
  - Audit IP address plans before provisioning VLANs or VRFs
  - Catch overlapping allocations across sites before they cause routing loops
  - Feed structured prefix data into IPAM tools or firewall rule generators

Usage:
    python subnet_inventory.py prefixes.txt
    python subnet_inventory.py --format json prefixes.txt
    python subnet_inventory.py --format csv  prefixes.txt
    echo "10.0.0.0/8" | python subnet_inventory.py -

Input format (prefixes.txt):
    # lines beginning with # are ignored
    10.0.0.0/8
    10.10.1.0/24
    192.168.0.0/16
    172.16.0.0/12

Exit codes:
    0  — success, no overlaps found
    1  — one or more overlapping pairs detected (output still produced)
    2  — fatal error (unreadable file, no valid prefixes)

Requires Python 3.7+ (standard library only — no pip install needed).
"""

import argparse
import csv
import ipaddress
import json
import sys
from typing import List, Set, Tuple


def load_lines(path: str) -> List[str]:
    if path == "-":
        return sys.stdin.readlines()
    with open(path) as fh:
        return fh.readlines()


def parse_prefixes(
    lines: List[str],
) -> Tuple[List[ipaddress.IPv4Network], List[str]]:
    """Return (valid_networks, error_messages) from raw text lines."""
    networks, errors = [], []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            # strict=False allows host bits set (e.g. 10.0.0.1/24 → 10.0.0.0/24)
            networks.append(ipaddress.IPv4Network(line, strict=False))
        except ValueError as exc:
            errors.append(f"skip {line!r}: {exc}")
    return networks, errors


def find_overlaps(
    nets: List[ipaddress.IPv4Network],
) -> List[Tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]]:
    """Return every (a, b) pair where a overlaps b, checked once per pair."""
    pairs = []
    for i, a in enumerate(nets):
        for b in nets[i + 1 :]:
            if a.overlaps(b):
                pairs.append((a, b))
    return pairs


def prefix_stats(net: ipaddress.IPv4Network) -> dict:
    plen = net.prefixlen
    if plen == 32:
        usable, first, last = 1, str(net.network_address), str(net.network_address)
    elif plen == 31:
        # RFC 3021: point-to-point links, both addresses usable
        addrs = list(net.hosts()) or [net.network_address, net.broadcast_address]
        usable, first, last = 2, str(addrs[0]), str(addrs[-1])
    else:
        usable = net.num_addresses - 2
        first = str(net.network_address + 1)
        last  = str(net.broadcast_address - 1)
    return {
        "prefix":          str(net),
        "network":         str(net.network_address),
        "broadcast":       str(net.broadcast_address),
        "first_usable":    first,
        "last_usable":     last,
        "usable_hosts":    usable,
        "total_addresses": net.num_addresses,
        "prefix_len":      plen,
        "netmask":         str(net.netmask),
        "wildcard":        str(net.hostmask),
    }


def render_table(rows: List[dict], flagged: Set[str]) -> None:
    cols = [
        ("Prefix",        "prefix",       20),
        ("Netmask",       "netmask",      17),
        ("First Usable",  "first_usable", 16),
        ("Last Usable",   "last_usable",  16),
        ("Usable Hosts",  "usable_hosts", 14),
        ("Flags",         None,            9),
    ]
    header = "  ".join(label.ljust(w) for label, _, w in cols)
    sep    = "  ".join("-" * w       for _,     _, w in cols)
    print(header)
    print(sep)
    for row in rows:
        vals = []
        for _, key, w in cols:
            cell = "OVERLAP" if key is None and row["prefix"] in flagged else str(row.get(key, ""))
            vals.append(cell.ljust(w))
        print("  ".join(vals))


def render_json(rows: List[dict], flagged: Set[str]) -> None:
    for row in rows:
        row["overlap"] = row["prefix"] in flagged
    print(json.dumps(rows, indent=2))


def render_csv(rows: List[dict], flagged: Set[str]) -> None:
    fields = [
        "prefix", "network", "broadcast", "first_usable", "last_usable",
        "usable_hosts", "total_addresses", "netmask", "wildcard", "overlap",
    ]
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        row["overlap"] = row["prefix"] in flagged
        writer.writerow(row)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate a subnet inventory from a CIDR prefix list.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("input", help="prefix-list file, or '-' for stdin")
    ap.add_argument(
        "--format", choices=["table", "json", "csv"], default="table",
        help="output format (default: table)",
    )
    args = ap.parse_args()

    try:
        lines = load_lines(args.input)
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    networks, errors = parse_prefixes(lines)
    for msg in errors:
        print(f"WARNING: {msg}", file=sys.stderr)

    if not networks:
        print("ERROR: no valid IPv4 prefixes found.", file=sys.stderr)
        return 2

    networks = sorted(set(networks))
    rows     = [prefix_stats(n) for n in networks]
    pairs    = find_overlaps(networks)
    flagged  = {str(n) for pair in pairs for n in pair}

    if args.format == "table":
        render_table(rows, flagged)
        if pairs:
            print(f"\nWARNING: {len(pairs)} overlapping pair(s) detected:", file=sys.stderr)
            for a, b in pairs:
                print(f"  {a}  overlaps  {b}", file=sys.stderr)
    elif args.format == "json":
        render_json(rows, flagged)
    else:
        render_csv(rows, flagged)

    return 1 if pairs else 0


if __name__ == "__main__":
    sys.exit(main())