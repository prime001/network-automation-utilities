#!/usr/bin/env python3
"""
032_prefix_aggregator.py - BGP/Route Prefix Aggregator

Collapses a list of IP prefixes into the minimal set of covering supernets,
reducing BGP table bloat and simplifying route policies.

Real-world use cases:
  - Summarizing customer prefixes before advertising to upstream peers
  - Generating aggregate-address statements for BGP router configs
  - Identifying consolidation opportunities in large routing tables

Usage:
    python 032_prefix_aggregator.py                  # runs built-in examples
    python 032_prefix_aggregator.py prefixes.txt     # reads prefixes from file
    echo "10.0.0.0/24\n10.0.1.0/24" | python 032_prefix_aggregator.py -
"""

import ipaddress
import sys
from typing import List, Tuple


def aggregate_prefixes(
    raw: List[str],
) -> Tuple[List[ipaddress.IPv4Network], List[ipaddress.IPv4Network]]:
    """
    Parse raw prefix strings and collapse them to the minimal covering set.

    Returns (aggregated_networks, parsed_input_networks).
    Invalid lines are skipped with a warning on stderr.
    """
    parsed = []
    for line in raw:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            parsed.append(ipaddress.ip_network(line, strict=False))
        except ValueError as exc:
            print(f"[WARN] skipping '{line}': {exc}", file=sys.stderr)

    collapsed = list(ipaddress.collapse_addresses(parsed)) if parsed else []
    return collapsed, parsed


def print_report(raw: List[str], label: str = "") -> None:
    """Print a human-readable aggregation report for a set of prefixes."""
    if label:
        print(f"\n{'='*62}\n  {label}\n{'='*62}")

    aggregated, parsed = aggregate_prefixes(raw)

    if not aggregated:
        print("  No valid prefixes to aggregate.")
        return

    reduction = 100 * (1 - len(aggregated) / len(parsed)) if parsed else 0
    print(f"\n  Input count   : {len(parsed)}")
    print(f"  Aggregated to : {len(aggregated)} prefix(es)  [{reduction:.0f}% reduction]")
    print()
    print("  Result (suitable for BGP aggregate-address):")
    for agg in aggregated:
        covered = [str(p) for p in parsed if agg.supernet_of(p)]
        print(f"    {str(agg):<22}  ← {', '.join(covered)}")

    host_mask = {4: 32, 6: 128}
    lone = [str(p) for p in parsed if p.prefixlen == host_mask[p.version]]
    if lone:
        print(f"\n  [NOTE] {len(lone)} host route(s) cannot aggregate further: {', '.join(lone)}")
    print()


def cisco_bgp_snippet(raw: List[str], as_set: bool = True) -> List[str]:
    """
    Generate Cisco IOS BGP aggregate-address config lines.

    as_set=True preserves AS_PATH info for transparency with peers.
    """
    aggregated, _ = aggregate_prefixes(raw)
    suffix = " summary-only as-set" if as_set else " summary-only"
    return [
        f"aggregate-address {str(net.network_address)} {str(net.netmask)}{suffix}"
        for net in aggregated
    ]


EXAMPLES = [
    (
        "Customer A — four contiguous /24s collapse to one /22",
        ["192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"],
    ),
    (
        "Customer B — mixed sizes with discontiguous blocks",
        [
            "10.0.0.0/22", "10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/23",
            "172.16.100.0/24", "172.16.101.0/24",
        ],
    ),
    (
        "ISP uplink — four /26s collapse; odd /25s and /24 stay separate",
        [
            "203.0.113.0/24",
            "198.51.100.0/25", "198.51.100.128/25",
            "192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26", "192.0.2.192/26",
        ],
    ),
]


def main() -> None:
    if len(sys.argv) > 1:
        src = sys.argv[1]
        lines = sys.stdin.read().splitlines() if src == '-' else open(src).read().splitlines()
        print_report(lines, label=f"Input: {src}")
        stmts = cisco_bgp_snippet(lines)
        if stmts:
            print("  Cisco IOS BGP snippet:")
            for s in stmts:
                print(f"    {s}")
            print()
    else:
        print("BGP Prefix Aggregator — built-in examples")
        for label, prefixes in EXAMPLES:
            print_report(prefixes, label=label)
            stmts = cisco_bgp_snippet(prefixes)
            print("  Cisco IOS BGP snippet:")
            for s in stmts:
                print(f"    {s}")
            print()


if __name__ == "__main__":
    main()