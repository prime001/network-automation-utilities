#!/usr/bin/env python3
"""
014_prefix_aggregator.py - Network Prefix Aggregator

Collapses a list of IPv4 prefixes into the minimal covering set.
Useful for:
  - Reducing BGP route advertisements (summarization before redistribution)
  - Simplifying firewall prefix-list / ACL entries
  - Compressing IPAM exports with many /32 host routes

Usage:
    python 014_prefix_aggregator.py prefixes.txt
    python 014_prefix_aggregator.py --prefixes 10.0.0.0/24 10.0.1.0/24 10.0.2.0/24
    cat routes.txt | python 014_prefix_aggregator.py -
    python 014_prefix_aggregator.py prefixes.txt --target 5 --supernet

Requires: Python 3.7+ (stdlib only — ipaddress module)
"""

import ipaddress
import sys
import argparse
from typing import List, Optional


def load_prefixes(source: str) -> List[ipaddress.IPv4Network]:
    """
    Load prefixes from a file path or stdin ('-').
    Skips blank lines and comment lines starting with '#'.
    Host bits in addresses are masked silently (e.g. 10.0.0.1/24 -> 10.0.0.0/24).
    """
    if source == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(source) as fh:
            lines = fh.read().splitlines()

    networks = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.IPv4Network(line, strict=False))
        except ValueError as exc:
            print(f"[WARN] Skipping invalid prefix '{line}': {exc}", file=sys.stderr)
    return networks


def aggregate_prefixes(
    networks: List[ipaddress.IPv4Network],
) -> List[ipaddress.IPv4Network]:
    """
    Collapse an arbitrary list of IPv4 networks into the minimal non-overlapping
    set of supernets, following RFC 4632 (CIDR) aggregation rules.
    Wraps stdlib collapse_addresses — handles deduplication and containment.
    """
    return list(ipaddress.collapse_addresses(networks))


def tightest_supernet(
    networks: List[ipaddress.IPv4Network],
) -> Optional[ipaddress.IPv4Network]:
    """
    Return the single smallest supernet that contains every prefix in the list.
    Useful for generating a summary-only advertisement (accept some overshoot).
    """
    if not networks:
        return None
    result = networks[0]
    for net in networks[1:]:
        while not result.supernet_of(net):
            result = result.supernet()
    return result


def reduce_to_count(
    networks: List[ipaddress.IPv4Network], target: int
) -> List[ipaddress.IPv4Network]:
    """
    Iteratively merge adjacent sibling prefixes until len(result) <= target.
    Siblings share the same prefix length and the same parent /N-1 block.

    This is lossy: the widened supernet may cover address space not in the
    original list. Always verify the result covers only intended ranges.
    """
    current = list(ipaddress.collapse_addresses(networks))
    while len(current) > target:
        merged = False
        for i in range(len(current) - 1):
            a, b = current[i], current[i + 1]
            if a.prefixlen == b.prefixlen and a.prefixlen > 0:
                parent = a.supernet()
                if parent.supernet_of(b):
                    current = current[:i] + [parent] + current[i + 2:]
                    current = list(ipaddress.collapse_addresses(current))
                    merged = True
                    break
        if not merged:
            break  # No more adjacent siblings; cannot reduce further
    return current


def print_results(
    original: List[ipaddress.IPv4Network],
    aggregated: List[ipaddress.IPv4Network],
    label: str = "Aggregated prefixes",
) -> None:
    print(f"\n{label}:")
    for net in aggregated:
        print(f"  {net}")
    reduction = len(original) - len(aggregated)
    pct = (reduction / len(original) * 100) if original else 0
    total_ips = sum(n.num_addresses for n in aggregated)
    print(f"\n  Input:     {len(original)} prefixes")
    print(f"  Output:    {len(aggregated)} prefixes  ({reduction} removed, {pct:.1f}% reduction)")
    print(f"  Addresses: {total_ips:,}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Aggregate IPv4 prefixes into the minimal covering set.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Requires:")[0].strip(),
    )
    parser.add_argument(
        "file", nargs="?", default=None,
        help="File with one prefix per line, or '-' for stdin",
    )
    parser.add_argument(
        "--prefixes", nargs="+", metavar="PREFIX",
        help="Prefixes to aggregate (space-separated, inline)",
    )
    parser.add_argument(
        "--target", type=int, default=None, metavar="N",
        help="Widen prefixes until result has at most N entries (lossy)",
    )
    parser.add_argument(
        "--supernet", action="store_true",
        help="Print the single tightest supernet covering all prefixes",
    )
    args = parser.parse_args()

    networks: List[ipaddress.IPv4Network] = []

    if args.prefixes:
        for p in args.prefixes:
            try:
                networks.append(ipaddress.IPv4Network(p, strict=False))
            except ValueError as exc:
                print(f"[WARN] Skipping '{p}': {exc}", file=sys.stderr)
    elif args.file:
        networks = load_prefixes(args.file)
    elif not sys.stdin.isatty():
        networks = load_prefixes("-")
    else:
        parser.print_help()
        sys.exit(1)

    if not networks:
        print("No valid prefixes supplied.", file=sys.stderr)
        sys.exit(1)

    original = networks[:]
    aggregated = aggregate_prefixes(networks)
    print_results(original, aggregated)

    if args.supernet:
        sup = tightest_supernet(aggregated)
        print(f"\n  Tightest supernet: {sup}")

    if args.target is not None:
        reduced = reduce_to_count(aggregated, args.target)
        print_results(original, reduced, label=f"Reduced (target ≤{args.target})")
        print("  [WARNING] Lossy reduction — verify no unintended space is covered.")


if __name__ == "__main__":
    if len(sys.argv) == 1 and sys.stdin.isatty():
        # Built-in demo: fragmented /22 block + two paired /25s
        print("=== Demo: Aggregating a fragmented address space ===")
        demo = [
            "10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24",
            "192.168.100.0/25", "192.168.100.128/25",
            "172.16.5.32/28", "172.16.5.48/28",
            "10.0.0.0/24",   # duplicate — should be collapsed
        ]
        nets = [ipaddress.IPv4Network(p) for p in demo]
        print("\nInput (with intentional duplicate):")
        for p in demo:
            print(f"  {p}")
        agg = aggregate_prefixes(nets)
        print_results(nets, agg)
        print(f"\n  Tightest supernet: {tightest_supernet(agg)}")
    else:
        main()