```python
#!/usr/bin/env python3
"""
004_ip_calculator.py - IP Address & Subnet Calculator

Provides detailed breakdown of IP addresses and subnets: network/broadcast
addresses, usable host ranges, binary representation, membership checks,
and route summarization. Uses only the Python standard library.

Usage:
    python 004_ip_calculator.py 192.168.10.50/24
    python 004_ip_calculator.py 10.0.0.1 255.255.252.0
    python 004_ip_calculator.py --summarize 10.0.1.0/24 10.0.2.0/24 10.0.3.0/24
    python 004_ip_calculator.py --contains 192.168.1.0/24 192.168.1.55
"""

import ipaddress
import sys
import argparse


def format_binary(addr: ipaddress.IPv4Address, sep: str = ".") -> str:
    """Return dotted-octet binary string for an IPv4 address."""
    octets = [f"{int(o):08b}" for o in addr.packed]
    return sep.join(octets)


def describe_network(cidr: str) -> None:
    """Print a full breakdown of an IPv4 network given CIDR notation."""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    host_ip = ipaddress.IPv4Address(cidr.split("/")[0])
    usable = net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses

    print(f"\n{'='*54}")
    print(f"  IP Address       : {host_ip}")
    print(f"  Network Address  : {net.network_address}")
    print(f"  Broadcast        : {net.broadcast_address}")
    print(f"  Subnet Mask      : {net.netmask}")
    print(f"  Wildcard Mask    : {net.hostmask}")
    print(f"  Prefix Length    : /{net.prefixlen}")
    print(f"  IP Class         : {_ip_class(host_ip)}")
    print(f"  Total Addresses  : {net.num_addresses:,}")
    print(f"  Usable Hosts     : {max(usable, 0):,}")

    if net.prefixlen < 31:
        first = net.network_address + 1
        last = net.broadcast_address - 1
        print(f"  First Usable     : {first}")
        print(f"  Last Usable      : {last}")

    print(f"\n  Binary Breakdown:")
    print(f"    IP      : {format_binary(host_ip)}")
    print(f"    Mask    : {format_binary(net.netmask)}")
    print(f"    Network : {format_binary(net.network_address)}")

    net_bits = format_binary(net.network_address, sep="").replace(".", "")
    host_bits = net.prefixlen
    print(f"    Split   : {net_bits[:host_bits]}|{net_bits[host_bits:]}")

    print(f"\n  Private Range    : {'Yes' if net.is_private else 'No'}")
    print(f"  Multicast        : {'Yes' if net.is_multicast else 'No'}")
    print(f"{'='*54}\n")


def _ip_class(addr: ipaddress.IPv4Address) -> str:
    first = int(addr.packed[0])
    if first < 128:
        return "A"
    elif first < 192:
        return "B"
    elif first < 224:
        return "C"
    elif first < 240:
        return "D (Multicast)"
    return "E (Reserved)"


def check_membership(network_cidr: str, host_ip: str) -> None:
    """Report whether host_ip falls within network_cidr."""
    try:
        net = ipaddress.IPv4Network(network_cidr, strict=False)
        addr = ipaddress.IPv4Address(host_ip)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    member = addr in net
    symbol = "✓" if member else "✗"
    status = "IS" if member else "IS NOT"
    print(f"\n  {symbol}  {addr} {status} in {net}\n")


def summarize_routes(prefixes: list[str]) -> None:
    """Collapse a list of prefixes into the minimal set of supernets."""
    try:
        networks = [ipaddress.IPv4Network(p, strict=True) for p in prefixes]
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    summarized = list(ipaddress.collapse_addresses(networks))
    print(f"\n  Input networks  ({len(networks)}):")
    for n in sorted(networks):
        print(f"    {n}")
    print(f"\n  Summarized into ({len(summarized)}):")
    for s in summarized:
        print(f"    {s}  ({s.num_addresses:,} addresses)")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="IP Address & Subnet Calculator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "target",
        nargs="+",
        help="CIDR (192.168.1.0/24), IP + mask (10.0.0.1 255.255.0.0), "
             "or list of CIDRs with --summarize",
    )
    parser.add_argument(
        "--summarize",
        action="store_true",
        help="Collapse multiple CIDRs into fewest supernets",
    )
    parser.add_argument(
        "--contains",
        metavar="HOST",
        help="Check whether HOST falls inside the given network",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.summarize:
        summarize_routes(args.target)
        return

    # Accept "IP mask" as two positional args
    if len(args.target) == 2 and not args.target[0].startswith("-"):
        try:
            ipaddress.IPv4Address(args.target[1])
            # Second arg looks like a mask, not a CIDR prefix
            cidr = f"{args.target[0]}/{ipaddress.IPv4Network('0.0.0.0/' + args.target[1]).prefixlen}"
        except ValueError:
            cidr = args.target[0]
    else:
        cidr = args.target[0]

    if args.contains:
        check_membership(cidr, args.contains)
    else:
        describe_network(cidr)


if __name__ == "__main__":
    main()
```