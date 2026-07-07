#!/usr/bin/env python3
"""
003_subnet_planner.py — VLSM Subnet Planner

Allocates subnets from a parent network block using Variable Length Subnet
Masking (VLSM). Subnets are assigned largest-first to minimise address-space
waste, then placed contiguously from the base of the parent network with
proper boundary alignment.

Depends only on the Python standard library (ipaddress, math, sys).

Usage:
    python 003_subnet_planner.py <parent-cidr> <NAME:HOSTS> [NAME:HOSTS ...]

    NAME   — label for the subnet (e.g. Engineering, DMZ, Management)
    HOSTS  — number of *usable* host addresses needed (excludes network +
             broadcast addresses from the count)

Examples:
    python 003_subnet_planner.py 10.0.0.0/16 Engineering:500 Operations:50 DMZ:30 Management:10
    python 003_subnet_planner.py 192.168.1.0/24 Servers:60 Printers:14 VoIP:28 Guest:14

Exit codes:
    0 — allocation succeeded
    1 — bad arguments or parent network too small to fit all requests
"""

import ipaddress
import math
import sys


def hosts_to_prefix(n: int) -> int:
    """Return the tightest prefix length that provides at least n usable hosts.

    Usable hosts in a subnet = 2^host_bits - 2 (subtracting network/broadcast).
    Solving for the minimum host_bits: ceil(log2(n + 2)).
    """
    return 32 - math.ceil(math.log2(n + 2))


def align_up(addr: ipaddress.IPv4Address, prefix: int) -> ipaddress.IPv4Address:
    """Return the smallest address >= addr aligned to the given prefix boundary."""
    block = 2 ** (32 - prefix)
    a = int(addr)
    return ipaddress.IPv4Address(((a + block - 1) // block) * block)


def plan_vlsm(
    parent: ipaddress.IPv4Network,
    requests: list[tuple[str, int]],
) -> list[tuple[str, ipaddress.IPv4Network]]:
    """Allocate subnets from *parent* satisfying each (name, required_hosts) pair.

    VLSM convention: sort largest-first before allocating so that big subnets
    claim well-aligned blocks at the front of the space, leaving the tail for
    smaller subnets without gaps from alignment padding.

    Returns allocations in descending-host-count order (address order).
    Raises ValueError if any subnet cannot fit within the parent.
    """
    sorted_req = sorted(requests, key=lambda r: r[1], reverse=True)
    allocations: list[tuple[str, ipaddress.IPv4Network]] = []
    cursor = parent.network_address

    for name, n_hosts in sorted_req:
        prefix = hosts_to_prefix(n_hosts)
        start = align_up(cursor, prefix)
        subnet = ipaddress.IPv4Network(f"{start}/{prefix}", strict=True)

        if not parent.supernet_of(subnet):
            raise ValueError(
                f"'{name}' ({n_hosts} hosts → /{prefix}) does not fit in {parent} "
                f"(would start at {start})"
            )

        allocations.append((name, subnet))
        cursor = ipaddress.IPv4Address(int(subnet.broadcast_address) + 1)

    return allocations


def fmt_row(name: str, net: ipaddress.IPv4Network) -> str:
    usable = net.num_addresses - 2
    first_host = net.network_address + 1
    last_host = net.broadcast_address - 1
    return (
        f"  {name:<20} /{net.prefixlen:<6}"
        f" {str(net.network_address):<16}"
        f" {str(net.broadcast_address):<16}"
        f" {str(first_host)} – {str(last_host):<16}"
        f" ({usable} hosts)"
    )


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    try:
        parent = ipaddress.IPv4Network(sys.argv[1], strict=False)
    except ValueError as e:
        print(f"Error: invalid parent network — {e}")
        sys.exit(1)

    requests: list[tuple[str, int]] = []
    for arg in sys.argv[2:]:
        try:
            name, hosts_str = arg.split(":", 1)
            hosts = int(hosts_str)
            if hosts < 1:
                raise ValueError("host count must be >= 1")
            requests.append((name.strip(), hosts))
        except ValueError as e:
            print(f"Error: invalid segment '{arg}' — {e}")
            print("  Expected: NAME:HOSTS  e.g.  Engineering:500")
            sys.exit(1)

    parent_usable = parent.num_addresses - 2
    print(f"\nParent : {parent}  ({parent_usable:,} usable hosts)\n")
    print(f"  {'Subnet':<20} {'Pfx':<7} {'Network':<16} {'Broadcast':<16} Usable Range")
    print("  " + "-" * 90)

    try:
        allocations = plan_vlsm(parent, requests)
    except ValueError as e:
        print(f"\nError: {e}")
        sys.exit(1)

    for name, subnet in allocations:
        print(fmt_row(name, subnet))

    print()
    first_net = allocations[0][1]
    last_net = allocations[-1][1]
    span = int(last_net.broadcast_address) - int(first_net.network_address) + 1
    free = int(parent.broadcast_address) - int(last_net.broadcast_address) - 1

    print(
        f"  Allocated : {first_net.network_address} – {last_net.broadcast_address}"
        f"  ({span:,} addresses)"
    )
    if free > 0:
        free_start = last_net.broadcast_address + 1
        free_end = parent.broadcast_address - 1
        print(f"  Free      : {free_start} – {free_end}  ({free:,} addresses remaining)")
    else:
        print("  Free      : none (parent fully consumed)")
    print()


if __name__ == "__main__":
    main()