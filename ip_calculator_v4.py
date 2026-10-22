The tool doesn't belong in `/opt/NetAutoCommitter` — that's a different project. The prompt asks to **output only the file content**. Here it is:

```
#!/usr/bin/env python3
```

Wait, the instruction says no markdown fences. Here is the raw file content:

---

#!/usr/bin/env python3
"""
033_ip_calculator.py — ACL Wildcard Mask & Route Summarization Calculator

Solves two tasks network engineers do constantly:
  1. Convert CIDR prefixes into Cisco ACL wildcard-mask notation
  2. Collapse a list of IPs / prefixes into the minimal set of CIDR blocks
     (for prefix-lists, ACLs, or BGP aggregate statements)

No external dependencies — stdlib ipaddress only.

Usage:
    # Wildcard mask for a single prefix
    python 033_ip_calculator.py wildcard 192.168.1.0/24

    # Summarize arbitrary IPs and/or CIDRs into minimal blocks
    python 033_ip_calculator.py summarize 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4

    # Minimal CIDR set covering a contiguous IP range
    python 033_ip_calculator.py range 10.2.0.0 10.2.3.255

    # Run built-in demo
    python 033_ip_calculator.py
"""

import ipaddress
import sys
from typing import List


def cidr_to_wildcard(cidr: str) -> str:
    """Return '<network> <wildcard>' string for Cisco ACL permit lines."""
    net = ipaddress.ip_network(cidr, strict=False)
    return f"{net.network_address} {net.hostmask}"


def summarize_addresses(addresses: List[str]) -> List[ipaddress.IPv4Network]:
    """Collapse a mix of host IPs and CIDR prefixes into minimal covering networks."""
    networks = [
        ipaddress.ip_network(a if "/" in a else f"{a}/32", strict=False)
        for a in addresses
    ]
    return list(ipaddress.collapse_addresses(networks))


def range_to_cidrs(start_ip: str, end_ip: str) -> List[ipaddress.IPv4Network]:
    """Return minimal CIDR blocks that exactly cover start_ip through end_ip."""
    return list(ipaddress.summarize_address_range(
        ipaddress.IPv4Address(start_ip),
        ipaddress.IPv4Address(end_ip),
    ))


# ---------------------------------------------------------------------------
# Formatted output helpers
# ---------------------------------------------------------------------------

def print_wildcard_info(cidr: str) -> None:
    net = ipaddress.ip_network(cidr, strict=False)
    first_host = net.network_address + (1 if net.prefixlen < 31 else 0)
    last_host = net.broadcast_address - (1 if net.prefixlen < 31 else 0)
    usable = max(net.num_addresses - 2, 0) if net.prefixlen < 31 else net.num_addresses

    print(f"Network    : {net.network_address}/{net.prefixlen}")
    print(f"Subnet mask: {net.netmask}")
    print(f"Wildcard   : {net.hostmask}")
    print(f"Broadcast  : {net.broadcast_address}")
    print(f"Host range : {first_host} – {last_host}  ({usable:,} usable)")
    print(f"Cisco ACL  : permit ip any {cidr_to_wildcard(cidr)}")


def print_summarized(addresses: List[str]) -> None:
    collapsed = summarize_addresses(addresses)
    print(f"Input  : {len(addresses)} address(es)")
    print(f"Summary: {len(collapsed)} block(s)\n")
    for net in collapsed:
        print(f"  {str(net):<22} wildcard: {cidr_to_wildcard(str(net))}")


def print_range_cidrs(start_ip: str, end_ip: str) -> None:
    cidrs = range_to_cidrs(start_ip, end_ip)
    print(f"Range  : {start_ip} – {end_ip}")
    print(f"Covered: {len(cidrs)} CIDR block(s)\n")
    for net in cidrs:
        print(f"  {str(net):<22} wildcard: {cidr_to_wildcard(str(net))}")


# ---------------------------------------------------------------------------
# Built-in demo
# ---------------------------------------------------------------------------

_DEMO = [
    ("wildcard",  ["192.168.10.0/24"]),
    ("wildcard",  ["10.0.0.0/8"]),
    ("summarize", ["10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4"]),
    ("summarize", ["172.16.0.0/24", "172.16.1.0/24", "172.16.2.0/24", "172.16.3.0/24"]),
    ("range",     ["10.2.0.0", "10.2.3.255"]),
    ("range",     ["192.0.2.5", "192.0.2.14"]),
]


def run_demo() -> None:
    print("=" * 62)
    print(" ACL Wildcard Mask & Route Summarization Calculator — Demo")
    print("=" * 62)
    for i, (cmd, args) in enumerate(_DEMO, 1):
        print(f"\n[{i}] {cmd} {' '.join(args)}")
        print("-" * 40)
        dispatch(cmd, args)


# ---------------------------------------------------------------------------
# Dispatch & entry point
# ---------------------------------------------------------------------------

def dispatch(cmd: str, args: List[str]) -> None:
    if cmd == "wildcard":
        print_wildcard_info(args[0])
    elif cmd == "summarize":
        print_summarized(args)
    elif cmd == "range":
        print_range_cidrs(args[0], args[1])
    else:
        print(f"Unknown command '{cmd}'. Use: wildcard | summarize | range")
        sys.exit(1)


def main() -> None:
    if len(sys.argv) < 2:
        run_demo()
        return

    cmd = sys.argv[1].lower()
    args = sys.argv[2:]

    if cmd == "wildcard" and len(args) >= 1:
        dispatch(cmd, args[:1])
    elif cmd == "summarize" and len(args) >= 1:
        dispatch(cmd, args)
    elif cmd == "range" and len(args) >= 2:
        dispatch(cmd, args[:2])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()