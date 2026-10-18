#!/usr/bin/env python3
"""
CIDR Block Aggregator - Combines multiple IP ranges into minimal CIDR blocks.

Solves the real network engineering problem of optimizing firewall rules,
route summarization, and ACL policies by aggregating overlapping subnets.

Real-world use cases:
  - Reduce firewall rule lists (50 rules → 5 aggregated blocks)
  - Summarize routes for BGP advertisements
  - Consolidate ACL entries
  - Validate network segmentation policies

Example usage:
  cidrs = ['192.168.0.0/25', '192.168.0.128/25', '192.168.1.0/24']
  aggregated = aggregate_cidrs(cidrs)
  # Returns: ['192.168.0.0/24', '192.168.1.0/24']
"""

import ipaddress
from typing import List, Dict, Any


def aggregate_cidrs(cidr_list: List[str]) -> List[str]:
    """
    Aggregate multiple CIDR blocks into the minimum required set.
    Removes overlaps and combines adjacent ranges where possible.
    
    Args:
        cidr_list: List of CIDR notation strings (e.g., '192.168.0.0/24')
    
    Returns:
        Sorted list of aggregated CIDR blocks in canonical form
    """
    networks = set()
    
    for cidr in cidr_list:
        try:
            networks.add(ipaddress.ip_network(cidr, strict=False))
        except ValueError as e:
            raise ValueError(f"Invalid CIDR '{cidr}': {e}")
    
    aggregated = list(ipaddress.collapse_addresses(networks))
    return sorted([str(net) for net in aggregated])


def expand_range(start_ip: str, end_ip: str) -> List[str]:
    """
    Convert an IP address range to the minimum set of CIDR blocks.
    
    Useful when firewall rules specify "IPs from X to Y" and need
    to be converted to CIDR notation for routing/ACLs.
    
    Args:
        start_ip: Starting IP address string
        end_ip: Ending IP address string
    
    Returns:
        List of CIDR blocks covering the range (sorted)
    """
    try:
        start = ipaddress.ip_address(start_ip)
        end = ipaddress.ip_address(end_ip)
        cidrs = list(ipaddress.summarize_address_range(start, end))
        return sorted([str(cidr) for cidr in cidrs])
    except ValueError as e:
        raise ValueError(f"Invalid IP range: {e}")


def get_network_info(cidr: str) -> Dict[str, Any]:
    """
    Extract detailed information about a network block.
    
    Useful for planning, documentation, and capacity analysis.
    
    Args:
        cidr: CIDR notation string
    
    Returns:
        Dictionary containing network analysis details
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        
        return {
            'cidr': str(net),
            'network': str(net.network_address),
            'netmask': str(net.netmask),
            'broadcast': str(net.broadcast_address),
            'prefix_length': net.prefixlen,
            'total_addresses': net.num_addresses,
            'usable_hosts': len(hosts),
            'first_usable': str(hosts[0]) if hosts else 'N/A',
            'last_usable': str(hosts[-1]) if hosts else 'N/A',
        }
    except ValueError as e:
        raise ValueError(f"Invalid CIDR '{cidr}': {e}")


def find_common_supernet(cidr_list: List[str]) -> str:
    """
    Find the smallest supernet containing all given CIDR blocks.
    
    Identifies if multiple policy/routing entries can be consolidated
    into a single rule, reducing configuration complexity.
    
    Args:
        cidr_list: List of CIDR notation strings
    
    Returns:
        The minimal supernet covering all blocks
    """
    try:
        networks = [ipaddress.ip_network(cidr, strict=False) for cidr in cidr_list]
        if not networks:
            raise ValueError("Empty network list")
        
        supernet = networks[0]
        for net in networks[1:]:
            while supernet.prefixlen > 0 and not supernet.supernet_of(net):
                supernet = supernet.supernet()
        
        return str(supernet)
    except (ValueError, IndexError) as e:
        raise ValueError(f"Cannot compute supernet: {e}")


if __name__ == "__main__":
    print("=" * 55)
    print("CIDR Block Aggregator - Network Optimization Tool")
    print("=" * 55 + "\n")
    
    print("Example 1: Aggregate overlapping subnets")
    print("-" * 55)
    cidrs = ["192.168.0.0/25", "192.168.0.128/25", "192.168.1.0/24"]
    print(f"Input:  {cidrs}")
    result = aggregate_cidrs(cidrs)
    print(f"Output: {result}")
    print(f"Optimization: {len(cidrs)} → {len(result)} blocks\n")
    
    print("Example 2: Convert IP range to CIDR blocks")
    print("-" * 55)
    result = expand_range("10.0.0.1", "10.0.0.254")
    print(f"Range: 10.0.0.1 - 10.0.0.254")
    print(f"CIDR:  {result}\n")
    
    print("Example 3: Network block analysis")
    print("-" * 55)
    info = get_network_info("172.16.0.0/22")
    for key, value in info.items():
        print(f"  {key:16s}: {value}")
    print()
    
    print("Example 4: Consolidate dispersed policy rules")
    print("-" * 55)
    cidrs = ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"]
    print(f"Networks: {cidrs}")
    result = find_common_supernet(cidrs)
    print(f"Supernet: {result} (can replace 3 rules with 1)")