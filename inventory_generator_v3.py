#!/usr/bin/env python3
"""
BGP Route Analyzer - Analyzes BGP routes for overlaps, redundancy, and optimization.

Analyzes a list of BGP routes (CIDR notation) to detect:
- Overlapping prefixes that may indicate misconfigurations
- Shadowed routes (completely contained in larger prefixes)
- Aggregation opportunities to reduce routing table size
- Network coverage metrics

Input format (one route per line):
    10.0.0.0/8 65001
    172.16.0.0/12 65002
    192.168.0.0/16 65001

Usage:
    python bgp_analyzer.py routes.txt
"""

import sys
from ipaddress import ip_network


class BGPAnalyzer:
    """Analyzes BGP route table for optimization and errors."""
    
    def __init__(self):
        self.routes = []
        self.errors = []
    
    def parse_routes(self, filename):
        """Parse routes from file. Format: CIDR_PREFIX AS_NUMBER"""
        try:
            with open(filename) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) < 2:
                        self.errors.append(f"Line {line_num}: Invalid format")
                        continue
                    
                    try:
                        prefix = ip_network(parts[0])
                        asn = int(parts[1])
                        self.routes.append((prefix, asn))
                    except ValueError as e:
                        self.errors.append(f"Line {line_num}: {e}")
            
            return len(self.errors) == 0
        
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found")
            return False
    
    def find_overlaps(self):
        """Identify overlapping CIDR blocks (potential conflicts)."""
        overlaps = []
        for i, (net1, asn1) in enumerate(self.routes):
            for net2, asn2 in self.routes[i+1:]:
                if net1.overlaps(net2) and net1 != net2:
                    overlaps.append((str(net1), str(net2)))
        return overlaps
    
    def find_shadowed(self):
        """Find routes completely contained in larger prefixes."""
        shadowed = []
        for i, (net1, _) in enumerate(self.routes):
            for net2, _ in self.routes:
                if i != self.routes.index((net2, _)) and net1.subnet_of(net2):
                    shadowed.append((str(net1), str(net2)))
        return shadowed
    
    def find_aggregatable(self):
        """Find consecutive routes that could be aggregated."""
        candidates = []
        ipv4 = sorted([r for r in self.routes if r[0].version == 4], 
                      key=lambda x: int(x[0].network_address))
        
        for i in range(len(ipv4) - 1):
            net1, asn1 = ipv4[i]
            net2, asn2 = ipv4[i + 1]
            
            if asn1 == asn2 and net1.prefixlen == net2.prefixlen:
                try:
                    parent = net1.supernet()
                    if parent == net2.supernet() and parent.num_subnets(new_prefix=net1.prefixlen) == 2:
                        candidates.append(([str(net1), str(net2)], str(parent)))
                except:
                    pass
        
        return candidates
    
    def coverage_stats(self):
        """Calculate total IP addresses covered."""
        ipv4_ips = sum(r[0].num_addresses for r in self.routes if r[0].version == 4)
        ipv6_ips = sum(r[0].num_addresses for r in self.routes if r[0].version == 6)
        return {
            'total_routes': len(self.routes),
            'ipv4_addresses': ipv4_ips,
            'ipv6_addresses': ipv6_ips
        }
    
    def report(self):
        """Generate analysis report."""
        lines = [
            "=" * 65,
            "BGP ROUTE ANALYZER REPORT",
            "=" * 65
        ]
        
        if self.errors:
            lines.append(f"\n⚠ PARSE ERRORS ({len(self.errors)}):")
            for err in self.errors[:3]:
                lines.append(f"  {err}")
            if len(self.errors) > 3:
                lines.append(f"  ... and {len(self.errors) - 3} more")
        
        stats = self.coverage_stats()
        lines.append(f"\n📊 COVERAGE ({stats['total_routes']} routes):")
        lines.append(f"  IPv4: {stats['ipv4_addresses']:,} addresses")
        lines.append(f"  IPv6: {stats['ipv6_addresses']:,} addresses")
        
        overlaps = self.find_overlaps()
        if overlaps:
            lines.append(f"\n🔴 OVERLAPPING ROUTES ({len(overlaps)} found):")
            for net1, net2 in overlaps[:4]:
                lines.append(f"  {net1} ↔ {net2}")
            if len(overlaps) > 4:
                lines.append(f"  ... and {len(overlaps) - 4} more")
        else:
            lines.append("\n✓ No overlapping routes")
        
        shadowed = self.find_shadowed()
        if shadowed:
            lines.append(f"\n⚠ SHADOWED ROUTES ({len(shadowed)} found):")
            for subnet, supernet in shadowed[:4]:
                lines.append(f"  {subnet} ⊂ {supernet}")
            if len(shadowed) > 4:
                lines.append(f"  ... and {len(shadowed) - 4} more")
        else:
            lines.append("\n✓ No shadowed routes")
        
        agg = self.find_aggregatable()
        if agg:
            lines.append(f"\n💡 AGGREGATION OPPORTUNITIES ({len(agg)}):")
            for routes, parent in agg[:3]:
                lines.append(f"  {' + '.join(routes)} → {parent}")
            if len(agg) > 3:
                lines.append(f"  ... and {len(agg) - 3} more")
        else:
            lines.append("\n✓ No aggregation opportunities")
        
        lines.append("\n" + "=" * 65)
        return "\n".join(lines)


def main():
    if len(sys.argv) != 2:
        print("Usage: python bgp_analyzer.py <route_file>")
        print("\nRoute file format (one per line):")
        print("  CIDR_PREFIX AS_NUMBER")
        print("  10.0.0.0/8 65001")
        sys.exit(1)
    
    analyzer = BGPAnalyzer()
    if analyzer.parse_routes(sys.argv[1]):
        print(analyzer.report())
    else:
        print("Failed to parse file")
        sys.exit(1)


if __name__ == "__main__":
    main()