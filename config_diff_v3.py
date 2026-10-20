#!/usr/bin/env python3
"""
BGP Route Summarization Tool

Analyzes a list of IP prefixes and suggests optimal route aggregation
to reduce BGP table size and improve routing efficiency.

Real-world use case: Network engineers managing BGP often need to aggregate
related routes into summary blocks. This tool automatically identifies
contiguous IP space and suggests the most efficient summarization.

Example:
    Input:  10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24
    Output: 10.0.0.0/22 (4 routes aggregated)
"""

import ipaddress
import argparse
import sys
from pathlib import Path
from typing import List, Set


class BGPRouteSummarizer:
    """Analyzes IP prefixes and suggests route summarization."""
    
    def __init__(self):
        self.original_prefixes: Set[ipaddress.IPv4Network] = set()
        self.summary_blocks: List[ipaddress.IPv4Network] = []
    
    def add_prefixes(self, prefixes: List[str]) -> int:
        """
        Parse and add CIDR notation prefixes.
        Returns count of valid prefixes added.
        """
        valid = 0
        for prefix in prefixes:
            try:
                net = ipaddress.IPv4Network(prefix.strip(), strict=False)
                if net not in self.original_prefixes:
                    self.original_prefixes.add(net)
                    valid += 1
            except ValueError as e:
                print(f"Warning: Invalid prefix '{prefix}': {e}", file=sys.stderr)
        return valid
    
    def summarize(self) -> List[ipaddress.IPv4Network]:
        """
        Calculate optimal route summarization using collapse_addresses.
        Returns sorted list of summary blocks.
        """
        if not self.original_prefixes:
            return []
        
        self.summary_blocks = sorted(
            ipaddress.collapse_addresses(self.original_prefixes),
            key=lambda x: x.network_address
        )
        return self.summary_blocks
    
    def get_stats(self) -> dict:
        """Calculate summarization efficiency metrics."""
        orig_count = len(self.original_prefixes)
        summ_count = len(self.summary_blocks)
        
        return {
            "original": orig_count,
            "summarized": summ_count,
            "reduced": orig_count - summ_count,
            "efficiency_percent": round(
                ((orig_count - summ_count) / orig_count * 100) if orig_count else 0,
                2
            )
        }
    
    def format_report(self) -> str:
        """Generate formatted summarization report."""
        stats = self.get_stats()
        lines = []
        
        lines.append("=" * 70)
        lines.append("BGP ROUTE SUMMARIZATION REPORT")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Original routes:     {stats['original']}")
        lines.append(f"Summarized routes:   {stats['summarized']}")
        lines.append(f"Routes reduced:      {stats['reduced']}")
        lines.append(f"Efficiency gain:     {stats['efficiency_percent']}%")
        lines.append("")
        
        if self.summary_blocks:
            lines.append("SUMMARY BLOCKS:")
            for block in self.summary_blocks:
                children = sum(
                    1 for p in self.original_prefixes if p.subnet_of(block)
                )
                lines.append(f"  {str(block):25s} covers {children} original route(s)")
        
        lines.append("")
        lines.append("=" * 70)
        
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="BGP Route Summarization Tool",
        epilog="""
Examples:
  # Read routes from file (one CIDR per line)
  python 029_bgp_route_summarizer.py --input routes.txt
  
  # Process inline routes
  python 029_bgp_route_summarizer.py --routes 10.0.0.0/24 10.0.1.0/24 10.0.2.0/24
  
  # Save report to file
  python 029_bgp_route_summarizer.py --input routes.txt --output summary.txt
        """
    )
    
    parser.add_argument("--input", "-i", type=Path,
                       help="Input file with CIDR routes (one per line)")
    parser.add_argument("--routes", "-r", nargs="+",
                       help="Routes as command-line arguments")
    parser.add_argument("--output", "-o", type=Path,
                       help="Output file for report")
    
    args = parser.parse_args()
    
    routes = []
    if args.input:
        try:
            routes = [line.strip() for line in args.input.read_text().split('\n')
                     if line.strip()]
        except FileNotFoundError:
            print(f"Error: File not found: {args.input}", file=sys.stderr)
            return 1
    elif args.routes:
        routes = args.routes
    else:
        parser.print_help()
        return 1
    
    summarizer = BGPRouteSummarizer()
    count = summarizer.add_prefixes(routes)
    
    if count == 0:
        print("Error: No valid prefixes provided", file=sys.stderr)
        return 1
    
    summarizer.summarize()
    report = summarizer.format_report()
    
    if args.output:
        args.output.write_text(report)
        print(f"Report saved to: {args.output}")
    else:
        print(report)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())