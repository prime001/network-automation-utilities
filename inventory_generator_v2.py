```python
#!/usr/bin/env python3
"""
BGP Configuration Analyzer and Validator

Analyzes BGP configurations for best practices and common misconfigurations.
Validates peer configurations, checks timer settings, detects configuration
issues, and generates device-specific BGP commands.

Real-world use: Validate BGP deployments before production, ensure consistent
configurations across network devices, detect routing security issues.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class BGPPeer:
    """Represents a BGP neighbor/peer configuration."""
    ip: str
    asn: int
    description: str = ""
    route_map_in: str = ""
    route_map_out: str = ""
    prefix_limit: Optional[int] = None
    timers_keepalive: int = 60
    timers_hold: int = 180


class BGPAnalyzer:
    """Analyzes BGP configurations for health and best practices."""
    
    RECOMMENDED_KEEPALIVE = 60
    RECOMMENDED_HOLD = 180
    PRIVATE_ASN_MIN = 64512
    PRIVATE_ASN_MAX = 65534
    
    def __init__(self, local_asn: int, device_type: str = "ios"):
        """Initialize BGP analyzer for a device.
        
        Args:
            local_asn: Local BGP AS number (1-4294967295)
            device_type: Target device type - 'ios', 'nxos', or 'arista'
        """
        self.local_asn = local_asn
        self.device_type = device_type
        self.peers: List[BGPPeer] = []
    
    def add_peer(self, ip: str, asn: int, description: str = "",
                route_map_in: str = "", route_map_out: str = "",
                prefix_limit: Optional[int] = None,
                timers_keepalive: int = 60, timers_hold: int = 180) -> None:
        """Add a BGP peer with validation.
        
        Args:
            ip: Peer IP address
            asn: Peer AS number
            description: Peer description for documentation
            route_map_in: Inbound route-map name
            route_map_out: Outbound route-map name
            prefix_limit: Max prefix limit for protection
            timers_keepalive: BGP keepalive interval in seconds
            timers_hold: BGP hold time in seconds
        """
        if timers_keepalive >= timers_hold:
            raise ValueError("Keepalive must be less than hold time")
        
        if not self._validate_ip(ip):
            raise ValueError(f"Invalid IP address: {ip}")
        
        peer = BGPPeer(ip, asn, description, route_map_in, route_map_out,
                      prefix_limit, timers_keepalive, timers_hold)
        self.peers.append(peer)
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    def analyze(self) -> Dict:
        """Analyze BGP configuration and return findings.
        
        Returns:
            Dictionary with analysis results including warnings and recommendations
        """
        findings = {
            "local_asn": self.local_asn,
            "total_peers": len(self.peers),
            "ibgp_count": sum(1 for p in self.peers if p.asn == self.local_asn),
            "ebgp_count": sum(1 for p in self.peers if p.asn != self.local_asn),
            "warnings": [],
            "recommendations": []
        }
        
        for peer in self.peers:
            # Timer recommendations
            if peer.timers_keepalive != self.RECOMMENDED_KEEPALIVE:
                findings["warnings"].append(
                    f"Peer {peer.ip}: keepalive {peer.timers_keepalive}s "
                    f"(recommended {self.RECOMMENDED_KEEPALIVE}s)"
                )
            
            # Missing documentation
            if not peer.description:
                findings["recommendations"].append(f"Peer {peer.ip}: add description")
            
            # EBGP security checks
            if peer.asn != self.local_asn:
                if not peer.route_map_in:
                    findings["recommendations"].append(
                        f"EBGP {peer.ip}: add inbound route-map for filtering"
                    )
                if not peer.prefix_limit:
                    findings["recommendations"].append(
                        f"EBGP {peer.ip}: add prefix-limit (recommend 5000-10000)"
                    )
                if self.PRIVATE_ASN_MIN <= peer.asn <= self.PRIVATE_ASN_MAX:
                    findings["warnings"].append(
                        f"EBGP {peer.ip}: uses private ASN {peer.asn}"
                    )
        
        # Topology checks
        ips = [p.ip for p in self.peers]
        if len(ips) != len(set(ips)):
            findings["warnings"].append("Duplicate peer IPs detected")
        
        ibgp = [p for p in self.peers if p.asn == self.local_asn]
        if len(ibgp) > 1:
            findings["recommendations"].append(
                "IBGP mesh detected: verify router IDs are unique"
            )
        
        return findings
    
    def generate_commands(self) -> List[str]:
        """Generate device-specific BGP configuration commands.
        
        Returns:
            List of configuration commands ready for deployment
        """
        commands = [f"router bgp {self.local_asn}"]
        
        for peer in self.peers:
            commands.append(f" neighbor {peer.ip} remote-as {peer.asn}")
            if peer.description:
                commands.append(f" neighbor {peer.ip} description {peer.description}")
            if peer.timers_keepalive != self.RECOMMENDED_KEEPALIVE:
                commands.append(
                    f" neighbor {peer.ip} timers {peer.timers_keepalive} "
                    f"{peer.timers_hold}"
                )
            if peer.prefix_limit:
                commands.append(
                    f" neighbor {peer.ip} maximum-prefix {peer.prefix_limit}"
                )
            if peer.route_map_in:
                commands.append(f" neighbor {peer.ip} route-map {peer.route_map_in} in")
            if peer.route_map_out:
                commands.append(f" neighbor {peer.ip} route-map {peer.route_map_out} out")
        
        return commands


# Example usage demonstrating typical BGP deployment
if __name__ == "__main__":
    # Initialize analyzer for AS 65000
    bgp = BGPAnalyzer(local_asn=65000, device_type="ios")
    
    # Add route reflector (IBGP)
    bgp.add_peer("10.1.1.1", 65000, "Route Reflector - HQ")
    
    # Add ISP peers (EBGP) with security settings
    bgp.add_peer("192.0.2.1", 64512, "ISP Primary",
                route_map_in="FILTER_ISP_IN",
                route_map_out="FILTER_ISP_OUT",
                prefix_limit=5000)
    
    bgp.add_peer("192.0.2.5", 64513, "ISP Secondary",
                prefix_limit=5000)
    
    # Run analysis
    analysis = bgp.analyze()
    print(f"ASN {analysis['local_asn']} - {analysis['total_peers']} peers "
          f"({analysis['ibgp_count']} IBGP, {analysis['ebgp_count']} EBGP)\n")
    
    if analysis["warnings"]:
        print("Warnings:")
        for w in analysis["warnings"]:
            print(f"  ⚠ {w}")
    
    if analysis["recommendations"]:
        print("\nRecommendations:")
        for r in analysis["recommendations"]:
            print(f"  ℹ {r}")
    
    print("\nGenerated IOS Commands:")
    for cmd in bgp.generate_commands():
        print(cmd)
```