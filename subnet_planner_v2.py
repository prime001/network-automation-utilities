#!/usr/bin/env python3
"""
Interface Statistics Analyzer - Identifies problematic network interfaces.

Analyzes interface statistics from device output and flags interfaces with:
- High error rates (input/output)
- High discard rates
- CRC errors
- Other anomalies

Real-world use: Spot interfaces with hardware issues, misconfigurations,
or high traffic loss before they cause customer impact.

Usage:
    analyzer = InterfaceAnalyzer()
    analyzer.load_from_dict({'Eth0/0': {'input_packets': 1000, ...}})
    print(analyzer.generate_report())
"""

import json
from typing import Dict, List


class InterfaceAnalyzer:
    """Analyzes network interface statistics and identifies health issues."""
    
    # Configurable thresholds
    ERROR_RATE_THRESHOLD = 0.001  # 0.1%
    CRC_THRESHOLD = 10
    
    def __init__(self):
        self.interfaces: Dict[str, Dict] = {}
        self.issues: List[Dict] = []
    
    def add_interface_stats(self, interface_name: str, stats: Dict) -> None:
        """Add interface statistics for analysis."""
        stats['interface'] = interface_name
        self.interfaces[interface_name] = stats
    
    def load_from_dict(self, data: Dict[str, Dict]) -> None:
        """Load multiple interfaces from dictionary."""
        for name, stats in data.items():
            self.add_interface_stats(name, stats)
    
    def analyze(self) -> List[Dict]:
        """Analyze interfaces and return list of issues found."""
        self.issues = []
        
        for iface, stats in self.interfaces.items():
            # Input error rate
            in_packets = stats.get('input_packets', 0)
            in_errors = stats.get('input_errors', 0)
            if in_packets > 0:
                error_rate = in_errors / in_packets
                if error_rate > self.ERROR_RATE_THRESHOLD:
                    severity = 'CRITICAL' if error_rate > 0.01 else 'WARNING'
                    self.issues.append({
                        'interface': iface,
                        'issue': f'Input error rate: {error_rate:.2%}',
                        'severity': severity
                    })
            
            # Output error rate
            out_packets = stats.get('output_packets', 0)
            out_errors = stats.get('output_errors', 0)
            if out_packets > 0:
                error_rate = out_errors / out_packets
                if error_rate > self.ERROR_RATE_THRESHOLD:
                    severity = 'CRITICAL' if error_rate > 0.01 else 'WARNING'
                    self.issues.append({
                        'interface': iface,
                        'issue': f'Output error rate: {error_rate:.2%}',
                        'severity': severity
                    })
            
            # Discard rate
            discards = stats.get('discards', 0)
            if in_packets > 0 and discards / in_packets > self.ERROR_RATE_THRESHOLD:
                self.issues.append({
                    'interface': iface,
                    'issue': f'High discard rate: {discards / in_packets:.2%}',
                    'severity': 'WARNING'
                })
            
            # CRC errors
            crc = stats.get('crc_errors', 0)
            if crc > self.CRC_THRESHOLD:
                self.issues.append({
                    'interface': iface,
                    'issue': f'CRC errors: {crc}',
                    'severity': 'CRITICAL'
                })
        
        return self.issues
    
    def generate_report(self, format: str = 'text') -> str:
        """Generate health report in text or JSON format."""
        self.analyze()
        
        if format == 'json':
            return json.dumps({
                'total_interfaces': len(self.interfaces),
                'problematic_interfaces': len(set(i['interface'] for i in self.issues)),
                'issues': self.issues
            }, indent=2)
        
        # Text format
        lines = [
            '=' * 70,
            'INTERFACE HEALTH ANALYSIS',
            '=' * 70,
            f'Analyzed: {len(self.interfaces)} | Issues found: {len(self.issues)}',
        ]
        
        if self.issues:
            critical = [i for i in self.issues if i['severity'] == 'CRITICAL']
            warnings = [i for i in self.issues if i['severity'] == 'WARNING']
            
            if critical:
                lines.append(f'\n🔴 CRITICAL ({len(critical)}):')
                for issue in critical:
                    lines.append(f"  {issue['interface']}: {issue['issue']}")
            
            if warnings:
                lines.append(f'\n🟡 WARNING ({len(warnings)}):')
                for issue in warnings:
                    lines.append(f"  {issue['interface']}: {issue['issue']}")
        else:
            lines.append('\n✓ All interfaces healthy')
        
        lines.append('=' * 70)
        return '\n'.join(lines)
    
    def get_healthy_interfaces(self) -> List[str]:
        """Return interfaces with no issues."""
        problematic = {i['interface'] for i in self.issues}
        return [name for name in self.interfaces if name not in problematic]


if __name__ == '__main__':
    analyzer = InterfaceAnalyzer()
    
    # Example data from device show interfaces output
    example_interfaces = {
        'Eth0/0': {
            'input_packets': 10000000,
            'input_errors': 15000,
            'output_packets': 9500000,
            'output_errors': 200,
            'discards': 5000,
            'crc_errors': 5
        },
        'Eth0/1': {
            'input_packets': 5000000,
            'input_errors': 50,
            'output_packets': 4800000,
            'output_errors': 25,
            'discards': 200,
            'crc_errors': 0
        },
        'Eth0/2': {
            'input_packets': 2000000,
            'input_errors': 500,
            'output_packets': 1900000,
            'output_errors': 300,
            'discards': 1000,
            'crc_errors': 25
        }
    }
    
    analyzer.load_from_dict(example_interfaces)
    print(analyzer.generate_report())
    print('\n' + analyzer.generate_report(format='json'))