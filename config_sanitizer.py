#!/usr/bin/env python3
"""
Network Config Sanitizer - Remove sensitive data from network device configurations.

Problem Solved:
    Network engineers need to share device configs for documentation and forums
    without exposing IP addresses, secrets, or hostnames. This tool redacts
    sensitive data while preserving config structure and syntax for easy review.

Features:
    - Masks IP addresses, hostnames, descriptions
    - Redacts SNMP communities, credentials, secrets
    - Removes TACACS/RADIUS keys and BGP communities
    - Preserves syntax for visual inspection

Usage:
    python 006_config_sanitizer.py --input device.conf [--output sanitized.conf]
    python 006_config_sanitizer.py --input device.conf --strict

Example:
    Input:  "snmp-server community SuperSecret123 RO"
    Output: "snmp-server community [REDACTED] RO"
"""

import re
import sys
import argparse
from pathlib import Path


class ConfigSanitizer:
    """Sanitize network device configurations by masking sensitive data."""
    
    PATTERNS = {
        'snmp': (r'(snmp-server community|snmp-server group)\s+(\S+)', r'\1 [REDACTED]'),
        'secrets': (r'(password|secret|enable secret|key)\s+(\S+)', r'\1 [REDACTED]'),
        'aaa': (r'(tacacs-server key|radius-server key)\s+(\S+)', r'\1 [REDACTED]'),
        'hostname': (r'(hostname|host-name)\s+(\S+)', r'\1 DEVICE-[REDACTED]'),
        'description': (r'(description)\s+(.+?)$', r'\1 [REDACTED]'),
        'ipv4': (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', '[REDACTED-IP]'),
        'email': (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[REDACTED-EMAIL]'),
        'community': (r'(route-target|community)\s+(\d+:\d+)', r'\1 [REDACTED]'),
    }
    
    def __init__(self, strict: bool = False):
        self.strict = strict
    
    def sanitize(self, config_text: str) -> str:
        """Sanitize configuration by redacting sensitive data."""
        sanitized = config_text
        
        for pattern_name, (pattern, replacement) in self.PATTERNS.items():
            if not self.strict and pattern_name in ('description', 'hostname'):
                continue
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.MULTILINE)
        
        sanitized = re.sub(r'#.*(?:password|key|secret|community|tacacs|radius|preshared).*$', 
                          r'# [comment redacted]', sanitized, flags=re.MULTILINE | re.IGNORECASE)
        return sanitized


def main():
    parser = argparse.ArgumentParser(description='Sanitize network device configurations')
    parser.add_argument('--input', '-i', required=True, help='Input config file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--strict', '-s', action='store_true', help='Redact all sensitive fields')
    
    args = parser.parse_args()
    
    try:
        config_text = Path(args.input).read_text()
    except FileNotFoundError:
        print(f"Error: File not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    
    sanitizer = ConfigSanitizer(strict=args.strict)
    sanitized = sanitizer.sanitize(config_text)
    
    if args.output:
        Path(args.output).write_text(sanitized)
        print(f"Sanitized config written to {args.output}")
    else:
        print(sanitized)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        example = """hostname core-router-01
!
interface GigabitEthernet0/0/1
 description Link to branch-office-site-02
 ip address 192.168.1.1 255.255.255.0
!
snmp-server community SuperSecret123 RO
tacacs-server host 10.0.0.1 key MySecretKey456
!
route-map CUSTOMER-IN permit 10
 set community 65000:100
"""
        sanitizer = ConfigSanitizer(strict=False)
        print("=== ORIGINAL ===\n" + example)
        print("\n=== SANITIZED ===\n" + sanitizer.sanitize(example))
    else:
        main()