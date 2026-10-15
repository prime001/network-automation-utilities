019_acl_analyzer.py - Network ACL Shadow & Conflict Analyzer

Parses Cisco-style extended ACL entries and detects shadowed rules —
entries that can never match because a broader preceding rule already
covers the same traffic. Shadowed rules with opposite actions are
security gaps (a "deny" that will never fire because a "permit" above
it matches first, or vice-versa).

Supported syntax:
    [seq] permit|deny <proto> <src> <wildcard> <dst> <wildcard> [eq <port>]
    [seq] permit|deny <proto> any any [eq <port>]
    [seq] permit|deny <proto> host <addr> any
    ! comments and blank lines are skipped

Usage:
    python 019_acl_analyzer.py acl.txt
    python 019_acl_analyzer.py --inline "permit ip 10.0.0.0 0.255.255.255 any
deny ip 10.1.0.0 0.0.0.255 any"

Example output:
    Parsed 5 ACL rules

    Found 2 shadowed rule(s):

      Line   3: deny ip 10.1.0.0 0.0.0.255 any
               shadowed by line 1: permit ip 10.0.0.0 0.255.255.255 any
               → OPPOSITE ACTION — security gap: traffic hits earlier rule

Requires: Python 3.9+, stdlib only
"""

import re
import sys
import ipaddress
from dataclasses import dataclass
from typing import Optional


@dataclass
class AclRule:
    line_num: int
    raw: str
    action: str
    protocol: str
    src_net: ipaddress.IPv4Network
    dst_net: ipaddress.IPv4Network
    dst_port: Optional[str] = None


def _wildcard_to_network(addr: str, wildcard: str) -> ipaddress.IPv4Network:
    """Convert a Cisco wildcard mask pair to an IPv4Network (strict=False)."""
    inverted = 0xFFFFFFFF ^ int(ipaddress.IPv4Address(wildcard))
    netmask = str(ipaddress.IPv4Address(inverted))
    return ipaddress.IPv4Network(f"{addr}/{netmask}", strict=False)


def _normalize(line: str) -> str:
    """Expand 'host X' shorthand to 'X 0.0.0.0' before tokenizing."""
    return re.sub(
        r"\bhost\s+(\d+\.\d+\.\d+\.\d+)",
        lambda m: f"{m.group(1)} 0.0.0.0",
        line,
        flags=re.IGNORECASE,
    )


_RULE_RE = re.compile(
    r"^(?:\d+\s+)?"
    r"(permit|deny)\s+"
    r"(\S+)\s+"
    r"(any|\d+\.\d+\.\d+\.\d+)\s*"
    r"(\d+\.\d+\.\d+\.\d+)?\s*"
    r"(any|\d+\.\d+\.\d+\.\d+)\s*"
    r"(\d+\.\d+\.\d+\.\d+)?\s*"
    r"(?:eq\s+(\S+))?\s*$",
    re.IGNORECASE,
)

_ANY = ipaddress.IPv4Network("0.0.0.0/0")


def parse_line(line_num: int, raw: str) -> Optional[AclRule]:
    """Return an AclRule for a valid ACL line, or None if not parseable."""
    stripped = raw.strip()
    if not stripped or stripped.startswith("!") or re.match(r"ip\s+access-list", stripped, re.I):
        return None

    m = _RULE_RE.match(_normalize(stripped))
    if not m:
        return None

    action, proto, src_addr, src_wc, dst_addr, dst_wc, dst_port = m.groups()

    try:
        src_net = _ANY if src_addr.lower() == "any" else _wildcard_to_network(src_addr, src_wc or "0.0.0.0")
        dst_net = _ANY if dst_addr.lower() == "any" else _wildcard_to_network(dst_addr, dst_wc or "0.0.0.0")
    except (ValueError, TypeError):
        return None

    return AclRule(
        line_num=line_num,
        raw=stripped,
        action=action.lower(),
        protocol=proto.lower(),
        src_net=src_net,
        dst_net=dst_net,
        dst_port=dst_port,
    )


def shadows(earlier: AclRule, candidate: AclRule) -> bool:
    """
    Return True when every packet matching 'candidate' also matches 'earlier',
    meaning 'earlier' will always fire first and 'candidate' is unreachable.
    """
    if earlier.protocol != "ip" and earlier.protocol != candidate.protocol:
        return False
    if not earlier.src_net.supernet_of(candidate.src_net):
        return False
    if not earlier.dst_net.supernet_of(candidate.dst_net):
        return False
    if earlier.dst_port and earlier.dst_port != candidate.dst_port:
        return False
    return True


def analyze(rules: list[AclRule]) -> list[dict]:
    """Return a list of shadow findings, one per shadowed rule."""
    findings = []
    for i, rule in enumerate(rules):
        for earlier in rules[:i]:
            if shadows(earlier, rule):
                findings.append(
                    {
                        "shadowed_line": rule.line_num,
                        "shadowed_rule": rule.raw,
                        "shadowing_line": earlier.line_num,
                        "shadowing_rule": earlier.raw,
                        "severity": (
                            "WARNING — opposite action creates security gap"
                            if rule.action != earlier.action
                            else "INFO    — redundant, same action"
                        ),
                    }
                )
                break
    return findings


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "--inline":
        if len(sys.argv) < 3:
            print("Usage: --inline \"<acl text>\"")
            sys.exit(1)
        raw_lines = sys.argv[2].splitlines()
    else:
        with open(sys.argv[1]) as fh:
            raw_lines = fh.readlines()

    rules = [r for i, ln in enumerate(raw_lines, 1) if (r := parse_line(i, ln))]
    print(f"Parsed {len(rules)} ACL rule(s)\n")

    findings = analyze(rules)
    if not findings:
        print("No shadowed rules detected.")
        return

    print(f"Found {len(findings)} shadowed rule(s):\n")
    for f in findings:
        print(f"  Line {f['shadowed_line']:>3}: {f['shadowed_rule']}")
        print(f"           shadowed by line {f['shadowing_line']}: {f['shadowing_rule']}")
        print(f"           → {f['severity']}\n")


if __name__ == "__main__":
    main()