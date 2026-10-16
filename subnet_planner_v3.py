The user's instruction says "Output ONLY the file content, no markdown fences, no explanation" — that explicit instruction overrides the brainstorming skill. Outputting directly.

#!/usr/bin/env python3
"""
023_acl_shadow_detector.py — Network ACL Shadow Rule Detector

Parses a plain-text ACL rule file and identifies rules that can never
be evaluated because a broader, earlier rule always matches first (shadow)
or because the rule is an exact duplicate.

Real-world use: auditing large firewall/ACL change requests before deploy.
A deny intended for a specific host silently becomes unreachable when a broad
permit above it already matches the same traffic.

Usage:
    python 023_acl_shadow_detector.py rules.acl
    python 023_acl_shadow_detector.py --example
    cat rules.acl | python 023_acl_shadow_detector.py -

Rule file format — one rule per line (# comments ignored):
    <action> <src> <dst> <protocol> <dst_port>

    action    : permit | deny
    src / dst : CIDR (10.0.0.0/8), bare host (10.1.2.3), or any
    protocol  : tcp | udp | icmp | any
    dst_port  : 0-65535 or any

Exit code 0 = clean, 1 = issues found.
"""

import ipaddress
import sys
from dataclasses import dataclass
from typing import Optional


@dataclass
class Rule:
    line_num: int
    raw: str
    action: str
    src: str
    dst: str
    protocol: str
    dst_port: str


def _parse_network(token: str) -> Optional[ipaddress.IPv4Network]:
    if token == "any":
        return None
    try:
        return ipaddress.IPv4Network(token if "/" in token else token + "/32", strict=False)
    except ValueError:
        return None


def _field_covered(earlier: str, later: str) -> bool:
    """Return True if every address/value matched by *later* is also matched by *earlier*."""
    if earlier == "any":
        return True
    if later == "any":
        return earlier == "any"
    e_net = _parse_network(earlier)
    l_net = _parse_network(later)
    if e_net is not None and l_net is not None:
        return e_net.supernet_of(l_net)
    return earlier == later


def _is_shadowed_by(earlier: Rule, later: Rule) -> bool:
    return (
        _field_covered(earlier.src, later.src)
        and _field_covered(earlier.dst, later.dst)
        and _field_covered(earlier.protocol, later.protocol)
        and _field_covered(earlier.dst_port, later.dst_port)
    )


def parse_rule(line_num: int, line: str) -> Optional[Rule]:
    text = line.split("#")[0].strip()
    if not text:
        return None
    parts = text.split()
    if len(parts) < 5 or parts[0] not in ("permit", "deny"):
        return None
    return Rule(
        line_num=line_num,
        raw=text,
        action=parts[0],
        src=parts[1].lower(),
        dst=parts[2].lower(),
        protocol=parts[3].lower(),
        dst_port=parts[4].lower(),
    )


def analyze(rules: list) -> dict:
    shadowed, duplicates = [], []
    seen: dict = {}

    for i, rule in enumerate(rules):
        key = (rule.action, rule.src, rule.dst, rule.protocol, rule.dst_port)
        if key in seen:
            duplicates.append((rule, seen[key]))
            continue
        seen[key] = rule

        for earlier in rules[:i]:
            if _is_shadowed_by(earlier, rule):
                shadowed.append((rule, earlier))
                break

    return {"shadowed": shadowed, "duplicates": duplicates, "total": len(rules)}


def print_report(results: dict) -> None:
    total = results["total"]
    shadowed = results["shadowed"]
    duplicates = results["duplicates"]
    issues = len(shadowed) + len(duplicates)

    print(f"\nACL Shadow Analysis")
    print("=" * 62)
    print(f"  Total rules : {total}")
    print(f"  Issues found: {issues}  "
          f"(shadowed={len(shadowed)}, duplicates={len(duplicates)})")

    if shadowed:
        print(f"\n[SHADOWED] Rules that can never match:")
        print("-" * 62)
        for rule, blocker in shadowed:
            tag = "CONFLICT" if rule.action != blocker.action else "SHADOW "
            print(f"  {tag}  line {rule.line_num:>4}: {rule.raw}")
            print(f"           blocked by line {blocker.line_num:>4}: {blocker.raw}")

    if duplicates:
        print(f"\n[DUPLICATE] Exact rule copies:")
        print("-" * 62)
        for rule, first in duplicates:
            print(f"  line {rule.line_num:>4}: {rule.raw}")
            print(f"  copy of line {first.line_num:>4}")

    if not issues:
        print("\n  No shadowed or duplicate rules detected. ACL looks clean.")
    print()


EXAMPLE = """\
# Sample ACL — demonstrates shadow detection
permit 10.0.0.0/8    any              tcp  443
deny   10.1.0.0/16   192.168.1.0/24   tcp  443
permit 172.16.0.0/12 10.10.0.0/16     any  any
deny   172.16.1.0/24 10.10.0.0/16     tcp  22
permit any            any              any  any
deny   10.5.0.1       any              tcp  80
"""


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if sys.argv[1] == "--example":
        print("--- example input ---")
        print(EXAMPLE.rstrip())
        lines = EXAMPLE.splitlines()
    elif sys.argv[1] == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(sys.argv[1]) as fh:
            lines = fh.read().splitlines()

    rules = [r for i, ln in enumerate(lines, 1) if (r := parse_rule(i, ln))]

    if not rules:
        print("No valid rules found.")
        sys.exit(1)

    results = analyze(rules)
    print_report(results)
    sys.exit(1 if (results["shadowed"] or results["duplicates"]) else 0)


if __name__ == "__main__":
    main()