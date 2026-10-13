The task is to generate the file content directly (no markdown, no explanation) — writing it now.

#!/usr/bin/env python3
"""
016_config_compliance.py - Cisco IOS Configuration Compliance Auditor

Audits Cisco IOS device configurations against security and operational
best-practice rules. Produces a pass/fail/warn report per check, helping
network engineers identify drift before deployment or during periodic audits.

Rules checked:
  Security   : SSH v2, telnet disabled on VTY, enable secret, password encryption, AAA
  Operational: NTP redundancy, remote + buffered logging, banner MOTD
  Hardening  : no ip directed-broadcast, no ip source-route, HTTP server off, CDP scope

Usage:
    python 016_config_compliance.py <config_file>
    python 016_config_compliance.py --example

Exit code: 1 if any FAIL results, 0 otherwise (CI-friendly).
"""

import re
import sys
from dataclasses import dataclass, field
from typing import List

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
INFO = "INFO"

_COLOR = {PASS: "\033[92m", FAIL: "\033[91m", WARN: "\033[93m", INFO: "\033[94m", "RESET": "\033[0m"}


@dataclass
class CheckResult:
    rule: str
    status: str
    detail: str = ""


@dataclass
class ComplianceReport:
    device: str
    results: List[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for r in self.results if r.status == WARN)

    def add(self, rule: str, status: str, detail: str = "") -> None:
        self.results.append(CheckResult(rule, status, detail))


def audit_config(config: str, device: str = "device") -> ComplianceReport:
    """Run all compliance checks against a raw IOS config string."""
    report = ComplianceReport(device=device)
    lines = config.splitlines()

    def has(pattern: str) -> bool:
        return any(re.search(pattern, line, re.IGNORECASE) for line in lines)

    def find(pattern: str) -> List[str]:
        return [line.strip() for line in lines if re.search(pattern, line, re.IGNORECASE)]

    # SSH version
    if has(r"^ip ssh version 2"):
        report.add("SSH version 2", PASS)
    elif has(r"^ip ssh version 1"):
        report.add("SSH version 2", FAIL, "SSHv1 configured — replace with 'ip ssh version 2'")
    else:
        report.add("SSH version 2", WARN, "No 'ip ssh version' line — device defaults to SSHv1")

    # Telnet on VTY lines
    vty_transport = find(r"transport input")
    telnet_lines = [l for l in vty_transport if re.search(r"\btelnet\b", l)]
    if telnet_lines:
        report.add("Telnet disabled on VTY", FAIL, f"Telnet allowed: {', '.join(telnet_lines)}")
    elif vty_transport:
        report.add("Telnet disabled on VTY", PASS)
    else:
        report.add("Telnet disabled on VTY", WARN, "No 'transport input' found — telnet may be default")

    # Password encryption
    if has(r"^service password-encryption"):
        report.add("Password encryption", PASS)
    else:
        report.add("Password encryption", FAIL, "Add 'service password-encryption'")

    # Enable secret vs enable password
    if has(r"^enable secret"):
        report.add("Enable secret configured", PASS)
    elif has(r"^enable password"):
        report.add("Enable secret configured", FAIL, "Replace 'enable password' with 'enable secret'")
    else:
        report.add("Enable secret configured", WARN, "No enable credential found")

    # AAA
    if has(r"^aaa new-model"):
        report.add("AAA new-model", PASS)
    else:
        report.add("AAA new-model", WARN, "AAA not enabled — device uses legacy local auth")

    # NTP redundancy
    ntp = find(r"^ntp server")
    if len(ntp) >= 2:
        servers = ", ".join(l.split()[-1] for l in ntp)
        report.add("NTP redundancy (≥2 servers)", PASS, f"Servers: {servers}")
    elif len(ntp) == 1:
        report.add("NTP redundancy (≥2 servers)", WARN, "Only 1 NTP server — add a second")
    else:
        report.add("NTP redundancy (≥2 servers)", FAIL, "No NTP servers configured")

    # Logging
    if has(r"^logging \d") or has(r"^logging host"):
        report.add("Remote syslog configured", PASS)
    else:
        report.add("Remote syslog configured", WARN, "No remote syslog host — add 'logging host <ip>'")

    if has(r"^logging buffered"):
        report.add("Buffered logging enabled", PASS)
    else:
        report.add("Buffered logging enabled", FAIL, "Add 'logging buffered <size>'")

    # Banner MOTD
    if has(r"^banner motd"):
        report.add("Banner MOTD present", PASS)
    else:
        report.add("Banner MOTD present", WARN, "No MOTD banner — required for unauthorized-access notice")

    # IP directed-broadcast
    db_on = [l for l in find(r"ip directed-broadcast") if not l.startswith("no ")]
    if db_on:
        report.add("IP directed-broadcast disabled", FAIL, f"Still enabled: {', '.join(db_on)}")
    else:
        report.add("IP directed-broadcast disabled", PASS)

    # IP source-route
    if has(r"^no ip source-route"):
        report.add("IP source-route disabled", PASS)
    elif has(r"^ip source-route"):
        report.add("IP source-route disabled", FAIL, "Remove 'ip source-route'")
    else:
        report.add("IP source-route disabled", WARN, "Not explicitly disabled — add 'no ip source-route'")

    # HTTP server
    if has(r"^no ip http server") or not has(r"^ip http server\s*$"):
        report.add("HTTP server disabled", PASS)
    else:
        report.add("HTTP server disabled", FAIL, "Add 'no ip http server' or restrict to HTTPS only")

    # CDP scope
    if has(r"^no cdp run"):
        report.add("CDP disabled globally", INFO, "Verify edge interfaces don't need CDP selectively")
    else:
        report.add("CDP disabled globally", WARN, "CDP running globally — disable on untrusted edge interfaces")

    return report


def print_report(report: ComplianceReport, color: bool = True) -> None:
    def c(status: str, text: str) -> str:
        return f"{_COLOR.get(status, '')}{text}{_COLOR['RESET']}" if color else text

    print(f"\nCompliance Audit — {report.device}")
    print("=" * 64)
    for r in report.results:
        tag = f"[{r.status:<4}]"
        detail = f"  {r.detail}" if r.detail else ""
        print(f"  {c(r.status, tag)} {r.rule}{detail}")
    print("-" * 64)
    print(
        f"  Total {len(report.results)}  |  "
        f"{c(PASS, str(report.passed) + ' passed')}  |  "
        f"{c(WARN, str(report.warnings) + ' warnings')}  |  "
        f"{c(FAIL, str(report.failed) + ' failed')}\n"
    )


# Minimal compliant config used by --example
_EXAMPLE = """\
hostname CORE-RTR-01
!
service password-encryption
enable secret 9 $9$XhzABCsamplehash
!
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
no ip http server
ip http secure-server
no ip source-route
!
aaa new-model
aaa authentication login default local
!
ntp server 192.168.1.10
ntp server 192.168.1.11
!
logging buffered 32768
logging host 192.168.1.20
!
banner motd ^C
  AUTHORIZED ACCESS ONLY. Disconnect immediately if unauthorized.
^C
!
line vty 0 15
 transport input ssh
 login authentication default
!
"""

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if sys.argv[1] == "--example":
        print("Auditing built-in example config...")
        report = audit_config(_EXAMPLE, device="CORE-RTR-01 (example)")
    else:
        path = sys.argv[1]
        try:
            with open(path) as fh:
                raw = fh.read()
        except FileNotFoundError:
            print(f"Error: file not found — {path}", file=sys.stderr)
            sys.exit(2)
        report = audit_config(raw, device=path)

    print_report(report, color=sys.stdout.isatty())
    sys.exit(1 if report.failed > 0 else 0)