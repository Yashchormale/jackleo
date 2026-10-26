#!/usr/bin/env python3
"""
================================================================================
  portscan.py - Authorized Port Scanner, Service Fingerprinter & CVE Matcher
================================================================================

LEGAL NOTICE
------------
For authorized security testing ONLY - systems you own or have explicit
written permission to test.

This tool has two tiers of checks:

  1. PASSIVE (always on): connects to ports, reads service banners, and
     compares product/version strings against a small built-in table of
     publicly known CVEs. Sends nothing beyond a harmless protocol
     greeting (a plain HTTP GET, an SMTP EHLO, etc).

  2. AUXILIARY / ACTIVE (opt-in via --aux-scan, msf auxiliary/scanner
     style): performs a small, safe, non-destructive protocol interaction
     to confirm a misconfiguration - e.g. attempting an anonymous FTP
     login, or issuing an unauthenticated INFO/stats command to Redis or
     Memcached. These are still read-only / non-destructive (no data is
     written, deleted, or modified, and no credential brute-forcing or
     exploitation is performed), but they DO constitute an actual
     authentication/interaction attempt against the target, not just a
     banner read. Only run --aux-scan against systems you are explicitly
     authorized to test.

WHAT IT DOES
------------
  1. Resolves / expands the target (single IP, hostname, or CIDR block).
  2. Multithreaded TCP connect scan across a port list (top common ports
     by default, or --full for all 65535).
  3. For every open port, grabs a banner and applies light protocol-aware
     parsing to pull out a product name + version (FTP, SSH, SMTP, HTTP/S,
     POP3/IMAP(+S), MySQL).
  4. Matches product+version against a small built-in CVE signature table
     and flags any hits with severity, CVE ID, and a remediation note.
  5. (Optional, --aux-scan) Runs a handful of auxiliary/scanner-style
     misconfiguration checks (anonymous FTP, unauthenticated Redis /
     Memcached / MongoDB / Elasticsearch, VNC "None" auth) similar in
     spirit to Metasploit's auxiliary/scanner/* modules.
  6. A rough TTL-based OS guess (heuristic only - treat it as a hint, not
     a fact).
  7. Prints a clean, tabular colored summary in the terminal and can
     optionally write a JSON report.

REQUIREMENTS
------------
  - Python 3.8+
  - Optional: pip install rich   (colored table output; falls back to a
    clean plain-text table if not installed)

USAGE
-----
    python3 portscan.py <target>                       # top common ports
    python3 portscan.py <target> --full                 # all 65535 ports
    python3 portscan.py <target> --aux-scan             # + active misconfig checks
    python3 portscan.py 10.0.0.0/28 --threads 300        # scan a subnet
    python3 portscan.py <target> --json out.json        # also save JSON report
    python3 portscan.py <target> -v                     # verbose reachability diagnostics
================================================================================
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import textwrap
import time
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box as rich_box
    _HAVE_RICH = True
    console = Console(highlight=False)
except ImportError:
    _HAVE_RICH = False
    console = None

TOOL_NAME = "JACKLEO"
TOOL_VERSION = "4.3"


def out(text: str = "") -> None:
    """Print with rich markup if available, else print plain (markup stripped)."""
    if _HAVE_RICH:
        console.print(text)
    else:
        print(re.sub(r"\[/?[a-zA-Z0-9 _]*\]", "", text), flush=True)


# ==========================================================================
# 0. BANNER / LOGO
# ==========================================================================
# Each entry in this dict is a 5-row block-letter glyph (5 rows tall,
# monospace-safe). Verified by construction rather than hand-drawn, so it
# always spells the right word regardless of terminal font.
_GLYPH_ROWS = 5

_GLYPHS: Dict[str, List[str]] = {
    "J": [
        "#####",
        "   # ",
        "   # ",
        "#  # ",
        " ##  ",
    ],
    "A": [
        " ### ",
        "#   #",
        "#####",
        "#   #",
        "#   #",
    ],
    "C": [
        " ####",
        "#    ",
        "#    ",
        "#    ",
        " ####",
    ],
    "K": [
        "#   #",
        "#  # ",
        "###  ",
        "#  # ",
        "#   #",
    ],
    "L": [
        "#    ",
        "#    ",
        "#    ",
        "#    ",
        "#####",
    ],
    "E": [
        "#####",
        "#    ",
        "#### ",
        "#    ",
        "#####",
    ],
    "O": [
        " ### ",
        "#   #",
        "#   #",
        "#   #",
        " ### ",
    ],
    " ": [
        "  ",
        "  ",
        "  ",
        "  ",
        "  ",
    ],
}



def _render_word(word: str, gap: str = " ") -> List[str]:
    rows = ["" for _ in range(_GLYPH_ROWS)]
    letters = [_GLYPHS[ch] for ch in word]
    for i in range(_GLYPH_ROWS):
        rows[i] = gap.join(letter[i] for letter in letters)
    return rows


def print_banner() -> None:
    logo_lines = _render_word(TOOL_NAME)
    tagline = "Authorized Recon  \u2022  CVE Matching  \u2022  Auxiliary Scanner"
    version_line = f"v{TOOL_VERSION}   |   legal use only - authorized targets"
    inner_width = max(len(l) for l in logo_lines + [tagline, version_line])
    border = "+" + "-" * (inner_width + 4) + "+"

    lines = [border]
    for l in logo_lines:
        lines.append(f"|  {l.center(inner_width)}  |")
    lines.append(f"|  {tagline.center(inner_width)}  |")
    lines.append(f"|  {version_line.center(inner_width)}  |")
    lines.append(border)

    if _HAVE_RICH:
        console.print()
        for i, line in enumerate(lines):
            style = "bold cyan" if 0 < i <= len(logo_lines) else "dim"
            console.print(line, style=style)
        console.print()
    else:
        print()
        for line in lines:
            print(line)
        print()


# ==========================================================================
# 1. PORT LISTS
# ==========================================================================
TOP_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 993, 995, 1433, 1521, 1723, 2049, 2082, 2083,
    2181, 27017, 3000, 3268, 3306, 3389, 3690, 5000, 5432, 5601, 5900,
    5985, 6379, 6443, 6667, 8000, 8008, 8080, 8081, 8088, 8443, 8888,
    9000, 9042, 9090, 9092, 9200, 9300, 11211, 27018, 50000,
]

SERVICE_NAMES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap2", 161: "snmp", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "submissions", 514: "syslog",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 6667: "ircd",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb",
}


def service_name(port: int) -> str:
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ==========================================================================
# 2. DATA MODELS
# ==========================================================================
@dataclass
class Finding:
    cve: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    description: str
    remediation: str
    cvss: Optional[float] = None
    source: str = "cve"    # "cve" or "aux"
    msf_module: str = ""   # module name only, no exploit code


@dataclass
class PortResult:
    port: int
    service: str
    product: str = ""
    version: str = ""
    banner: str = ""
    findings: List[Finding] = field(default_factory=list)
    # Metasploit discovery results. These are module names only; JACKLEO
    # never executes exploit/auxiliary modules.
    msf_auxiliary: List[str] = field(default_factory=list)
    msf_exploit: List[str] = field(default_factory=list)

    @property
    def product_version(self) -> str:
        return " ".join(x for x in (self.product, self.version) if x)


@dataclass
class HostResult:
    target_input: str
    ip: str
    os_guess: str = "Unknown"
    os_confidence: int = 0
    ports: List[PortResult] = field(default_factory=list)
    host_findings: List[Finding] = field(default_factory=list)
    scan_seconds: float = 0.0
    nmap_vuln_results: List[Dict[str, Any]] = field(default_factory=list)
    nmap_all_results: List[Dict[str, Any]] = field(default_factory=list)


SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "INFO": "bold blue",
}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


# ===========================================================================
# 2b. DEEP NMAP / METASPLOIT DISCOVERY
# ===========================================================================
# These integrations DISCOVER and report findings/modules only. They never
# execute exploit modules, brute-force credentials, or modify the target.

NMAP_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _severity_from_nmap(script_id: str, output: str) -> str:
    text = f"{script_id} {output}".lower()
    if "vulnerable" in text and any(x in text for x in ("remote code execution", "rce", "command execution", "arbitrary code")):
        return "CRITICAL"
    if "vulnerable" in text:
        return "HIGH"
    if any(x in text for x in ("remote code execution", "rce", "arbitrary command", "auth bypass")):
        return "CRITICAL"
    if any(x in text for x in ("dos", "denial of service", "authentication bypass", "privilege escalation")):
        return "HIGH"
    if any(x in text for x in ("anonymous", "unauthenticated", "weak authentication", "default credentials")):
        return "HIGH"
    if any(x in text for x in ("disclosure", "exposure", "information leak", "weak cipher", "ssl", "tls")):
        return "MEDIUM"
    if any(x in text for x in ("deprecated", "version", "header", "certificate")):
        return "LOW"
    return "INFO"


def _extract_cves(text: str) -> List[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)), key=str.lower)


def _extract_cvss(text: str) -> Optional[float]:
    m = re.search(r"(?:CVSS(?:\s*(?:v[23])?)?\s*[:=]?\s*)(10(?:\.0)?|[0-9](?:\.[0-9])?)", text, re.I)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _severity_from_cvss(cvss: Optional[float], fallback: str) -> str:
    if cvss is None:
        return fallback
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0:
        return "LOW"
    return "INFO"


def _nmap_xml_root(path: str) -> Optional[ET.Element]:
    """Parse Nmap XML robustly from raw bytes."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        if not data.strip():
            return None
        return ET.fromstring(data)
    except (ET.ParseError, OSError):
        return None


def _nmap_run_to_file(cmd: List[str], timeout: int) -> Tuple[Optional[ET.Element], str, str, bool]:
    """Run Nmap to a temporary XML file and return parsed XML plus diagnostics."""
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="jackleo_nmap_", suffix=".xml")
        os.close(fd)

        full_cmd = list(cmd) + ["-oX", tmp_path]
        try:
            proc = subprocess.run(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout_b = exc.stdout or b""
            stderr_b = exc.stderr or b""
            root = _nmap_xml_root(tmp_path) if os.path.exists(tmp_path) else None
            return (
                root,
                stdout_b.decode("utf-8", errors="replace") if isinstance(stdout_b, bytes) else str(stdout_b),
                stderr_b.decode("utf-8", errors="replace") if isinstance(stderr_b, bytes) else str(stderr_b),
                True,
            )

        root = _nmap_xml_root(tmp_path) if os.path.exists(tmp_path) else None
        stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
        stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""

        if root is None and proc.returncode == 0:
            retry_path = None
            try:
                fd2, retry_path = tempfile.mkstemp(prefix="jackleo_nmap_retry_", suffix=".xml")
                os.close(fd2)
                retry_cmd = list(cmd) + ["--noninteractive", "-oX", retry_path]
                retry = subprocess.run(
                    retry_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    text=False,
                )
                root = _nmap_xml_root(retry_path) if os.path.exists(retry_path) else None
                if retry.stderr:
                    stderr += "\n" + retry.stderr.decode("utf-8", errors="replace")
                if retry.stdout:
                    stdout += "\n" + retry.stdout.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired as exc:
                return None, stdout, stderr + "\n" + str(exc), True
            finally:
                if retry_path:
                    try:
                        os.unlink(retry_path)
                    except OSError:
                        pass

        return root, stdout, stderr, False

    except FileNotFoundError:
        return None, "", "Nmap is not installed or not in PATH.", False
    except Exception as exc:
        return None, "", str(exc), False
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _nmap_service_records(root: Optional[ET.Element]) -> Dict[int, Dict[str, str]]:
    """Extract Nmap's service/version fingerprint by TCP port."""
    records: Dict[int, Dict[str, str]] = {}
    if root is None:
        return records
    for host in root.findall(".//host"):
        for port in host.findall("./ports/port"):
            if port.get("protocol", "tcp") != "tcp":
                continue
            try:
                portid = int(port.get("portid", "0"))
            except ValueError:
                continue
            state = port.find("./state")
            if state is not None and state.get("state") != "open":
                continue
            service = port.find("./service")
            if service is None:
                continue
            records[portid] = {
                "name": service.get("name", ""),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "extrainfo": service.get("extrainfo", ""),
                "tunnel": service.get("tunnel", ""),
                "cpe": service.get("cpe", ""),
            }
    return records


def run_nmap_service_detection(ip: str, ports: List[int], timeout: int = 120) -> Dict[int, Dict[str, str]]:
    """Focused -sV pass. This is what fixes services such as Samba on 139/tcp."""
    if not ports:
        return {}
    port_arg = ",".join(str(p) for p in sorted(set(ports)))
    cmd = ["nmap", "-sV", "--version-all", "-Pn", "-p", port_arg, ip]
    root, _stdout, _stderr, _timed_out = _nmap_run_to_file(cmd, timeout)
    return _nmap_service_records(root)


def _parse_nmap_xml(
    root: Optional[ET.Element],
    ip: str,
) -> Tuple[List[Finding], Dict[int, Dict[str, str]]]:
    """Parse Nmap XML into JACKLEO findings and service records.

    This parser is shared by both --script=vuln and --script=all. It only
    reports security-relevant NSE output and keeps ordinary informational
    scripts out of the vulnerability table.
    """
    findings: List[Finding] = []
    seen = set()

    if root is None:
        return findings, {}

    for host in root.findall(".//host"):
        for port in host.findall("./ports/port"):
            portid = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")

            state = port.find("./state")
            if state is not None and state.get("state") not in (None, "open"):
                continue

            for script in port.findall("./script"):
                sid = script.get("id", "nmap-script")
                output = (
                    " ".join(x.strip() for x in script.itertext() if x.strip())
                    or script.get("output", "")
                ).strip()

                if not output:
                    continue

                low = output.lower()

                # Keep only useful security/vulnerability evidence.
                security_relevant = (
                    bool(_extract_cves(output))
                    or any(k in low for k in (
                        "vulnerable",
                        "anonymous",
                        "unauthenticated",
                        "weak authentication",
                        "default credential",
                        "authentication bypass",
                        "remote code execution",
                        "command execution",
                        "privilege escalation",
                        "denial of service",
                        "dos",
                        "disclosure",
                        "information leak",
                        "exposed",
                        "misconfiguration",
                        "weak cipher",
                        "cleartext",
                        "plaintext",
                        "critical",
                        "high risk",
                    ))
                )

                if not security_relevant:
                    continue

                cvss = _extract_cvss(output)
                severity = _severity_from_cvss(
                    cvss, _severity_from_nmap(sid, output)
                )
                cves = _extract_cves(output)
                ident = ", ".join(cves) if cves else f"NMAP-{sid}"

                key = (portid, protocol, sid, ident, output[:300])
                if key in seen:
                    continue
                seen.add(key)

                findings.append(Finding(
                    cve=ident,
                    severity=severity,
                    description=(
                        f"Nmap NSE {sid} on {portid}/{protocol}: "
                        f"{output[:700]}"
                    ),
                    remediation=(
                        "Review the NSE evidence and verify it against the "
                        "vendor advisory/CVE before treating a version-only "
                        "result as confirmed."
                    ),
                    cvss=cvss,
                    source="nmap",
                    msf_module="",
                ))

    return findings, _nmap_service_records(root)


def _nmap_status(name: str, description: str, remediation: str) -> Finding:
    return Finding(cve=name, severity="INFO", description=description,
                   remediation=remediation, source="nmap", msf_module="")


def run_nmap_all(
    ip: str,
    ports: List[int],
    timeout: int = 300,
) -> Tuple[List[Finding], Dict[int, Dict[str, str]], str]:
    """Run --script=all only against JACKLEO-discovered open TCP ports."""
    if not ports:
        return [], {}, "no-open-ports"

    port_arg = ",".join(str(p) for p in sorted(set(ports)))
    cmd = ["nmap", "-sV", "-Pn", "--script=all", "-p", port_arg, ip]
    root, _stdout, stderr, timed_out = _nmap_run_to_file(cmd, timeout)

    if root is None:
        if "not installed" in stderr.lower():
            return [_nmap_status("NMAP-MISSING", stderr.strip(), "Install Nmap and ensure it is in PATH.")], {}, "error"
        if timed_out:
            return [_nmap_status("NMAP-TIMEOUT", f"Nmap --script=all timed out after {timeout}s.",
                                 "Use a longer --nmap-timeout or a narrower NSE set. Focused -sV detection is still used.")], {}, "timeout"
        detail = stderr.strip()[-600:] if stderr.strip() else "Nmap produced no usable XML."
        return [_nmap_status(
            "NMAP-OUTPUT-ERROR",
            f"Nmap completed, but JACKLEO could not parse the XML output. {detail}",
            "Run the same Nmap command manually and check Nmap/NSE errors. The focused -sV pass remains available."
        )], {}, "parse-error"

    findings: List[Finding] = []
    seen = set()
    for host in root.findall(".//host"):
        for port in host.findall("./ports/port"):
            portid = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            for script in port.findall("./script"):
                sid = script.get("id", "nmap-script")
                output = " ".join(x.strip() for x in script.itertext() if x.strip()) or script.get("output", "")
                if not output:
                    continue
                low = output.lower()
                security_relevant = (
                    bool(_extract_cves(output)) or any(k in low for k in (
                        "vulnerable", "anonymous", "unauthenticated", "weak authentication",
                        "default credential", "authentication bypass", "remote code execution",
                        "command execution", "privilege escalation", "denial of service", "dos",
                        "disclosure", "information leak", "exposed", "misconfiguration",
                        "weak cipher", "cleartext", "plaintext", "critical", "high risk",
                    ))
                )
                if not security_relevant:
                    continue
                cvss = _extract_cvss(output)
                severity = _severity_from_cvss(cvss, _severity_from_nmap(sid, output))
                cves = _extract_cves(output)
                ident = ", ".join(cves) if cves else f"NMAP-{sid}"
                key = (portid, sid, ident)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    cve=ident, severity=severity,
                    description=f"Nmap NSE {sid} on {portid}/{protocol}: {output[:700]}",
                    remediation="Review the NSE evidence and verify it against the vendor advisory/CVE before treating a version-only result as confirmed.",
                    cvss=cvss, source="nmap", msf_module="",
                ))
    return findings, _nmap_service_records(root), "ok"



def run_nmap_all_dedicated(
    ip: str,
    ports: List[int],
    timeout: int = 600,
) -> Tuple[List[Finding], Dict[int, Dict[str, str]], Dict[str, Any]]:
    """Run the requested full NSE scan as a dedicated process.

    The scan is intentionally kept separate from the normal vulnerability
    scan. JACKLEO waits for this process to finish and records its complete
    stdout/stderr, exit status and XML findings in the dedicated HTML section.
    """
    if not ports:
        return [], {}, {
            "status": "skipped",
            "script": "--script=all",
            "command": "",
            "elapsed_seconds": 0,
            "stdout": "",
            "stderr": "",
            "findings": [],
            "message": "No discovered open TCP ports."
        }

    port_arg = ",".join(str(p) for p in sorted(set(ports)))
    cmd = [
        "nmap",
        "-sV",
        "-Pn",
        "--script=all",
        "-p", port_arg,
        "-oX", "-",       # XML on stdout; captured completely as bytes.
        ip,
    ]

    started = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
        try:
            stdout_b, stderr_b = proc.communicate(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_b, stderr_b = proc.communicate()
            timed_out = True
    except FileNotFoundError:
        return [], {}, {
            "status": "nmap-not-found",
            "script": "--script=all",
            "command": " ".join(cmd),
            "elapsed_seconds": round(time.time() - started, 2),
            "stdout": "",
            "stderr": "nmap is not installed or not in PATH.",
            "findings": [],
            "message": "Nmap executable was not found."
        }
    except Exception as exc:
        return [], {}, {
            "status": "launcher-error",
            "script": "--script=all",
            "command": " ".join(cmd),
            "elapsed_seconds": round(time.time() - started, 2),
            "stdout": "",
            "stderr": str(exc),
            "findings": [],
            "message": "Could not launch the Nmap process."
        }

    elapsed = round(time.time() - started, 2)
    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")

    # Extract the XML document even if Nmap printed diagnostic text around it.
    xml_root = None
    xml_error = ""
    xml_start = stdout.find("<?xml")
    nmaprun_start = stdout.find("<nmaprun")
    if xml_start < 0 or (nmaprun_start >= 0 and nmaprun_start < xml_start):
        xml_start = nmaprun_start

    if xml_start >= 0:
        xml_text = stdout[xml_start:]
        try:
            xml_root = ET.fromstring(xml_text.encode("utf-8", errors="replace"))
        except ET.ParseError as exc:
            xml_error = str(exc)

    # A crash is determined from the actual process result/diagnostics,
    # not from an XML parser failure.
    crash_text = (stderr + "\n" + stdout).lower()
    nsock_crash = (
        "nse_nsock.cc" in crash_text
        or "assertion" in crash_text
        or "aborted" in crash_text
        or "segmentation fault" in crash_text
    )

    if timed_out:
        status = "timeout"
        message = f"Nmap --script=all did not finish within {timeout}s."
    elif proc.returncode != 0:
        status = "nmap-crash" if nsock_crash else "nmap-error"
        message = (
            "Nmap exited unexpectedly during --script=all."
            if nsock_crash
            else f"Nmap exited with return code {proc.returncode}."
        )
    elif xml_root is None:
        status = "xml-error"
        message = "Nmap completed but no valid XML document was returned."
    else:
        status = "ok"
        message = "Nmap --script=all completed successfully."

    findings: List[Finding] = []
    records: Dict[int, Dict[str, str]] = {}
    if xml_root is not None:
        findings, records = _parse_nmap_xml(xml_root, ip)

    # Keep the diagnostic section useful but bounded.
    diagnostic = stderr.strip()
    if len(diagnostic) > 12000:
        diagnostic = diagnostic[-12000:]

    run_record: Dict[str, Any] = {
        "status": status,
        "script": "--script=all",
        "command": " ".join(cmd),
        "elapsed_seconds": elapsed,
        "return_code": proc.returncode,
        "stdout_bytes": len(stdout_b),
        "stderr_bytes": len(stderr_b),
        "stdout_tail": stdout[-12000:] if stdout else "",
        "stderr": diagnostic,
        "xml_parse_error": xml_error,
        "findings": [
            {
                "id": f.cve,
                "severity": f.severity,
                "description": f.description,
                "port": f.port,
            }
            for f in findings
        ],
        "message": message,
    }
    return findings, records, run_record



def _nmap_script_run(
    ip: str,
    port: int,
    script_mode: str,
    timeout: int,
) -> Tuple[List[Finding], Dict[int, Dict[str, str]], Dict[str, Any]]:
    """Run one NSE category against one TCP port in its own Nmap process.

    This function is intentionally isolated from the full --script=all runner.
    A timeout/crash on one port cannot terminate the remaining port scans.
    """
    if script_mode not in ("vuln", "all"):
        raise ValueError("script_mode must be 'vuln' or 'all'")

    # Keep each subprocess bounded. The caller can still use a larger global
    # --nmap-timeout for the dedicated --script=all scan.
    script_timeout = "20s" if script_mode == "vuln" else "30s"
    host_timeout = max(45, min(int(timeout), 120))

    cmd = [
        "nmap",
        "-sV",
        "-Pn",
        "--script", script_mode,
        "--script-timeout", script_timeout,
        "--host-timeout", f"{host_timeout}s",
        "-p", str(port),
        "-oX", "-",
        ip,
    ]

    started = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
        try:
            stdout_b, stderr_b = proc.communicate(
                timeout=max(host_timeout + 20, 60)
            )
            timed_out = False
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_b, stderr_b = proc.communicate()
            timed_out = True
    except FileNotFoundError:
        return [], {}, {
            "port": port,
            "script": f"--script={script_mode}",
            "command": " ".join(cmd),
            "status": "nmap-not-found",
            "elapsed_seconds": round(time.time() - started, 2),
            "return_code": None,
            "stdout": "",
            "stderr": "nmap is not installed or not in PATH.",
            "findings": [],
            "message": "Nmap executable was not found.",
        }
    except Exception as exc:
        return [], {}, {
            "port": port,
            "script": f"--script={script_mode}",
            "command": " ".join(cmd),
            "status": "launcher-error",
            "elapsed_seconds": round(time.time() - started, 2),
            "return_code": None,
            "stdout": "",
            "stderr": str(exc),
            "findings": [],
            "message": "Could not launch Nmap.",
        }

    elapsed = round(time.time() - started, 2)
    stdout = (stdout_b or b"").decode("utf-8", errors="replace")
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")

    # Nmap XML is normally stdout because -oX - is used. Locate the XML even
    # if diagnostics were printed before it.
    xml_root = None
    xml_error = ""
    xml_start = stdout.find("<?xml")
    nmaprun_start = stdout.find("<nmaprun")
    if xml_start < 0 or (nmaprun_start >= 0 and nmaprun_start < xml_start):
        xml_start = nmaprun_start

    if xml_start >= 0:
        try:
            xml_root = ET.fromstring(stdout[xml_start:].encode(
                "utf-8", errors="replace"
            ))
        except ET.ParseError as exc:
            xml_error = str(exc)

    diagnostics = (stderr + "\n" + stdout).strip()
    lower_diag = diagnostics.lower()
    nmap_crash = any(marker in lower_diag for marker in (
        "nse_nsock.cc",
        "assertion",
        "segmentation fault",
        "aborted",
        "core dumped",
    ))

    if timed_out:
        status = "timeout"
        message = f"Nmap --script={script_mode} exceeded its isolated timeout."
    elif proc.returncode != 0:
        status = "nmap-crash" if nmap_crash else "nmap-error"
        message = (
            f"Nmap --script={script_mode} crashed during {port}/tcp."
            if nmap_crash
            else f"Nmap --script={script_mode} exited with code {proc.returncode}."
        )
    elif xml_root is None:
        status = "xml-error"
        message = (
            f"Nmap --script={script_mode} completed without usable XML "
            f"for {port}/tcp."
        )
    else:
        status = "ok"
        message = f"Nmap --script={script_mode} completed for {port}/tcp."

    findings: List[Finding] = []
    records: Dict[int, Dict[str, str]] = {}

    if xml_root is not None:
        findings, records = _parse_nmap_xml(xml_root, ip)

    diagnostic_tail = stderr.strip()
    if len(diagnostic_tail) > 5000:
        diagnostic_tail = diagnostic_tail[-5000:]

    run_record = {
        "port": port,
        "script": f"--script={script_mode}",
        "command": " ".join(cmd),
        "status": status,
        "elapsed_seconds": elapsed,
        "return_code": proc.returncode,
        "stdout": stdout[-5000:] if stdout else "",
        "stderr": diagnostic_tail,
        "xml_parse_error": xml_error,
        "findings": [
            {
                "id": f.cve,
                "severity": f.severity,
                "description": f.description,
                "port": getattr(f, "port", None),
            }
            for f in findings
        ],
        "message": message,
    }

    return findings, records, run_record


def run_nmap_category_isolated(
    ip: str, ports: List[int], script_mode: str, timeout: int
) -> Tuple[List[Finding], Dict[int, Dict[str, str]], List[Dict[str, Any]]]:
    """Run the requested Nmap category one port at a time."""
    findings: List[Finding] = []
    records: Dict[int, Dict[str, str]] = {}
    runs: List[Dict[str, Any]] = []

    for port in sorted(set(ports)):
        f, r, run = _nmap_script_run(ip, port, script_mode, timeout)
        findings.extend(f)
        records.update(r)
        runs.append(run)

    return findings, records, runs



def _run_msf_search(term: str, timeout: int = 60) -> List[str]:
    """Discover Metasploit auxiliary/exploit module names only.

    This function never loads, configures, runs, or exploits a module.
    """
    if not term.strip():
        return []
    query = re.sub(r"[^A-Za-z0-9._:+/-]+", " ", term).strip()[:140]
    if not query:
        return []

    # One read-only Metasploit search. We deliberately search the local
    # module database and return only module paths.
    cmd = ["msfconsole", "-q", "-x", f"search {query}; exit"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []

    modules: List[str] = []
    for line in (proc.stdout + "\n" + proc.stderr).splitlines():
        # Typical msfconsole search rows contain a module path such as:
        # exploit/unix/ftp/vsftpd_234_backdoor
        # auxiliary/scanner/ssh/ssh_version
        for m in re.finditer(r"\b((?:exploit|auxiliary)/[A-Za-z0-9_./-]+)", line):
            mod = m.group(1).rstrip(".,;)")
            if mod not in modules:
                modules.append(mod)
    return modules


def _module_tokens(value: str) -> List[str]:
    """Useful lowercase tokens for relevance scoring."""
    return [t for t in re.findall(r"[a-z0-9]+", value.lower()) if len(t) >= 3]


def _module_relevance(module: str, product: str, version: str, service: str, kind: str) -> int:
    """Score a Metasploit module for this specific service fingerprint.

    Higher score = more likely to be useful. This intentionally filters broad
    Metasploit search noise instead of dumping every module returned by `search`.
    """
    m = module.lower()
    score = 0
    service_l = service.lower()
    product_tokens = _module_tokens(product)
    version_tokens = _module_tokens(version)

    if version and version.lower() in m:
        score += 12
    for token in version_tokens:
        if token in m:
            score += 6
    for token in product_tokens:
        if token in m:
            score += 5

    service_aliases = {
        "http-proxy": ["http"], "https-alt": ["http", "https"],
        "submission": ["smtp"], "submissions": ["smtp"],
        "microsoft-ds": ["smb", "samba"], "netbios-ssn": ["netbios", "smb", "samba"],
        "netbios-ns": ["netbios", "smb"], "domain": ["dns"],
        "postgresql": ["postgres", "postgresql"], "ms-sql-s": ["mssql", "ms_sql"],
        "vnc": ["vnc"], "ircd": ["irc", "ircd", "unrealirc"], "rpcbind": ["rpcbind", "rpc"],
        "nfs": ["nfs"], "ftp": ["ftp"], "ssh": ["ssh"], "mysql": ["mysql"],
    }
    aliases = service_aliases.get(service_l, [service_l])
    if any(a and a in m for a in aliases):
        score += 5

    if kind == "auxiliary":
        # Prefer scanner modules; suppress broad admin/server/capture noise unless
        # the module is strongly product/version specific.
        if "/scanner/" in m:
            score += 4
        elif any(x in m for x in ("/admin/", "/server/", "/capture/")):
            score -= 5
    else:
        # Generic exploit buckets are not useful without a product/service match.
        if m.endswith("/windows") or m.endswith("/unix") or m.endswith("/multi"):
            score -= 10

    return score


def _select_important_modules(modules: List[str], product: str, version: str,
                              service: str, kind: str, limit: int = 6) -> List[str]:
    """Return only high-relevance module candidates, sorted best-first."""
    scored = []
    for mod in modules:
        score = _module_relevance(mod, product, version, service, kind)
        # Require meaningful evidence that the module maps to this service.
        minimum = 5
        if score >= minimum:
            scored.append((score, mod))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [m for _, m in scored[:limit]]


def discover_msf_modules(product: str, version: str, service: str) -> Dict[str, List[str]]:
    """Find only relevant Metasploit auxiliary/exploit module candidates.

    Results are candidates only. A module appearing here does NOT prove the
    target is vulnerable. Broad generic modules are deliberately suppressed.
    """
    terms: List[str] = []
    if product and version:
        terms.append(f"{product} {version}")
    elif product:
        terms.append(product)
    service_terms = {
        "netbios-ssn": ["smb", "samba", "netbios"],
        "microsoft-ds": ["smb", "samba"],
        "ircd": ["irc", "unrealircd"], "domain": ["dns"],
        "rpcbind": ["rpcbind"], "nfs": ["nfs"],
        "postgresql": ["postgres"], "ms-wbt-server": ["rdp"],
    }
    if service:
        terms.extend(service_terms.get(service.lower(), [service]))

    all_modules: List[str] = []
    for term in terms[:3]:
        for mod in _run_msf_search(term):
            if mod not in all_modules:
                all_modules.append(mod)

    auxiliary = [m for m in all_modules if m.startswith("auxiliary/")]
    exploit = [m for m in all_modules if m.startswith("exploit/")]
    return {
        "auxiliary": _select_important_modules(auxiliary, product, version, service, "auxiliary"),
        "exploit": _select_important_modules(exploit, product, version, service, "exploit"),
    }


# ==========================================================================
# 3. CVE SIGNATURE TABLE (passive - version string based)
# ==========================================================================
def _version_lt(version: str, ceiling: Tuple[int, ...]) -> bool:
    try:
        parts = tuple(int(p) for p in re.findall(r"\d+", version)[:len(ceiling)])
    except ValueError:
        return False
    return parts < ceiling if parts else False


CVE_SIGNATURES: List[Dict[str, Any]] = [
    {
        "services": {"ssh"},
        "product_re": re.compile(r"OpenSSH", re.I),
        "check": lambda v: _version_lt(v, (7, 7)),
        "finding": Finding(
            cve="CVE-2018-15473",
            severity="MEDIUM",
            cvss=5.3,
            description="OpenSSH versions before 7.7 allow remote username "
                        "enumeration via a timing/response difference in "
                        "authentication packet handling.",
            remediation="Upgrade OpenSSH to 7.7 or later.",
            msf_module="auxiliary/scanner/ssh/ssh_enumusers",
        ),
    },
    {
        "services": {"ftp"},
        "product_re": re.compile(r"vsftpd", re.I),
        "check": lambda v: v.strip() == "2.3.4",
        "finding": Finding(
            cve="CVE-2011-2523",
            severity="CRITICAL",
            cvss=None,
            description="vsftpd 2.3.4 as distributed from a compromised "
                        "upstream contained a backdoor allowing unauthenticated "
                        "remote command execution triggered by a ':)' in the "
                        "username during login.",
            remediation="Replace this binary immediately - it is a known "
                        "backdoored build, not a normal vulnerable version. "
                        "Reinstall vsftpd from an official, verified source.",
            msf_module="exploit/unix/ftp/vsftpd_234_backdoor",
        ),
    },
    {
        "services": {"ftp"},
        "product_re": re.compile(r"ProFTPD", re.I),
        "check": lambda v: v.strip().startswith("1.3.5"),
        "finding": Finding(
            cve="CVE-2015-3306",
            severity="CRITICAL",
            cvss=9.8,
            description="ProFTPD 1.3.5's mod_copy module allows unauthenticated "
                        "attackers to copy files anywhere on the filesystem via "
                        "SITE CPFR/CPTO, which can lead to remote code execution.",
            remediation="Upgrade ProFTPD past 1.3.5, or disable mod_copy if "
                        "not required.",
            msf_module="exploit/unix/ftp/proftpd_modcopy_exec",
        ),
    },
    {
        "services": {"smtp", "submission", "submissions"},
        "product_re": re.compile(r"Exim", re.I),
        "check": lambda v: _version_lt(v, (4, 92)),
        "finding": Finding(
            cve="CVE-2019-10149",
            severity="CRITICAL",
            cvss=9.8,
            description="Exim versions 4.87-4.91 ('Return of the WIZard') "
                        "contain a remote code execution flaw reachable via "
                        "crafted RCPT TO addresses under certain configurations.",
            remediation="Upgrade Exim to 4.92 or later.",
            msf_module="exploit/unix/smtp/exim4_string_format",
        ),
    },
    {
        "services": {"http", "https", "http-proxy", "https-alt"},
        "product_re": re.compile(r"Apache", re.I),
        "check": lambda v: v.strip() in ("2.4.49", "2.4.50"),
        "finding": Finding(
            cve="CVE-2021-41773 / CVE-2021-42013",
            severity="CRITICAL",
            cvss=9.8,
            description="Apache HTTP Server 2.4.49/2.4.50 path traversal flaw "
                        "that can lead to source disclosure or, where CGI is "
                        "enabled, remote code execution.",
            remediation="Upgrade Apache httpd to 2.4.51 or later immediately.",
            msf_module="exploit/multi/http/apache_normalize_path_rce",
        ),
    },
]


def match_cve_signatures(svc: str, product: str, version: str) -> List[Finding]:
    if not product or not version:
        return []
    hits = []
    for sig in CVE_SIGNATURES:
        if svc not in sig["services"]:
            continue
        if not sig["product_re"].search(product):
            continue
        try:
            if sig["check"](version):
                hits.append(sig["finding"])
        except Exception:
            continue
    return hits


# ==========================================================================
# 3b. AUXILIARY / ACTIVE MISCONFIGURATION SCANNERS (msf auxiliary/scanner style)
# ==========================================================================
def _aux_finding(name: str, severity: str, description: str, remediation: str,
                  msf_module: str = "") -> Finding:
    return Finding(cve=f"MISCONFIG-{name}", severity=severity, cvss=None,
                    description=description, remediation=remediation, source="aux",
                    msf_module=msf_module)


def aux_check_ftp_anonymous(ip: str, port: int, timeout: float) -> Optional[Finding]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.recv(512)
            sock.sendall(b"USER anonymous\r\n")
            resp = sock.recv(512).decode(errors="ignore")
            if not resp.startswith("331"):
                return None
            sock.sendall(b"PASS anonymous@example.com\r\n")
            resp2 = sock.recv(512).decode(errors="ignore")
            if resp2.startswith("230"):
                return _aux_finding(
                    "FTP-ANON", "MEDIUM",
                    "FTP server accepts anonymous login (USER anonymous / "
                    "any password), allowing unauthenticated file listing "
                    "and potentially download/upload depending on permissions.",
                    "Disable anonymous FTP access unless explicitly required, "
                    "and restrict anonymous write/upload permissions.",
                    msf_module="auxiliary/scanner/ftp/anonymous",
                )
    except Exception:
        pass
    return None


def aux_check_redis_unauth(ip: str, port: int, timeout: float) -> Optional[Finding]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"INFO\r\n")
            resp = sock.recv(2048).decode(errors="ignore")
            if "redis_version" in resp.lower():
                return _aux_finding(
                    "REDIS-NOAUTH", "CRITICAL",
                    "Redis instance responds to INFO without authentication, "
                    "exposing server internals and allowing full unauthenticated "
                    "read/write access to stored data.",
                    "Set 'requirepass' in redis.conf, bind Redis to localhost "
                    "or a trusted interface, and enable protected-mode.",
                    msf_module="auxiliary/scanner/redis/redis_server",
                )
    except Exception:
        pass
    return None


def aux_check_memcached_unauth(ip: str, port: int, timeout: float) -> Optional[Finding]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"stats\r\n")
            resp = sock.recv(2048).decode(errors="ignore")
            if resp.startswith("STAT"):
                return _aux_finding(
                    "MEMCACHED-EXPOSED", "HIGH",
                    "Memcached is reachable and answering 'stats' on a network "
                    "interface with no authentication (memcached has no built-in "
                    "auth). Exposed memcached instances are commonly abused for "
                    "data disclosure and large UDP amplification DDoS.",
                    "Bind memcached to localhost/private interfaces only, block "
                    "the port at the firewall, and disable the UDP listener "
                    "(-U 0) if UDP isn't required.",
                    msf_module="auxiliary/gather/memcached_extractor",
                )
    except Exception:
        pass
    return None


def aux_check_mongodb_unauth(ip: str, port: int, timeout: float) -> Optional[Finding]:
    try:
        key = b"isMaster\x00"
        elem = b"\x10" + key + struct.pack("<i", 1)
        body = elem + b"\x00"
        bson_doc = struct.pack("<i", 4 + len(body)) + body

        flags = struct.pack("<i", 0)
        full_collection_name = b"admin.$cmd\x00"
        number_to_skip = struct.pack("<i", 0)
        number_to_return = struct.pack("<i", -1)
        query = flags + full_collection_name + number_to_skip + number_to_return + bson_doc

        header = struct.pack("<iiii", 16 + len(query), 1, 0, 2004)
        message = header + query

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(message)
            resp = sock.recv(2048)
            if len(resp) > 16 and b"ismaster" in resp.lower():
                return _aux_finding(
                    "MONGODB-NOAUTH", "CRITICAL",
                    "MongoDB responds to an isMaster query with no authentication, "
                    "indicating authorization is disabled and the database is "
                    "likely fully readable/writable by anyone who can reach it.",
                    "Enable MongoDB authentication (security.authorization: "
                    "enabled), bind to trusted interfaces only, and enforce "
                    "network-level access control.",
                    msf_module="auxiliary/scanner/mongodb/mongodb_login",
                )
    except Exception:
        pass
    return None


def aux_check_elasticsearch_unauth(ip: str, port: int, timeout: float) -> Optional[Finding]:
    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        raw_sock.sendall(
            f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
        )
        resp = b""
        try:
            while True:
                chunk = raw_sock.recv(2048)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 4096:
                    break
        except socket.timeout:
            pass
        finally:
            raw_sock.close()

        text = resp.decode(errors="ignore")
        if "cluster_name" in text and "401 " not in text.split("\r\n")[0]:
            return _aux_finding(
                "ELASTIC-NOAUTH", "HIGH",
                "Elasticsearch cluster info is readable with no authentication, "
                "exposing cluster/version metadata and typically full index "
                "read/write access via the REST API.",
                "Enable Elasticsearch security features (authentication + TLS), "
                "or place the cluster behind a network boundary / reverse proxy "
                "that enforces auth.",
                msf_module="auxiliary/scanner/http/elasticsearch_traversal",
            )
    except Exception:
        pass
    return None


def aux_check_vnc_noauth(ip: str, port: int, timeout: float) -> Optional[Finding]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            server_version = sock.recv(12)
            if not server_version.startswith(b"RFB"):
                return None
            sock.sendall(server_version)
            num_types_byte = sock.recv(1)
            if not num_types_byte:
                return None
            num_types = num_types_byte[0]
            if num_types == 0:
                return None
            sec_types = sock.recv(num_types)
            if 1 in sec_types:
                return _aux_finding(
                    "VNC-NOAUTH", "CRITICAL",
                    "VNC server offers security type 'None', meaning any client "
                    "can obtain full remote desktop control with no password.",
                    "Configure the VNC server to require VNC/password "
                    "authentication (or tunnel VNC over SSH) and remove the "
                    "'None' security type.",
                    msf_module="auxiliary/scanner/vnc/vnc_none_auth",
                )
    except Exception:
        pass
    return None


AUX_CHECKS: Dict[str, List[Callable[[str, int, float], Optional[Finding]]]] = {
    "ftp": [aux_check_ftp_anonymous],
    "redis": [aux_check_redis_unauth],
    "memcached": [aux_check_memcached_unauth],
    "mongodb": [aux_check_mongodb_unauth],
    "elasticsearch": [aux_check_elasticsearch_unauth],
    "vnc": [aux_check_vnc_noauth],
}


def run_aux_checks(ip: str, port: int, svc: str, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    for check in AUX_CHECKS.get(svc, []):
        try:
            result = check(ip, port, timeout)
        except Exception:
            result = None
        if result:
            findings.append(result)
    return findings


# ==========================================================================
# 4. TARGET HANDLING
# ==========================================================================
def expand_target(raw: str, max_hosts: int = 256) -> List[str]:
    raw = raw.strip()
    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        hosts = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
        return hosts[:max_hosts]
    try:
        ipaddress.ip_address(raw)
        return [raw]
    except ValueError:
        pass
    try:
        return [socket.gethostbyname(raw)]
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve '{raw}': {exc}")


def guess_os_by_ttl(ip: str, verbose: bool = False) -> Tuple[str, int]:
    is_windows_host = sys.platform.startswith("win")
    cmd = ["ping", "-n" if is_windows_host else "-c", "1",
           "-w" if is_windows_host else "-W", "2" if is_windows_host else "1", ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        output = proc.stdout
    except Exception as exc:
        if verbose:
            out(f"  [dim]ping failed to run: {exc}[/dim]")
        return "Unknown", 0

    match = re.search(r"ttl[=:](\d+)", output, re.I)
    if not match:
        if verbose:
            first_line = output.strip().splitlines()[0] if output.strip() else "(no output)"
            out(f"  [dim]No ICMP reply parsed from ping (host may block ICMP, "
                f"or may be unreachable): {first_line}[/dim]")
        return "Unknown", 0
    ttl = int(match.group(1))
    if ttl <= 64:
        return "Linux/Unix/macOS (TTL~64)", 50
    if ttl <= 128:
        return "Windows (TTL~128)", 50
    return "Network device / other (TTL~255)", 40


# ==========================================================================
# 5. BANNER GRABBING / PROTOCOL-AWARE FINGERPRINTING
# ==========================================================================
def _recv_banner(sock: socket.socket, size: int = 512) -> str:
    try:
        return sock.recv(size).decode(errors="ignore").strip()
    except Exception:
        return ""


def _parse_ftp(banner: str) -> Tuple[str, str]:
    m = re.search(r"\(?vsftpd\s*([\d.]+)?\)?", banner, re.I)
    if m:
        return "vsftpd", m.group(1) or ""
    m = re.search(r"ProFTPD\s*([\d.]+)?", banner, re.I)
    if m:
        return "ProFTPD", m.group(1) or ""
    m = re.search(r"Pure-FTPd", banner, re.I)
    if m:
        return "Pure-FTPd", ""
    return "", ""


def _parse_ssh(banner: str) -> Tuple[str, str]:
    m = re.search(r"SSH-[\d.]+-OpenSSH[_-]([\d.p]+)", banner, re.I)
    if m:
        return "OpenSSH", m.group(1)
    m = re.search(r"SSH-[\d.]+-(\S+)", banner)
    if m:
        return m.group(1), ""
    return "", ""


def _parse_smtp(banner: str) -> Tuple[str, str]:
    m = re.search(r"Exim\s*([\d.]+)?", banner, re.I)
    if m:
        return "Exim", m.group(1) or ""
    m = re.search(r"Postfix", banner, re.I)
    if m:
        return "Postfix", ""
    m = re.search(r"Microsoft ESMTP MAIL", banner, re.I)
    if m:
        return "Microsoft Exchange", ""
    return "", ""


def _parse_pop_imap(banner: str) -> Tuple[str, str]:
    m = re.search(r"Dovecot\s*([\d.]+)?", banner, re.I)
    if m:
        return "Dovecot", m.group(1) or ""
    m = re.search(r"Courier", banner, re.I)
    if m:
        return "Courier", ""
    return "", ""


def _parse_mysql(sock: socket.socket) -> Tuple[str, str]:
    try:
        data = sock.recv(128)
        if len(data) > 5:
            end = data.find(b"\x00", 5)
            version = data[5:end].decode(errors="ignore") if end != -1 else ""
            return "MySQL", version
    except Exception:
        pass
    return "", ""


def _parse_http(ip: str, port: int, use_tls: bool, timeout: float) -> Tuple[str, str, str]:
    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout)
        sock = ssl.create_default_context().wrap_socket(
            raw_sock, server_hostname=ip
        ) if use_tls else raw_sock
        sock.settimeout(timeout)
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        resp = b""
        try:
            while True:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 8192:
                    break
        except socket.timeout:
            pass
        finally:
            sock.close()

        text = resp.decode(errors="ignore")
        status_line = text.splitlines()[0] if text else ""
        headers = dict(
            re.findall(r"^([A-Za-z-]+):\s*(.+)$", text, re.MULTILINE)
        )
        server = headers.get("Server", "")
        date = headers.get("Date", "")

        if server:
            m = re.match(r"([A-Za-z._-]+)/?([\d.]+)?", server)
            if m:
                return m.group(1), m.group(2) or "", ""
            return server, "", ""

        fallback = " | ".join(x for x in (status_line, f"Date: {date}" if date else "") if x)
        return "", "", fallback
    except Exception:
        return "", "", ""


def fingerprint_port(ip: str, port: int, svc: str, timeout: float, nmap_record: Optional[Dict[str, str]] = None) -> PortResult:
    result = PortResult(port=port, service=svc)

    try:
        if svc in ("http", "http-proxy"):
            product, version, fallback = _parse_http(ip, port, use_tls=False, timeout=timeout)
            result.product, result.version = product, version
            result.banner = fallback
        elif svc in ("https", "https-alt"):
            product, version, fallback = _parse_http(ip, port, use_tls=True, timeout=timeout)
            result.product, result.version = product, version
            result.banner = fallback
        elif svc == "mysql":
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                result.product, result.version = _parse_mysql(sock)
        else:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner = _recv_banner(sock)
                result.banner = banner
                if svc == "ftp":
                    result.product, result.version = _parse_ftp(banner)
                elif svc == "ssh":
                    result.product, result.version = _parse_ssh(banner)
                elif svc in ("smtp", "submission", "submissions"):
                    result.product, result.version = _parse_smtp(banner)
                elif svc in ("pop3", "pop3s", "imap2", "imaps"):
                    result.product, result.version = _parse_pop_imap(banner)
    except Exception:
        pass

    if nmap_record:
        if nmap_record.get("name"):
            result.service = nmap_record["name"]
        if nmap_record.get("product"):
            result.product = nmap_record["product"]
        if nmap_record.get("version"):
            result.version = nmap_record["version"]
        if nmap_record.get("extrainfo"):
            result.banner = " ".join(x for x in (result.banner, nmap_record["extrainfo"]) if x).strip()

    result.findings = match_cve_signatures(result.service, result.product, result.version)
    return result


# ==========================================================================
# 6. PORT SCANNING
# ==========================================================================
def _try_connect(ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            err = sock.connect_ex((ip, port))
            if err == 0:
                return True, ""
            return False, os.strerror(err) if err else "refused"
    except socket.timeout:
        return False, "timed out"
    except OSError as exc:
        return False, str(exc)


def scan_host(target_input: str, ip: str, ports: List[int], threads: int,
              timeout: float, aux_scan: bool = False,
              verbose: bool = False, nmap_records: Optional[Dict[int, Dict[str, str]]] = None) -> HostResult:
    start = time.time()
    host = HostResult(target_input=target_input, ip=ip)
    os_name, os_conf = guess_os_by_ttl(ip, verbose=verbose)
    host.os_guess, host.os_confidence = os_name, os_conf

    open_ports: List[int] = []
    fail_reasons: Dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_try_connect, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port = futures[fut]
            try:
                is_open, reason = fut.result()
                if is_open:
                    open_ports.append(port)
                elif reason:
                    fail_reasons[reason] = fail_reasons.get(reason, 0) + 1
            except Exception as exc:
                fail_reasons[str(exc)] = fail_reasons.get(str(exc), 0) + 1
                continue

    if verbose and fail_reasons:
        out("  [dim]Closed/unreachable breakdown:[/dim]")
        for reason, count in sorted(fail_reasons.items(), key=lambda x: -x[1]):
            out(f"    [dim]{count:>4}x  {reason}[/dim]")
        top_reason, top_count = max(fail_reasons.items(), key=lambda x: x[1])
        if top_count >= max(1, int(0.9 * len(ports))) and top_reason.lower() in (
            "no route to host", "network is unreachable", "timed out", "host is down",
        ):
            out(f"  [bold yellow]Warning:[/bold yellow] {top_count}/{len(ports)} ports "
                f"failed with '{top_reason}'. This usually means {ip} is not actually "
                f"reachable from this machine (wrong interface, VPN/routing, or the "
                f"host is down) rather than the target simply having no open ports.")

    with ThreadPoolExecutor(max_workers=min(threads, 50)) as pool:
        futures = {
            pool.submit(fingerprint_port, ip, p, service_name(p), timeout, (nmap_records or {}).get(p)): p
            for p in open_ports
        }
        for fut in as_completed(futures):
            try:
                host.ports.append(fut.result())
            except Exception:
                continue

    if aux_scan:
        with ThreadPoolExecutor(max_workers=min(threads, 25)) as pool:
            futures = {
                pool.submit(run_aux_checks, ip, p.port, p.service, timeout): p
                for p in host.ports
            }
            for fut in as_completed(futures):
                port_result = futures[fut]
                try:
                    port_result.findings.extend(fut.result())
                except Exception:
                    continue

    host.ports.sort(key=lambda r: r.port)
    host.scan_seconds = round(time.time() - start, 2)
    return host


# ==========================================================================
# 7. DISPLAY  (table-based)
# ==========================================================================
def _wrap(text: str, width: int) -> str:
    return "\n".join(textwrap.wrap(text, width=width)) if text else ""


def _plain_table(headers: List[str], rows: List[List[str]], widths: List[int]) -> None:
    """Fallback ASCII table for environments without `rich` installed."""
    def sep(char="-", corner="+"):
        return corner + corner.join(char * (w + 2) for w in widths) + corner

    def fmt_row(cells: List[str]) -> List[str]:
        # each cell may contain '\n' (wrapped); pad all cells to equal line count
        cell_lines = [c.split("\n") if c else [""] for c in cells]
        height = max(len(cl) for cl in cell_lines)
        lines = []
        for i in range(height):
            parts = []
            for cl, w in zip(cell_lines, widths):
                text = cl[i] if i < len(cl) else ""
                parts.append(f" {text:<{w}} ")
            lines.append("|" + "|".join(parts) + "|")
        return lines

    print(sep("="))
    for line in fmt_row(headers):
        print(line)
    print(sep("="))
    for row in rows:
        for line in fmt_row(row):
            print(line)
        print(sep("-"))


def _compact_module_list(modules: List[str], max_each: int = 4) -> str:
    """Keep the table readable: show only the most relevant module names."""
    if not modules:
        return "-"
    shown = modules[:max_each]
    text = "\n".join(shown)
    if len(modules) > max_each:
        text += f"\n... +{len(modules) - max_each} more"
    return text


def render_ports_table(host: HostResult) -> None:
    headers = ["PORT", "SERVICE", "PRODUCT / VERSION", "RISK", "FINDINGS", "AUXILIARY", "EXPLOIT"]
    if _HAVE_RICH:
        table = Table(title=f"Open Ports â€” {host.ip}", box=rich_box.SQUARE_DOUBLE_HEAD,
                      header_style="bold cyan", show_lines=False, expand=False)
        table.add_column("PORT", style="bold", no_wrap=True)
        table.add_column("SERVICE", no_wrap=True)
        table.add_column("PRODUCT / VERSION", style="green")
        table.add_column("RISK", no_wrap=True)
        table.add_column("FINDINGS")
        table.add_column("AUXILIARY", max_width=38)
        table.add_column("EXPLOIT", max_width=38)
        for p in host.ports:
            pv = p.product_version or p.banner or "-"
            if p.findings:
                worst = max(p.findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0))
                tag = "NMAP" if any(f.source == "nmap" for f in p.findings) else ("MISCONFIG" if all(f.source == "aux" for f in p.findings) else "CVE")
                risk_txt = f"[{SEVERITY_STYLE[worst.severity]}]{worst.severity}[/{SEVERITY_STYLE[worst.severity]}]"
                findings_txt = f"{len(p.findings)} finding(s) ({tag})"
            else:
                risk_txt = "[dim]INFO[/dim]"
                findings_txt = "-"
            aux_txt = _compact_module_list(getattr(p, "msf_auxiliary", []) or [], 4)
            exp_txt = _compact_module_list(getattr(p, "msf_exploit", []) or [], 4)
            table.add_row(f"{p.port}/tcp", p.service, pv, risk_txt, findings_txt, aux_txt, exp_txt)
        console.print(table)
    else:
        widths = [10, 13, 30, 9, 24, 34, 34]
        rows = []
        for p in host.ports:
            pv = p.product_version or p.banner or "-"
            if p.findings:
                worst = max(p.findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0))
                findings_txt = f"{len(p.findings)} finding(s) (worst: {worst.severity})"
            else:
                findings_txt = "-"
            rows.append([
                _wrap(f"{p.port}/tcp", widths[0]), _wrap(p.service, widths[1]),
                _wrap(pv, widths[2]), _wrap(worst.severity if p.findings else "INFO", widths[3]),
                _wrap(findings_txt, widths[4]),
                _wrap(_compact_module_list(getattr(p, "msf_auxiliary", []) or [], 4), widths[5]),
                _wrap(_compact_module_list(getattr(p, "msf_exploit", []) or [], 4), widths[6]),
            ])
        _plain_table(headers, rows, widths=widths)


def render_msf_modules_table(host: HostResult) -> None:
    """Show only selected important modules in separate auxiliary/exploit columns."""
    rows_data = []
    for p in host.ports:
        aux = getattr(p, "msf_auxiliary", []) or []
        exp = getattr(p, "msf_exploit", []) or []
        if aux or exp:
            rows_data.append((p, _compact_module_list(aux, 6), _compact_module_list(exp, 6)))

    if not rows_data:
        return

    out("\n[bold]Important Metasploit Module Candidates[/bold]")
    if _HAVE_RICH:
        table = Table(box=rich_box.SQUARE_DOUBLE_HEAD, header_style="bold cyan",
                      show_lines=True, expand=False)
        table.add_column("PORT", no_wrap=True)
        table.add_column("AUXILIARY", max_width=48, style="yellow")
        table.add_column("EXPLOIT", max_width=48, style="red")
        for p, aux, exp in rows_data:
            table.add_row(f"{p.port}/{p.service}", aux, exp)
        console.print(table)
    else:
        headers = ["PORT", "AUXILIARY", "EXPLOIT"]
        rows = [[_wrap(f"{p.port}/{p.service}", 14), _wrap(aux, 48), _wrap(exp, 48)]
                for p, aux, exp in rows_data]
        _plain_table(headers, rows, [14, 48, 48])


def render_findings_table(host: HostResult) -> None:
    all_findings: List[Tuple[PortResult, Finding]] = [
        (p, f) for p in host.ports for f in p.findings
    ]
    if not all_findings:
        return
    all_findings.sort(key=lambda pf: -SEVERITY_RANK.get(pf[1].severity, 0))

    headers = ["PORT", "TYPE", "ID", "SEVERITY", "DESCRIPTION", "REMEDIATION", "MSF MODULE"]
    if _HAVE_RICH:
        table = Table(title="Findings Detail", box=rich_box.SQUARE_DOUBLE_HEAD,
                       header_style="bold cyan", show_lines=True, expand=False)
        table.add_column("PORT", no_wrap=True)
        table.add_column("TYPE", no_wrap=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("SEVERITY", no_wrap=True)
        table.add_column("DESCRIPTION", max_width=42)
        table.add_column("REMEDIATION", max_width=32)
        table.add_column("MSF MODULE", max_width=28, style="dim")
        for p, f in all_findings:
            type_tag = "MISCONFIG" if f.source == "aux" else ("NMAP" if f.source == "nmap" else "CVE")
            sev_style = SEVERITY_STYLE[f.severity]
            table.add_row(
                f"{p.port}/{p.service}",
                type_tag,
                f.cve,
                f"[{sev_style}]{f.severity}[/{sev_style}]",
                f.description,
                f.remediation,
                f.msf_module or "-",
            )
        console.print(table)
    else:
        widths = [12, 10, 24, 8, 40, 30, 28]
        rows = []
        for p, f in all_findings:
            type_tag = "MISCONFIG" if f.source == "aux" else ("NMAP" if f.source == "nmap" else "CVE")
            rows.append([
                _wrap(f"{p.port}/{p.service}", widths[0]),
                _wrap(type_tag, widths[1]),
                _wrap(f.cve, widths[2]),
                _wrap(f.severity, widths[3]),
                _wrap(f.description, widths[4]),
                _wrap(f.remediation, widths[5]),
                _wrap(f.msf_module or "-", widths[6]),
            ])
        _plain_table(headers, rows, widths=widths)


def is_host_live(host: HostResult) -> bool:
    """A host counts as 'live' if it answered ICMP (ping succeeded, giving
    an OS guess) or had at least one open TCP port - either is evidence
    something is actually there, unlike a host that failed every probe."""
    return bool(host.ports) or host.os_confidence > 0


def render_subnet_summary(all_hosts: List[HostResult]) -> None:
    """Prints a one-row-per-live-host overview table for a whole-subnet
    scan: host IP, OS guess, and the open ports found on it. Shown before
    the detailed per-host tables so a /24 scan is skimmable at a glance."""
    live_hosts = [h for h in all_hosts if is_host_live(h)]
    dead_count = len(all_hosts) - len(live_hosts)

    out(f"\n[bold]Live Hosts Summary[/bold]  "
        f"({len(live_hosts)} live / {len(all_hosts)} scanned"
        + (f", {dead_count} unreachable/no response" if dead_count else "") + ")")

    if not live_hosts:
        out("  [dim]No live hosts found.[/dim]")
        return

    headers = ["HOST", "OS GUESS", "OPEN PORTS"]
    if _HAVE_RICH:
        table = Table(box=rich_box.SQUARE_DOUBLE_HEAD, header_style="bold cyan",
                       show_lines=False, expand=False)
        table.add_column("HOST", style="bold", no_wrap=True)
        table.add_column("OS GUESS")
        table.add_column("OPEN PORTS")
        for h in live_hosts:
            if h.ports:
                ports_txt = ", ".join(f"{p.port}/{p.service}" for p in h.ports)
            else:
                ports_txt = "[dim]none open (ping only)[/dim]"
            table.add_row(h.ip, h.os_guess, ports_txt)
        console.print(table)
    else:
        widths = [16, 26, 60]
        rows = []
        for h in live_hosts:
            if h.ports:
                ports_txt = ", ".join(f"{p.port}/{p.service}" for p in h.ports)
            else:
                ports_txt = "none open (ping only)"
            rows.append([
                _wrap(h.ip, widths[0]),
                _wrap(h.os_guess, widths[1]),
                _wrap(ports_txt, widths[2]),
            ])
        _plain_table(headers, rows, widths=widths)


def display_host(host: HostResult, thread_count: int, port_count: int, aux_scan: bool) -> Tuple[int, int]:
    out(f"\n[bold]Scanning[/bold] {host.target_input} ([cyan]{host.ip}[/cyan]) - "
        f"{port_count} ports, {thread_count} threads"
        + (" [yellow](aux-scan on)[/yellow]" if aux_scan else ""))
    out(f"  OS guess: [magenta]{host.os_guess}[/magenta] (~{host.os_confidence}%)\n")

    if not host.ports:
        out("  [dim]No open ports found.[/dim]")
    else:
        render_ports_table(host)
        render_msf_modules_table(host)
        render_findings_table(host)

    if host.host_findings:
        out("\n[bold]Host-level findings[/bold]")
        for f in host.host_findings:
            out(f"  [{SEVERITY_STYLE.get(f.severity, 'bold')}]{f.severity}[/{SEVERITY_STYLE.get(f.severity, 'bold')}] {f.cve}: {f.description}")

    cve_count = sum(1 for p in host.ports for f in p.findings if f.source == "cve")
    aux_count = sum(1 for p in host.ports for f in p.findings if f.source == "aux")
    critical_count = sum(1 for p in host.ports for f in p.findings if f.severity == "CRITICAL")

    out("")
    out(f"  [bold]Summary:[/bold] {len(host.ports)} open, {cve_count} known CVE match(es), "
        + (f"{aux_count} auxiliary misconfig(s), " if aux_scan else "")
        + f"{critical_count} critical, in {host.scan_seconds}s")
    return len(host.ports), cve_count + aux_count


# ==========================================================================
# 7b. HTML REPORT
# ==========================================================================
def sanitize_filename(name: str) -> str:
    """Turns a target string (hostname, IP, or CIDR) into a safe filename
    stem - e.g. '10.0.0.0/24' -> '10.0.0.0_24', 'example.com' stays as-is."""
    name = name.strip()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    safe = safe.strip("_.")
    return safe or "scan_target"


_HTML_SEVERITY_COLORS = {
    "CRITICAL": "#ff4d4d",
    "HIGH": "#ff9800",
    "MEDIUM": "#ffd54f",
    "LOW": "#4fc3f7",
    "INFO": "#90a4ae",
}

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  :root {{
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0; padding: 0 0 60px 0;
  }}
  header {{
    background: linear-gradient(135deg, #161b22, #0d1117);
    border-bottom: 1px solid var(--border);
    padding: 32px 5vw;
  }}
  header h1 {{
    margin: 0 0 6px 0; font-size: 28px; letter-spacing: 1px;
    color: #fff;
  }}
  header .sub {{ color: var(--muted); font-size: 14px; }}
  .container {{ padding: 24px 5vw; }}
  .summary-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px; margin-bottom: 32px;
  }}
  .card {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px 18px;
  }}
  .card .num {{ font-size: 26px; font-weight: 700; color: #fff; }}
  .card .label {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
  .card.crit .num {{ color: {crit_color}; }}
  h2 {{
    font-size: 18px; margin: 36px 0 12px 0; color: #fff;
    border-left: 4px solid var(--accent); padding-left: 10px;
  }}
  table {{
    width: 100%; border-collapse: collapse; background: var(--panel);
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
  }}
  th, td {{
    text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border);
    vertical-align: top; font-size: 13.5px;
  }}
  th {{
    background: #1c2128; color: var(--accent); text-transform: uppercase;
    font-size: 11.5px; letter-spacing: 0.5px;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1c2128; }}
  .pill {{
    display: inline-block; padding: 2px 10px; border-radius: 999px;
    font-size: 11px; font-weight: 700; color: #0d1117;
  }}
  .mono {{ font-family: "SFMono-Regular", Consolas, monospace; }}
  .msf {{
    font-family: "SFMono-Regular", Consolas, monospace; font-size: 12.5px;
    color: #79c0ff; background: #0d1117; padding: 2px 8px; border-radius: 4px;
    display: inline-block;
  }}
  .muted {{ color: var(--muted); }}
  .module-list {{ line-height: 1.45; word-break: break-word; }}
  .nmap-diagnostic {{
    white-space: pre-wrap; word-break: break-word; margin: 8px 0 0;
    padding: 8px; background: #0d1117; border: 1px solid var(--border);
    color: #f0883e; font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 11.5px;
  }}
  footer {{
    text-align: center; color: var(--muted); font-size: 12px; margin-top: 40px;
  }}
  .host-block {{ margin-bottom: 48px; }}
  .no-findings {{ color: var(--muted); font-style: italic; padding: 14px; }}
</style>
</head>
<body>
<header>
  <h1>&#128272; {tool_name} v{tool_version} &mdash; Scan Report</h1>
  <div class="sub">Target: <b>{target}</b> &nbsp;|&nbsp; Generated: {generated} &nbsp;|&nbsp;
  Mode: {mode}</div>
</header>
<div class="container">
  <div class="summary-grid">
    <div class="card"><div class="num">{host_count}</div><div class="label">Host(s) Scanned</div></div>
    <div class="card"><div class="num">{total_open}</div><div class="label">Open Ports</div></div>
    <div class="card"><div class="num">{total_findings}</div><div class="label">Total Findings</div></div>
    <div class="card crit"><div class="num">{total_critical}</div><div class="label">Critical</div></div>
  </div>
  {live_hosts_summary}
  {host_sections}
  <footer>
    Generated by {tool_name} v{tool_version} &mdash; for authorized security testing only.<br>
    This report may contain sensitive information; handle and store it accordingly.
  </footer>
</div>
</body>
</html>
"""


def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_host_html(host: HostResult) -> str:
    ports_rows = []
    for p in host.ports:
        pv = _html_escape(p.product_version or p.banner or "-")
        n_findings = len(p.findings)
        worst = max((f.severity for f in p.findings), key=lambda s: SEVERITY_RANK.get(s, 0)) \
            if p.findings else None
        badge = (
            f'<span class="pill" style="background:{_HTML_SEVERITY_COLORS[worst]}">{worst}</span>'
            if worst else '<span class="muted">-</span>'
        )
        aux = getattr(p, "msf_auxiliary", []) or []
        exp = getattr(p, "msf_exploit", []) or []
        aux_html = "".join(f'<div class="msf aux">{_html_escape(mod)}</div>' for mod in aux[:6]) or '<span class="muted">-</span>'
        exp_html = "".join(f'<div class="msf exp">{_html_escape(mod)}</div>' for mod in exp[:6]) or '<span class="muted">-</span>'

        ports_rows.append(
            f"<tr><td class='mono'>{p.port}/tcp</td><td>{_html_escape(p.service)}</td>"
            f"<td>{pv}</td><td>{n_findings}</td><td>{badge}</td><td>{aux_html}</td><td>{exp_html}</td></tr>"
        )
    ports_table = (
        "<table><thead><tr><th>Port</th><th>Service</th>"
        "<th>Product / Version</th><th># Findings</th><th>Worst Severity</th><th>Auxiliary</th><th>Exploit</th></tr></thead>"
        f"<tbody>{''.join(ports_rows)}</tbody></table>"
        if host.ports else '<div class="no-findings">No open ports found.</div>'
    )

    finding_rows = []
    all_findings = [(p, f) for p in host.ports for f in p.findings]
    all_findings.sort(key=lambda pf: -SEVERITY_RANK.get(pf[1].severity, 0))
    for p, f in all_findings:
        type_tag = "MISCONFIG" if f.source == "aux" else ("NMAP" if f.source == "nmap" else "CVE")
        cvss_txt = f" (CVSS {f.cvss})" if f.cvss else ""
        msf_html = f'<span class="msf">msf&gt; use {_html_escape(f.msf_module)}</span>' \
            if f.msf_module else '<span class="muted">-</span>'
        finding_rows.append(
            "<tr>"
            f"<td class='mono'>{p.port}/{_html_escape(p.service)}</td>"
            f"<td>{type_tag}</td>"
            f"<td class='mono'>{_html_escape(f.cve)}{cvss_txt}</td>"
            f"<td><span class='pill' style='background:{_HTML_SEVERITY_COLORS[f.severity]}'>"
            f"{f.severity}</span></td>"
            f"<td>{_html_escape(f.description)}</td>"
            f"<td>{_html_escape(f.remediation)}</td>"
            f"<td>{msf_html}</td>"
            "</tr>"
        )
    findings_table = (
        "<table><thead><tr><th>Port</th><th>Type</th><th>ID</th><th>Severity</th>"
        "<th>Description</th><th>Remediation</th><th>MSF Module</th></tr></thead>"
        f"<tbody>{''.join(finding_rows)}</tbody></table>"
        if finding_rows else '<div class="no-findings">No CVE or misconfiguration findings.</div>'
    )

    def _nmap_html(title: str, records: List[Dict[str, Any]]) -> str:
        if not records:
            return ""
        rows = []
        for r in records:
            status = str(r.get("status", "unknown"))
            bg = "#3fb950" if status == "ok" else "#d29922"
            diagnostic = str(r.get("stderr", "") or r.get("message", ""))
            if len(diagnostic) > 2500:
                diagnostic = diagnostic[-2500:]
            diag_html = (
                f"<pre class='nmap-diagnostic'>{_html_escape(diagnostic)}</pre>"
                if diagnostic else ""
            )
            rows.append(
                "<tr>"
                f"<td class='mono'>{_html_escape(str(r.get('port', '-')))}/tcp</td>"
                f"<td class='mono'>{_html_escape(str(r.get('script', '-')))}</td>"
                f"<td><span class='pill' style='background:{bg}'>{_html_escape(status.upper())}</span></td>"
                f"<td>{len(r.get('findings', []) or [])}</td>"
                f"<td>{_html_escape(str(r.get('elapsed_seconds', '-')))}s</td>"
                f"<td><div class='mono'>{_html_escape(str(r.get('command', '-')))}</div>{diag_html}</td>"
                "</tr>"
            )
        return (
            f"<h2>{title}</h2>"
            "<p class='muted'>Per-port isolated Nmap execution. "
            "A timeout or NSE crash on one port does not terminate the other port scans.</p>"
            "<table><thead><tr><th>Port</th><th>Mode</th><th>Status</th>"
            "<th>Findings</th><th>Time</th><th>Command / Diagnostics</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def _nmap_all_dedicated_html(records: List[Dict[str, Any]]) -> str:
        if not records:
            return ""
        blocks = []
        for r in records:
            status = str(r.get("status", "unknown"))
            badge = "#3fb950" if status == "ok" else "#d29922"
            stderr = str(r.get("stderr", ""))
            stdout_tail = str(r.get("stdout_tail", ""))
            xml_error = str(r.get("xml_parse_error", ""))
            findings = r.get("findings", []) or []

            finding_rows = []
            for f in findings:
                finding_rows.append(
                    "<tr>"
                    f"<td class='mono'>{_html_escape(str(f.get('port', '-')))}</td>"
                    f"<td>{_html_escape(str(f.get('id', '-')))}</td>"
                    f"<td>{_html_escape(str(f.get('severity', '-')))}</td>"
                    f"<td>{_html_escape(str(f.get('description', '-')))}</td>"
                    "</tr>"
                )

            diagnostic = ""
            if stderr:
                diagnostic += (
                    "<details><summary>Nmap stderr / diagnostics</summary>"
                    f"<pre class='nmap-diagnostic'>{_html_escape(stderr)}</pre></details>"
                )
            if stdout_tail:
                diagnostic += (
                    "<details><summary>Nmap stdout tail</summary>"
                    f"<pre class='nmap-diagnostic'>{_html_escape(stdout_tail)}</pre></details>"
                )
            if xml_error:
                diagnostic += (
                    "<div><b>XML parse diagnostic:</b> "
                    f"{_html_escape(xml_error)}</div>"
                )

            blocks.append(
                "<div class='host-block' style='margin-top:16px'>"
                f"<h3><span class='pill' style='background:{badge}'>{_html_escape(status.upper())}</span> "
                f"--script=all</h3>"
                f"<p><b>Message:</b> {_html_escape(str(r.get('message', '')))}</p>"
                f"<p><b>Elapsed:</b> {_html_escape(str(r.get('elapsed_seconds', '-')))}s "
                f"&nbsp; <b>Return code:</b> {_html_escape(str(r.get('return_code', '-')))}</p>"
                f"<p><b>Command:</b></p><pre class='nmap-diagnostic'>{_html_escape(str(r.get('command', '')))}</pre>"
                f"<p><b>Parsed NSE findings:</b> {len(findings)}</p>"
                + (
                    "<table><thead><tr><th>Port</th><th>ID</th><th>Severity</th><th>Finding</th></tr></thead>"
                    f"<tbody>{''.join(finding_rows)}</tbody></table>"
                    if finding_rows else
                    "<p class='muted'>No NSE findings were parsed from the completed XML.</p>"
                )
                + diagnostic
                + "</div>"
            )

        return (
            "<h2>Nmap Full NSE Results â€” --script=all</h2>"
            "<p class='muted'>This is a dedicated result section. "
            "The complete process status, command, parsed findings, and diagnostics "
            "are retained here. A failed full-NSE process does not overwrite the "
            "normal service/CVE/MSF results.</p>"
            + "".join(blocks)
        )

    nmap_all_dedicated_html = _nmap_all_dedicated_html(host.nmap_all_results)

    nmap_vuln_html = _nmap_html(
        "Nmap NSE Results â€” --script=vuln", host.nmap_vuln_results
    )
    nmap_all_html = _nmap_html(
        "Nmap NSE Results â€” --script=all", host.nmap_all_results
    )

    return f"""
  <div class="host-block">
    <h2>Host: {_html_escape(host.ip)} <span class="muted">({_html_escape(host.target_input)})</span></h2>
    <p class="muted">OS guess: {_html_escape(host.os_guess)} (~{host.os_confidence}%) &nbsp;|&nbsp;
    Scan time: {host.scan_seconds}s &nbsp;|&nbsp; Open ports: {len(host.ports)}</p>
    {ports_table}
         {nmap_vuln_html}
     {nmap_all_html}
     {nmap_all_dedicated_html}
<h2>Findings &amp; Suggested MSF Modules</h2>
    {findings_table}
    {("<h2>Host-level Findings</h2><div class='no-findings'>" + "<br>".join(_html_escape(f"{f.severity}: {f.cve} â€” {f.description}") for f in host.host_findings) + "</div>") if host.host_findings else ""}
  </div>
"""


def _write_html_file(outdir: str, stem: str, html: str) -> str:
    """Writes html to <outdir>/<stem>.html, auto-suffixing (_2, _3, ...) if
    that path already exists so previous reports are never overwritten."""
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, f"{stem}.html")
    if os.path.exists(path):
        i = 2
        while os.path.exists(os.path.join(outdir, f"{stem}_{i}.html")):
            i += 1
        path = os.path.join(outdir, f"{stem}_{i}.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


def _render_live_hosts_html(all_hosts: List[HostResult]) -> str:
    """Renders the 'Live Hosts' overview table (host / OS guess / open ports)
    for the HTML report - only emitted when more than one host was scanned
    (a subnet/CIDR run), so a single-target report stays uncluttered."""
    if len(all_hosts) <= 1:
        return ""

    live_hosts = [h for h in all_hosts if is_host_live(h)]
    dead_count = len(all_hosts) - len(live_hosts)

    rows = []
    for h in live_hosts:
        if h.ports:
            ports_txt = ", ".join(
                f"<span class='mono'>{p.port}/{_html_escape(p.service)}</span>" for p in h.ports
            )
        else:
            ports_txt = "<span class='muted'>none open (ping only)</span>"
        rows.append(
            f"<tr><td class='mono'>{_html_escape(h.ip)}</td>"
            f"<td>{_html_escape(h.os_guess)} <span class='muted'>(~{h.os_confidence}%)</span></td>"
            f"<td>{ports_txt}</td></tr>"
        )

    table = (
        "<table><thead><tr><th>Host</th><th>OS Guess</th><th>Open Ports</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        if rows else '<div class="no-findings">No live hosts found.</div>'
    )

    return f"""
  <h2>Live Hosts Summary <span class="muted">({len(live_hosts)} live / {len(all_hosts)} scanned"""\
    + (f", {dead_count} unreachable/no response" if dead_count else "") + f""")</span></h2>
  {table}
"""


def generate_html_report(target_label: str, all_hosts: List[HostResult], aux_scan: bool, mode_label: str = "") -> str:
    """Builds a full HTML report (one or more hosts) and returns the HTML string."""
    total_open = sum(len(h.ports) for h in all_hosts)
    total_findings = sum(len(p.findings) for h in all_hosts for p in h.ports)
    total_critical = sum(
        1 for h in all_hosts for p in h.ports for f in p.findings if f.severity == "CRITICAL"
    )
    live_hosts_summary = _render_live_hosts_html(all_hosts)
    host_sections = "".join(_render_host_html(h) for h in all_hosts)

    html = _HTML_TEMPLATE.format(
        title=f"{TOOL_NAME} report - {_html_escape(target_label)}",
        tool_name=TOOL_NAME,
        tool_version=TOOL_VERSION,
        target=_html_escape(target_label),
        generated=time.strftime("%Y-%m-%d %H:%M:%S"),
        mode=_html_escape(mode_label or ("Passive + Auxiliary" if aux_scan else "Passive (CVE match only)")),
        host_count=len(all_hosts),
        total_open=total_open,
        total_findings=total_findings,
        total_critical=total_critical,
        crit_color=_HTML_SEVERITY_COLORS["CRITICAL"],
        live_hosts_summary=live_hosts_summary,
        host_sections=host_sections,
    )
    return html


def save_html_report(target_raw: str, all_hosts: List[HostResult], aux_scan: bool,
                      outdir: str = ".", mode_label: str = "") -> str:
    """Renders one combined HTML report for the whole run (all hosts covered
    by target_raw, whether that's a single host or a CIDR block) and writes
    it to <outdir>/<sanitized-target_raw>.html - e.g. scanning
    '10.10.10.0/24' saves '10.10.10.0_24.html' ('/' isn't legal in a
    filename, so it becomes '_'); scanning 'example.com' saves
    'example.com.html'. If that path already exists, a numeric suffix is
    appended so previous reports are never overwritten. Returns the path
    written."""
    html = generate_html_report(target_raw, all_hosts, aux_scan, mode_label=mode_label)
    stem = sanitize_filename(target_raw)
    return _write_html_file(outdir, stem, html)


# ==========================================================================
# 8. MAIN
# ==========================================================================
def confirm_authorization() -> bool:
    answer = input(
        "\nDo you have explicit, documented authorization to scan this "
        "target? (type 'yes' to continue): "
    ).strip().lower()
    return answer == "yes"


def confirm_aux_scan() -> bool:
    answer = input(
        "\n--aux-scan performs active login/protocol attempts (e.g. "
        "anonymous FTP login, unauthenticated Redis/Mongo/Elasticsearch "
        "queries, VNC auth probing) rather than passive banner reads. "
        "Confirm this is also covered by your authorization (type 'yes'): "
    ).strip().lower()
    return answer == "yes"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{TOOL_VERSION} - authorized port scanner, "
                    "service fingerprinter, known-CVE matcher, and optional "
                    "auxiliary/scanner-style misconfiguration checks"
    )
    parser.add_argument("target", nargs="?", help="IP, CIDR block, or hostname")
    parser.add_argument("--full", action="store_true",
                         help="Scan all 65535 TCP ports instead of the top common ports")
    parser.add_argument("--aux-scan", action="store_true",
                         help="Run active auxiliary/scanner-style misconfiguration "
                              "checks (anonymous FTP, unauthenticated Redis/"
                              "Memcached/MongoDB/Elasticsearch, VNC no-auth).")
    parser.add_argument("--nmap-all", action="store_true",
                         help="Run Nmap -sV -Pn --script=all only against ports discovered by JACKLEO.")
    parser.add_argument("--msf-modules", action="store_true",
                         help="Query local Metasploit search for candidate auxiliary/exploit modules; never executes them.")
    parser.add_argument("--deep", action="store_true",
                         help="Run focused service-aware NSE checks and Metasploit module discovery.")
    parser.add_argument("--threads", type=int, default=200, help="Thread pool size (default: 200)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-port connect timeout in seconds (default: 1.0)")
    parser.add_argument("--nmap-timeout", type=int, default=300, help="NSE per-service timeout budget in seconds (default: 300; focused checks cap at 60)")
    parser.add_argument("--json", metavar="FILE", help="Also write a structured JSON report to FILE")
    parser.add_argument("--yes", action="store_true",
                         help="Skip the interactive authorization prompt(s) (scripted/CI use only)")
    parser.add_argument("-v", "--verbose", action="store_true",
                         help="Show a breakdown of why closed/unreachable ports failed.")
    parser.add_argument("--no-banner", action="store_true",
                         help="Suppress the startup logo/banner.")
    parser.add_argument("--no-html", action="store_true",
                         help="Skip auto-saving the HTML report (saved by default).")
    parser.add_argument("--outdir", default=".",
                         help="Directory to save the HTML (and JSON, if --json is a bare "
                              "filename) report into. Default: current directory.")
    args = parser.parse_args()
    if args.deep:
        # Deep mode uses focused service-aware NSE checks + MSF discovery.
        # Full --script=all is opt-in via --nmap-all.
        args.msf_modules = True

    if not args.no_banner:
        print_banner()

    out("[bold]portscan[/bold] - reporting known CVE/misconfig matches. "
        "[yellow]Authorized targets only.[/yellow]")
    if args.yes:
        out("[dim]Authorization prompt skipped because --yes was supplied.[/dim]")

    if not args.yes and not confirm_authorization():
        out("[red]Authorization not confirmed. Exiting.[/red]")
        return 1

    if args.aux_scan and not args.yes and not confirm_aux_scan():
        out("[red]Auxiliary-scan authorization not confirmed. Exiting.[/red]")
        return 1

    if (args.nmap_all or args.deep) and not args.yes:
        answer = input("\nNmap NSE scanning (--script=vuln/--script=all) may perform active checks. Confirm explicit authorization (type 'yes'): ").strip().lower()
        if answer != "yes":
            out("[red]Nmap deep-scan authorization not confirmed. Exiting.[/red]")
            return 1

    target_raw = args.target or input("\nEnter target (IP, CIDR, or hostname): ").strip()
    try:
        ips = expand_target(target_raw)
    except ValueError as exc:
        out(f"[red]{exc}[/red]")
        return 1

    ports = list(range(1, 65536)) if args.full else TOP_PORTS
    is_subnet_scan = len(ips) > 1

    all_hosts: List[HostResult] = []
    total_open = 0
    total_flagged = 0

    for ip in ips:
        out(f"\n[bold cyan]Port scan[/bold cyan] {ip} - checking {len(ports)} TCP ports...")
        host = scan_host(target_raw, ip, ports, args.threads, args.timeout,
                          aux_scan=args.aux_scan, verbose=args.verbose)

        if args.deep or args.nmap_all:
            open_port_numbers = [p.port for p in host.ports]

            if open_port_numbers:
                out(f"\n[bold cyan]Nmap service/version detection[/bold cyan] {ip}")
                nmap_records = run_nmap_service_detection(
                    ip, open_port_numbers, timeout=min(args.nmap_timeout, 120)
                )
                if nmap_records:
                    for pr in host.ports:
                        rec = nmap_records.get(pr.port)
                        if rec:
                            pr.service = rec.get("name") or pr.service
                            pr.product = rec.get("product") or pr.product
                            pr.version = rec.get("version") or pr.version
                            if rec.get("extrainfo"):
                                pr.banner = " ".join(
                                    x for x in (pr.banner, rec["extrainfo"]) if x
                                ).strip()
                            pr.findings = (
                                match_cve_signatures(pr.service, pr.product, pr.version)
                                + [f for f in pr.findings if f.source in ("aux", "nmap")]
                            )
                    out(f"  Identified {len(nmap_records)}/{len(open_port_numbers)} open service(s) with Nmap -sV.")

            deep_ports = sorted(set(open_port_numbers))

            # --deep always runs the real Nmap --script=vuln category, but
            # isolates every port in its own Nmap subprocess.
            if args.deep and deep_ports:
                out(f"\n[bold cyan]Nmap NSE[/bold cyan] {ip} â€” --script=vuln")
                out(f"  Isolated ports: {','.join(map(str, deep_ports))}")
                vuln_findings, _, vuln_runs = run_nmap_category_isolated(
                    ip, deep_ports, "vuln", min(args.nmap_timeout, 60)
                )
                host.nmap_vuln_results.extend(vuln_runs)

                for finding in vuln_findings:
                    m = re.search(r"on (\d+)/(tcp|udp):", finding.description)
                    target_port = int(m.group(1)) if m else None
                    attached = False
                    for pr in host.ports:
                        if target_port is not None and pr.port == target_port:
                            pr.findings.append(finding)
                            attached = True
                            break
                    if not attached:
                        host.host_findings.append(finding)

                ok = sum(r["status"] == "ok" for r in vuln_runs)
                bad = len(vuln_runs) - ok
                out(f"  --script=vuln: {ok}/{len(vuln_runs)} completed; {len(vuln_findings)} finding(s).")
                if bad:
                    failed_ports = [
                        f"{r.get('port')}/tcp:{r.get('status')}"
                        for r in vuln_runs
                        if r.get("status") != "ok"
                    ]
                    out(
                        "  [yellow]"
                        f"{bad} isolated vuln NSE run(s) did not complete. "
                        f"Diagnostics: {', '.join(failed_ports)}"
                        "[/yellow]"
                    )

            # --nmap-all is now a real --script=all run, but isolated per port.
            if args.nmap_all and deep_ports:
                out(f"\n[bold yellow]Dedicated Nmap full NSE scan[/bold yellow] {ip}")
                out(f"  Command: nmap -sV -Pn --script=all -p {','.join(map(str, deep_ports))} -oX - {ip}")
                out("  Waiting for the complete --script=all process to finish...")
                out("  Results will be stored in the dedicated HTML section.")

                all_findings, all_records, all_run = run_nmap_all_dedicated(
                    ip, deep_ports, timeout=max(60, args.nmap_timeout)
                )
                host.nmap_all_results.append(all_run)

                # Only attach actual parsed findings to ports. Process errors,
                # crashes and timeout diagnostics stay in the dedicated section.
                for finding in all_findings:
                    m = re.search(r"on (\d+)/(tcp|udp):", finding.description)
                    target_port = int(m.group(1)) if m else getattr(finding, "port", None)
                    attached = False
                    for pr in host.ports:
                        if target_port is not None and pr.port == target_port:
                            pr.findings.append(finding)
                            attached = True
                            break
                    if not attached:
                        host.host_findings.append(finding)

                status = all_run.get("status", "unknown")
                if status == "ok":
                    out(f"  [green]--script=all completed successfully in {all_run.get('elapsed_seconds', 0)}s.[/green]")
                    out(f"  Parsed {len(all_findings)} Nmap NSE finding(s).")
                else:
                    out(
                        f"  [yellow]--script=all finished with status: {status}. "
                        "The full diagnostic is preserved in the HTML report.[/yellow]"
                    )


        if args.msf_modules:
            out("\n[bold cyan]Metasploit module discovery[/bold cyan]")
            for pr in host.ports:
                if not pr.product and not pr.service:
                    continue
                mods = discover_msf_modules(pr.product, pr.version, pr.service)
                pr.msf_auxiliary = mods["auxiliary"]
                pr.msf_exploit = mods["exploit"]
                if pr.msf_auxiliary or pr.msf_exploit:
                    out(f"  {pr.port}/{pr.service} {pr.product_version or '-'}: "
                        f"{len(pr.msf_auxiliary)} auxiliary, {len(pr.msf_exploit)} exploit candidates")
                    for mod in pr.msf_auxiliary:
                        out(f"    [yellow]AUXILIARY[/yellow] {mod}")
                    for mod in pr.msf_exploit:
                        out(f"    [red]EXPLOIT[/red] {mod}")

        open_n, flagged_n = display_host(host, args.threads, len(ports), args.aux_scan)
        total_open += open_n
        total_flagged += flagged_n
        all_hosts.append(host)

    if is_subnet_scan:
        render_subnet_summary(all_hosts)

    out(f"\n[bold]Done.[/bold] {total_open} open port(s), {total_flagged} "
        f"flagged for review across {len(ips)} host(s).")

    if args.json:
        report = {
            "target": target_raw,
            "aux_scan": args.aux_scan,
            "nmap_all": args.nmap_all,
            "msf_modules": args.msf_modules,
            "hosts": [
                {
                    "ip": h.ip,
                    "os_guess": h.os_guess,
                    "os_confidence": h.os_confidence,
                    "scan_seconds": h.scan_seconds,
                    "nmap_vuln_results": h.nmap_vuln_results,
                    "nmap_all_results": h.nmap_all_results,
                    "host_findings": [
                        {
                            "id": f.cve,
                            "severity": f.severity,
                            "source": f.source,
                            "description": f.description,
                            "remediation": f.remediation,
                        }
                        for f in h.host_findings
                    ],
                    "ports": [
                        {
                            "port": p.port,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                            "banner": p.banner,
                            "msf_auxiliary": getattr(p, "msf_auxiliary", []),
                            "msf_exploit": getattr(p, "msf_exploit", []),
                            "findings": [
                                {
                                    "cve": f.cve,
                                    "severity": f.severity,
                                    "cvss": f.cvss,
                                    "source": f.source,
                                    "description": f.description,
                                    "remediation": f.remediation,
                                    "msf_module": f.msf_module,
                                }
                                for f in p.findings
                            ],
                        }
                        for p in h.ports
                    ],
                }
                for h in all_hosts
            ],
        }
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
        out(f"\n[green]JSON report written to {args.json}[/green]")

    if not args.no_html:
        try:
            mode_label = "Deep: Nmap service detection + NSE + MSF discovery" if args.deep else ("Nmap NSE + MSF discovery" if (args.nmap_all or args.msf_modules) else ("Passive + Auxiliary" if args.aux_scan else "Passive (CVE match only)"))
            html_path = save_html_report(target_raw, all_hosts, args.aux_scan, outdir=args.outdir, mode_label=mode_label)
            out(f"\n[green]HTML report saved to {html_path}[/green]")
        except Exception as exc:
            out(f"\n[red]Failed to write HTML report: {exc}[/red]")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        out("\n[red]Interrupted.[/red]")
        sys.exit(130)