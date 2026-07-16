"""Docker-backed defensive tools.

Each tool spins up a real container (`docker run --rm <image> …`) against a target you
own or are authorized to test, runs, and parses the output into findings for the same
unified report as the native checks. Read-only / posture-focused — TLS analysis, service
exposure, and templated misconfiguration/exposure checks. No exploitation.

Uses well-maintained public per-tool images, so there's no Kali image to build. A target
of `localhost` / `127.0.0.1` is remapped to `host.docker.internal` so the container can
reach an app running on your host.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse

from .checks import Finding

KALI_SHELL_IMAGE = "kalilinux/kali-rolling"


def docker_available() -> tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "docker not found on PATH"
    try:
        p = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=12)
        return (True, "") if p.returncode == 0 else (False, "docker daemon not running")
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _host(url: str) -> str:
    return urlparse(url if "://" in url else "https://" + url).hostname or url


def _port(url: str) -> int:
    u = urlparse(url if "://" in url else "https://" + url)
    return u.port or (443 if u.scheme == "https" else 80)


def _container_host(host: str) -> str:
    return "host.docker.internal" if host in ("localhost", "127.0.0.1", "::1") else host


def _run(image: str, argv: list[str], timeout: int, extra: tuple = ()) -> tuple[int, str, str]:
    cmd = ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
           *extra, image, *argv]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


@dataclass
class Tool:
    key: str
    name: str
    image: str
    desc: str
    cat: str
    argv: Callable[[str, int, str], list[str]]     # (host, port, url) -> tool args
    parse: Callable[[str, str], list[Finding]]     # (stdout, target) -> findings
    extra: tuple = ()                              # extra docker-run args (volumes, …)
    default_timeout: int = 300


# ── parsers ─────────────────────────────────────────────────────────────────
def _parse_testssl(out: str, target: str) -> list[Finding]:
    findings, seen = [], set()
    for line in out.splitlines():
        low = line.lower()
        m = re.search(r"\b(SSLv2|SSLv3|TLS 1(?:\.1)?)\b", line)
        if m and "offered" in low and ("not ok" in low or "deprecated" in low or "vuln" in low):
            proto = m.group(1)
            if proto not in seen:
                seen.add(proto)
                findings.append(Finding(f"Deprecated TLS protocol offered: {proto}", "medium", "tls",
                                        re.sub(r"\s+", " ", line).strip()[:200],
                                        "Disable TLS < 1.2 (prefer 1.3) and remove weak ciphers."))
    for line in out.splitlines():
        if re.search(r"\bVULNERABLE\b", line):
            t = re.sub(r"\s+", " ", line).strip()[:200]
            if t and t[:60] not in seen:
                seen.add(t[:60])
                findings.append(Finding("TLS vulnerability flagged (testssl)", "high", "tls", t,
                                        "Review the testssl finding and patch / reconfigure TLS."))
    if not findings:
        findings.append(Finding("TLS posture looks clean (testssl)", "info", "tls",
                                "No deprecated protocols or flagged vulnerabilities in testssl output.",
                                "Keep TLS 1.2+/1.3 only, strong ciphers, HSTS, and current certificates."))
    return findings


def _parse_nmap(out: str, target: str) -> list[Finding]:
    findings, open_ports = [], []
    risky = {"telnet", "ftp", "rlogin", "vnc", "ms-wbt-server", "rdp", "microsoft-ds",
             "netbios-ssn", "mysql", "postgresql", "redis", "mongod", "memcached", "elasticsearch"}
    for line in out.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line.strip())
        if not m:
            continue
        port, proto, svc, ver = m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip()
        open_ports.append(f"{port}/{proto} {svc}" + (f" ({ver})" if ver else ""))
        if svc in risky:
            findings.append(Finding(f"Sensitive service exposed: {svc} on {port}/{proto}", "medium", "ports",
                                    re.sub(r"\s+", " ", line).strip()[:200],
                                    f"Restrict {svc} to trusted networks / VPN — don't expose it publicly."))
    if open_ports:
        findings.append(Finding(f"{len(open_ports)} open port(s) found (nmap)", "info", "ports",
                                "; ".join(open_ports[:24]),
                                "Firewall or close any port that doesn't need to be public."))
    else:
        findings.append(Finding("No open ports in the scanned range (nmap)", "info", "ports",
                                "nmap found no open TCP ports in the top-ports range.",
                                "Good — minimal attack surface."))
    return findings


def _parse_nuclei(out: str, target: str) -> list[Finding]:
    sev_map = {"critical": "high", "high": "high", "medium": "medium",
               "low": "low", "info": "info", "unknown": "info"}
    findings = []
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^\[(?P<id>[^\]]+)\]\s+\[[^\]]+\]\s+\[(?P<sev>[a-z]+)\]\s+(?P<url>\S+)", line)
        if m:
            findings.append(Finding(f"nuclei: {m.group('id')}", sev_map.get(m.group('sev').lower(), "info"),
                                    "templates", line[:220],
                                    "Review the matched nuclei template and fix the underlying issue."))
    if not findings:
        findings.append(Finding("No nuclei template matches", "info", "templates",
                                "nuclei ran and matched no misconfiguration/exposure templates.",
                                "Nothing flagged — keep the app and templates current."))
    return findings


TOOLS: dict[str, Tool] = {
    "testssl": Tool(
        "testssl", "TLS posture (testssl)", "drwetter/testssl.sh:3.2",
        "deep TLS/crypto analysis — protocols, ciphers, certificate", "tls",
        lambda h, p, u: ["--quiet", "--color", "0", "--protocols", f"{h}:{p if p != 80 else 443}"],
        parse=_parse_testssl, default_timeout=420),
    "nmap": Tool(
        "nmap", "Service / port scan (nmap)", "instrumentisto/nmap:latest",
        "service + version detection on the common ports", "ports",
        lambda h, p, u: ["-sV", "-Pn", "--top-ports", "200", h],
        parse=_parse_nmap, default_timeout=300),
    "nuclei": Tool(
        "nuclei", "Templated checks (nuclei)", "projectdiscovery/nuclei:latest",
        "misconfiguration + exposure templates (first run downloads templates)", "templates",
        lambda h, p, u: ["-u", u, "-silent", "-severity", "low,medium,high,critical",
                         "-tags", "misconfig,exposure,tech"],
        parse=_parse_nuclei,
        extra=("-v", "templeguard-nuclei:/root/nuclei-templates"), default_timeout=600),
}
DEFENSIVE = ["testssl", "nmap", "nuclei"]   # what `--deep` runs


def run_tool(key: str, url: str, timeout: Optional[int] = None) -> tuple[list[Finding], str, bool]:
    """Run one tool in its container. Returns (findings, raw_output, ok)."""
    tool = TOOLS[key]
    rc, out, err = _run(tool.image, tool.argv(_container_host(_host(url)), _port(url), url),
                        timeout or tool.default_timeout, tool.extra)
    raw = out if out.strip() else err
    if rc != 0 and not out.strip():
        return ([Finding(f"{tool.name} did not complete", "info", tool.cat,
                         (err or f"exit {rc}")[:200],
                         "Check Docker is running and the image pulled, then retry.")], raw, False)
    return tool.parse(out, url), raw, True


def run_raw(name: str, args: list, timeout: Optional[int] = None) -> tuple[int, str]:
    """Run a tool in its container with the user's OWN arguments (full tool flags).
    Returns (exit_code, combined_output). `localhost` / `127.0.0.1` in any argument is
    auto-remapped to `host.docker.internal` so an app on your machine is reachable."""
    tool = TOOLS[name]
    remapped = [re.sub(r"\b(localhost|127\.0\.0\.1)\b", "host.docker.internal", a) for a in args]
    rc, out, err = _run(tool.image, remapped, timeout or tool.default_timeout, tool.extra)
    return rc, (out if out.strip() else err)


def kali_shell(image: Optional[str] = None) -> int:
    """Drop into an interactive shell in a Kali container (real TTY; inherits stdio)."""
    cmd = ["docker", "run", "--rm", "-it", "--add-host=host.docker.internal:host-gateway",
           image or KALI_SHELL_IMAGE, "/bin/bash"]
    try:
        return subprocess.run(cmd).returncode
    except Exception as exc:  # noqa: BLE001
        print(f"could not start shell: {exc}")
        return 1
