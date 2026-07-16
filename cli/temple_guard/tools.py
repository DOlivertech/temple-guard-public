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


_LOCAL_RE = re.compile(r"\b(localhost|127\.0\.0\.1|host\.docker\.internal)\b")
_HOST_IP_CACHE = None   # resolved once per process; "" = couldn't resolve → fall back to the hostname


def _host_gateway_ip() -> str:
    """The host's reachable IPv4 as seen from a container.

    Docker Desktop dual-stacks `host.docker.internal` to BOTH the good IPv4 and an
    unreachable IPv6 (fdXX::254); tools that prefer IPv6 (Ruby's whatweb/wafw00f…)
    then fail with "Network unreachable". Pinning the numeric IPv4 sidesteps it —
    a number has no AAAA record to prefer. Resolved once and cached; falls back to
    the hostname if resolution fails (e.g. plain Linux Docker, where it isn't needed)."""
    global _HOST_IP_CACHE
    if _HOST_IP_CACHE is not None:
        return _HOST_IP_CACHE
    _HOST_IP_CACHE = ""
    try:
        p = subprocess.run(
            ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
             "alpine", "getent", "ahostsv4", "host.docker.internal"],
            capture_output=True, text=True, timeout=40)
        for line in p.stdout.splitlines():
            parts = line.split()
            if parts and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                _HOST_IP_CACHE = parts[0]
                break
    except Exception:  # noqa: BLE001
        pass
    return _HOST_IP_CACHE


def _container_host(host: str) -> str:
    if host in ("localhost", "127.0.0.1", "::1"):
        return _host_gateway_ip() or "host.docker.internal"
    return host


def _remap(s: str) -> str:
    """Rewrite localhost / 127.0.0.1 / host.docker.internal inside a string (e.g. a URL)
    to the host's numeric IPv4 so a container reliably reaches an app on your machine."""
    if not _LOCAL_RE.search(s):
        return s
    return _LOCAL_RE.sub(_host_gateway_ip() or "host.docker.internal", s)


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
    what: str = ""                                 # plain-English: what the tool is / does
    usage: str = ""                                # example invocation(s)
    risk: str = ""                                 # risks / caveats before you run it
    flags: str = ""                                # the most useful flags to know


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


def _parse_nikto(out: str, target: str) -> list[Finding]:
    findings = []
    risky = ("outdated", "vulnerab", "default file", "traversal", "injection",
             "disclosure", "phpinfo", "backup", "/.git", "/.env", ".sql", "admin",
             "password", "upload", "shell", "cgi", "directory indexing")
    for line in out.splitlines():
        s = line.strip()
        if not s.startswith("+"):
            continue
        body = s.lstrip("+ ").strip()
        low = body.lower()
        if low.startswith(("target ", "start time", "end time", "root page")):
            continue
        if re.match(r"^\d[\d,]*\s+requests?:", low):        # "7891 requests: 0 error(s)…"
            continue
        if low.startswith("server:"):
            findings.append(Finding("Server banner disclosed (nikto)", "low", "web", body[:200],
                                    "Suppress or genericize the Server header to avoid version disclosure."))
            continue
        sev = "medium" if any(k in low for k in risky) else "low"
        findings.append(Finding(f"nikto: {body[:90]}", sev, "web", body[:220],
                                "Review and remove / lock down the item nikto flagged."))
        if len(findings) >= 40:
            break
    if not findings:
        findings.append(Finding("No notable web-server issues (nikto)", "info", "web",
                                "nikto completed with no notable items in the allotted time.",
                                "Good — keep the server patched, headers set, and admin paths protected."))
    return findings


def _parse_wafw00f(out: str, target: str) -> list[Finding]:
    findings = []
    for line in out.splitlines():
        low = line.lower()
        if "is behind" in low:
            waf = line.split("is behind", 1)[1].strip()
            waf = re.sub(r"\s*waf\.?\s*$", "", waf, flags=re.I).strip().rstrip(".")
            findings.append(Finding(f"WAF / CDN detected: {waf or 'unknown'}", "info", "waf", line.strip()[:200],
                                    "Good — a WAF/CDN fronts the app. Keep its rules tuned; don't treat it as the only control."))
        elif "seems to be behind a waf" in low:
            findings.append(Finding("A WAF / security solution appears to be present", "info", "waf", line.strip()[:200],
                                    "Generic detection only — confirm which WAF and that it's actively filtering."))
    if not findings:
        findings.append(Finding("No WAF / CDN detected in front of the app", "low", "waf",
                                "wafw00f did not fingerprint a WAF/CDN protecting this target.",
                                "Consider fronting the app with a WAF/CDN (Cloudflare, AWS WAF, Fastly…) for attack "
                                "filtering + rate-limiting — a common gap in AI-built apps."))
    return findings


def _parse_whatweb(out: str, target: str) -> list[Finding]:
    plugins: dict[str, str] = {}
    for line in out.splitlines():
        s = line.strip()
        if not s or s.lower().startswith("whatweb"):
            continue
        seg = re.split(r"\[\d{3}[^\]]*\]", s, maxsplit=1)
        seg = seg[1] if len(seg) > 1 else s
        for name, detail in re.findall(r"([A-Za-z][\w\-]{1,})(?:\[([^\]]*)\])?", seg):
            if name not in plugins:
                plugins[name] = detail or ""
    noise = {"IP", "Country", "Title", "HTML5", "Script", "UncommonHeaders", "Meta",
             "Open", "RedirectLocation", "Strict", "Cookies", "HTTPOnly"}
    tech = {k: v for k, v in plugins.items() if k not in noise}
    findings = []
    if tech:
        summary = ", ".join(k + (f" {v}" if v else "") for k, v in list(tech.items())[:16])
        findings.append(Finding("Tech stack fingerprint (whatweb)", "info", "tech", summary[:220],
                                "Know exactly what your app advertises; strip banners/headers you don't need."))
        disclosed = [f"{k}[{v}]" for k, v in tech.items()
                     if re.search(r"\d+\.\d+", v) or k in ("HTTPServer", "X-Powered-By", "PoweredBy", "PHP")]
        if disclosed:
            findings.append(Finding("Software version / stack disclosed", "low", "tech",
                                    "; ".join(disclosed[:12])[:220],
                                    "Suppress version tokens (Server, X-Powered-By, framework banners) so attackers "
                                    "can't map your exact versions to known CVEs."))
    if not findings:
        findings.append(Finding("No tech stack fingerprinted (whatweb)", "info", "tech",
                                "whatweb did not fingerprint notable technologies.",
                                "Minimal stack disclosure — good."))
    return findings


TOOLS: dict[str, Tool] = {
    "testssl": Tool(
        "testssl", "TLS posture (testssl)", "drwetter/testssl.sh:3.2",
        "deep TLS/crypto analysis — protocols, ciphers, certificate", "tls",
        lambda h, p, u: ["--quiet", "--color", "0", "--protocols", f"{h}:{p if p != 80 else 443}"],
        parse=_parse_testssl, default_timeout=420,
        what="Deep TLS/SSL analyzer. Inspects the protocol versions, cipher strength, "
             "certificate chain, and known TLS flaws (Heartbleed, ROBOT, BEAST…) a host offers.",
        usage="temple-guard tool testssl example.com\n"
              "temple-guard tool testssl --severity LOW example.com:443",
        risk="Read-only, but chatty — it opens many probe handshakes and can take a few minutes. "
             "Fine against your own host; don't point it at someone else's.",
        flags="--severity <LOW|MEDIUM|HIGH>  ·  -p/--protocols  ·  -U (all vuln checks)  ·  "
              "--sneaky (quieter UA)  ·  --fast  ·  --jsonfile <f>"),
    "nmap": Tool(
        "nmap", "Service / port scan (nmap)", "instrumentisto/nmap:latest",
        "service + version detection on the common ports", "ports",
        lambda h, p, u: ["-sV", "-Pn", "--top-ports", "200", h],
        parse=_parse_nmap, default_timeout=300,
        what="The network mapper. Finds which TCP ports are open and fingerprints the "
             "service/version behind each — the fastest way to catch a database, admin port, "
             "or forgotten service exposed to the world.",
        usage="temple-guard tool nmap -sV -p 1-1000 host.docker.internal\n"
              "temple-guard tool nmap -A -T4 -Pn scanme.nmap.org",
        risk="-sV and default scans are safe & read-only. Aggressive timing (-T5) or DoS NSE "
             "scripts (--script dos) can disrupt a live app — don't. Scanning hosts you don't "
             "own may be illegal.",
        flags="-sV service/version  ·  -p <ports> / --top-ports N  ·  -A OS+version+scripts  ·  "
              "-T0..5 timing  ·  -Pn skip host-discovery  ·  -sC default scripts  ·  "
              "--script <cat>  ·  -sU UDP  ·  -oN/-oX <file>  ·  -v verbose"),
    "nuclei": Tool(
        "nuclei", "Templated checks (nuclei)", "projectdiscovery/nuclei:latest",
        "misconfiguration + exposure templates (first run downloads templates)", "templates",
        lambda h, p, u: ["-u", _remap(u), "-silent", "-severity", "low,medium,high,critical",
                         "-tags", "misconfig,exposure,tech"],
        parse=_parse_nuclei,
        extra=("-v", "templeguard-nuclei:/root/nuclei-templates"), default_timeout=600,
        what="Template-driven scanner (ProjectDiscovery). Runs thousands of community YAML "
             "templates for misconfigurations, exposures, default creds, and known CVEs against a URL.",
        usage="temple-guard tool nuclei -u https://example.com -tags exposure,misconfig\n"
              "temple-guard tool nuclei -u https://example.com -severity high,critical",
        risk="Detection templates are read-only, but some send crafted requests — keep to your own "
             "apps. First run downloads the template set (~cached in a Docker volume afterwards).",
        flags="-u <url>  ·  -tags <a,b>  ·  -severity low,medium,high,critical  ·  -id <template-id>  ·  "
              "-t <template-path>  ·  -rl <rate-limit>  ·  -silent  ·  -stats"),
    "nikto": Tool(
        "nikto", "Web-server scan (nikto)", "frapsoft/nikto:latest",
        "server misconfig, dangerous files, admin paths, outdated software", "web",
        lambda h, p, u: ["-h", _remap(u), "-ask", "no", "-maxtime", "180"],
        parse=_parse_nikto, default_timeout=300,
        what="Classic web-server scanner. Probes for dangerous files/CGIs, outdated server "
             "software, default/backup files, missing security headers, and interesting admin paths.",
        usage="temple-guard tool nikto -h http://host.docker.internal:8081\n"
              "temple-guard tool nikto -h https://example.com -ssl",
        risk="NOISY and slow — thousands of requests. It WILL show in logs/IDS and can trip "
             "rate-limits. A scanner, not an exploit, but point it only at your own app. "
             "(temple-guard caps it with -maxtime 180.)",
        flags="-h <host|url>  ·  -p <port>  ·  -ssl / -nossl  ·  -Tuning <0-9,x>  ·  "
              "-maxtime <t>  ·  -Display V  ·  -o <file> -Format <txt|html|csv>"),
    "wafw00f": Tool(
        "wafw00f", "WAF fingerprint (wafw00f)", "secsi/wafw00f:latest",
        "detects whether a WAF/CDN fronts the app, and which one", "waf",
        lambda h, p, u: [_remap(u)],
        parse=_parse_wafw00f, default_timeout=120,
        what="Web Application Firewall fingerprinter. Tells you whether a WAF/CDN (Cloudflare, "
             "AWS WAF, Akamai, ModSecurity…) sits in front of the app, and which one.",
        usage="temple-guard tool wafw00f https://example.com\n"
              "temple-guard tool wafw00f -a https://example.com   (test every signature)",
        risk="Very light — a handful of requests, read-only. Finding *no* WAF is itself a useful "
             "hardening signal for AI-built apps.",
        flags="-a test all WAFs (don't stop at first)  ·  -l list detectable WAFs  ·  "
              "-v verbose  ·  -o <file>  ·  -i <urls-file>"),
    "whatweb": Tool(
        "whatweb", "Tech fingerprint (whatweb)", "secsi/whatweb:latest",
        "identifies server, framework, CMS, JS libs — and their versions", "tech",
        lambda h, p, u: ["--color=never", _remap(u)],
        parse=_parse_whatweb, default_timeout=120,
        what="Tech-stack fingerprinter. Identifies the web server, framework, CMS, JS libraries, "
             "and often their versions — so you see exactly what your app advertises to the world.",
        usage="temple-guard tool whatweb https://example.com\n"
              "temple-guard tool whatweb -a 3 https://example.com   (more aggressive)",
        risk="Light and read-only at the default aggression (1); higher -a levels send more "
             "requests. Great for catching version/stack disclosure AI-scaffolded apps leak by default.",
        flags="-a <1|3|4> aggression  ·  -v verbose  ·  --log-json <file>  ·  "
              "-U <user-agent>  ·  --color=never"),
}
# what `--deep` runs: the fast-to-moderate recon set (nikto is opt-in via --tools nikto — it's slow)
DEFENSIVE = ["whatweb", "wafw00f", "testssl", "nmap", "nuclei"]


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
    Returns (exit_code, combined_output). `localhost` / `127.0.0.1` / `host.docker.internal`
    in any argument is auto-remapped to the host's numeric IPv4 so an app on your machine
    is reliably reachable."""
    tool = TOOLS[name]
    remapped = [_remap(a) for a in args]
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
