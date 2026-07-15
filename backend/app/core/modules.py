"""Scan modules.

Each module knows how to (a) build a real tool command for a provisioner and
parse its output into findings, and (b) produce a deterministic *simulated*
result so the whole platform is demoable with zero infrastructure.

Real parsing here is intentionally lightweight — production would use the
tools' native XML/JSON output. The simulation path is rich enough to exercise
the full findings → report pipeline.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
from dataclasses import dataclass, field

from . import remediation
from .provisioner import ExecResult, Provisioner


@dataclass
class ModuleResult:
    raw_output: str
    findings: list[dict] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    instance_ref: str | None = None
    ok: bool = True
    error: str | None = None


def _seed(*parts: str) -> int:
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()
    return int(h[:8], 16)


# One Kali image hosts every containerized CLI tool (nmap, nikto, nuclei,
# sqlmap, testssl.sh, app-audit helpers). Built from backend/docker/kali/.
# Consolidates the toolset, matches the Kali consoles, and kills image sprawl.
KALI_IMAGE = "templeguard/kali:latest"


class ScanModule:
    name = "base"
    image = KALI_IMAGE
    pretty = "Base module"
    # Pre-flight authorization notice shown before an active/intrusive tool runs.
    # Empty for passive/OSINT modules; set on tools that send intrusive traffic.
    warning = ""
    # True → executes inside a Docker container (so localhost targets must be
    # rewritten to host.docker.internal). False → runs in-process (e.g. Playwright).
    runs_in_container = True

    def __init__(self, params: dict | None = None):
        self.params = params or {}

    # --- real execution -------------------------------------------------
    def command(self, target: str) -> list[str]:
        raise NotImplementedError

    def parse(self, result: ExecResult, target: str) -> ModuleResult:
        raise NotImplementedError

    def run_real(self, provisioner: Provisioner, target: str, timeout: int,
                 labels: list[str] | None = None) -> ModuleResult:
        res = provisioner.run(self.image, self.command(target), timeout, labels)
        if not res.ok and not res.stdout:
            return ModuleResult(raw_output=res.stderr, ok=False, error=res.stderr)
        out = self.parse(res, target)
        out.instance_ref = res.ref
        return out

    # --- simulation -----------------------------------------------------
    def simulate(self, target: str) -> ModuleResult:
        raise NotImplementedError


class NmapModule(ScanModule):
    name = "nmap"
    image = KALI_IMAGE
    pretty = "Nmap network / service scan"
    warning = (
        "⚠ Active network scan. Port/service scanning sends intrusive traffic and may "
        "violate acceptable-use policies, hosting terms, or law if you lack permission. "
        "Only run against systems within an authorized engagement scope and ROE window — "
        "by proceeding you confirm you have written authorization."
    )

    def command(self, target: str) -> list[str]:
        profile = self.params.get("profile", "service-version")
        flags = {"full": ["-p-", "-sV"], "service-version": ["-sV"],
                 "config-audit": ["-sV"]}.get(profile, ["-sV"])
        scripts = self.params.get("scripts")
        cmd = ["nmap", *flags]
        if scripts:
            cmd += [f"--script={scripts}"]
        cmd.append(self._host(target))
        return cmd

    @staticmethod
    def _host(target: str) -> str:
        return re.sub(r"^https?://", "", target).split("/")[0]

    def parse(self, result: ExecResult, target: str) -> ModuleResult:
        findings, ports = [], []
        for line in result.stdout.splitlines():
            m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line.strip())
            if m:
                port, proto, svc, banner = m.groups()
                ports.append({"port": int(port), "proto": proto, "service": svc, "banner": banner})
                if int(port) in (22, 3389, 3306, 5432, 6379) :
                    findings.append(remediation.enrich(
                        "open_admin_interface",
                        evidence=f"{port}/{proto} {svc} {banner}".strip()))
                if "ssl" in line.lower() and "TLSv1.0" in result.stdout:
                    findings.append(remediation.enrich("tls_weak_cipher", evidence=line.strip()))
        asset = {"ip": self._host(target), "hostname": self._host(target),
                 "asset_type": "host", "open_ports": ports}
        return ModuleResult(raw_output=result.stdout, findings=findings, assets=[asset])

    def simulate(self, target: str) -> ModuleResult:
        host = self._host(target)
        s = _seed(self.name, host)
        port_pool = [
            {"port": 22, "proto": "tcp", "service": "ssh", "banner": "OpenSSH 7.4"},
            {"port": 80, "proto": "tcp", "service": "http", "banner": "nginx 1.14.0"},
            {"port": 443, "proto": "tcp", "service": "https", "banner": "nginx 1.14.0 (TLSv1.0)"},
            {"port": 3306, "proto": "tcp", "service": "mysql", "banner": "MySQL 5.5.62"},
            {"port": 8080, "proto": "tcp", "service": "http-proxy", "banner": "Apache Tomcat 8.0"},
        ]
        ports = [p for i, p in enumerate(port_pool) if (s >> i) & 1 or i < 2]
        findings = []
        for p in ports:
            if p["port"] in (22, 3306):
                findings.append(remediation.enrich(
                    "open_admin_interface", evidence=f"{p['port']}/tcp {p['service']} {p['banner']}"))
            if "TLSv1.0" in p["banner"]:
                findings.append(remediation.enrich("tls_weak_cipher", evidence=p["banner"]))
            if "5.5.62" in p["banner"] or "1.14.0" in p["banner"]:
                findings.append(remediation.enrich(
                    "outdated_software", evidence=f"{p['service']}: {p['banner']}"))
        raw = f"# nmap (simulated) {host}\n" + "\n".join(
            f"{p['port']}/{p['proto']} open {p['service']}  {p['banner']}" for p in ports)
        asset = {"ip": host, "hostname": host, "asset_type": "host", "open_ports": ports}
        return ModuleResult(raw_output=raw, findings=findings, assets=[asset])


class NiktoModule(ScanModule):
    """Nikto — comprehensive web-server scan: misconfigurations, dangerous files,
    outdated software, info disclosure, headers. Runs all test classes except DoS,
    bounded by a max runtime, and emits structured JSON we classify per finding."""
    name = "nikto"
    image = KALI_IMAGE
    pretty = "Nikto web server scan"
    warning = (
        "⚠ Active web-server scan. Sends thousands of probe requests (files, paths, "
        "misconfig checks) and shows up clearly in target logs. Run only against web "
        "apps within an authorized engagement scope and ROE window."
    )

    SKIP = ("target ip", "target hostname", "target port", "start time", "end time",
            "ssl info", "ciphers:", "ca:", "subject:", "altnames:", "root page",
            "no cgi directories", "scan terminated", "host(s) tested", "requests:",
            "0 host", "1 host tested", "platform:", "server:", "multiple ips",
            "detected via", "cgi tests skipped")

    def command(self, target: str) -> list[str]:
        # -Tuning x6 = every test class EXCEPT denial-of-service. Text output (the
        # build's JSON writer is unreliable); the parser classifies the "+" lines.
        return ["nikto", "-h", target, "-nointeractive", "-ask", "no",
                "-Tuning", "x6", "-maxtime", "240", "-timeout", "10"]

    def _classify(self, msg: str):
        low = msg.lower()
        if any(h in low for h in ("x-frame-options", "x-content-type", "strict-transport",
                                  "content-security-policy", "header")):
            return "missing_security_headers", "low"
        if "index of /" in low or "directory indexing" in low:
            return "directory_listing", "medium"
        if "outdated" in low or ("server" in low and "appears" in low):
            return "outdated_software", "medium"
        if "sql" in low and "inject" in low:
            return "sql_injection", "high"
        if "xss" in low or "cross site" in low:
            return "xss_reflected", "medium"
        if any(k in low for k in ("admin", "login", "backup", "config", ".git", "phpinfo", "test")):
            return "info_disclosure", "medium"
        return None, "low"

    def parse(self, result: ExecResult, target: str) -> ModuleResult:
        import json as _json
        host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
        vulns = []
        try:
            data = _json.loads(result.stdout)
            if isinstance(data, list):
                data = data[0] if data else {}
            vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        except (ValueError, TypeError):
            vulns = []
        findings = []
        if vulns:
            for v in vulns[:120]:
                msg = (v.get("msg") or v.get("message") or "").strip()
                if not msg:
                    continue
                cat, sev = self._classify(msg)
                ev = f"{v.get('method', 'GET')} {v.get('url', '')} — {msg}".strip()
                if cat:
                    findings.append(remediation.enrich(cat, evidence=ev))
                else:
                    findings.append({"title": f"Nikto: {msg[:70]}", "severity": sev,
                        "category": "web", "standard_refs": ["OWASP Top 10 A05", "NIST 800-115"],
                        "description": "Nikto web-server finding.", "evidence": ev,
                        "remediation": "Review the flagged item; remove/restrict if unintended."})
        else:
            # Text output: every substantive "+" line becomes a finding (classified
            # where possible, generic otherwise) — a comprehensive report.
            for line in result.stdout.splitlines():
                s = line.strip()
                if not s.startswith("+ ") or len(s) < 8:
                    continue
                msg = s[2:].strip()
                if any(k in msg.lower() for k in self.SKIP):
                    continue
                cat, sev = self._classify(msg)
                if cat:
                    findings.append(remediation.enrich(cat, evidence=msg))
                else:
                    findings.append({"title": f"Nikto: {msg[:70]}", "severity": sev,
                        "category": "web", "standard_refs": ["OWASP Top 10 A05", "NIST 800-115"],
                        "description": "Nikto web-server finding.", "evidence": msg,
                        "remediation": "Review the flagged item; remove/restrict if unintended."})
        findings.insert(0, {"title": f"Nikto scan — {host} ({len(findings)} findings)",
            "severity": "info", "category": "web", "standard_refs": ["OWASP Top 10 A05", "NIST 800-115"],
            "description": "Comprehensive Nikto web-server scan (all test classes except DoS).",
            "evidence": "\n".join(f"+ {(v.get('msg') or '')[:90]}" for v in vulns[:25]) or
                        (result.stdout[:600] if result.stdout else "no issues reported"),
            "remediation": "Informational — see findings below."})
        return ModuleResult(raw_output=result.stdout[:8000], findings=findings,
                            assets=[{"hostname": host, "asset_type": "web"}])

    def simulate(self, target: str) -> ModuleResult:
        s = _seed(self.name, target)
        candidates = [
            ("missing_security_headers", "The anti-clickjacking X-Frame-Options header is not present."),
            ("missing_security_headers", "Strict-Transport-Security header not defined."),
            ("directory_listing", "/backup/: Directory indexing found."),
            ("info_disclosure", "Server leaks internal IP in Location header."),
            ("outdated_software", "Apache/2.4.18 appears outdated (current is >=2.4.59)."),
        ]
        findings = [remediation.enrich(c, evidence=e)
                    for i, (c, e) in enumerate(candidates) if (s >> i) & 1 or i == 0]
        raw = f"# nikto (simulated) {target}\n" + "\n".join(f"+ {e}" for _, e in candidates)
        return ModuleResult(raw_output=raw, findings=findings,
                            assets=[{"hostname": target, "asset_type": "web"}])


class NucleiModule(ScanModule):
    """ProjectDiscovery Nuclei — template-based vulnerability scanning (CVEs,
    misconfigurations, exposures, default creds, weak-auth, injection templates).
    The single highest-coverage CEH 'vulnerability analysis' tool."""
    name = "nuclei"
    image = KALI_IMAGE
    pretty = "Nuclei vulnerability scan"
    warning = (
        "⚠ Active vulnerability scan. Fires template probes (CVE/exposure/misconfig "
        "checks) at the target — intrusive and logged. Only run within an authorized "
        "engagement scope and ROE window."
    )

    def command(self, target: str) -> list[str]:
        url = target if re.match(r"^https?://", target) else f"https://{target}"
        sev = self.params.get("severity", "low,medium,high,critical")
        return ["nuclei", "-u", url, "-jsonl", "-silent", "-disable-update-check",
                "-severity", sev, "-timeout", "8"]

    def parse(self, result, target):
        import json as _json
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                j = _json.loads(line)
            except ValueError:
                continue
            info = j.get("info", {})
            sev = info.get("severity", "info")
            sev = sev if sev in ("critical", "high", "medium", "low", "info") else "info"
            findings.append({
                "title": info.get("name", j.get("template-id", "Nuclei finding")),
                "severity": sev, "category": "nuclei",
                "standard_refs": ["OWASP Top 10 A06", "NIST 800-115"],
                "description": (info.get("description") or "")[:500],
                "evidence": f"{j.get('template-id')} matched at {j.get('matched-at', target)}",
                "remediation": info.get("remediation")
                or "Patch/remediate the matched component; consult the Nuclei template "
                   "and vendor advisory.",
            })
        return ModuleResult(raw_output=result.stdout[:8000], findings=findings,
                            assets=[{"hostname": self._host(target), "asset_type": "web"}])

    @staticmethod
    def _host(target: str) -> str:
        return re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

    def simulate(self, target: str) -> ModuleResult:
        s = _seed(self.name, target)
        pool = [
            ("info", "tech-detect: nginx", "tech-detect"),
            ("medium", "Exposed .git directory", "git-config"),
            ("high", "CVE-2021-41773 Apache path traversal", "CVE-2021-41773"),
            ("low", "Missing security headers", "http-missing-security-headers"),
            ("medium", "Open redirect", "open-redirect"),
        ]
        findings = [{
            "title": name, "severity": sev, "category": "nuclei",
            "standard_refs": ["OWASP Top 10 A06", "NIST 800-115"],
            "description": f"Nuclei template {tid} matched (simulated).",
            "evidence": f"{tid} matched at {target}", "remediation": "Patch/remediate per template.",
        } for i, (sev, name, tid) in enumerate(pool) if (s >> i) & 1 or i == 0]
        return ModuleResult(raw_output=f"# nuclei (simulated) {target}", findings=findings,
                            assets=[{"hostname": self._host(target), "asset_type": "web"}])


class TLSAuditModule(ScanModule):
    """testssl.sh — TLS/crypto posture (protocols, ciphers, cert, known attacks).
    Covers CEH 'cryptography' + PCI/HIPAA transport-security controls."""
    name = "tls_audit"
    image = KALI_IMAGE
    pretty = "TLS / crypto audit (testssl.sh)"

    def command(self, target: str) -> list[str]:
        host = re.sub(r"^https?://", "", target).split("/")[0]
        if ":" not in host:
            host = f"{host}:443"
        return ["testssl", "--quiet", "--color", "0", "--protocols", "--vulnerable", host]

    def parse(self, result, target):
        findings, seen = [], set()
        for line in result.stdout.splitlines():
            low = line.lower()
            # Deprecated/weak protocol offered (e.g. "TLS 1   offered (deprecated)").
            m = re.match(r"\s*(SSLv2|SSLv3|TLS 1(\.1)?)\b", line)
            if m and "offered" in low and ("deprecated" in low or "not ok" in low):
                proto = m.group(1)
                if proto not in seen:
                    seen.add(proto)
                    findings.append(remediation.enrich(
                        "tls_weak_cipher",
                        title=f"Weak/deprecated protocol offered: {proto}",
                        evidence=line.strip()))
            elif "vulnerable" in low and "not vulnerable" not in low and "vulnerable (" in low:
                key = line.strip()[:40]
                if key not in seen:
                    seen.add(key)
                    findings.append(remediation.enrich(
                        "tls_weak_cipher", title="TLS vulnerability detected",
                        evidence=line.strip()))
        return ModuleResult(raw_output=result.stdout[:8000], findings=findings,
                            assets=[{"hostname": re.sub(r"^https?://", "", target).split("/")[0],
                                     "asset_type": "host"}])

    def simulate(self, target: str) -> ModuleResult:
        s = _seed(self.name, target)
        findings = []
        if s & 1:
            findings.append(remediation.enrich("tls_weak_cipher",
                            evidence="TLS 1.0 offered (NOT ok) (simulated)"))
        if s & 2:
            findings.append(remediation.enrich("tls_weak_cipher",
                            title="VULNERABLE to ROBOT (simulated)", evidence="ROBOT: VULNERABLE"))
        return ModuleResult(raw_output=f"# testssl (simulated) {target}", findings=findings,
                            assets=[{"hostname": re.sub(r"^https?://", "", target).split("/")[0],
                                     "asset_type": "host"}])


class SqlmapModule(ScanModule):
    """sqlmap — automated SQL injection (CEH module 15). Real runs need an
    injectable parameter; against a clean target it reports no injection."""
    name = "sqlmap"
    image = KALI_IMAGE
    pretty = "SQL injection (sqlmap)"
    warning = (
        "⚠ Active SQL-injection testing. Submits crafted payloads to the target's "
        "parameters; unauthorized injection testing is prosecutable (CFAA and equivalents). "
        "Run ONLY against systems you have explicit written authorization to test, within "
        "the engagement scope and ROE window."
    )

    def command(self, target: str) -> list[str]:
        url = target if re.match(r"^https?://", target) else f"http://{target}"
        return ["sqlmap", "-u", url, "--batch", "--crawl=1", "--level=1", "--risk=1",
                "--random-agent", "--flush-session", "--timeout=10"]

    def parse(self, result, target):
        findings = []
        out = result.stdout
        if re.search(r"is vulnerable|appears to be .* injectable|parameter '[^']+' is", out, re.I):
            for m in re.finditer(r"parameter '([^']+)'[^\n]*?(injectable|vulnerable)", out, re.I):
                findings.append(remediation.enrich("sql_injection",
                                evidence=f"Parameter '{m.group(1)}' is injectable (sqlmap)."))
            if not findings:
                findings.append(remediation.enrich("sql_injection",
                                evidence="sqlmap reported an injectable parameter."))
        return ModuleResult(raw_output=out[:8000], findings=findings,
                            assets=[{"hostname": re.sub(r"^https?://", "", target).split("/")[0].split(":")[0],
                                     "asset_type": "web"}])

    def simulate(self, target: str) -> ModuleResult:
        s = _seed(self.name, target)
        findings = []
        if s & 1:
            findings.append(remediation.enrich("sql_injection",
                            evidence="Parameter 'id' is injectable (boolean-based blind) (simulated)."))
        return ModuleResult(raw_output=f"# sqlmap (simulated) {target}", findings=findings,
                            assets=[{"hostname": re.sub(r"^https?://", "", target).split("/")[0].split(":")[0],
                                     "asset_type": "web"}])


class WebEvidenceModule(ScanModule):
    """Drives a real browser (Playwright) to capture visual + header evidence.

    Two jobs:
      * grab a full-page **screenshot** of the target so the report shows the
        client exactly what was assessed / what's exposed
      * verify security headers live (CSP, HSTS, X-Frame-Options, nosniff) and
        attach the same screenshot to any finding

    Findings may carry a `_image` (PNG bytes); the runner persists it and links
    it to the finding via `evidence_path`.
    """
    name = "web_evidence"
    pretty = "Web evidence capture (Playwright)"
    runs_in_container = False  # Playwright runs in-process; can reach localhost

    SEC_HEADERS = {
        "content-security-policy": "missing_security_headers",
        "strict-transport-security": "missing_security_headers",
        "x-frame-options": "missing_security_headers",
        "x-content-type-options": "missing_security_headers",
    }

    @staticmethod
    def _url(target: str) -> str:
        return target if target.startswith("http") else f"http://{target}"

    def run_real(self, provisioner, target, timeout, labels=None) -> ModuleResult:
        # Playwright runs in-process (these scans execute on worker threads with
        # no event loop, so the sync API is safe). Ignores the docker provisioner.
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return ModuleResult(raw_output="playwright not installed", ok=False,
                                error="pip install playwright && playwright install chromium")

        url = self._url(target)
        nav_ms = min(max(timeout, 15), 45) * 1000
        findings: list[dict] = []
        lines = [f"# web_evidence {url}"]
        shot = None
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(args=["--no-sandbox", "--disable-gpu"])
                page = browser.new_page(viewport={"width": 1280, "height": 900},
                                        ignore_https_errors=True)
                resp = page.goto(url, wait_until="domcontentloaded", timeout=nav_ms)
                page.wait_for_timeout(800)
                title = page.title()
                shot = page.screenshot(full_page=True)
                headers = {k.lower(): v for k, v in (resp.headers.items() if resp else [])}
                status = resp.status if resp else "n/a"
                forms = page.locator("form").count()
                pw_inputs = page.locator("input[type=password]").count()
                lines += [f"status: {status}", f"title: {title}",
                          f"forms: {forms}  password-inputs: {pw_inputs}"]

                # Headline evidence finding (always) carries the screenshot.
                findings.append({
                    "title": f"Web page captured — {title or url}",
                    "severity": "info", "category": "web_recon",
                    "standard_refs": ["OWASP WSTG-INFO"],
                    "description": f"Live capture of {url} (HTTP {status}). "
                                   f"{forms} form(s), {pw_inputs} password field(s).",
                    "evidence": f"GET {url} → {status} · title: {title!r}",
                    "remediation": "Informational — visual evidence for the report.",
                    "_image": shot,
                })
                # Missing-header findings, each with the screenshot attached.
                for h, cat in self.SEC_HEADERS.items():
                    if h not in headers:
                        f = remediation.enrich(cat, evidence=f"Response from {url} is "
                                               f"missing the '{h}' header.")
                        f["title"] = f"Missing header: {h}"
                        f["_image"] = shot
                        findings.append(f)
                if pw_inputs and not (resp and url.startswith("https")):
                    f = remediation.enrich("info_disclosure",
                                           evidence=f"Password field served over "
                                           f"non-HTTPS at {url}.")
                    f["title"] = "Credentials form over cleartext HTTP"
                    f["severity"] = "high"
                    f["_image"] = shot
                    findings.append(f)
                browser.close()
        except Exception as exc:  # noqa: BLE001
            return ModuleResult(raw_output="\n".join(lines) + f"\nerror: {exc}",
                                ok=False, error=str(exc),
                                assets=[{"hostname": target, "asset_type": "web"}])

        return ModuleResult(raw_output="\n".join(lines), findings=findings,
                            assets=[{"hostname": target, "asset_type": "web"}])

    def command(self, target: str) -> list[str]:
        return ["true"]

    def parse(self, result, target):
        return ModuleResult(raw_output=result.stdout)

    def simulate(self, target: str) -> ModuleResult:
        # No browser in simulation; emit header findings without an image.
        url = self._url(target)
        findings = [{
            "title": f"Web page captured — {url}",
            "severity": "info", "category": "web_recon",
            "standard_refs": ["OWASP WSTG-INFO"],
            "description": "Simulated capture. Run in docker/real mode for an "
                           "actual Playwright screenshot.",
            "evidence": f"GET {url} (simulated)",
            "remediation": "Informational.",
        }]
        s = _seed(self.name, target)
        if s & 1:
            findings.append(remediation.enrich(
                "missing_security_headers",
                evidence="Content-Security-Policy header not present (simulated)."))
        return ModuleResult(raw_output=f"# web_evidence (simulated) {url}",
                            findings=findings,
                            assets=[{"hostname": target, "asset_type": "web"}])


_APP_AUDIT_SCRIPT = r"""
set +e
SRC="$1"; OS="$2"; OUT=/work/app
mkdir -p /work/ex
if echo "$SRC" | grep -qiE '^https?://'; then
  curl -fsSL --max-time 180 "$SRC" -o "$OUT" || { echo "ERR|download failed: $SRC"; exit 0; }
else
  cp "$SRC" "$OUT" 2>/dev/null || { echo "ERR|cannot read $SRC"; exit 0; }
fi
echo "INFO|os=$OS"
echo "INFO|file=$(file -b "$OUT" 2>/dev/null)"
echo "INFO|sha256=$(sha256sum "$OUT" 2>/dev/null | awk '{print $1}')"
echo "INFO|size=$(wc -c < "$OUT" 2>/dev/null) bytes"
strings -n 6 "$OUT" 2>/dev/null > /work/str
( cd /work/ex && (7z x -y "$OUT" >/dev/null 2>&1 || unzip -o "$OUT" >/dev/null 2>&1 \
   || ar x "$OUT" >/dev/null 2>&1 || tar xf "$OUT" >/dev/null 2>&1) )
EXN=$(find /work/ex -type f 2>/dev/null | wc -l)
[ "$EXN" -gt 0 ] && { echo "INFO|extracted=$EXN files"; find /work/ex -type f -exec strings -n 6 {} \; 2>/dev/null >> /work/str; }
grep -aoiE '(AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|access[_-]?token)["'"'"' :=]+[A-Za-z0-9/+_.-]{6,})' /work/str 2>/dev/null \
  | sort -u | head -25 | while IFS= read -r m; do echo "FINDING|high|hardcoded_secret|Embedded secret or credential|${m:0:120}"; done
grep -aoiE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{6,}' /work/str 2>/dev/null \
  | sort -u | head -25 | while IFS= read -r u; do echo "FINDING|info|exposed_endpoint|Embedded endpoint / URL|${u:0:120}"; done
if find /work/ex -name package.json 2>/dev/null | grep -q .; then
  echo "FINDING|info|vulnerable_dependency|Bundled package.json present — run SCA/SBOM|node dependency manifest in bundle"
fi
case "$OS" in
  windows) grep -aqi 'wintrust\|authenticode' "$OUT" 2>/dev/null || echo "FINDING|medium|unsigned_binary|No Authenticode signature markers (heuristic)|windows installer";;
  macos)   grep -aqi 'codesign\|Developer ID\|notariz' "$OUT" 2>/dev/null || echo "FINDING|medium|unsigned_binary|No macOS signing markers (heuristic)|macOS app bundle";;
esac
echo "DONE"
"""


class AppAnalysisModule(ScanModule):
    """Spins up a container, fetches the app (URL or mounted path), and statically
    dissects it: file type, hashes, embedded secrets/endpoints, bundled manifests,
    and code-signing heuristics. Read-only — it does not execute the installer.

    Dynamic detonation (install + run + fuzz) is Linux-feasible and a roadmap item;
    Windows/macOS dynamic runs need OS-specific sandbox VMs (also roadmap).
    """
    name = "app_analysis"
    pretty = "App static analysis (containerized)"
    image = KALI_IMAGE  # kali ships file/strings/7z/unzip/curl the audit script needs
    runs_in_container = True  # but builds its own docker invocation (volume mounts)

    def command(self, target: str) -> list[str]:
        return ["true"]

    def parse(self, result, target):
        return ModuleResult(raw_output=getattr(result, "stdout", ""))

    def run_real(self, provisioner, target, timeout, labels=None) -> ModuleResult:
        os_name = self.params.get("os", "linux")
        is_url = bool(re.match(r"^https?://", target, re.I))
        cmd = ["docker", "run", "--rm", "--network", "bridge", *(labels or [])]
        if is_url:
            src = target
        else:
            host_path = os.path.abspath(os.path.expanduser(target))
            if not os.path.exists(host_path):
                return ModuleResult(raw_output=f"path not found: {host_path}",
                                    ok=False, error="app path does not exist")
            host_dir, fname = os.path.dirname(host_path), os.path.basename(host_path)
            cmd += ["-v", f"{host_dir}:/target:ro"]
            src = f"/target/{fname}"
        cmd += [self.image, "bash", "-c", _APP_AUDIT_SCRIPT, "_", src, os_name]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return ModuleResult(raw_output="timeout", ok=False, error=f"timeout after {timeout}s")
        except Exception as exc:  # noqa: BLE001
            return ModuleResult(raw_output=str(exc), ok=False, error=str(exc))
        return self._parse_output(proc.stdout + "\n" + proc.stderr, target, os_name)

    def _parse_output(self, out: str, target: str, os_name: str) -> ModuleResult:
        findings, info = [], []
        ok = True
        for line in out.splitlines():
            if line.startswith("FINDING|"):
                parts = line.split("|", 4)
                if len(parts) == 5:
                    _, sev, cat, title, ev = parts
                    findings.append(remediation.enrich(cat, evidence=ev, title=title, severity=sev))
            elif line.startswith("INFO|"):
                info.append(line[5:])
            elif line.startswith("ERR|"):
                ok = False
                info.append("ERROR: " + line[4:])
        label = target if len(target) < 60 else target[:57] + "…"
        # Headline summary finding so even a clean app shows up as evidence.
        findings.insert(0, {
            "title": f"App analyzed ({os_name}) — {label}",
            "severity": "info", "category": "app_recon",
            "standard_refs": ["NIST 800-115", "OWASP MASVS"],
            "description": "Static analysis of the application artifact. " + " · ".join(info[:6]),
            "evidence": "\n".join(info),
            "remediation": "Informational — see findings below for issues.",
        })
        return ModuleResult(raw_output="# app_analysis\n" + "\n".join(info), findings=findings,
                            ok=ok, assets=[{"hostname": label, "asset_type": "app"}])

    def simulate(self, target: str) -> ModuleResult:
        os_name = self.params.get("os", "linux")
        s = _seed(self.name, target)
        findings = [{
            "title": f"App analyzed ({os_name}) — {target}",
            "severity": "info", "category": "app_recon",
            "standard_refs": ["NIST 800-115"],
            "description": "Simulated static analysis. Run in docker mode to actually "
            "fetch and dissect the artifact.",
            "evidence": f"target={target} os={os_name} (simulated)",
            "remediation": "Informational.",
        }]
        if s & 1:
            findings.append(remediation.enrich("hardcoded_secret",
                            evidence="api_key=sk_live_… (simulated match)"))
        if s & 2:
            findings.append(remediation.enrich("unsigned_binary",
                            evidence=f"{os_name} artifact (simulated heuristic)"))
        return ModuleResult(raw_output=f"# app_analysis (simulated) {target}", findings=findings,
                            assets=[{"hostname": target, "asset_type": "app"}])


class RedTeamPlaceholderModule(ScanModule):
    name = "redteam_placeholder"
    pretty = "Red team adversary emulation (placeholder)"
    runs_in_container = False

    def command(self, target: str) -> list[str]:
        return ["true"]

    def parse(self, result: ExecResult, target: str) -> ModuleResult:
        return self.simulate(target)

    def run_real(self, provisioner, target, timeout, labels=None):
        return self.simulate(target)

    def simulate(self, target: str) -> ModuleResult:
        return ModuleResult(
            raw_output="Red team module is a roadmap placeholder. No actions executed.",
            findings=[], assets=[], ok=True)


_API_SPEC_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs",
                   "/swagger/v1/swagger.json", "/openapi.yaml", "/v2/api-docs"]
_API_COMMON_PATHS = ["/", "/api", "/api/v1", "/v1", "/health", "/healthz", "/status",
                     "/version", "/info", "/metrics", "/actuator", "/actuator/health",
                     "/users", "/user", "/admin", "/login", "/auth", "/swagger", "/docs",
                     "/robots.txt"]


def discover_api_endpoints(base: str) -> list[dict]:
    """Discover API endpoints from an OpenAPI/Swagger spec, or by probing common
    paths. Returns [{method, path, source, status?}], in-process (reaches localhost)."""
    import httpx
    base = base.rstrip("/")
    out: list[dict] = []
    seen = set()

    def add(method, path, source, status=None):
        key = (method.upper(), path)
        if key not in seen:
            seen.add(key)
            out.append({"method": method.upper(), "path": path, "source": source,
                        "status": status})

    with httpx.Client(timeout=8, verify=False, follow_redirects=True,
                      headers={"User-Agent": "TempleGuard-API/1.0"}) as c:
        # 1) OpenAPI / Swagger spec
        for sp in _API_SPEC_PATHS:
            try:
                r = c.get(base + sp)
            except Exception:
                continue
            if r.status_code == 200 and "json" in r.headers.get("content-type", "").lower():
                try:
                    spec = r.json() or {}
                except Exception:
                    continue
                paths = spec.get("paths", {})
                for path, ops in paths.items():
                    methods = [m for m in ("get", "post", "put", "patch", "delete", "options")
                               if isinstance(ops, dict) and m in ops] or ["get"]
                    for m in methods:
                        add(m, path, f"spec:{sp}")
                if out:
                    return out
        # 2) probe common paths (GET)
        for p in _API_COMMON_PATHS:
            try:
                r = c.get(base + p)
                if r.status_code < 500:
                    add("GET", p, "probe", r.status_code)
            except Exception:
                continue
    return out


class ApiTestModule(ScanModule):
    """Bounded API security + performance testing.

    Takes a base URL plus explicit endpoints and/or discovers them (OpenAPI/
    Swagger spec, robots.txt, common paths). For each endpoint it sends a
    hard-capped set of requests and logs status, latency (min/avg/p95/max), and
    size — then flags slow endpoints, unauthenticated access, missing rate
    limiting, and verbose errors. Non-destructive (caps below), not a flood.
    """
    name = "api_test"
    pretty = "API security & performance test"
    runs_in_container = False

    MAX_ENDPOINTS = 25
    REQS_PER_ENDPOINT = 8
    SLOW_P95_MS = 1500
    COMMON_PATHS = ["", "/", "/api", "/api/v1", "/v1", "/health", "/healthz",
                    "/status", "/version", "/info", "/metrics", "/actuator",
                    "/users", "/user", "/admin", "/swagger", "/docs"]
    SPEC_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs",
                  "/swagger/v1/swagger.json", "/openapi.yaml"]
    SENSITIVE = ("/users", "/user", "/admin", "/metrics", "/actuator", "/config",
                 "/secret", "/internal", "/debug")

    def command(self, target): return ["true"]
    def parse(self, result, target): return ModuleResult(raw_output="")

    @staticmethod
    def _base(target: str) -> str:
        return (target if re.match(r"^https?://", target) else f"http://{target}").rstrip("/")

    def run_real(self, provisioner, target, timeout, labels=None) -> ModuleResult:
        return self._execute(target)

    def _execute(self, target):
        import httpx
        base = self._base(target)
        host = re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
        # endpoints come pre-selected (list of {method, path}); else discover.
        selected = self.params.get("endpoints") or []
        if not selected:
            selected = discover_api_endpoints(base)
        selected = selected[: self.MAX_ENDPOINTS]
        lines = [f"# API test {base}  ({len(selected)} endpoints)", ""]
        rows, any_429, findings = [], False, []

        with httpx.Client(timeout=8, verify=False, follow_redirects=True,
                          headers={"User-Agent": "TempleGuard-API/1.0"}) as c:
            for ep in selected:
                method = (ep.get("method") or "GET").upper()
                path = ep.get("path", "/")
                url = path if path.startswith("http") else base + (path if path.startswith("/") else "/" + path)
                lat, codes, sizes = [], {}, []
                for _ in range(self.REQS_PER_ENDPOINT):
                    t0 = time.monotonic()
                    try:
                        r = c.request(method, url)
                        lat.append((time.monotonic() - t0) * 1000)
                        codes[r.status_code] = codes.get(r.status_code, 0) + 1
                        sizes.append(len(r.content))
                        if r.status_code == 429:
                            any_429 = True
                    except Exception:
                        codes["err"] = codes.get("err", 0) + 1
                if not lat:
                    lines.append(f"ERR   {method} {path[:42]}")
                    continue
                lat.sort()
                p95 = lat[min(len(lat) - 1, int(len(lat) * 0.95))]
                avg = sum(lat) / len(lat)
                main_code = max(codes, key=codes.get)
                lines.append(f"{main_code}  {method:5} {path[:40]:40}  avg {round(avg):>4}ms  p95 {round(p95):>4}ms")
                tag = f"{method} {path}"
                if p95 >= self.SLOW_P95_MS:
                    findings.append({"title": f"Slow endpoint: {tag}", "severity": "low",
                        "category": "api", "standard_refs": ["OWASP API4:2023", "T1499"],
                        "description": f"p95 latency {round(p95)}ms over {self.REQS_PER_ENDPOINT} requests.",
                        "evidence": f"{method} {url} → avg {round(avg)}ms, p95 {round(p95)}ms, max {round(max(lat))}ms",
                        "remediation": "Profile/optimize; add caching, pagination, query limits, timeouts."})
                if main_code == 200 and any(s in path.lower() for s in self.SENSITIVE):
                    findings.append({"title": f"Unauthenticated access: {tag}", "severity": "high",
                        "category": "api", "standard_refs": ["OWASP API1:2023", "OWASP API2:2023"],
                        "description": "A sensitive endpoint returned 200 without authentication.",
                        "evidence": f"{method} {url} → 200 (no auth)",
                        "remediation": "Require auth + object-level authorization (BOLA); deny by default."})
                if any(isinstance(k, int) and k >= 500 for k in codes) and sizes and max(sizes) > 1500:
                    findings.append({"title": f"Verbose server error: {tag}", "severity": "medium",
                        "category": "api", "standard_refs": ["OWASP API8:2023"],
                        "description": "Large 5xx body (possible stack trace / disclosure).",
                        "evidence": f"{method} {url} codes={codes}",
                        "remediation": "Return generic errors; disable debug output in production."})

            if selected and not any_429:
                findings.append({"title": "No rate limiting observed across API", "severity": "medium",
                    "category": "api", "standard_refs": ["OWASP API4:2023"],
                    "description": f"No 429 across {len(selected)} endpoints under a bounded burst.",
                    "evidence": f"{self.REQS_PER_ENDPOINT} reqs/endpoint × {len(selected)} endpoints, no 429",
                    "remediation": "Add per-client/-endpoint rate limiting and quotas (API4)."})

        findings.insert(0, {"title": f"API tested — {base} ({len(selected)} endpoints)",
            "severity": "info", "category": "api", "standard_refs": ["OWASP API Security Top 10"],
            "description": "Bounded API security + latency assessment.",
            "evidence": "\n".join(lines[:60]), "remediation": "Informational — see findings."})
        return ModuleResult(raw_output="\n".join(lines), findings=findings,
                            assets=[{"hostname": host, "asset_type": "api"}])

    def simulate(self, target: str) -> ModuleResult:
        base = self._base(target)
        eps = ["/api/v1/users", "/api/v1/health", "/metrics", "/api/v1/orders"]
        findings = [{"title": f"API tested — {base} ({len(eps)} endpoints)", "severity": "info",
            "category": "api", "standard_refs": ["OWASP API Security Top 10"],
            "description": "Simulated API assessment.", "evidence": "discovery: common paths (simulated)",
            "remediation": "Informational."},
            {"title": "Slow endpoint: /api/v1/orders", "severity": "low", "category": "api",
             "standard_refs": ["OWASP API4:2023"], "description": "p95 latency 2100ms (simulated).",
             "evidence": "/api/v1/orders → avg 1800ms, p95 2100ms", "remediation": "Optimize + cache."},
            {"title": "No rate limiting observed across API", "severity": "medium", "category": "api",
             "standard_refs": ["OWASP API4:2023"], "description": "No 429 under bounded burst (simulated).",
             "evidence": "no 429 observed", "remediation": "Add rate limiting (API4)."}]
        return ModuleResult(raw_output=f"# api_test (simulated) {base}", findings=findings,
                            assets=[{"hostname": re.sub(r'^https?://', '', base).split('/')[0].split(':')[0],
                                     "asset_type": "api"}])


class RedTeamModule(ScanModule):
    """Executes a red/purple/blue-team operation from the catalog.

    Executable ops run bounded, non-destructive checks in-process. Destructive /
    out-of-scope ops are simulated to produce the attack narrative + a hardening
    finding (no real attack is performed).
    """
    name = "redteam_op"
    pretty = "Red team operation"
    runs_in_container = False

    def command(self, target):
        return ["true"]

    def parse(self, result, target):
        return ModuleResult(raw_output="")

    def run_real(self, provisioner, target, timeout, labels=None) -> ModuleResult:
        self._provisioner, self._timeout, self._labels = provisioner, timeout, labels
        return self._execute(target, simulate=False)

    def simulate(self, target: str) -> ModuleResult:
        self._provisioner, self._timeout, self._labels = None, 120, None
        return self._execute(target, simulate=True)

    @staticmethod
    def _host(target: str) -> str:
        return re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

    def _execute(self, target: str, simulate: bool) -> ModuleResult:
        from . import redteam
        op = redteam.get_op(self.params.get("operation", ""))
        host = self._host(target)
        if not op:
            return ModuleResult(raw_output="unknown red-team operation", ok=False,
                                error="unknown operation")
        url = target if re.match(r"^https?://", target) else f"https://{host}"
        lines = [f"# Red team op: {op.name}  [{op.team}/{op.aggressiveness}]",
                 f"# ATT&CK: {op.attack}", f"# Target: {target}", ""]
        findings: list[dict] = []

        if op.executable and not simulate:
            if op.id in ("recon_surface", "posture_check", "header_drift"):
                findings = self._http_recon(url, op, lines)
            elif op.id in ("resilience_probe", "detection_validation"):
                findings = self._resilience(url, op, lines)
            elif op.id in ("cred_spray", "detection_replay"):
                findings = self._auth_lockout(url, op, lines)
            elif op.id == "user_enumeration":
                findings = self._user_enum(url, op, lines)
            elif op.id == "http_methods":
                findings = self._http_methods(url, op, lines)
            elif op.id == "cors_probe":
                findings = self._cors(url, op, lines)
            elif op.id == "cookie_security":
                findings = self._cookies(url, op, lines)
            elif op.id == "security_txt":
                findings = self._security_txt(url, op, lines)
            elif op.id == "detection_canary":
                findings = self._soc_canary(url, op, lines)
            elif op.id == "tls_posture":
                findings = self._kali_tls(host, op, lines)
            elif op.id == "email_auth":
                findings = self._kali_email_auth(host, op, lines)
        else:
            sev = {"destructive": "high", "aggressive": "high", "moderate": "medium",
                   "low": "low", "passive": "info"}.get(op.aggressiveness, "info")
            lines.append("[SIMULATED — not executed]")
            lines.append(op.explanation)
            findings.append({
                "title": f"{op.name} — technique assessed (simulated)",
                "severity": sev, "category": "redteam",
                "standard_refs": [op.attack],
                "description": op.explanation,
                "evidence": f"Simulated {op.aggressiveness} operation vs {target}. "
                            "Temple Guard did not execute this technique.",
                "remediation": op.hardening,
            })
        return ModuleResult(raw_output="\n".join(lines), findings=findings,
                            assets=[{"hostname": host, "asset_type": "host"}])

    def _http_recon(self, url, op, lines):
        import httpx
        findings = []
        try:
            r = httpx.get(url, follow_redirects=True, timeout=15, verify=False)
        except Exception as exc:  # noqa: BLE001
            lines.append(f"request failed: {exc}")
            return findings
        headers = {k.lower(): v for k, v in r.headers.items()}
        lines.append(f"HTTP {r.status_code}  server={headers.get('server', '?')}")
        findings.append({
            "title": f"{op.name} — {url}", "severity": "info", "category": "redteam",
            "standard_refs": [op.attack],
            "description": op.explanation,
            "evidence": f"HTTP {r.status_code}, server={headers.get('server', 'n/a')}, "
                        f"https_enforced={url.startswith('https')}",
            "remediation": op.hardening,
        })
        for h in ["content-security-policy", "strict-transport-security",
                  "x-frame-options", "x-content-type-options", "referrer-policy"]:
            if h not in headers:
                f = remediation.enrich("missing_security_headers",
                                       evidence=f"'{h}' header missing on {url}")
                f["title"] = f"Missing header: {h}"
                f["standard_refs"] = (f.get("standard_refs", []) + [op.attack])
                f["remediation"] = op.hardening
                findings.append(f)
            else:
                lines.append(f"  ✓ {h}")
        return findings

    def _resilience(self, url, op, lines):
        import httpx
        from .redteam import RESILIENCE_MAX_REQUESTS
        codes: dict = {}
        latencies: list[float] = []
        errors = 0
        with httpx.Client(timeout=8, verify=False, follow_redirects=True) as c:
            for _ in range(RESILIENCE_MAX_REQUESTS):
                t0 = time.monotonic()
                try:
                    resp = c.get(url)
                    codes[resp.status_code] = codes.get(resp.status_code, 0) + 1
                    latencies.append(time.monotonic() - t0)
                except Exception:  # noqa: BLE001
                    errors += 1
        avg_ms = (sum(latencies) / len(latencies) * 1000) if latencies else 0
        lines.append(f"sent {RESILIENCE_MAX_REQUESTS} requests · codes={codes} · "
                     f"errors={errors} · avg {avg_ms:.0f}ms")
        defended = codes.get(429, 0) > 0 or codes.get(503, 0) > 0
        if defended:
            return [{
                "title": "Rate limiting / load shedding observed",
                "severity": "info", "category": "redteam", "standard_refs": [op.attack],
                "description": "Under a bounded burst the target returned 429/503 — a "
                "positive sign of application-layer DoS resilience.",
                "evidence": f"codes={codes}, avg {avg_ms:.0f}ms",
                "remediation": "Maintain rate limiting; validate thresholds + alerting.",
            }]
        return [{
            "title": "No rate limiting under light burst",
            "severity": "medium", "category": "redteam", "standard_refs": [op.attack],
            "description": "A hard-capped burst did not trigger any rate limiting or "
            "429 responses — the endpoint may be exposed to application-layer DoS.",
            "evidence": f"codes={codes}, errors={errors}, avg {avg_ms:.0f}ms "
                        f"({RESILIENCE_MAX_REQUESTS} reqs)",
            "remediation": op.hardening,
        }]

    # --- new RED probes -------------------------------------------------
    def _http_methods(self, url, op, lines):
        import httpx
        risky = []
        try:
            with httpx.Client(timeout=10, verify=False, follow_redirects=True) as c:
                opt = c.request("OPTIONS", url)
                allow = opt.headers.get("allow", opt.headers.get("Allow", ""))
                lines.append(f"OPTIONS → {opt.status_code}  Allow: {allow or '(none)'}")
                for m in ("TRACE", "PUT", "DELETE", "CONNECT"):
                    try:
                        r = c.request(m, url)
                        lines.append(f"  {m} → {r.status_code}")
                        if r.status_code < 400 or m.upper() in allow.upper():
                            risky.append(f"{m} ({r.status_code})")
                    except Exception:
                        pass
        except Exception as exc:  # noqa: BLE001
            lines.append(f"request failed: {exc}")
            return []
        if risky:
            return [{"title": f"Risky HTTP methods enabled: {', '.join(risky)}",
                     "severity": "medium", "category": "redteam", "standard_refs": [op.attack],
                     "description": "Write/diagnostic HTTP verbs are reachable. TRACE enables "
                     "Cross-Site Tracing; PUT/DELETE without auth allow tampering.",
                     "evidence": "; ".join(risky), "remediation": op.hardening}]
        lines.append("  no risky methods enabled ✓")
        return [self._ok_finding(op, url, "Only safe HTTP methods exposed")]

    def _cors(self, url, op, lines):
        import httpx
        evil = "https://evil.example.com"
        try:
            r = httpx.get(url, headers={"Origin": evil}, timeout=10, verify=False,
                          follow_redirects=True)
        except Exception as exc:  # noqa: BLE001
            lines.append(f"request failed: {exc}")
            return []
        acao = r.headers.get("access-control-allow-origin", "")
        acc = r.headers.get("access-control-allow-credentials", "")
        lines.append(f"Origin: {evil} → ACAO: {acao or '(none)'}  ACAC: {acc or '(none)'}")
        if acao == evil or acao == "*":
            sev = "high" if (acao == evil and acc.lower() == "true") else "medium"
            return [{"title": "CORS misconfiguration — origin reflected",
                     "severity": sev, "category": "redteam", "standard_refs": [op.attack],
                     "description": "The app reflects an arbitrary Origin in "
                     "Access-Control-Allow-Origin" + (" with credentials" if acc.lower() == "true" else "") +
                     ", enabling cross-site data theft.",
                     "evidence": f"ACAO={acao}, ACAC={acc} for Origin {evil}",
                     "remediation": op.hardening}]
        lines.append("  origin not reflected ✓")
        return [self._ok_finding(op, url, "CORS does not reflect arbitrary origins")]

    def _cookies(self, url, op, lines):
        import httpx
        try:
            r = httpx.get(url, timeout=10, verify=False, follow_redirects=True)
        except Exception as exc:  # noqa: BLE001
            lines.append(f"request failed: {exc}")
            return []
        raw = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else \
            [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
        if not raw:
            lines.append("no Set-Cookie headers")
            return [self._ok_finding(op, url, "No cookies set on the homepage")]
        findings = []
        for ck in raw:
            name = ck.split("=", 1)[0]
            low = ck.lower()
            missing = [a for a in ("secure", "httponly", "samesite") if a not in low]
            lines.append(f"  {name}: {'OK' if not missing else 'missing ' + ','.join(missing)}")
            if missing:
                findings.append({"title": f"Cookie '{name}' missing: {', '.join(missing)}",
                                 "severity": "medium", "category": "redteam",
                                 "standard_refs": [op.attack],
                                 "description": "Session cookie lacks protective attributes.",
                                 "evidence": ck[:160], "remediation": op.hardening})
        return findings or [self._ok_finding(op, url, "All cookies carry Secure/HttpOnly/SameSite")]

    def _security_txt(self, url, op, lines):
        import httpx
        base = re.match(r"^https?://[^/]+", url).group(0)
        for p in ("/.well-known/security.txt", "/security.txt"):
            try:
                r = httpx.get(base + p, timeout=8, verify=False, follow_redirects=True)
                if r.status_code == 200 and "contact" in r.text.lower():
                    lines.append(f"found {p} ✓")
                    return [self._ok_finding(op, base + p, "security.txt published")]
            except Exception:
                pass
        lines.append("no security.txt found")
        return [{"title": "No security.txt (vulnerability-disclosure contact)",
                 "severity": "low", "category": "redteam", "standard_refs": [op.attack],
                 "description": "No /.well-known/security.txt — reporters have no documented "
                 "contact for disclosing vulnerabilities (RFC 9116).",
                 "evidence": f"{base}/.well-known/security.txt → not found",
                 "remediation": op.hardening}]

    def _user_enum(self, url, op, lines):
        import httpx
        login = self._find_login(url)
        if not login:
            lines.append("no login endpoint discovered (set params.login_url)")
            return [self._info_finding(op, url, "No login endpoint discovered to test.")]
        real = (self.params.get("usernames") or ["admin"])[0]
        bogus = "zz_nope_" + re.sub(r"\W", "", real)[:6]
        out = {}
        with httpx.Client(timeout=10, verify=False, follow_redirects=True) as c:
            for label, u in (("valid-ish", real), ("bogus", bogus)):
                t0 = time.monotonic()
                r = self._post_login(c, login, u, "x")
                out[label] = (r.status_code if r else "err",
                              len(r.text) if r else 0, round((time.monotonic() - t0) * 1000))
                lines.append(f"  {label} '{u}' → {out[label][0]} ({out[label][1]}b, {out[label][2]}ms)")
        a, b = out.get("valid-ish"), out.get("bogus")
        if a and b and (a[0] != b[0] or abs(a[1] - b[1]) > 40):
            return [{"title": "Possible username enumeration",
                     "severity": "medium", "category": "redteam", "standard_refs": [op.attack],
                     "description": "Login responses differ for likely-valid vs bogus "
                     "usernames (status/length), letting an attacker enumerate accounts.",
                     "evidence": f"valid={a} vs bogus={b} at {login}",
                     "remediation": op.hardening}]
        lines.append("  responses indistinguishable ✓")
        return [self._ok_finding(op, login, "Login does not appear to leak account existence")]

    def _auth_lockout(self, url, op, lines):
        """Capped credential test: a few FAKE-password logins to see if lockout fires."""
        import httpx
        from .redteam import AUTH_MAX_ATTEMPTS, AUTH_DUMMY_PASSWORDS
        login = self.params.get("login_url") or self._find_login(url)
        if not login:
            lines.append("no login endpoint discovered (set params.login_url)")
            return [self._info_finding(op, url,
                    "No login endpoint discovered. Provide params.login_url to run the lockout test.")]
        users = self.params.get("usernames") or ["admin"]
        lines.append(f"login: {login} · users: {users} · ≤{AUTH_MAX_ATTEMPTS} attempts, DUMMY passwords")
        codes, defended, attempts = {}, None, 0
        with httpx.Client(timeout=10, verify=False, follow_redirects=True) as c:
            for user in users:
                for pw in AUTH_DUMMY_PASSWORDS:
                    if attempts >= AUTH_MAX_ATTEMPTS:
                        break
                    attempts += 1
                    r = self._post_login(c, login, user, pw)
                    sc = r.status_code if r else "err"
                    codes[sc] = codes.get(sc, 0) + 1
                    body = (r.text.lower() if r else "")
                    lines.append(f"  attempt {attempts}: {user} → {sc}")
                    if sc == 429 or any(k in body for k in
                                        ("locked", "too many", "try again later", "temporarily", "captcha")):
                        defended = f"{sc} / lockout-or-throttle signal"
                        break
                if defended:
                    break
        if defended:
            lines.append(f"  defense fired: {defended} after {attempts} attempts ✓")
            return [{"title": "Account lockout / throttling enforced",
                     "severity": "info", "category": "redteam", "standard_refs": [op.attack],
                     "description": "The login enforced lockout/throttling/CAPTCHA within a "
                     "few failed attempts — a positive auth-abuse control.",
                     "evidence": f"defense after {attempts} attempts: {defended}; codes={codes}",
                     "remediation": "Maintain lockout + alert on spray patterns."}]
        return [{"title": "No account lockout / throttling observed",
                 "severity": "medium", "category": "redteam", "standard_refs": [op.attack],
                 "description": f"{attempts} failed logins produced no lockout, throttling, "
                 "429, or CAPTCHA — the account is exposed to password spraying / brute-force.",
                 "evidence": f"{attempts} attempts, codes={codes}, no defensive response",
                 "remediation": op.hardening}]

    def _soc_canary(self, url, op, lines):
        import httpx
        base = re.match(r"^https?://[^/]+", url).group(0)
        probes = [
            ("scanner UA", base + "/", {"User-Agent": "sqlmap/1.8 (detection-canary)"}),
            ("/.git/config", base + "/.git/config", {}),
            ("sqli marker", base + "/?id=1%27--", {}),
        ]
        sent = []
        with httpx.Client(timeout=8, verify=False, follow_redirects=True) as c:
            for label, u, h in probes:
                try:
                    r = c.get(u, headers=h)
                    sent.append(f"{label}→{r.status_code}")
                    lines.append(f"  canary {label} → {r.status_code}")
                except Exception:
                    sent.append(f"{label}→err")
        return [{"title": "SOC detection canary emitted",
                 "severity": "info", "category": "redteam", "standard_refs": [op.attack],
                 "description": "Sent benign, recognizable attack signatures. Confirm your "
                 "WAF/IDS/SIEM logged and alerted on these — if not, add the rules.",
                 "evidence": "; ".join(sent),
                 "remediation": op.hardening}]

    # --- BLUE ops that run real tools inside the Kali image -------------
    def _kali_tls(self, host, op, lines):
        prov = getattr(self, "_provisioner", None)
        if prov is None:
            return [self._info_finding(op, host, "TLS posture needs the Kali image (docker mode).")]
        tgt = host if ":" in host else f"{host}:443"
        res = prov.run(KALI_IMAGE, ["testssl", "--quiet", "--color", "0", "--protocols", tgt],
                       getattr(self, "_timeout", 300), getattr(self, "_labels", None))
        findings, seen = [], set()
        for line in (res.stdout or "").splitlines():
            low = line.lower()
            m = re.match(r"\s*(SSLv2|SSLv3|TLS 1(\.1)?)\b", line)
            if m and "offered" in low and ("deprecated" in low or "not ok" in low):
                proto = m.group(1)
                if proto not in seen:
                    seen.add(proto)
                    lines.append(f"  weak: {line.strip()}")
                    findings.append({"title": f"Weak/deprecated protocol offered: {proto}",
                                     "severity": "medium", "category": "redteam",
                                     "standard_refs": [op.attack], "description": op.explanation,
                                     "evidence": line.strip(), "remediation": op.hardening})
        if not findings:
            lines.append("  no deprecated protocols offered ✓")
            return [self._ok_finding(op, host, "TLS posture clean (no deprecated protocols)")]
        return findings

    def _kali_email_auth(self, host, op, lines):
        prov = getattr(self, "_provisioner", None)
        if prov is None:
            return [self._info_finding(op, host, "Email-auth check needs the Kali image (docker mode).")]
        script = f"dig +short TXT {host}; echo '==DMARC=='; dig +short TXT _dmarc.{host}"
        res = prov.run(KALI_IMAGE, ["bash", "-c", script],
                       getattr(self, "_timeout", 120), getattr(self, "_labels", None))
        out = res.stdout or ""
        spf = next((l for l in out.splitlines() if "v=spf1" in l.lower()), "")
        dmarc = next((l for l in out.splitlines() if "v=dmarc1" in l.lower()), "")
        lines.append(f"  SPF: {spf or 'MISSING'}")
        lines.append(f"  DMARC: {dmarc or 'MISSING'}")
        gaps = []
        if not spf:
            gaps.append("no SPF record")
        elif "-all" not in spf and "~all" not in spf:
            gaps.append("SPF not enforcing (no -all/~all)")
        if not dmarc:
            gaps.append("no DMARC record")
        elif "p=reject" not in dmarc.lower() and "p=quarantine" not in dmarc.lower():
            gaps.append("DMARC policy is p=none (monitor only)")
        if gaps:
            return [{"title": f"Email spoofing defenses incomplete: {', '.join(gaps)}",
                     "severity": "medium", "category": "redteam", "standard_refs": [op.attack],
                     "description": "SPF/DMARC are missing or not enforcing, allowing domain "
                     "spoofing in phishing.", "evidence": f"SPF={spf or 'none'} | DMARC={dmarc or 'none'}",
                     "remediation": op.hardening}]
        return [self._ok_finding(op, host, "SPF + DMARC present and enforcing")]

    # --- shared helpers -------------------------------------------------
    def _find_login(self, url):
        import httpx
        base = re.match(r"^https?://[^/]+", url).group(0)
        for p in ("/api/login", "/api/auth/login", "/login", "/auth/login",
                  "/api/sessions", "/signin", "/users/sign_in"):
            try:
                r = httpx.request("POST", base + p, json={"username": "x", "password": "x"},
                                  timeout=6, verify=False)
                if r.status_code not in (404, 405, 501):
                    return base + p
            except Exception:
                continue
        return None

    @staticmethod
    def _post_login(c, login, user, pw):
        """Best-effort login POST trying JSON then form, common field names."""
        for payload, kind in (({"username": user, "password": pw}, "json"),
                              ({"email": user, "password": pw}, "json"),
                              ({"username": user, "password": pw}, "data")):
            try:
                r = c.request("POST", login, **({"json": payload} if kind == "json" else {"data": payload}))
                if r.status_code != 415:
                    return r
            except Exception:
                continue
        return None

    @staticmethod
    def _ok_finding(op, where, msg):
        return {"title": f"✓ {msg}", "severity": "info", "category": "redteam",
                "standard_refs": [op.attack], "description": msg,
                "evidence": f"{op.name} vs {where}: control present.",
                "remediation": op.hardening}

    @staticmethod
    def _info_finding(op, where, msg):
        return {"title": f"{op.name} — {msg}", "severity": "info", "category": "redteam",
                "standard_refs": [op.attack], "description": msg,
                "evidence": f"{op.name} vs {where}", "remediation": op.hardening}


def _host_of(target: str) -> str:
    return re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]


def _url_of(target: str) -> str:
    return target if re.match(r"^https?://", target) else f"https://{target}"


class SubfinderModule(ScanModule):
    """subfinder — passive subdomain enumeration (CEH footprinting). Discovered
    subdomains become assets and expand the mapped attack surface."""
    name = "subfinder"
    image = KALI_IMAGE
    pretty = "Subdomain enumeration (subfinder)"

    def command(self, target):
        return ["subfinder", "-d", _host_of(target), "-silent", "-timeout", "12"]

    def parse(self, result, target):
        domain = _host_of(target)
        subs = sorted({l.strip() for l in result.stdout.splitlines()
                       if l.strip() and "." in l and " " not in l.strip()})
        assets = [{"hostname": s, "asset_type": "subdomain"} for s in subs[:200]]
        return ModuleResult(raw_output=result.stdout[:8000], assets=assets, findings=[{
            "title": f"{len(subs)} subdomains discovered for {domain}",
            "severity": "info", "category": "recon", "standard_refs": ["NIST 800-115", "T1595"],
            "description": "Passive subdomain enumeration (subfinder). Each host expands the "
            "attack surface and should be in scope and hardened.",
            "evidence": "\n".join(subs[:60]) or "no subdomains found",
            "remediation": "Inventory all exposed subdomains; decommission stale ones; keep each "
            "within the authorized scope and monitored."}])

    def simulate(self, target):
        d = _host_of(target)
        subs = [f"www.{d}", f"api.{d}", f"dev.{d}", f"staging.{d}", f"mail.{d}"]
        return ModuleResult(raw_output="# subfinder (simulated)\n" + "\n".join(subs),
            assets=[{"hostname": s, "asset_type": "subdomain"} for s in subs],
            findings=[{"title": f"{len(subs)} subdomains discovered for {d}", "severity": "info",
                "category": "recon", "standard_refs": ["NIST 800-115"],
                "description": "Simulated subdomain enumeration.", "evidence": "\n".join(subs),
                "remediation": "Inventory + harden all subdomains."}])


def _wp_vuln(v, where):
    title = v.get("title", "WordPress vulnerability")
    cve = (v.get("references", {}).get("cve") or [None])[0]
    return {"title": f"{where}: {title}", "severity": "high", "category": "wordpress",
            "standard_refs": ["OWASP Top 10 A06"] + ([f"CVE-{cve}"] if cve else []),
            "description": f"Known vulnerability in {where} (wpscan/WPVulnDB).",
            "evidence": title, "remediation": "Update or remove the affected component immediately."}


class WpscanModule(ScanModule):
    """wpscan — WordPress assessment: core version, vulnerable plugins/themes, and
    user enumeration (CEH web-app hacking). Vuln data needs a WPVulnDB token; without
    one it still enumerates version/plugins/users."""
    name = "wpscan"
    image = KALI_IMAGE
    pretty = "WordPress scan (wpscan)"

    def command(self, target):
        return ["wpscan", "--url", _url_of(target), "--no-banner", "--format", "json",
                "--random-user-agent", "--disable-tls-checks", "--enumerate", "vp,u",
                "--request-timeout", "15", "--connect-timeout", "10"]

    def parse(self, result, target):
        import json as _json
        host = _host_of(target)
        try:
            data = _json.loads(result.stdout)
        except ValueError:
            return ModuleResult(raw_output=result.stdout[:4000], assets=[{"hostname": host, "asset_type": "web"}],
                findings=[{"title": "wpscan — target not identified as WordPress", "severity": "info",
                    "category": "wordpress", "standard_refs": ["OWASP Top 10 A06"],
                    "description": "wpscan did not detect a WordPress install (or it was blocked).",
                    "evidence": (result.stdout or result.stderr or "")[:300],
                    "remediation": "If this is WordPress, ensure it is reachable for assessment."}])
        findings = []
        ver = data.get("version") or {}
        if ver.get("number"):
            status = ver.get("status", "")
            findings.append({"title": f"WordPress {ver['number']}" + (f" ({status})" if status else ""),
                "severity": "medium" if status and status != "latest" else "info", "category": "wordpress",
                "standard_refs": ["OWASP Top 10 A06", "T1595"], "description": "WordPress core version disclosed.",
                "evidence": f"version {ver['number']} status={status or '?'}",
                "remediation": "Keep core updated; suppress version disclosure where feasible."})
            for v in ver.get("vulnerabilities", [])[:10]:
                findings.append(_wp_vuln(v, "core"))
        for pname, p in (data.get("plugins") or {}).items():
            for v in (p.get("vulnerabilities") or [])[:8]:
                findings.append(_wp_vuln(v, f"plugin {pname}"))
        users = list((data.get("users") or {}).keys())
        if users:
            findings.append({"title": f"WordPress user enumeration ({len(users)})", "severity": "medium",
                "category": "wordpress", "standard_refs": ["OWASP Top 10 A07", "T1589"],
                "description": "Usernames are enumerable, aiding password attacks.",
                "evidence": "users: " + ", ".join(users[:15]),
                "remediation": "Block author/REST user enumeration; enforce MFA + login lockout."})
        findings.insert(0, {"title": f"WordPress scanned — {host} ({len(findings)} issues)", "severity": "info",
            "category": "wordpress", "standard_refs": ["OWASP Top 10 A06"], "description": "wpscan assessment.",
            "evidence": f"version={ver.get('number', '?')}, plugins={len(data.get('plugins') or {})}",
            "remediation": "Informational — see findings."})
        return ModuleResult(raw_output=result.stdout[:8000], findings=findings,
                            assets=[{"hostname": host, "asset_type": "web"}])

    def simulate(self, target):
        host = _host_of(target)
        return ModuleResult(raw_output=f"# wpscan (simulated) {host}", assets=[{"hostname": host, "asset_type": "web"}],
            findings=[{"title": f"WordPress scanned — {host} (simulated)", "severity": "info", "category": "wordpress",
                "standard_refs": ["OWASP Top 10 A06"], "description": "Simulated WordPress scan.",
                "evidence": "version 6.1 (outdated)", "remediation": "Update core/plugins."},
                {"title": "WordPress user enumeration (2)", "severity": "medium", "category": "wordpress",
                 "standard_refs": ["OWASP Top 10 A07"], "description": "Usernames enumerable (simulated).",
                 "evidence": "users: admin, editor", "remediation": "Block user enumeration; MFA + lockout."}])


class FfufModule(ScanModule):
    """ffuf — content/endpoint discovery (bounded directory brute-force) surfacing
    hidden paths: admin panels, backups, .git, configs (CEH web hacking)."""
    name = "ffuf"
    image = KALI_IMAGE
    pretty = "Content discovery (ffuf)"
    warning = (
        "⚠ Active content discovery. Brute-forces paths with many rapid requests — "
        "intrusive and logged, and can trip rate limits/WAFs. Run only within an "
        "authorized engagement scope and ROE window."
    )
    WORDLIST = "/usr/share/wordlists/dirb/common.txt"
    INTERESTING = ("admin", "backup", ".git", "config", ".env", "login", "phpmyadmin",
                   "wp-admin", "dashboard", "old", "dev", "upload", "api", "secret", "test")

    def command(self, target):
        url = _url_of(target).rstrip("/")
        return ["ffuf", "-u", f"{url}/FUZZ", "-w", self.WORDLIST, "-mc",
                "200,204,301,302,307,401,403", "-of", "json", "-o", "/dev/stdout",
                "-s", "-maxtime", "90", "-t", "20", "-rate", "120"]

    def parse(self, result, target):
        import json as _json
        host = _host_of(target)
        try:
            results = (_json.loads(result.stdout) or {}).get("results", [])
        except ValueError:
            results = []
        findings = []
        for r in results[:80]:
            path = (r.get("input") or {}).get("FUZZ", "")
            status, url = r.get("status"), r.get("url", "")
            sev = "info"
            if any(k in path.lower() for k in self.INTERESTING):
                sev = "medium" if status in (200, 301, 302, 307) else "low"
            findings.append({"title": f"Path found: /{path} [{status}]", "severity": sev, "category": "web",
                "standard_refs": ["OWASP Top 10 A05", "T1595"], "description": "Content discovery surfaced a reachable path.",
                "evidence": f"{status}  {url}", "remediation": "Remove/restrict exposed paths; require auth on "
                "sensitive endpoints; disable directory listing."})
        findings.insert(0, {"title": f"Content discovery — {host} ({len(results)} paths)", "severity": "info",
            "category": "web", "standard_refs": ["NIST 800-115"],
            "description": f"ffuf tested the common-path wordlist; {len(results)} responded.",
            "evidence": "\n".join(f"{r.get('status')}  /{(r.get('input') or {}).get('FUZZ','')}" for r in results[:40]) or "none",
            "remediation": "Informational — see findings."})
        return ModuleResult(raw_output=result.stdout[:6000], findings=findings,
                            assets=[{"hostname": host, "asset_type": "web"}])

    def simulate(self, target):
        host = _host_of(target)
        paths = [("admin", 301), ("login", 200), (".git/config", 200), ("backup", 403)]
        f = [{"title": f"Path found: /{p} [{s}]", "severity": "medium", "category": "web",
              "standard_refs": ["OWASP Top 10 A05"], "description": "Content discovery (simulated).",
              "evidence": f"{s}  https://{host}/{p}", "remediation": "Restrict/remove exposed paths."} for p, s in paths]
        f.insert(0, {"title": f"Content discovery — {host} (simulated)", "severity": "info", "category": "web",
            "standard_refs": ["NIST 800-115"], "description": "Simulated content discovery.",
            "evidence": "4 paths", "remediation": "Informational."})
        return ModuleResult(raw_output=f"# ffuf (simulated) {host}", findings=f, assets=[{"hostname": host, "asset_type": "web"}])


class SslyzeModule(ScanModule):
    """sslyze — structured TLS configuration analysis (accepted protocols + ciphers,
    certificate posture). Complements testssl with a second engine (CEH cryptography)."""
    name = "sslyze"
    image = KALI_IMAGE
    pretty = "TLS config scan (sslyze)"

    def command(self, target):
        host = re.sub(r"^https?://", "", target).split("/")[0]
        return ["sslyze", host if ":" in host else f"{host}:443"]

    def parse(self, result, target):
        out = result.stdout
        host = _host_of(target)
        findings = []
        for proto, label in (("SSL 2.0", "SSLv2"), ("SSL 3.0", "SSLv3"),
                             ("TLS 1.0", "TLS 1.0"), ("TLS 1.1", "TLS 1.1")):
            m = re.search(re.escape(proto) + r" Cipher Suites:\s*\n\s*(.+)", out)
            if m and "the server accepted" in m.group(1).lower():
                findings.append(remediation.enrich("tls_weak_cipher",
                    title=f"Deprecated protocol supported: {label}", evidence=m.group(1).strip()[:160]))
        if "not trusted" in out.lower() or "certificate is not trusted" in out.lower():
            findings.append(remediation.enrich("tls_weak_cipher",
                title="Certificate trust problem", evidence="sslyze: certificate not trusted"))
        findings.insert(0, {"title": f"TLS config scanned — {host}", "severity": "info", "category": "crypto",
            "standard_refs": ["PCI-DSS 4.1", "NIST 800-52"], "description": "sslyze TLS configuration analysis.",
            "evidence": ("deprecated protocols found" if len(findings) else "no deprecated protocols accepted"),
            "remediation": "Disable TLS<1.2, prefer 1.3, remove weak ciphers, keep certs valid."})
        return ModuleResult(raw_output=out[:8000], findings=findings,
                            assets=[{"hostname": host, "asset_type": "host"}])

    def simulate(self, target):
        host = _host_of(target)
        return ModuleResult(raw_output=f"# sslyze (simulated) {host}", assets=[{"hostname": host, "asset_type": "host"}],
            findings=[{"title": f"TLS config scanned — {host} (simulated)", "severity": "info", "category": "crypto",
                "standard_refs": ["PCI-DSS 4.1"], "description": "Simulated TLS scan.",
                "evidence": "TLS 1.0 accepted", "remediation": "Disable legacy TLS."}])


class Wafw00fModule(ScanModule):
    """wafw00f — fingerprint a WAF/CDN in front of the target (recognition, not evasion)."""
    name = "wafw00f"
    image = KALI_IMAGE
    pretty = "WAF detection (wafw00f)"

    def command(self, target):
        return ["wafw00f", _url_of(target), "-a"]

    def parse(self, result, target):
        out = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)  # strip ANSI colour codes
        host = _host_of(target)
        behind = [re.sub(r"\s*WAF\.?$", "", m.group(1).strip())
                  for m in re.finditer(r"is behind (.+)", out)]
        if behind:
            findings = [{"title": f"WAF detected: {', '.join(sorted(set(behind)))[:120]}", "severity": "info",
                "category": "web", "standard_refs": ["OWASP Top 10 A05"],
                "description": "A web application firewall / CDN fronts the target (a positive control).",
                "evidence": "; ".join(behind[:5]),
                "remediation": "Tune WAF rules; ensure it can't be bypassed via direct-to-origin access."}]
        else:
            findings = [{"title": "No WAF detected", "severity": "low", "category": "web",
                "standard_refs": ["OWASP Top 10 A05"], "description": "wafw00f detected no WAF/CDN in front of the app.",
                "evidence": out.strip()[:200] or "no WAF signature matched",
                "remediation": "Consider a WAF/CDN for L7 filtering, rate limiting, and DoS protection."}]
        return ModuleResult(raw_output=out[:4000], findings=findings, assets=[{"hostname": host, "asset_type": "web"}])

    def simulate(self, target):
        host = _host_of(target)
        return ModuleResult(raw_output=f"# wafw00f (simulated) {host}", assets=[{"hostname": host, "asset_type": "web"}],
            findings=[{"title": "No WAF detected", "severity": "low", "category": "web",
                "standard_refs": ["OWASP Top 10 A05"], "description": "Simulated WAF check.",
                "evidence": "no WAF signature", "remediation": "Add a WAF/CDN."}])


class Enum4linuxModule(ScanModule):
    """enum4linux-ng — SMB/Windows enumeration (shares, users, OS) for network/AD
    targets (CEH enumeration). Against non-SMB hosts it simply reports nothing found."""
    name = "enum4linux"
    image = KALI_IMAGE
    pretty = "SMB enumeration (enum4linux-ng)"
    warning = (
        "⚠ Active SMB/Windows enumeration. Connects to SMB/RPC/LDAP and queries shares, "
        "users, and policy — intrusive and logged. Run only against hosts within an "
        "authorized engagement scope and ROE window."
    )

    def command(self, target):
        return ["enum4linux-ng", "-A", _host_of(target)]

    def parse(self, result, target):
        out = result.stdout
        host = _host_of(target)
        findings = []
        if "null session" in out.lower() and "allowed" in out.lower():
            findings.append({"title": "SMB null session allowed", "severity": "high", "category": "network",
                "standard_refs": ["CIS", "T1135"], "description": "Anonymous SMB access is permitted.",
                "evidence": "null session allowed", "remediation": "Disable null sessions; restrict anonymous access."})
        shares = sorted(set(re.findall(r"^\s*([A-Za-z0-9_$.\-]+)\s+(?:DISK|IPC|PRINTER)", out, re.M)))
        if shares:
            findings.append({"title": f"SMB shares enumerated ({len(shares)})", "severity": "medium",
                "category": "network", "standard_refs": ["T1135"], "description": "SMB shares are visible.",
                "evidence": "shares: " + ", ".join(shares[:15]),
                "remediation": "Restrict share permissions; remove unnecessary shares."})
        users = sorted(set(re.findall(r"(?:username|user):\s*([^\s,]+)", out, re.I)))
        if users:
            findings.append({"title": f"SMB users enumerated ({len(users)})", "severity": "medium",
                "category": "network", "standard_refs": ["T1087"], "description": "Local/domain users are enumerable.",
                "evidence": "users: " + ", ".join(users[:15]),
                "remediation": "Restrict anonymous enumeration; enforce MFA + lockout."})
        findings.insert(0, {"title": f"SMB enumeration — {host}", "severity": "info", "category": "network",
            "standard_refs": ["NIST 800-115"], "description": "enum4linux-ng SMB/Windows enumeration.",
            "evidence": ("findings below" if len(findings) else "no SMB service or no anonymous info exposed"),
            "remediation": "Informational — see findings."})
        return ModuleResult(raw_output=out[:8000], findings=findings, assets=[{"hostname": host, "asset_type": "host"}])

    def simulate(self, target):
        host = _host_of(target)
        return ModuleResult(raw_output=f"# enum4linux-ng (simulated) {host}", assets=[{"hostname": host, "asset_type": "host"}],
            findings=[{"title": f"SMB enumeration — {host} (simulated)", "severity": "info", "category": "network",
                "standard_refs": ["NIST 800-115"], "description": "Simulated SMB enumeration.",
                "evidence": "no SMB service", "remediation": "Informational."}])


class PhoneInfogaModule(ScanModule):
    """PhoneInfoga — phone-number OSINT. Validates/normalizes a number and reports
    country, carrier, and line type plus the OSINT footprint an attacker could pivot
    on (social engineering / SIM-swap / vishing exposure). Target is a phone number."""
    name = "phoneinfoga"
    image = KALI_IMAGE
    pretty = "Phone-number OSINT (PhoneInfoga)"

    @staticmethod
    def _normalize(target: str) -> str:
        num = (target or "").strip()
        digits = re.sub(r"[^0-9]", "", num)
        return num if num.startswith("+") else "+" + digits

    def command(self, target: str) -> list[str]:
        return ["phoneinfoga", "scan", "-n", self._normalize(target)]

    def parse(self, result, target):
        out = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout or "")
        num = self._normalize(target)

        def grab(*labels):
            for lab in labels:
                m = re.search(rf"^\s*{lab}\s*:?\s*(.+?)\s*$", out, re.I | re.M)
                if m and m.group(1).strip() not in ("", "NULL", "-"):
                    return m.group(1).strip()
            return ""

        country = grab("Country", "Local country")
        carrier = grab("Carrier")
        line = grab("Line type", "Number type")
        valid = "results for local" in out.lower()
        footprints = [l.strip() for l in out.splitlines()
                      if re.search(r"https?://", l) and any(k in l.lower() for k in
                      ("google", "facebook", "linkedin", "twitter", "search", "ovh", "whitepages"))]
        detail = " · ".join(filter(None, [
            f"country={country}" if country else "", f"carrier={carrier}" if carrier else "",
            f"line={line}" if line else "", f"valid={valid}"]))
        findings = [{
            "title": f"Phone OSINT footprint — {num}", "severity": "info", "category": "osint",
            "standard_refs": ["NIST 800-115", "T1589.001"],
            "description": "Phone-number reconnaissance (PhoneInfoga). A valid, attributable "
            "number plus a discoverable OSINT footprint enables social engineering, vishing, "
            "and SIM-swap targeting of staff.",
            "evidence": detail + (("\nfootprint sources:\n" + "\n".join(footprints[:8])) if footprints else ""),
            "remediation": "Treat staff numbers as sensitive: limit public exposure, train against "
            "vishing/SIM-swap, enable carrier port-out PINs, and prefer app-based MFA over SMS."}]
        if line and "mobile" in line.lower():
            findings.append({"title": f"Mobile line exposed to SIM-swap / SMS-OTP risk — {num}",
                "severity": "low", "category": "osint", "standard_refs": ["T1451"],
                "description": "The number is a mobile line; SMS-based OTP and account recovery are "
                "vulnerable to SIM-swap.", "evidence": detail,
                "remediation": "Move MFA off SMS where possible; set a carrier port-out/transfer PIN."})
        return ModuleResult(raw_output=out[:6000], findings=findings,
                            assets=[{"hostname": num, "asset_type": "phone"}])

    def simulate(self, target):
        num = self._normalize(target)
        return ModuleResult(raw_output=f"# phoneinfoga (simulated) {num}",
            assets=[{"hostname": num, "asset_type": "phone"}],
            findings=[{"title": f"Phone OSINT footprint — {num}", "severity": "info", "category": "osint",
                "standard_refs": ["NIST 800-115"], "description": "Simulated phone OSINT.",
                "evidence": "country=US · carrier=Example Wireless · line=mobile · valid=True",
                "remediation": "Limit public exposure; protect against vishing/SIM-swap."}])


def _strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s or "")


class ReconngModule(ScanModule):
    """recon-ng — OSINT framework. Runs keyless modules (subdomain discovery +
    whois points-of-contact) headless via a resource script. The whois POCs are the
    HUMINT angle: real names/emails/titles exposed in domain registration."""
    name = "reconng"
    image = KALI_IMAGE
    pretty = "OSINT recon framework (recon-ng)"

    def command(self, target: str) -> list[str]:
        domain = re.sub(r"[^a-zA-Z0-9.\-]", "", _host_of(target))
        rc = "\n".join([
            "marketplace install recon/domains-hosts/hackertarget",
            "marketplace install recon/domains-contacts/whois_pocs",
            "workspaces create tg",
            "modules load recon/domains-hosts/hackertarget",
            f"options set SOURCE {domain}", "run",
            "modules load recon/domains-contacts/whois_pocs",
            f"options set SOURCE {domain}", "run",
            "show hosts", "show contacts", "exit",
        ])
        script = f"cat > /tmp/r.rc <<'RCEOF'\n{rc}\nRCEOF\nrecon-ng -r /tmp/r.rc 2>&1"
        return ["bash", "-c", script]

    def parse(self, result, target):
        out = _strip_ansi(result.stdout)
        domain = _host_of(target)
        hosts = sorted({m.group(1) for m in re.finditer(r"Host:\s*(\S+)", out)
                        if "." in m.group(1) and m.group(1) != "None"})
        emails = sorted({e for e in re.findall(r"[\w.\-+]+@[\w.\-]+\.\w+", out)})
        names = sorted({f"{m.group(1)} {m.group(2)}".strip()
                        for m in re.finditer(r"Fname:\s*(\S+).*?Lname:\s*(\S+)", out, re.S)
                        if m.group(1) != "None"})
        findings = [{
            "title": f"OSINT recon — {domain} ({len(hosts)} hosts, {len(emails)} contacts)",
            "severity": "info", "category": "osint", "standard_refs": ["NIST 800-115", "T1590", "T1589"],
            "description": "recon-ng OSINT sweep (subdomains + whois points-of-contact).",
            "evidence": "hosts:\n" + "\n".join(hosts[:30]) + ("\n\ncontacts:\n" + "\n".join(emails[:20]) if emails else ""),
            "remediation": "Reduce passive footprint: WHOIS privacy, role-based registration "
            "contacts (not individuals), and decommission stale hosts."}]
        for em in emails[:15]:
            findings.append({"title": f"Exposed contact (HUMINT): {em}", "severity": "low",
                "category": "osint", "standard_refs": ["T1589.002"],
                "description": "A staff email is publicly attributable to the org via OSINT, "
                "enabling phishing/spear-phishing and credential targeting.",
                "evidence": f"{em} (recon-ng whois POC / source data)",
                "remediation": "Use role accounts + WHOIS privacy; train staff against spear-phishing; enforce MFA."})
        assets = [{"hostname": h, "asset_type": "subdomain"} for h in hosts[:200]]
        return ModuleResult(raw_output=out[:8000], findings=findings, assets=assets)

    def simulate(self, target):
        domain = _host_of(target)
        return ModuleResult(raw_output=f"# recon-ng (simulated) {domain}",
            assets=[{"hostname": f"www.{domain}", "asset_type": "subdomain"}],
            findings=[{"title": f"OSINT recon — {domain} (3 hosts, 2 contacts)", "severity": "info",
                "category": "osint", "standard_refs": ["NIST 800-115"], "description": "Simulated recon-ng sweep.",
                "evidence": "hosts: www, api, mail · contacts: admin@, jane.doe@",
                "remediation": "WHOIS privacy + role accounts."},
                {"title": "Exposed contact (HUMINT): jane.doe@" + domain, "severity": "low", "category": "osint",
                 "standard_refs": ["T1589.002"], "description": "Staff email attributable via OSINT (simulated).",
                 "evidence": "whois POC", "remediation": "Role accounts; anti-phishing training; MFA."}])


class SpiderfootModule(ScanModule):
    """SpiderFoot — automated OSINT. Runs a curated keyless module set headless and
    classifies the exposure: subdomains, emails, social accounts, breaches, open
    ports. The HUMINT view of an org's external footprint."""
    name = "spiderfoot"
    image = KALI_IMAGE
    pretty = "OSINT automation (SpiderFoot)"
    MODULES = ("sfp_dnsresolve,sfp_whois,sfp_sslcert,sfp_email,"
               "sfp_socialprofiles,sfp_accounts,sfp_names,sfp_pageinfo")

    def command(self, target: str) -> list[str]:
        return ["spiderfoot", "-s", _host_of(target), "-m", self.MODULES, "-o", "json", "-q"]

    def parse(self, result, target):
        import json as _json
        domain = _host_of(target)
        try:
            events = _json.loads(result.stdout)
        except (ValueError, TypeError):
            events = []
        by_type: dict[str, list[str]] = {}
        for e in events if isinstance(events, list) else []:
            t = (e.get("type") or "").strip()
            d = (e.get("data") or "").strip()
            if t and d:
                by_type.setdefault(t, [])
                if d not in by_type[t]:
                    by_type[t].append(d)

        def has(*kw):
            return [t for t in by_type if any(k.lower() in t.lower() for k in kw)]

        findings, assets = [], []
        # HUMINT — emails + human names
        emails = sorted({d for t in has("email") for d in by_type[t]})
        names = sorted({d for t in has("human name", "person") for d in by_type[t]})
        for em in emails[:15]:
            findings.append({"title": f"Exposed email (HUMINT): {em}", "severity": "low", "category": "osint",
                "standard_refs": ["T1589.002"], "description": "Staff/org email discoverable via OSINT.",
                "evidence": em, "remediation": "Role accounts; anti-phishing training; MFA."})
        # breaches
        for t in has("leak", "compromis", "breach", "password"):
            for d in by_type[t][:8]:
                findings.append({"title": f"Breach/leak exposure: {d[:70]}", "severity": "high", "category": "osint",
                    "standard_refs": ["T1589.001"], "description": f"SpiderFoot flagged '{t}'.",
                    "evidence": d[:200], "remediation": "Force password resets; enforce MFA; monitor breach feeds."})
        # social accounts
        for t in has("account on external", "social media"):
            for d in by_type[t][:10]:
                findings.append({"title": f"Linked account: {d[:70]}", "severity": "info", "category": "osint",
                    "standard_refs": ["T1593.001"], "description": "An external account tied to the org/staff.",
                    "evidence": d[:200], "remediation": "Review staff social exposure; limit role/title disclosure."})
        # open ports / vulns
        for t in has("open tcp port", "open port"):
            for d in by_type[t][:15]:
                findings.append({"title": f"Exposed service: {d[:60]}", "severity": "medium", "category": "osint",
                    "standard_refs": ["NIST 800-115"], "description": "Internet-exposed port found via OSINT.",
                    "evidence": d[:120], "remediation": "Close/firewall unneeded services."})
        for t in has("vulnerability", "cve"):
            for d in by_type[t][:15]:
                findings.append({"title": f"Vulnerability (OSINT): {d[:60]}", "severity": "high", "category": "osint",
                    "standard_refs": ["OWASP Top 10 A06"], "description": "Known vulnerability surfaced via OSINT.",
                    "evidence": d[:120], "remediation": "Patch the affected component."})
        # assets — discovered hostnames/IPs
        for t in has("internet name", "subdomain", "co-hosted", "affiliate - internet"):
            for d in by_type[t][:200]:
                assets.append({"hostname": d, "asset_type": "subdomain"})

        findings.insert(0, {"title": f"OSINT footprint — {domain} ({len(events)} data points)",
            "severity": "info", "category": "osint", "standard_refs": ["NIST 800-115", "T1590"],
            "description": "SpiderFoot automated OSINT across DNS, certs, emails, social, and accounts.",
            "evidence": " · ".join(f"{t}: {len(v)}" for t, v in sorted(by_type.items(), key=lambda x: -len(x[1]))[:12])
                        or "no data points returned",
            "remediation": "Shrink the public footprint; protect staff identities; monitor for leaks."})
        return ModuleResult(raw_output=result.stdout[:8000], findings=findings, assets=assets)

    def simulate(self, target):
        domain = _host_of(target)
        return ModuleResult(raw_output=f"# spiderfoot (simulated) {domain}",
            assets=[{"hostname": f"vpn.{domain}", "asset_type": "subdomain"}],
            findings=[{"title": f"OSINT footprint — {domain} (simulated)", "severity": "info", "category": "osint",
                "standard_refs": ["NIST 800-115"], "description": "Simulated SpiderFoot OSINT.",
                "evidence": "Internet Name: 6 · Email Address: 3 · Open TCP Port: 2",
                "remediation": "Shrink public footprint; protect staff identities."},
                {"title": "Breach/leak exposure: corp creds in 2019 dump", "severity": "high", "category": "osint",
                 "standard_refs": ["T1589.001"], "description": "Simulated breach exposure.",
                 "evidence": "haveibeenpwned (simulated)", "remediation": "Force resets; enforce MFA."}])


class TheHarvesterModule(ScanModule):
    """theHarvester — OSINT email + subdomain harvesting from public sources (cert
    transparency, search engines, passive DNS). HUMINT angle: exposed staff emails."""
    name = "theharvester"
    image = KALI_IMAGE
    pretty = "OSINT email/host harvest (theHarvester)"
    SOURCES = "crtsh,duckduckgo,hackertarget,rapiddns,otx,anubis"

    def command(self, target: str) -> list[str]:
        return ["theHarvester", "-d", _host_of(target), "-b", self.SOURCES, "-l", "200"]

    def parse(self, result, target):
        domain = _host_of(target)
        out = _strip_ansi(result.stdout or "")
        # Drop theHarvester's own banner/author email so it isn't reported as a finding.
        emails = sorted({e for e in re.findall(r"[\w.+\-]+@[\w.\-]+\.\w+", out)
                         if "edge-security.com" not in e.lower()})
        hosts = sorted({h for h in re.findall(rf"[\w.\-]+\.{re.escape(domain)}", out)
                        if not h.startswith("@")})
        findings = [{
            "title": f"OSINT harvest — {domain} ({len(emails)} emails, {len(hosts)} hosts)",
            "severity": "info", "category": "osint", "standard_refs": ["NIST 800-115", "T1589.002"],
            "description": "theHarvester OSINT sweep across cert transparency, search engines, and passive DNS.",
            "evidence": ("emails:\n" + "\n".join(emails[:25]) if emails else "no emails found") +
                        ("\n\nhosts:\n" + "\n".join(hosts[:25]) if hosts else ""),
            "remediation": "Reduce public email exposure (role accounts, anti-harvesting); inventory subdomains."}]
        for em in emails[:15]:
            findings.append({"title": f"Harvested email (HUMINT): {em}", "severity": "low", "category": "osint",
                "standard_refs": ["T1589.002"], "description": "Staff email harvested from public OSINT sources.",
                "evidence": em, "remediation": "Role accounts; anti-phishing training; enforce MFA."})
        assets = [{"hostname": h, "asset_type": "subdomain"} for h in hosts[:200]]
        return ModuleResult(raw_output=out[:8000], findings=findings, assets=assets)

    def simulate(self, target):
        domain = _host_of(target)
        return ModuleResult(raw_output=f"# theHarvester (simulated) {domain}",
            assets=[{"hostname": f"mail.{domain}", "asset_type": "subdomain"}],
            findings=[{"title": f"OSINT harvest — {domain} (2 emails, 3 hosts)", "severity": "info", "category": "osint",
                "standard_refs": ["NIST 800-115"], "description": "Simulated theHarvester sweep.",
                "evidence": "emails: info@, hr@ · hosts: www, mail, vpn",
                "remediation": "Role accounts; reduce public exposure."}])


class MetasploitModule(ScanModule):
    """Metasploit — vulnerability IDENTIFICATION only. Runs a curated set of
    auxiliary/scanner + check modules headless (msfconsole -x) and reports what they
    flag. No exploit modules, payloads, or sessions are invoked; exploitation stays
    gated. Heavy framework, so it runs from its own templeguard/metasploit image."""
    name = "metasploit"
    image = "templeguard/metasploit:latest"
    pretty = "Metasploit vuln scan (auxiliary, detection-only)"
    warning = (
        "⚠ Active vulnerability checks via Metasploit auxiliary/scanner modules "
        "(detection only — no exploits/payloads). Sends intrusive probes and is logged. "
        "Run only within an authorized engagement scope and ROE window."
    )

    # (module, {local options}). All are scanners/checks — none exploit.
    SCANNERS = [
        ("auxiliary/scanner/smb/smb_ms17_010", {}),
        ("auxiliary/scanner/smb/smb_version", {}),
        ("auxiliary/scanner/ssh/ssh_version", {}),
        ("auxiliary/scanner/ftp/ftp_version", {}),
        ("auxiliary/scanner/http/http_version", {"RPORT": "80"}),
        ("auxiliary/scanner/http/http_version", {"RPORT": "443", "SSL": "true"}),
        ("auxiliary/scanner/ssl/openssl_heartbleed", {"RPORT": "443", "verbose": "true"}),
    ]

    def command(self, target: str) -> list[str]:
        host = _host_of(target)
        cmds = [f"setg RHOSTS {host}", "setg ConsoleLogging false"]
        for mod, opts in self.SCANNERS:
            cmds.append(f"use {mod}")
            for k, v in opts.items():
                cmds.append(f"set {k} {v}")
            cmds.append("run")
        cmds.append("exit")
        return ["msfconsole", "-q", "-x", "; ".join(cmds)]

    def parse(self, result, target):
        host = _host_of(target)
        out = _strip_ansi(result.stdout or "")
        findings = []
        seen = set()
        for line in out.splitlines():
            s = line.strip()
            if not s.startswith("[+]"):
                continue
            msg = s[3:].strip()
            low = msg.lower()
            # Skip pure status noise; keep substantive detections.
            if not msg or any(k in low for k in ("scanned ", "completed", "auxiliary module execution")):
                continue
            key = msg[:60]
            if key in seen:
                continue
            seen.add(key)
            sev = "high" if any(k in low for k in
                  ("vulnerable", "ms17-010", "heartbleed", "cve-", "exploit")) else "medium"
            findings.append({"title": f"Metasploit: {msg[:75]}", "severity": sev, "category": "vuln",
                "standard_refs": ["NIST 800-115", "OWASP Top 10 A06"],
                "description": "Detection by a Metasploit auxiliary scanner / check module.",
                "evidence": s, "remediation": "Patch/remediate the affected service; "
                "restrict exposure and re-test. (Exploitation is not performed by the platform.)"})
        summary = [l.strip() for l in out.splitlines() if l.strip().startswith(("[+]", "[*]"))]
        findings.insert(0, {"title": f"Metasploit vuln scan — {host} ({len(findings)} detections)",
            "severity": "info", "category": "vuln", "standard_refs": ["NIST 800-115"],
            "description": "Curated Metasploit auxiliary/scanner sweep (detection-only; no exploitation).",
            "evidence": "\n".join(summary[:40]) or "no scanner output (no matching services exposed)",
            "remediation": "Informational — see detections below."})
        return ModuleResult(raw_output=out[:8000], findings=findings,
                            assets=[{"hostname": host, "asset_type": "host"}])

    def simulate(self, target):
        host = _host_of(target)
        return ModuleResult(raw_output=f"# metasploit (simulated) {host}", assets=[{"hostname": host, "asset_type": "host"}],
            findings=[{"title": f"Metasploit vuln scan — {host} (simulated)", "severity": "info", "category": "vuln",
                "standard_refs": ["NIST 800-115"], "description": "Simulated Metasploit auxiliary sweep.",
                "evidence": "[*] SMB version: Windows Server 2016", "remediation": "Informational."},
                {"title": "Metasploit: Host is likely VULNERABLE to MS17-010 (simulated)", "severity": "high",
                 "category": "vuln", "standard_refs": ["NIST 800-115", "OWASP Top 10 A06"],
                 "description": "Simulated EternalBlue check.", "evidence": "[+] Host is likely VULNERABLE to MS17-010",
                 "remediation": "Patch MS17-010; disable SMBv1."}])


class CVEScanModule(ScanModule):
    """CVE identification (DETECTION ONLY). Runs Nmap service detection + the built-in
    `vuln` NSE category to map a target's running versions to KNOWN, published CVEs,
    then reports them with references + remediation. It does NOT exploit anything —
    weaponized exploitation remains an executable=False, documented-only red-team op
    (`exploit_known_cve`). This is the same posture as the Metasploit module."""
    name = "cve_scan"
    image = KALI_IMAGE
    pretty = "CVE identification (Nmap vuln NSE)"
    warning = (
        "⚠ Active vulnerability scan. Runs Nmap version detection + the `vuln` NSE "
        "scripts — intrusive checks that are logged on the target. Detection only, no "
        "exploitation. Run only within an authorized engagement scope and ROE window."
    )

    @staticmethod
    def _host(target: str) -> str:
        return re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

    def command(self, target: str) -> list[str]:
        # -sV version detect + the built-in `vuln` category (known-CVE detection
        # scripts); per-script timeout so a slow script can't hang the run.
        return ["nmap", "-sV", "-Pn", "--script", "vuln",
                "--script-timeout", "120s", self._host(target)]

    def parse(self, result, target):
        host = self._host(target)
        out = result.stdout or ""
        ports = []
        for line in out.splitlines():
            m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line.strip())
            if m:
                port, proto, svc, banner = m.groups()
                ports.append({"port": int(port), "proto": proto, "service": svc, "banner": banner})
        # One finding per unique published CVE (reliable regex), with its context line.
        cve_evidence: dict[str, str] = {}
        for line in out.splitlines():
            for cve in re.findall(r"CVE-\d{4}-\d{3,7}", line):
                cve_evidence.setdefault(cve, line.strip("| _\t").strip()[:180])
        findings = []
        for cve, ev in sorted(cve_evidence.items())[:50]:
            findings.append({
                "title": f"Known vulnerability: {cve}", "severity": "high", "category": "cve",
                "standard_refs": ["NIST 800-115", "OWASP Top 10 A06", cve],
                "description": "A running service version is affected by this published CVE "
                "(Nmap `vuln` NSE, version-based detection — not exploited).",
                "evidence": ev or cve,
                "remediation": "Patch/upgrade the affected component to a fixed version; "
                "see the CVE advisory. Validate exploitability only under explicit authorization."})
        # VULNERABLE checks that didn't carry an explicit CVE id.
        vuln_scripts = sorted({m.group(1) for line in out.splitlines()
                               if "VULNERABLE" in line.upper()
                               for m in [re.search(r"([a-z0-9][\w\-]+)", line)] if m})
        findings.insert(0, {
            "title": f"CVE scan — {host} ({len(cve_evidence)} CVEs, {len(ports)} services)",
            "severity": "info", "category": "cve", "standard_refs": ["NIST 800-115", "OWASP Top 10 A06"],
            "description": "Nmap service detection + `vuln` NSE CVE identification (detection only).",
            "evidence": ("CVEs: " + ", ".join(sorted(cve_evidence)[:30])) if cve_evidence else
                        ("services: " + ", ".join(f"{p['port']}/{p['service']}" for p in ports[:15]) or
                         "no open ports / no known CVEs detected"),
            "remediation": "Informational — patch the flagged components below."})
        asset = {"ip": host, "hostname": host, "asset_type": "host", "open_ports": ports}
        return ModuleResult(raw_output=out[:8000], findings=findings, assets=[asset])

    def simulate(self, target):
        host = self._host(target)
        return ModuleResult(raw_output=f"# cve_scan (simulated) {host}",
            assets=[{"ip": host, "hostname": host, "asset_type": "host", "open_ports": []}],
            findings=[
                {"title": f"CVE scan — {host} (2 CVEs, 3 services)", "severity": "info", "category": "cve",
                 "standard_refs": ["NIST 800-115", "OWASP Top 10 A06"],
                 "description": "Simulated CVE identification.", "evidence": "CVEs: CVE-2021-44228, CVE-2017-5638",
                 "remediation": "Patch the flagged components."},
                {"title": "Known vulnerability: CVE-2017-5638", "severity": "high", "category": "cve",
                 "standard_refs": ["NIST 800-115", "CVE-2017-5638"],
                 "description": "Apache Struts RCE — known-vulnerable version detected (simulated, not exploited).",
                 "evidence": "http-vuln-cve2017-5638: VULNERABLE; CVE-2017-5638",
                 "remediation": "Upgrade Apache Struts to a fixed release."}])


_REGISTRY = {
    "nmap": NmapModule,
    "nikto": NiktoModule,
    "nuclei": NucleiModule,
    "tls_audit": TLSAuditModule,
    "sqlmap": SqlmapModule,
    "subfinder": SubfinderModule,
    "wpscan": WpscanModule,
    "ffuf": FfufModule,
    "sslyze": SslyzeModule,
    "wafw00f": Wafw00fModule,
    "enum4linux": Enum4linuxModule,
    "phoneinfoga": PhoneInfogaModule,
    "reconng": ReconngModule,
    "spiderfoot": SpiderfootModule,
    "theharvester": TheHarvesterModule,
    "metasploit": MetasploitModule,
    "cve_scan": CVEScanModule,
    "api_test": ApiTestModule,
    "web_evidence": WebEvidenceModule,
    "app_analysis": AppAnalysisModule,
    "redteam_op": RedTeamModule,
    "redteam_placeholder": RedTeamPlaceholderModule,
}


def get_module(name: str, params: dict | None = None) -> ScanModule:
    cls = _REGISTRY.get(name, NmapModule)
    return cls(params)
