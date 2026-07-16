"""Defensive checks — bounded, read-only assessments of a web app you own.

Every check is passive/low-impact (GET + one OPTIONS): it inspects what the app
returns and reports what to remediate. Nothing here exploits, floods, or brute-forces.
"""
from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urlparse

import httpx

SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Finding:
    title: str
    severity: str          # high | medium | low | info
    category: str          # headers | cookies | transport | disclosure | exposure
    evidence: str
    remediation: str


@dataclass
class ScanResult:
    url: str
    reachable: bool = True
    error: str = ""
    status: int | None = None
    server: str = ""
    findings: list[Finding] = field(default_factory=list)

    @property
    def by_severity(self) -> dict[str, int]:
        out = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


# (header, pretty name, severity, remediation) — the ones an app should set.
SECURITY_HEADERS = [
    ("content-security-policy", "Content-Security-Policy", "high",
     "Add a strict CSP (e.g. default-src 'self') to mitigate XSS and data injection."),
    ("strict-transport-security", "Strict-Transport-Security (HSTS)", "high",
     "Send HSTS (max-age>=31536000; includeSubDomains) over HTTPS to force secure transport."),
    ("x-frame-options", "X-Frame-Options", "medium",
     "Set X-Frame-Options: DENY (or a frame-ancestors CSP) to prevent clickjacking."),
    ("x-content-type-options", "X-Content-Type-Options", "low",
     "Set X-Content-Type-Options: nosniff to stop MIME-type sniffing."),
    ("referrer-policy", "Referrer-Policy", "low",
     "Set Referrer-Policy: strict-origin-when-cross-origin to limit referrer leakage."),
    ("permissions-policy", "Permissions-Policy", "low",
     "Set a Permissions-Policy to disable unused browser features (camera, geolocation, …)."),
]

# The read-only checks this tool runs — also used to render --dry-run and verbose steps.
CHECK_PLAN = [
    ("transport", "HTTPS / TLS", "Is the app served over HTTPS with a valid, current certificate?"),
    ("headers", "Security headers", "CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy."),
    ("cookies", "Cookie flags", "Set-Cookie carries Secure / HttpOnly / SameSite."),
    ("disclosure", "Info disclosure", "Server/tech version banners exposed in responses."),
    ("exposure", "Sensitive paths", "Probes a few well-known files (/.git/config, /.env, /.well-known/security.txt)."),
    ("methods", "HTTP methods", "OPTIONS — flags risky verbs (TRACE/PUT/DELETE) exposed without auth."),
    ("email", "Email auth (SPF/DMARC)", "The domain's SPF + DMARC DNS records — spoofing defense."),
]

SENSITIVE_PATHS = ["/.git/config", "/.env", "/.aws/credentials", "/config.json"]

# on_event(kind, **data): kind in {"step","finding","clean","unreachable"}.
EventFn = Optional[Callable[..., None]]


def _host_port(url: str) -> tuple[str, int, bool]:
    u = urlparse(url if "://" in url else "https://" + url)
    https = u.scheme == "https"
    return u.hostname or "", u.port or (443 if https else 80), https


def scan(url: str, timeout: float = 10.0, on_event: EventFn = None) -> ScanResult:
    """Run all defensive checks against `url` and return findings + remediation.

    If `on_event` is given it is called as the scan runs so callers can show live,
    verbose progress:
      * on_event("step", category=…, name=…, desc=…)  — a check group is starting
      * on_event("finding", finding=Finding)           — a finding was surfaced
      * on_event("clean", category=…, name=…)          — a group finished clean
      * on_event("unreachable", url=…, error=…)        — the target didn't respond
    """
    plan = {cat: (name, desc) for cat, name, desc in CHECK_PLAN}

    def emit(kind: str, **kw) -> None:
        if on_event:
            on_event(kind, **kw)

    if "://" not in url:
        url = "https://" + url
    res = ScanResult(url=url)
    host, port, https = _host_port(url)

    def add(f: Finding) -> None:
        res.findings.append(f)
        emit("finding", finding=f)

    def step(cat: str) -> int:
        name, desc = plan.get(cat, (cat, ""))
        emit("step", category=cat, name=name, desc=desc)
        return len(res.findings)

    def done(cat: str, n0: int) -> None:
        if len(res.findings) == n0:
            name, _ = plan.get(cat, (cat, ""))
            emit("clean", category=cat, name=name)

    try:
        with httpx.Client(timeout=timeout, verify=True, follow_redirects=True,
                          headers={"User-Agent": "temple-guard/0.1 (+self-scan)"}) as c:
            r = c.get(url)
    except httpx.HTTPError as exc:
        # retry without cert verification so we can still report on a bad cert
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as c:
                r = c.get(url)
            step("transport")
            add(Finding(
                "TLS certificate not trusted", "high", "transport",
                f"{host}:{port} — certificate failed verification ({exc}).",
                "Install a valid CA-signed certificate; renew before expiry."))
        except Exception as exc2:  # noqa: BLE001
            res.reachable = False
            res.error = str(exc2)
            emit("unreachable", url=url, error=res.error)
            return res

    res.status = r.status_code
    headers = {k.lower(): v for k, v in r.headers.items()}
    res.server = headers.get("server", "")

    # transport
    n0 = step("transport")
    if not https:
        add(Finding(
            "App served over plain HTTP", "high", "transport",
            f"{url} responded on HTTP without TLS.",
            "Serve exclusively over HTTPS and redirect HTTP→HTTPS; add HSTS."))
    else:
        _check_cert(host, port, add)
    done("transport", n0)

    # security headers
    n0 = step("headers")
    for key, name, sev, fix in SECURITY_HEADERS:
        if key not in headers:
            add(Finding(
                f"Missing security header: {name}", sev, "headers",
                f"Response from {url} did not include '{name}'.", fix))
    done("headers", n0)

    # cookies
    n0 = step("cookies")
    cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else \
        [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
    for ck in cookies:
        cname = ck.split("=", 1)[0]
        low = ck.lower()
        missing = [a for a in ("secure", "httponly", "samesite") if a not in low]
        if missing:
            add(Finding(
                f"Cookie '{cname}' missing: {', '.join(missing)}", "medium", "cookies",
                ck[:160],
                "Set Secure + HttpOnly + SameSite=Lax/Strict on session cookies."))
    done("cookies", n0)

    # info disclosure
    n0 = step("disclosure")
    if res.server and any(ch.isdigit() for ch in res.server):
        add(Finding(
            f"Server version disclosed: {res.server}", "low", "disclosure",
            f"Server header: {res.server}",
            "Suppress version banners (Server / X-Powered-By) to slow attacker recon."))
    if "x-powered-by" in headers:
        add(Finding(
            f"Technology disclosed via X-Powered-By: {headers['x-powered-by']}", "low",
            "disclosure", f"X-Powered-By: {headers['x-powered-by']}",
            "Remove the X-Powered-By header."))
    done("disclosure", n0)

    # sensitive path exposure — guarded against catch-all / SPA servers that 200 everything
    n0 = step("exposure")
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as c:
            # probe a path that should NOT exist; if the server 200s it, it's a catch-all
            # (SPA / framework fallback) and a 200 on a sensitive path proves nothing.
            catch_all_len = None
            try:
                probe = c.get(base + "/__temple_guard_probe_404__")
                if probe.status_code == 200:
                    catch_all_len = len(probe.content)
            except httpx.HTTPError:
                pass
            for p in SENSITIVE_PATHS:
                try:
                    pr = c.get(base + p)
                    if pr.status_code != 200 or not pr.content:
                        continue
                    ctype = pr.headers.get("content-type", "").lower()
                    # skip if it looks like the catch-all page (≈ same size) or a generic
                    # HTML page — a real .env / .git/config / creds file isn't text/html.
                    if catch_all_len is not None and abs(len(pr.content) - catch_all_len) <= 24:
                        continue
                    if "html" in ctype:
                        continue
                    add(Finding(
                        f"Sensitive file exposed: {p}", "high", "exposure",
                        f"GET {base}{p} → 200 ({len(pr.content)} bytes, {ctype or 'unknown type'})",
                        "Remove the file from the web root or block it at the edge."))
                except httpx.HTTPError:
                    pass
    except Exception:  # noqa: BLE001
        pass
    done("exposure", n0)

    # methods
    n0 = step("methods")
    try:
        with httpx.Client(timeout=timeout, verify=False) as c:
            opt = c.request("OPTIONS", url)
            allow = opt.headers.get("allow", "")
            risky = [m for m in ("TRACE", "PUT", "DELETE", "CONNECT") if m in allow.upper()]
            if risky:
                add(Finding(
                    f"Risky HTTP methods advertised: {', '.join(risky)}", "medium", "methods",
                    f"OPTIONS {url} → Allow: {allow}",
                    "Disable TRACE/TRACK; restrict PUT/DELETE to authenticated APIs."))
    except httpx.HTTPError:
        pass
    done("methods", n0)

    # email auth (SPF / DMARC) — DNS posture, only meaningful for real domains
    n0 = step("email")
    _email_auth(host, add)
    done("email", n0)

    res.findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    return res


def _check_cert(host: str, port: int, add: Callable[[Finding], None]) -> None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                add(Finding(
                    "TLS certificate expired", "high", "transport",
                    f"Certificate expired {abs(days)} days ago ({not_after}).",
                    "Renew the certificate immediately and automate renewal."))
            elif days < 21:
                add(Finding(
                    f"TLS certificate expiring soon ({days}d)", "medium", "transport",
                    f"Certificate valid until {not_after}.",
                    "Renew the certificate and automate renewal (e.g. ACME)."))
    except Exception:  # noqa: BLE001 — cert introspection is best-effort
        pass


def _is_domain(host: str) -> bool:
    """True for real DNS names (skip localhost / IP literals — no SPF/DMARC there)."""
    if not host or host in ("localhost",):
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) or ":" in host:  # IPv4 / IPv6
        return False
    return "." in host


def _txt_with(resolver, name: str, marker: str) -> Optional[str]:
    try:
        for rec in resolver.resolve(name, "TXT"):
            txt = b"".join(rec.strings).decode("utf-8", "replace") if hasattr(rec, "strings") else str(rec).strip('"')
            if marker.lower() in txt.lower():
                return txt
    except Exception:  # noqa: BLE001 — NXDOMAIN / no answer / timeout
        return None
    return None


def _email_auth(host: str, add: Callable[[Finding], None]) -> None:
    """Check the domain's SPF + DMARC records (spoofing defense). Skipped for
    localhost / IPs. Best-effort — silent if DNS can't be resolved."""
    if not _is_domain(host):
        return
    try:
        import dns.resolver  # dnspython
    except Exception:  # noqa: BLE001 — optional dep; skip cleanly if missing
        return
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = 6.0

    spf = _txt_with(resolver, host, "v=spf1")
    if spf is None:
        add(Finding("No SPF record", "medium", "email",
                    f"No 'v=spf1' TXT record found on {host}.",
                    "Publish an SPF record ending in -all so unlisted senders can't spoof the domain."))
    elif "-all" not in spf and "~all" not in spf:
        add(Finding("SPF not enforcing", "low", "email",
                    f"SPF present but no -all/~all: {spf[:140]}",
                    "End SPF with -all (hard fail) or ~all (soft fail) to actually reject spoofed senders."))

    dmarc = _txt_with(resolver, "_dmarc." + host, "v=DMARC1")
    if dmarc is None:
        add(Finding("No DMARC record", "medium", "email",
                    f"No 'v=DMARC1' TXT record on _dmarc.{host}.",
                    "Publish DMARC (start at p=none for monitoring, then move to quarantine/reject)."))
    elif "p=none" in dmarc.lower():
        add(Finding("DMARC is monitor-only (p=none)", "low", "email",
                    f"DMARC present but p=none: {dmarc[:140]}",
                    "Move DMARC to p=quarantine or p=reject once your sources are aligned."))
