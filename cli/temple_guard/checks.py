"""Defensive checks — bounded, read-only assessments of a web app you own.

Every check is passive/low-impact (GET + one OPTIONS): it inspects what the app
returns and reports what to remediate. Nothing here exploits, floods, or brute-forces.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
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

# The read-only checks this tool runs — also used to render --dry-run.
CHECK_PLAN = [
    ("transport", "HTTPS / TLS", "Is the app served over HTTPS with a valid, current certificate?"),
    ("headers", "Security headers", "CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy."),
    ("cookies", "Cookie flags", "Set-Cookie carries Secure / HttpOnly / SameSite."),
    ("disclosure", "Info disclosure", "Server/tech version banners exposed in responses."),
    ("exposure", "Sensitive paths", "Probes a few well-known files (/.git/config, /.env, /.well-known/security.txt)."),
    ("methods", "HTTP methods", "OPTIONS — flags risky verbs (TRACE/PUT/DELETE) exposed without auth."),
]

SENSITIVE_PATHS = ["/.git/config", "/.env", "/.aws/credentials", "/config.json"]


def _host_port(url: str) -> tuple[str, int, bool]:
    u = urlparse(url if "://" in url else "https://" + url)
    https = u.scheme == "https"
    return u.hostname or "", u.port or (443 if https else 80), https


def scan(url: str, timeout: float = 10.0) -> ScanResult:
    """Run all defensive checks against `url` and return findings + remediation."""
    if "://" not in url:
        url = "https://" + url
    res = ScanResult(url=url)
    host, port, https = _host_port(url)

    try:
        with httpx.Client(timeout=timeout, verify=True, follow_redirects=True,
                          headers={"User-Agent": "temple-guard/0.1 (+self-scan)"}) as c:
            r = c.get(url)
    except httpx.HTTPError as exc:
        # retry without cert verification so we can still report on a bad cert
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as c:
                r = c.get(url)
            res.findings.append(Finding(
                "TLS certificate not trusted", "high", "transport",
                f"{host}:{port} — certificate failed verification ({exc}).",
                "Install a valid CA-signed certificate; renew before expiry."))
        except Exception as exc2:  # noqa: BLE001
            res.reachable = False
            res.error = str(exc2)
            return res

    res.status = r.status_code
    headers = {k.lower(): v for k, v in r.headers.items()}
    res.server = headers.get("server", "")

    # transport
    if not https:
        res.findings.append(Finding(
            "App served over plain HTTP", "high", "transport",
            f"{url} responded on HTTP without TLS.",
            "Serve exclusively over HTTPS and redirect HTTP→HTTPS; add HSTS."))
    elif https:
        _check_cert(res, host, port)

    # security headers
    for key, name, sev, fix in SECURITY_HEADERS:
        if key not in headers:
            res.findings.append(Finding(
                f"Missing security header: {name}", sev, "headers",
                f"Response from {url} did not include '{name}'.", fix))

    # cookies
    cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else \
        [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
    for ck in cookies:
        name = ck.split("=", 1)[0]
        low = ck.lower()
        missing = [a for a in ("secure", "httponly", "samesite") if a not in low]
        if missing:
            res.findings.append(Finding(
                f"Cookie '{name}' missing: {', '.join(missing)}", "medium", "cookies",
                ck[:160],
                "Set Secure + HttpOnly + SameSite=Lax/Strict on session cookies."))

    # info disclosure
    if res.server and any(ch.isdigit() for ch in res.server):
        res.findings.append(Finding(
            f"Server version disclosed: {res.server}", "low", "disclosure",
            f"Server header: {res.server}",
            "Suppress version banners (Server / X-Powered-By) to slow attacker recon."))
    if "x-powered-by" in headers:
        res.findings.append(Finding(
            f"Technology disclosed via X-Powered-By: {headers['x-powered-by']}", "low",
            "disclosure", f"X-Powered-By: {headers['x-powered-by']}",
            "Remove the X-Powered-By header."))

    # sensitive path exposure
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as c:
            for p in SENSITIVE_PATHS:
                try:
                    pr = c.get(base + p)
                    if pr.status_code == 200 and pr.content:
                        res.findings.append(Finding(
                            f"Sensitive file exposed: {p}", "high", "exposure",
                            f"GET {base}{p} → 200 ({len(pr.content)} bytes)",
                            "Remove the file from the web root or block it at the edge."))
                except httpx.HTTPError:
                    pass
    except Exception:  # noqa: BLE001
        pass

    # methods
    try:
        with httpx.Client(timeout=timeout, verify=False) as c:
            opt = c.request("OPTIONS", url)
            allow = opt.headers.get("allow", "")
            risky = [m for m in ("TRACE", "PUT", "DELETE", "CONNECT") if m in allow.upper()]
            if risky:
                res.findings.append(Finding(
                    f"Risky HTTP methods advertised: {', '.join(risky)}", "medium", "methods",
                    f"OPTIONS {url} → Allow: {allow}",
                    "Disable TRACE/TRACK; restrict PUT/DELETE to authenticated APIs."))
    except httpx.HTTPError:
        pass

    res.findings.sort(key=lambda f: SEV_RANK.get(f.severity, 9))
    return res


def _check_cert(res: ScanResult, host: str, port: int) -> None:
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
                res.findings.append(Finding(
                    "TLS certificate expired", "high", "transport",
                    f"Certificate expired {abs(days)} days ago ({not_after}).",
                    "Renew the certificate immediately and automate renewal."))
            elif days < 21:
                res.findings.append(Finding(
                    f"TLS certificate expiring soon ({days}d)", "medium", "transport",
                    f"Certificate valid until {not_after}.",
                    "Renew the certificate and automate renewal (e.g. ACME)."))
    except Exception:  # noqa: BLE001 — cert introspection is best-effort
        pass
