"""OSINT / HUMINT + extra recon tools — a self-contained, Docker-backed module.

A sibling of ``tools.py`` (same ``Tool`` shape, same ``_run`` plumbing) that adds
open-source-intelligence and extra web/network reconnaissance to the defensive CLI.
Each tool spins up a real container (``docker run --rm <image> …``) against a target
you **own or are explicitly authorized to assess**, runs bounded + read-only, and
parses the output into the same ``Finding`` objects the rest of the report uses.

The target here is often NOT a URL: it can be a **domain**, an **email**, a **person
name** (HUMINT), a **phone number**, or a plain **host/IP**. ``run_recon(key, target)``
passes the raw target string straight through (unlike ``tools.run_tool`` which parses a
URL first), and each tool's ``argv`` normalizes it for its own needs. Anything that hits
``localhost`` / ``127.0.0.1`` is remapped to the host's numeric IPv4 (via ``tools._remap``
/ ``tools._container_host``) so a container can reach an app on your machine.

Everything is passive-to-light and detection-only — no exploitation, no flooding, no
credential attacks. OSINT queries public sources (search engines, CT logs, passive DNS,
WHOIS); the web/network tools send bounded, read-only probes. Use only where authorized.

Images are pulled on demand. A few OSINT images publish **amd64 only**, so those tools
pin ``--platform linux/amd64`` (native on Intel, emulated on Apple Silicon — slower but
works). ``enum4linux-ng`` has no clean maintained image, so it falls back to
``kalilinux/kali-rolling`` with an apt-install+run one-liner (the first run is slow).
"""
from __future__ import annotations

import csv
import io
import os
import re
import shlex
import tempfile
from datetime import datetime, timezone

from .checks import Finding
# Reuse the exact same dataclass + plumbing as tools.py so RECON_TOOLS merges cleanly
# into tools.TOOLS (``TOOLS.update(RECON_TOOLS)``) and shares one execution path.
from .tools import (
    Tool,
    _run,
    _remap,
    _container_host,
    _host,
    _port,
    _diagnose,
)

_AMD64 = ("--platform", "linux/amd64")   # for images published amd64-only
KALI_IMAGE = "kalilinux/kali-rolling:latest"


# ── target normalizers ──────────────────────────────────────────────────────
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def _domain(target: str) -> str:
    """Bare registrable host from any target form (``https://a.b.com/x`` → ``a.b.com``)."""
    t = (target or "").strip()
    return _host(t) or t


def _root_domain(target: str) -> str:
    """Last two labels of a domain (``api.foo.co`` → ``foo.co``) — for subdomain matching."""
    d = _domain(target)
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def _url_target(target: str) -> str:
    """Full http(s) URL for the web tools; adds a scheme and remaps localhost → host IPv4."""
    t = (target or "").strip()
    if "://" not in t:
        t = "http://" + t
    return _remap(t)


# ── ffuf built-in wordlist ──────────────────────────────────────────────────
# secsi/ffuf ships no wordlists, so we vendor a small, high-signal "interesting paths"
# list and bind-mount it read-only. Written once to a temp dir on first import.
_FFUF_WORDS = [
    "admin", "administrator", "login", "logout", "signin", "signup", "register",
    "dashboard", "account", "accounts", "user", "users", "profile", "settings",
    "api", "api/v1", "api/v2", "graphql", "rest", "swagger", "swagger-ui",
    "openapi.json", "openapi.yaml", "api-docs", "docs", "redoc", "health",
    "healthz", "status", "ping", "ready", "live", "metrics", "debug", "trace",
    "actuator", "actuator/health", "actuator/env", "server-status", "server-info",
    "config", "config.json", "config.yaml", "configuration", "settings.json",
    "env", ".env", ".env.local", ".env.production", ".env.dev", "app.config",
    "backup", "backups", "backup.zip", "backup.sql", "dump.sql", "db.sql",
    "database.sql", "data", "export", "exports", "old", "bak", "tmp", "temp",
    "test", "tests", "testing", "dev", "development", "staging", "stage", "beta",
    "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php", "upload.php",
    "wp-admin", "wp-login.php", "wp-content", "wp-config.php", "wp-json",
    "xmlrpc.php", "phpmyadmin", "pma", "adminer.php", "mysql", "sql",
    ".git", ".git/config", ".git/HEAD", ".gitignore", ".svn", ".hg", ".ds_store",
    ".htaccess", ".htpasswd", "web.config", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "security.txt", ".well-known", ".well-known/security.txt",
    "console", "manage", "management", "portal", "internal", "private", "secret",
    "secrets", "credentials", "creds", "token", "tokens", "keys", "apikey",
    "auth", "oauth", "sso", "saml", "jwt", "session", "reset", "forgot",
    "upload", "uploads", "files", "file", "download", "downloads", "media",
    "assets", "static", "public", "images", "img", "js", "css", "fonts",
    "cgi-bin", "bin", "scripts", "includes", "lib", "vendor", "node_modules",
    "storage", "logs", "log", "error_log", "access_log", "audit", "monitor",
    "billing", "invoice", "invoices", "payment", "payments", "checkout", "cart",
    "webhook", "webhooks", "callback", "notify", "cron", "queue", "worker",
    "graphiql", "playground", "explorer", "flower", "kibana", "grafana",
    "jenkins", "gitlab", "jira", "confluence", "prometheus", "traefik",
]
_FFUF_DIR = os.path.join(tempfile.gettempdir(), "temple_guard_recon", "ffuf")
_FFUF_WORDLIST = os.path.join(_FFUF_DIR, "wordlist.txt")


def _ensure_ffuf_wordlist() -> str:
    """Create the built-in ffuf wordlist if missing; return the dir to bind-mount.
    Best-effort — if it can't be written the tool still runs (ffuf just errors cleanly)."""
    try:
        os.makedirs(_FFUF_DIR, exist_ok=True)
        if not os.path.exists(_FFUF_WORDLIST):
            with open(_FFUF_WORDLIST, "w", encoding="utf-8") as fh:
                fh.write("\n".join(_FFUF_WORDS) + "\n")
    except OSError:
        pass
    return _FFUF_DIR


_ensure_ffuf_wordlist()


# ── source / module presets (keyless only) ──────────────────────────────────
# theHarvester: engines confirmed valid in 4.10.x that need NO API key. A single
# invalid engine name aborts the whole run, so keep this list conservative.
THEHARVESTER_SOURCES = "crtsh,hackertarget,otx,rapiddns,urlscan,certspotter,duckduckgo"
# SpiderFoot 3.3 CLI modules — passive/keyless, chosen per target kind below. Kept
# deliberately small: with -q SpiderFoot only emits its CSV once the whole scan finishes,
# and CT-enumeration modules (sfp_crt) explode on high-footprint domains (tens of thousands
# of names → resolve storm → timeout). Subdomain breadth is covered by subfinder/theHarvester;
# SpiderFoot here does bounded correlation (DNS, WHOIS, live cert). Pass -m for deeper OSINT.
SPIDERFOOT_DOMAIN_MODS = "sfp_dnsresolve,sfp_whois,sfp_ssl"
SPIDERFOOT_EMAIL_MODS = "sfp_dnsresolve,sfp_names,sfp_email,sfp_emailrep"
SPIDERFOOT_NAME_MODS = "sfp_names"          # HUMINT: light on purpose (no account-storm)
SPIDERFOOT_PHONE_MODS = "sfp_names,sfp_phone"
# recon-ng (v4): a reliably keyless module. Richer recon needs API keys (see risk/flags).
RECONNG_MODULE = "recon/domains-hosts/hackertarget"
# sslyze 5.x explicit scan commands (``--regular`` was removed): protocol support,
# certificate info, and the classic TLS vulns. All read-only handshakes.
SSLYZE_FLAGS = [
    "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3",
    "--certinfo", "--heartbleed", "--robot", "--openssl_ccs", "--compression",
    "--reneg", "--elliptic_curves",
]


def _spiderfoot_mods(target: str) -> str:
    """Pick a bounded, keyless SpiderFoot module set from the target's shape."""
    t = (target or "").strip()
    if "@" in t and "." in t.split("@")[-1]:
        return SPIDERFOOT_EMAIL_MODS                       # email
    if re.fullmatch(r"\+?[\d][\d\s()\-.]{5,}\d", t):
        return SPIDERFOOT_PHONE_MODS                       # phone number
    if "." not in t and re.search(r"[A-Za-z]", t) and (" " in t or "," in t):
        return SPIDERFOOT_NAME_MODS                        # human name (HUMINT)
    return SPIDERFOOT_DOMAIN_MODS                          # domain / host / IP


# ── argv builders ────────────────────────────────────────────────────────────
# Signature matches tools.Tool.argv: (host, port, target). ``host``/``port`` are the
# remapped host + port (used by the host/TLS tools); ``t`` is the RAW target string
# (used by the domain / name / phone / URL tools). This keeps them callable from BOTH
# run_recon(raw target) and tools.run_tool(url) without surprises.

def _enum4linux_argv(host: str, port: int, t: str) -> list[str]:
    tgt = shlex.quote(host)
    script = (
        "apt-get update -qq >/dev/null 2>&1 && "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq enum4linux-ng >/dev/null 2>&1 && "
        f"enum4linux-ng -A {tgt}"
    )
    return ["sh", "-c", script]


# ── parsers ───────────────────────────────────────────────────────────────────
def _parse_theharvester(out: str, target: str) -> list[Finding]:
    root = _root_domain(target)
    emails, hosts, ips = set(), set(), set()
    for m in re.finditer(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", out):
        e = m.group(0).lower()
        if e.endswith("edge-security.com"):     # theHarvester's own banner author
            continue
        emails.add(e)
    for line in out.splitlines():
        s = line.strip()
        m = re.match(r"^((?:[\w\-]+\.)+[\w\-]+)(?::((?:\d{1,3}\.){3}\d{1,3}))?$", s)
        if m and (root and m.group(1).lower().endswith(root)):
            hosts.add(m.group(1).lower())
            if m.group(2):
                ips.add(m.group(2))
    findings: list[Finding] = []
    if emails:
        findings.append(Finding(
            f"theHarvester: {len(emails)} email address(es) exposed", "medium", "osint",
            "; ".join(sorted(emails)[:20]),
            "Public email addresses fuel phishing and credential-stuffing. Prefer role "
            "aliases, and enforce MFA on any account tied to these addresses."))
    if hosts:
        findings.append(Finding(
            f"theHarvester: {len(hosts)} host/subdomain(s) discovered", "low", "osint",
            "; ".join(sorted(hosts)[:25]) + (f"  ({len(ips)} resolved IPs)" if ips else ""),
            "Each host is attack surface. Retire stale/forgotten names (subdomain-takeover "
            "risk) and confirm every live one is patched and intended to be public."))
    if not findings:
        findings.append(Finding(
            "theHarvester: no public emails or hosts found", "info", "osint",
            f"No emails/subdomains surfaced for {_domain(target)} via keyless OSINT sources.",
            "Low public OSINT footprint — good. Re-check periodically as exposure changes."))
    return findings


def _parse_subfinder(out: str, target: str) -> list[Finding]:
    subs = set()
    for line in out.splitlines():
        s = line.strip().lower()
        if s and re.fullmatch(r"(?:[\w\-]+\.)+[\w\-]+", s):
            subs.add(s)
    if subs:
        return [Finding(
            f"subfinder: {len(subs)} subdomain(s) enumerated", "low", "recon",
            "; ".join(sorted(subs)[:30]),
            "Passive subdomain enumeration maps your external surface. Audit for stale "
            "records (subdomain takeover), dev/staging hosts, and anything not meant to "
            "be public; put internal-only names behind auth/VPN.")]
    return [Finding(
        "subfinder: no subdomains found", "info", "recon",
        f"No subdomains surfaced for {_domain(target)} from passive sources.",
        "Minimal passive DNS footprint — good.")]


def _parse_reconng(out: str, target: str) -> list[Finding]:
    text = _strip_ansi(out)
    hosts, emails = set(), set()
    for m in re.finditer(r"\[host\]\s+([^\s()]+)(?:\s+\(([^)]*)\))?", text):
        hosts.add(m.group(1).lower())
    for m in re.finditer(r"\[(?:contact|email)\][^\n]*?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})", text):
        emails.add(m.group(1).lower())
    total = None
    mt = re.search(r"(\d+)\s+total\s+\(", text)
    if mt:
        total = int(mt.group(1))
    findings: list[Finding] = []
    if emails:
        findings.append(Finding(
            f"recon-ng: {len(emails)} contact email(s) found", "medium", "osint",
            "; ".join(sorted(emails)[:20]),
            "Harvested contacts enable targeted phishing. Enforce MFA and awareness training."))
    if hosts:
        findings.append(Finding(
            f"recon-ng: {len(hosts)} host(s) discovered", "low", "osint",
            "; ".join(sorted(hosts)[:25]),
            "Review each host — retire stale names and confirm intended public exposure."))
    if not findings:
        findings.append(Finding(
            "recon-ng: no hosts/contacts found", "info", "osint",
            f"Keyless recon-ng modules returned nothing for {_domain(target)}"
            + (f" ({total} records)." if total is not None else "."),
            "Add API keys (Shodan, Censys, Hunter, …) for deeper recon-ng coverage."))
    return findings


def _parse_spiderfoot(out: str, target: str) -> list[Finding]:
    # CSV rows: module, event_type, source_data, data  (data may contain commas)
    buckets: dict[str, set] = {}
    NOISE = {"Raw Data from RIRs/APIs", "Raw DNS Records", "Search Engine Web Content",
             "Raw File Meta Data", "TARGET_WEB_CONTENT"}
    try:
        reader = csv.reader(io.StringIO(out))
        for row in reader:
            if len(row) < 4:
                continue
            etype, data = row[1].strip(), row[3].strip()
            if not etype or etype in NOISE or etype.lower() in ("type", "event type"):
                continue
            buckets.setdefault(etype, set()).add(data[:120])
    except csv.Error:
        pass

    def _pick(*names):
        s = set()
        for n in names:
            for et, vals in buckets.items():
                if n.lower() in et.lower():
                    s |= vals
        return s

    emails = _pick("Email Address")
    hosts = _pick("Internet Name", "Subdomain", "Co-Hosted", "Similar Domain")
    ips = _pick("IP Address", "IPV6 Address")
    accounts = _pick("Account on External Site", "Username", "Social Media", "Human Name")
    findings: list[Finding] = []
    if emails:
        findings.append(Finding(
            f"SpiderFoot: {len(emails)} email address(es)", "medium", "osint",
            "; ".join(sorted(emails)[:20]),
            "Exposed emails enable phishing/credential-stuffing — enforce MFA."))
    if accounts:
        findings.append(Finding(
            f"SpiderFoot: {len(accounts)} identity/account signal(s)", "low", "humint",
            "; ".join(sorted(accounts)[:20]),
            "Names/usernames/social accounts aid social engineering. Review what is "
            "publicly attributable to your org and people; minimize where possible."))
    if hosts or ips:
        detail = "; ".join(sorted(hosts)[:20])
        if ips:
            detail += f"  ({len(ips)} IPs)"
        findings.append(Finding(
            f"SpiderFoot: {len(hosts)} host(s), {len(ips)} IP(s)", "low", "osint",
            detail or f"{len(ips)} IPs", "Map every host/IP to an intended, patched service."))
    if not findings:
        total = sum(len(v) for v in buckets.values())
        types = ", ".join(sorted(buckets)[:8])
        findings.append(Finding(
            "SpiderFoot: no notable OSINT data", "info", "osint",
            f"{total} event(s) collected" + (f" ({types})" if types else "")
            + f" for target '{_domain(target) or target}'.",
            "Low OSINT footprint for this target, or add API keys for deeper coverage."))
    return findings


def _parse_phoneinfoga(out: str, target: str) -> list[Finding]:
    scanners = sorted(set(re.findall(r"Results for (\w+)", out)))
    links = len(re.findall(r"URL:\s*https?://", out))
    country = (re.search(r"^\s*Country:\s*(.+)$", out, re.M) or [None, ""])[1].strip()
    carrier = (re.search(r"^\s*Carrier:\s*(.+)$", out, re.M) or [None, ""])[1].strip()
    e164 = (re.search(r"^\s*E164:\s*(.+)$", out, re.M) or [None, ""])[1].strip()
    number = e164 or target
    if re.search(r"is not valid|invalid number|could not.*parse", out, re.I):
        return [Finding(
            "PhoneInfoga: number not valid / unrecognized", "info", "phone",
            f"PhoneInfoga could not validate {target}.",
            "Confirm the number is in E.164 format (e.g. +14155552671).")]
    detail_bits = [b for b in (f"country={country}" if country else "",
                               f"carrier={carrier}" if carrier else "",
                               f"{links} OSINT search leads across {len(scanners)} scanner(s)"
                               if links else "") if b]
    if not detail_bits and not scanners:
        return [Finding(
            "PhoneInfoga: no OSINT leads generated", "info", "phone",
            f"PhoneInfoga returned no results for {number}.",
            "Number may be unlisted — good. Re-check if it is used publicly.")]
    return [Finding(
        f"PhoneInfoga: OSINT footprint for {number}", "info", "phone",
        "; ".join(detail_bits) or f"scanners: {', '.join(scanners)}",
        "Phone numbers surface in breach dumps, listings, and social profiles. Avoid "
        "reusing a personal number for business/2FA; treat SMS 2FA as weak.")]


def _parse_sslyze(out: str, target: str) -> list[Finding]:
    findings, seen = [], set()
    lines = out.splitlines()
    # Deprecated protocols that should be rejected outright.
    for proto, label in (("SSL 2.0", "SSLv2"), ("SSL 3.0", "SSLv3"),
                         ("TLS 1.0", "TLS 1.0"), ("TLS 1.1", "TLS 1.1")):
        for i, line in enumerate(lines):
            if re.search(rf"\*\s+{re.escape(proto)} Cipher Suites:", line):
                window = " ".join(lines[i:i + 4]).lower()
                if "the server accepted" in window and label not in seen:
                    seen.add(label)
                    sev = "medium" if label.startswith("TLS 1.1") or label.startswith("TLS 1.0") else "high"
                    findings.append(Finding(
                        f"Deprecated TLS protocol enabled: {label}", sev, "tls",
                        re.sub(r"\s+", " ", line).strip()[:180],
                        "Disable SSLv2/SSLv3/TLS 1.0/1.1 — serve only TLS 1.2+ (prefer 1.3)."))
                break
    # Vulnerabilities flagged by sslyze (Heartbleed, ROBOT, CCS, insecure reneg…).
    for line in lines:
        if "VULNERABLE" in line:
            key = re.sub(r"\s+", " ", line).strip()[:60]
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    "TLS vulnerability flagged (sslyze)", "high", "tls",
                    re.sub(r"\s+", " ", line).strip()[:200],
                    "Patch the TLS stack / disable the affected feature and re-test."))
    # Certificate trust + expiry.
    if re.search(r"FAILED - Certificate is NOT Trusted", out):
        findings.append(Finding(
            "TLS certificate not trusted (sslyze)", "medium", "tls",
            "sslyze reported the certificate chain is not trusted by a major store.",
            "Install a valid CA-signed certificate with the correct intermediate chain."))
    dates = re.findall(r"Not After:\s*(\d{4}-\d{2}-\d{2})", out)
    if dates:
        try:
            soonest = min(datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc) for d in dates)
            days = (soonest - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(Finding("TLS certificate expired (sslyze)", "high", "tls",
                                        f"Earliest cert expiry {soonest.date()} ({abs(days)}d ago).",
                                        "Renew the certificate immediately and automate renewal."))
            elif days < 21:
                findings.append(Finding(f"TLS certificate expiring soon ({days}d)", "medium", "tls",
                                        f"Earliest cert expiry {soonest.date()}.",
                                        "Renew now and automate renewal (e.g. ACME)."))
        except ValueError:
            pass
    if not findings:
        findings.append(Finding(
            "TLS posture looks clean (sslyze)", "info", "tls",
            "No deprecated protocols, flagged vulnerabilities, or near-term cert expiry.",
            "Keep TLS 1.2+/1.3 only, strong ciphers, HSTS, and current certificates."))
    return findings


def _parse_wpscan(out: str, target: str) -> list[Finding]:
    text = _strip_ansi(out)
    low = text.lower()
    if "does not seem to be running wordpress" in low or ("scan aborted" in low and "wordpress" in low):
        return [Finding(
            "wpscan: target is not running WordPress", "info", "web",
            "The site responded but WPScan did not detect WordPress.",
            "Nothing to harden here for WordPress. (Point WPScan at a WordPress site.)")]
    findings: list[Finding] = []
    mv = re.search(r"WordPress version ([\d.]+) identified", text)
    if mv:
        outdated = "out of date" in low or "insecure" in low
        findings.append(Finding(
            f"wpscan: WordPress {mv.group(1)}" + (" (out of date)" if outdated else " identified"),
            "medium" if outdated else "low", "web",
            re.sub(r"\s+", " ", mv.group(0))[:180],
            "Keep WordPress core, themes, and plugins fully updated; remove version banners."))
    users = re.findall(r"\[[+i]\]\s+([A-Za-z0-9._\-]+)\s*\n\s*\|\s+Found By", text)
    if users:
        findings.append(Finding(
            f"wpscan: {len(users)} WordPress user(s) enumerated", "medium", "web",
            "; ".join(sorted(set(users))[:20]),
            "Block user enumeration (REST /wp-json/wp/v2/users, ?author=N), enforce strong "
            "passwords + MFA, and rate-limit wp-login.php."))
    vulns = len(re.findall(r"\[!\].*(?:vulnerabilit|CVE-)", text, re.I))
    if vulns:
        findings.append(Finding(
            f"wpscan: {vulns} potential vulnerability finding(s)", "high", "web",
            "WPScan flagged known-vulnerability indicators — review the raw output.",
            "Update the affected core/theme/plugin immediately; subscribe to WPScan feeds."))
    if not findings:
        findings.append(Finding(
            "wpscan: WordPress detected, nothing notable", "info", "web",
            "WordPress was detected but no version/user/vuln items were surfaced "
            "(vulnerability data needs a free WPScan API token).",
            "Add --api-token for CVE enrichment; keep everything patched and enumeration off."))
    return findings


def _parse_ffuf(out: str, target: str) -> list[Finding]:
    paths = []
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith((":", "[", "*", "_", "|", "#")) or " " in s:
            continue
        paths.append(s)
    paths = sorted(set(paths))
    if paths:
        sensitive = [p for p in paths if re.search(
            r"(admin|login|\.env|\.git|config|backup|secret|token|cred|wp-|phpmyadmin|"
            r"actuator|debug|dump|sql|console|private)", p, re.I)]
        sev = "high" if sensitive else "medium"
        detail = "; ".join(paths[:30])
        if sensitive:
            detail = "SENSITIVE: " + "; ".join(sensitive[:12]) + " || " + detail
        return [Finding(
            f"ffuf: {len(paths)} path(s) discovered" + (f", {len(sensitive)} sensitive" if sensitive else ""),
            sev, "discovery", detail[:240],
            "Review each discovered path. Remove or lock down admin panels, configs, "
            "backups, .env/.git, API docs, and debug endpoints that should not be public.")]
    return [Finding(
        "ffuf: no additional paths discovered", "info", "discovery",
        "No paths from the built-in common wordlist returned an interesting status code.",
        "Minimal content-discovery surface with this wordlist — good.")]


def _parse_enum4linux(out: str, target: str) -> list[Finding]:
    text = _strip_ansi(out)
    low = text.lower()
    findings: list[Finding] = []
    if re.search(r"allows sessions using username ''|null session", low):
        findings.append(Finding(
            "SMB null session allowed (enum4linux-ng)", "high", "smb",
            "The host permitted an anonymous/null SMB session — a common information leak.",
            "Disable anonymous/null SMB access; require authentication; restrict SMB to trusted nets."))
    shares = re.findall(r"^\s*([A-Za-z0-9_$\-.]+)\s+.*(?:Disk|IPC|Printer)\b", text, re.M)
    shares = [s for s in shares if s.lower() not in ("mapping", "listing")]
    if shares:
        findings.append(Finding(
            f"SMB shares visible: {len(set(shares))} (enum4linux-ng)", "medium", "smb",
            "; ".join(sorted(set(shares))[:20]),
            "Audit every share's ACLs; remove anonymous read/write; expose only what's needed."))
    users = re.findall(r"username:\s*([A-Za-z0-9._\-]+)", low)
    if users:
        findings.append(Finding(
            f"SMB/RID users enumerated: {len(set(users))} (enum4linux-ng)", "medium", "smb",
            "; ".join(sorted(set(users))[:20]),
            "Restrict RID cycling / anonymous enumeration; enforce strong auth + lockout."))
    if not findings:
        if re.search(r"could not connect to smb|neither smb nor ldap|aborting remainder", low):
            findings.append(Finding(
                "No SMB/LDAP exposed (enum4linux-ng)", "info", "smb",
                "SMB (139/445) and LDAP (389/636) were not reachable on the target.",
                "Good — no Windows/Samba enumeration surface exposed to this vantage point."))
        else:
            findings.append(Finding(
                "enum4linux-ng: no notable SMB findings", "info", "smb",
                "enum4linux-ng completed without surfacing shares, users, or null sessions.",
                "Keep SMB patched, authenticated, and off the public internet."))
    return findings


# ── tool definitions ──────────────────────────────────────────────────────────
RECON_TOOLS: dict[str, Tool] = {
    # ---- OSINT / HUMINT -----------------------------------------------------
    "theharvester": Tool(
        "theharvester", "Domain OSINT (theHarvester)", "secsi/theharvester:latest",
        "emails, subdomains & hosts for a domain from public sources  ·  target_kind: DOMAIN",
        "osint",
        lambda h, p, t: ["-d", _domain(t), "-b", THEHARVESTER_SOURCES, "-l", "100"],
        parse=_parse_theharvester, default_timeout=240,
        what="theHarvester (Edge-Security). Classic OSINT collector: gathers emails, "
             "subdomains, hosts and IPs for a DOMAIN from search engines, certificate "
             "transparency, and passive-DNS sources — the attacker's first look at you.",
        usage="temple-guard osint theharvester example.com\n"
              "temple-guard osint theharvester example.com",
        risk="Passive/read-only — it queries third-party OSINT sources, not your target "
             "directly. Only assess domains you own or are authorized to. No API keys needed "
             "for the bundled source set.",
        flags="-d domain  ·  -b <sources|all>  ·  -l <limit>  ·  -g (dns brute)  ·  "
              "-n (dns lookup)  ·  -c (dns bruteforce)  ·  -f <file> (save). Keyless sources: "
              + THEHARVESTER_SOURCES),
    "reconng": Tool(
        "reconng", "Domain recon (recon-ng)", "n4n0m4c/recon-ng:latest",
        "keyless domain→hosts recon via recon-ng modules  ·  target_kind: DOMAIN",
        "osint",
        lambda h, p, t: ["-w", "templeguard", "-m", RECONNG_MODULE,
                         "-o", f"SOURCE={_domain(t)}", "-x"],
        parse=_parse_reconng, default_timeout=180, extra=_AMD64 + ("--entrypoint", "/recon-ng/recon-cli"),
        what="recon-ng (Tim Tomes). A modular recon framework; run headless via recon-cli. "
             "This ships a keyless module (hackertarget → hosts). Add API keys for Shodan, "
             "Censys, Hunter, etc. to unlock its deeper modules.",
        usage="temple-guard osint reconng example.com\n"
              "temple-guard osint reconng example.com",
        risk="Light/passive with the keyless module. amd64-only image (emulated on Apple "
             "Silicon). Only recon domains you're authorized to. Most modules need API keys.",
        flags="-m <module>  ·  -o name=value (module opt, e.g. SOURCE=domain)  ·  -x (execute)  "
              "·  -w <workspace>  ·  -c/-C <command>. Default keyless module: " + RECONNG_MODULE),
    "spiderfoot": Tool(
        "spiderfoot", "OSINT automation (SpiderFoot)", "ctdc/spiderfoot:latest",
        "automated OSINT — modules picked by target kind  ·  target_kind: DOMAIN|EMAIL|NAME|PHONE|IP",
        "osint",
        lambda h, p, t: ["sf.py", "-s", (t or "").strip(), "-m", _spiderfoot_mods(t),
                         "-o", "csv", "-q"],
        parse=_parse_spiderfoot, default_timeout=420, extra=_AMD64,
        what="SpiderFoot — automates OSINT across 200+ modules and correlates the results. "
             "Accepts a DOMAIN, EMAIL, human NAME (HUMINT), PHONE, or IP as the target and "
             "auto-selects a bounded, keyless module set for that type.",
        usage="temple-guard osint spiderfoot example.com\n"
              "temple-guard osint spiderfoot \"Jane Doe\"      # HUMINT (name in quotes)\n"
              "temple-guard osint spiderfoot person@example.com",
        risk="Runs a deliberately small, passive, keyless module set (no social-account "
             "storm). amd64-only image (emulated on Apple Silicon → slower). Authorized "
             "targets only; HUMINT on people is sensitive — have a lawful basis.",
        flags="-s target  ·  -m mod1,mod2  ·  -t type1,type2  ·  -o tab|csv|json  ·  -q "
              "(quiet)  ·  -M (list modules). Free modules only; keyed modules stay off."),
    "phoneinfoga": Tool(
        "phoneinfoga", "Phone OSINT (PhoneInfoga)", "sundowndev/phoneinfoga:latest",
        "phone-number OSINT — format, country, search leads  ·  target_kind: PHONE (E.164)",
        "phone",
        lambda h, p, t: ["scan", "-n", (t or "").strip()],
        parse=_parse_phoneinfoga, default_timeout=180, extra=_AMD64,
        what="PhoneInfoga — reconnaissance for phone numbers. Validates/normalizes the number "
             "(country, line format) and generates OSINT search leads (Google/social dorks). "
             "Deeper carrier/owner lookups need a paid Numverify API key.",
        usage="temple-guard osint phoneinfoga +14155552671\n"
              "temple-guard osint phoneinfoga \"+1 415-555-2671\"",
        risk="Read-only: local number parsing + generated search-engine links (it does not "
             "auto-run the searches). amd64-only image (emulated on Apple Silicon). Only look "
             "up numbers you're authorized to investigate.",
        flags="scan -n <number>  ·  official image sundowndev/phoneinfoga. Add a NUMVERIFY_API_KEY "
              "for carrier/line-type enrichment (otherwise local + search-dork scanners only)."),
    "subfinder": Tool(
        "subfinder", "Subdomain enum (subfinder)", "projectdiscovery/subfinder:latest",
        "fast passive subdomain enumeration  ·  target_kind: DOMAIN", "recon",
        lambda h, p, t: ["-d", _domain(t), "-silent", "-all"],
        parse=_parse_subfinder, default_timeout=180,
        what="subfinder (ProjectDiscovery). Fast passive subdomain enumeration from dozens of "
             "public sources (CT logs, passive DNS, search APIs). The quickest way to see your "
             "external DNS attack surface.",
        usage="temple-guard osint subfinder example.com\n"
              "temple-guard osint subfinder example.com",
        risk="Passive — queries public sources, never brute-forces the target. Some sources "
             "yield more with (optional) free API keys in a provider config. Authorized "
             "domains only.",
        flags="-d domain  ·  -all (all sources)  ·  -silent  ·  -recursive  ·  -o <file>  ·  "
              "-nW (only resolvable)  ·  -pc <provider-config> for keyed sources."),
    # ---- extra web / network ------------------------------------------------
    "sslyze": Tool(
        "sslyze", "TLS analysis (sslyze)", "nablac0d3/sslyze:latest",
        "TLS protocols, ciphers, cert & classic TLS vulns  ·  target_kind: HOST[:port]", "tls",
        lambda h, p, t: SSLYZE_FLAGS + [f"{h}:{p if p else 443}"],
        parse=_parse_sslyze, default_timeout=300,
        what="SSLyze (nabla-c0d3) — fast, reliable TLS configuration analyzer. Enumerates "
             "supported protocols and cipher suites, inspects the certificate chain, and tests "
             "for Heartbleed, ROBOT, CCS-injection, insecure renegotiation, and compression.",
        usage="temple-guard recon sslyze example.com\n"
              "temple-guard recon sslyze example.com:443",
        risk="Read-only handshakes, but many of them — point it only at hosts you own. Needs a "
             "TLS port (defaults to 443); pointing it at a plain-HTTP port just fails to handshake.",
        flags="--tlsv1_2/--tlsv1_3/--sslv3… (per-protocol)  ·  --certinfo  ·  --heartbleed  ·  "
              "--robot  ·  --reneg  ·  --compression  ·  --json_out <f>  ·  --mozilla_config."),
    "wpscan": Tool(
        "wpscan", "WordPress scan (wpscan)", "wpscanteam/wpscan:latest",
        "WordPress version/plugin/user/vuln enumeration  ·  target_kind: URL", "web",
        lambda h, p, t: ["--url", _url_target(t), "--no-banner", "--no-update",
                         "--random-user-agent", "--disable-tls-checks"],
        parse=_parse_wpscan, default_timeout=300,
        what="WPScan — the WordPress security scanner. Fingerprints core/theme/plugin versions, "
             "enumerates users, and (with a free API token) maps them to known vulnerabilities. "
             "Cleanly reports when a site isn't WordPress.",
        usage="temple-guard recon wpscan https://blog.example.com\n"
              "temple-guard recon wpscan http://localhost:8000",
        risk="Active but bounded enumeration — many requests, visible in logs. Vulnerability "
             "data needs a free wpscan.com API token (--api-token); without it you get version/"
             "user info only. Authorized WordPress sites only.",
        flags="--url <url>  ·  --enumerate vp,vt,u (vuln plugins/themes, users)  ·  --api-token "
              "<t>  ·  --plugins-detection <passive|mixed|aggressive>  ·  --random-user-agent."),
    "ffuf": Tool(
        "ffuf", "Content discovery (ffuf)", "secsi/ffuf:latest",
        "fast web content/endpoint discovery (built-in wordlist)  ·  target_kind: URL",
        "discovery",
        lambda h, p, t: ["-u", _url_target(t).rstrip("/") + "/FUZZ", "-w", "/tg/wordlist.txt",
                         "-mc", "200,204,301,302,307,401,403", "-t", "20", "-s"],
        parse=_parse_ffuf, default_timeout=300, extra=("-v", f"{_ensure_ffuf_wordlist()}:/tg:ro"),
        what="ffuf — a very fast web fuzzer, here used for content discovery: it requests a "
             "curated built-in list of ~180 interesting paths (admin panels, configs, backups, "
             ".env/.git, API docs, debug endpoints) and reports which ones exist.",
        usage="temple-guard recon ffuf http://localhost:8000\n"
              "temple-guard recon ffuf https://example.com",
        risk="Active — sends one request per wordlist entry (bounded to the built-in list, 20 "
             "threads). Shows up in logs and can trip rate-limits/WAFs. Authorized targets only.",
        flags="-u <url-with-FUZZ>  ·  -w <wordlist>  ·  -mc <codes>  ·  -fc/-fs (filter code/"
              "size)  ·  -e <exts>  ·  -t <threads>  ·  -recursion  ·  -s (silent). Built-in "
              "wordlist is mounted at /tg/wordlist.txt; pass your own -w to override."),
    "enum4linux": Tool(
        "enum4linux", "SMB enumeration (enum4linux-ng)", KALI_IMAGE,
        "SMB/LDAP shares, users, OS & null-session enum  ·  target_kind: HOST/IP", "smb",
        _enum4linux_argv,
        parse=_parse_enum4linux, default_timeout=480,
        what="enum4linux-ng — next-gen Windows/Samba (SMB) enumeration: shares, users, groups, "
             "OS info, password policy, and anonymous/null-session checks. No clean maintained "
             "image exists, so it installs into kalilinux/kali-rolling at run time.",
        usage="temple-guard recon enum4linux 192.168.1.10\n"
              "temple-guard recon enum4linux fileserver.local",
        risk="Read-only enumeration, but noisy and SMB-specific — aimed at Windows/Samba hosts "
             "on internal networks you're authorized to assess. FIRST RUN IS SLOW: it apt-"
             "installs enum4linux-ng into the Kali image before scanning.",
        flags="-A (all simple enumeration)  ·  -U users  ·  -S shares  ·  -G groups  ·  -P "
              "password policy  ·  -o (oplock)  ·  runs against host/IP (needs 139/445 reachable)."),
}

# Grouping hints for wiring the CLI (e.g. `temple-guard osint <target>` vs `recon <target>`).
OSINT = ["theharvester", "reconng", "spiderfoot", "phoneinfoga", "subfinder"]
RECON = ["sslyze", "wpscan", "ffuf", "enum4linux"]
# Images that publish amd64 only (emulated on arm64) — handy for a doctor/preflight note.
AMD64_ONLY = ["reconng", "spiderfoot", "phoneinfoga"]


def recon_images() -> list[str]:
    """Every image these recon tools use, deduped — for preflight / doctor --pull."""
    imgs: list[str] = []
    for t in RECON_TOOLS.values():
        if t.image not in imgs:
            imgs.append(t.image)
    return imgs


def run_recon(key: str, target: str, timeout=None, stop_event=None):
    """Run one recon/OSINT tool in its container. Returns (findings, raw_output, ok).

    Mirrors ``tools.run_tool`` but passes the RAW target string straight through (the
    target may be a domain, email, person name, phone number, or host — not a URL), so
    each tool's ``argv`` normalizes it itself. ``localhost`` is remapped to the host IPv4
    for reachability. Pass ``stop_event`` (a threading.Event) to make it cancellable.
    """
    tool = RECON_TOOLS[key]
    raw = (target or "").strip()
    host = _container_host(_host(raw))
    port = _port(raw)
    rc, out, err = _run(tool.image, tool.argv(host, port, raw),
                        timeout or tool.default_timeout, tool.extra, stop_event=stop_event)
    combined = out if out.strip() else err
    if rc == 130:                                   # stopped by the user — abort quietly
        return [], combined, False
    if rc != 0 and not out.strip():
        # Only stderr came back. If it's a recognizable infra failure (docker down, image
        # missing, network, timeout) surface a diagnostic; otherwise the tool may have put a
        # legit message on stderr (e.g. wpscan's "not WordPress"), so fall through to parse.
        reason, fix = _diagnose(err, rc)
        if reason != "did not complete" or not err.strip():
            return ([Finding(f"{tool.name} — {reason}", "info", tool.cat,
                             (err or f"exit {rc}")[:200], fix)], combined, False)
    return tool.parse(combined, raw), combined, True


__all__ = ["RECON_TOOLS", "run_recon", "recon_images", "OSINT", "RECON", "AMD64_ONLY"]
