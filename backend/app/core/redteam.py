"""Blue / SOC team operations catalog.

Defensive posture checks and detection-readiness probes. Each operation is data:
what it does (full explanation), its MITRE ATT&CK / control mapping, which team it
belongs to, where it executes (`engine`), the hardening it validates, and a
pre-flight note.

Safety model
------------
Every operation here is **bounded, non-destructive, and read-only** — security-header
and TLS posture, cookie flags, security.txt / disclosure readiness, SPF/DMARC via
DNS, and a benign SOC detection canary. Nothing in this catalog exploits, floods,
brute-forces, or performs any offensive action.

`engine`
--------
  * "in-process" — a bounded Python/httpx script in the backend (no container).
  * "kali"       — runs a real tool inside the templeguard/kali image.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class RedTeamOp:
    id: str
    name: str
    team: str            # blue | soc
    category: str        # defense | detection
    attack: str          # MITRE ATT&CK technique / control
    attack_url: str
    aggressiveness: str  # passive | low
    executable: bool
    engine: str          # in-process | kali
    summary: str
    explanation: str     # exactly what will be done
    hardening: str       # how to defend
    warning: str         # shown pre-flight
    refusal: str = ""    # reserved (unused — this catalog is defensive-only)


CATALOG: list[RedTeamOp] = [
    # ════════════════════════ BLUE — defensive posture, executable ══════════════
    RedTeamOp(
        id="posture_check", name="Defensive posture check", team="blue", category="defense",
        attack="Hardening / Headers", attack_url="https://owasp.org/www-project-secure-headers/",
        aggressiveness="passive", executable=True, engine="in-process",
        summary="Validate security headers + transport posture and report gaps.",
        explanation="Non-intrusive blue-team check: fetches the target and evaluates security "
        "headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy) and whether "
        "HTTPS/redirects are enforced. Produces a hardening checklist.",
        hardening="Add the missing headers at the edge, force HTTPS with HSTS preload, set a "
        "strict CSP. Re-run until clean.",
        warning="Read-only. Sends a single request to read headers.",
    ),
    RedTeamOp(
        id="tls_posture", name="TLS / crypto posture (testssl)", team="blue", category="defense",
        attack="Cryptography / Transport", attack_url="https://owasp.org/www-project-transport-layer-protection/",
        aggressiveness="passive", executable=True, engine="kali",
        summary="Run testssl in the Kali image for deprecated protocols + weak ciphers.",
        explanation="Runs the real testssl.sh tool inside the templeguard/kali container "
        "against :443 and reports deprecated protocols (TLS 1.0/1.1, SSLv3) and weak cipher "
        "suites. Blue-team transport-security validation.",
        hardening="Disable TLS<1.2, prefer 1.3, remove weak ciphers, enable HSTS, and keep "
        "certificates current.",
        warning="Read-only TLS handshakes against the target's 443.",
    ),
    RedTeamOp(
        id="cookie_security", name="Cookie security-flag review", team="blue", category="defense",
        attack="Session Management", attack_url="https://owasp.org/www-community/controls/SecureCookieAttribute",
        aggressiveness="passive", executable=True, engine="in-process",
        summary="Check Set-Cookie for Secure / HttpOnly / SameSite.",
        explanation="Reads Set-Cookie headers and flags cookies missing Secure, HttpOnly, or "
        "SameSite — the attributes that defend session cookies against theft and CSRF.",
        hardening="Set Secure + HttpOnly + SameSite=Lax/Strict on session cookies; scope "
        "Path/Domain tightly.",
        warning="Read-only. Sends a single request to read cookies.",
    ),
    RedTeamOp(
        id="security_txt", name="security.txt / disclosure readiness", team="blue",
        category="defense", attack="Vulnerability Disclosure (RFC 9116)",
        attack_url="https://www.rfc-editor.org/rfc/rfc9116",
        aggressiveness="passive", executable=True, engine="in-process",
        summary="Check for /.well-known/security.txt (a contact for reporters).",
        explanation="Fetches /.well-known/security.txt and the root variant, reporting "
        "whether a vulnerability-disclosure contact exists — a basic blue-team readiness "
        "signal.",
        hardening="Publish a signed security.txt with a Contact and Policy URL per RFC 9116.",
        warning="Read-only. Sends one or two requests.",
    ),
    RedTeamOp(
        id="email_auth", name="Email auth (SPF/DMARC) via DNS", team="blue", category="defense",
        attack="Spoofing defense", attack_url="https://dmarc.org/",
        aggressiveness="passive", executable=True, engine="kali",
        summary="Use dig in the Kali image to check SPF + DMARC records.",
        explanation="Runs dig inside the templeguard/kali container to resolve the domain's "
        "SPF (TXT v=spf1) and DMARC (_dmarc TXT) records and reports whether spoofing "
        "defenses are configured and enforcing (p=reject/quarantine).",
        hardening="Publish SPF with -all, DKIM signing, and DMARC at p=reject once aligned.",
        warning="Read-only DNS lookups. No traffic to the target host itself.",
    ),

    # ════════════════════════ SOC — detection readiness, executable ═════════════
    RedTeamOp(
        id="detection_canary", name="SOC detection canary", team="soc", category="detection",
        attack="Detection validation", attack_url="https://attack.mitre.org/",
        aggressiveness="low", executable=True, engine="in-process",
        summary="Emit recognizable benign attack signatures so the SOC can confirm alerts.",
        explanation="Sends a small set of benign, clearly-tagged probes that look like "
        "common scanner/attacker behavior (a known scanner User-Agent, a /.git/config "
        "request, a harmless ?id=1' marker) so the SOC can verify these generate log "
        "entries and fire alerts. Nothing malicious is sent.",
        hardening="Ensure WAF/IDS + SIEM detect and alert on these signatures; if they were "
        "silent, add the rules and re-run until the canary is caught.",
        warning="Sends a few harmless, clearly-marked probe requests for detection testing.",
    ),
]

_BY_ID = {o.id: o for o in CATALOG}
TEAMS = ["blue", "soc"]


def all_ops() -> list[dict]:
    return [asdict(o) for o in CATALOG]


def ops_for_team(team: str) -> list[RedTeamOp]:
    return [o for o in CATALOG if o.team == team]


def executable_ops_for_team(team: str) -> list[RedTeamOp]:
    return [o for o in CATALOG if o.team == team and o.executable]


def get_op(op_id: str) -> RedTeamOp | None:
    return _BY_ID.get(op_id)
