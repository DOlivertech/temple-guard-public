"""Red / Purple / Blue / SOC team operations catalog.

Each operation is data: what it does (full explanation), its MITRE ATT&CK
mapping, how aggressive it is, which team it belongs to, where it executes
(`engine`), the hardening that defends against it, and a pre-flight warning.

Safety model
------------
Only operations with `executable=True` actually run, and those are limited to
**non-destructive, bounded** probes: light recon, posture validation, a
hard-capped availability/rate-limit check, and a *capped* authentication-control
test (a handful of attempts to see whether lockout / throttling fires — never a
real brute-force).

Genuinely offensive techniques (volumetric DoS, real brute-force/cracking,
exploitation/RCE, web-shell upload, phishing payloads, lateral movement,
exfiltration, destruction) are `executable=False`. They are documented and
*simulated* so a team gets the attack narrative + hardening report, without the
platform ever shipping a weapon. `refusal` explains why we won't execute it.

`engine`
--------
  * "in-process" — a bounded Python/httpx script in the backend (no container).
  * "kali"       — runs a real tool inside the templeguard/kali image.
  * "simulated"  — documented only; nothing is executed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Bounded limits for the real, executable probes.
RESILIENCE_MAX_REQUESTS = 40
RESILIENCE_CONCURRENCY = 5
AUTH_MAX_ATTEMPTS = 6          # total login attempts across a cred test — capped low
AUTH_DUMMY_PASSWORDS = ["Password1!", "Welcome2024", "Spring2024!", "Changeme123"]


@dataclass
class RedTeamOp:
    id: str
    name: str
    team: str            # red | purple | blue | soc
    category: str        # recon | initial_access | resilience | defense | detection | ...
    attack: str          # MITRE ATT&CK technique
    attack_url: str
    aggressiveness: str  # passive | low | moderate | aggressive | destructive
    executable: bool
    engine: str          # in-process | kali | simulated
    summary: str
    explanation: str     # exactly what will be done
    hardening: str       # how to defend
    warning: str         # shown pre-flight
    refusal: str = ""    # why we won't execute it (executable=False offensive ops)


CATALOG: list[RedTeamOp] = [
    # ════════════════════════ RED — executable, bounded ════════════════════════
    RedTeamOp(
        id="recon_surface", name="Attack-surface recon", team="red", category="recon",
        attack="T1595 — Active Scanning", attack_url="https://attack.mitre.org/techniques/T1595/",
        aggressiveness="passive", executable=True, engine="in-process",
        summary="Fingerprint the target: server, technologies, headers, exposed paths.",
        explanation="Light, non-intrusive HTTP fingerprint — fetches the homepage, reads "
        "response headers and server/tech banners, notes security-header posture, records "
        "the title. No exploitation, no fuzzing.",
        hardening="Minimize information disclosure: suppress version banners, remove "
        "X-Powered-By/Server detail, ensure CSP/HSTS/X-Frame-Options/nosniff are present.",
        warning="Sends a small number of normal HTTP requests to the target.",
    ),
    RedTeamOp(
        id="http_methods", name="HTTP method & verb audit", team="red", category="recon",
        attack="T1595 — Active Scanning", attack_url="https://attack.mitre.org/techniques/T1595/",
        aggressiveness="low", executable=True, engine="in-process",
        summary="Probe which HTTP methods are allowed (OPTIONS/TRACE/PUT/DELETE).",
        explanation="Sends an OPTIONS request and tests for risky verbs (TRACE, PUT, "
        "DELETE, CONNECT). Flags TRACE (XST) and write methods exposed without auth.",
        hardening="Disable TRACE/TRACK, restrict PUT/DELETE to authenticated APIs, and "
        "return 405 for unsupported methods at the edge.",
        warning="Sends a handful of benign method-probe requests.",
    ),
    RedTeamOp(
        id="cors_probe", name="CORS misconfiguration probe", team="red", category="recon",
        attack="T1190 — Exploit Public-Facing Application",
        attack_url="https://attack.mitre.org/techniques/T1190/",
        aggressiveness="low", executable=True, engine="in-process",
        summary="Send a foreign Origin and detect reflective ACAO + credentials.",
        explanation="Issues a request with an attacker-style Origin header and inspects "
        "Access-Control-Allow-Origin / -Allow-Credentials. Reflecting an arbitrary origin "
        "with credentials allows cross-site data theft.",
        hardening="Allow-list trusted origins only; never reflect Origin with "
        "Allow-Credentials: true; deny by default.",
        warning="Sends a couple of benign cross-origin preflight-style requests.",
    ),
    RedTeamOp(
        id="user_enumeration", name="Username enumeration check", team="red",
        category="initial_access", attack="T1589 — Gather Victim Identity Information",
        attack_url="https://attack.mitre.org/techniques/T1589/",
        aggressiveness="low", executable=True, engine="in-process",
        summary="Compare login/reset responses for likely-valid vs invalid users.",
        explanation="Sends two or three requests to a login/reset endpoint with a "
        "plausible username and an obviously-bogus one, then compares status codes, "
        "timing, and messages to detect whether the app reveals which accounts exist.",
        hardening="Return identical responses + timing for valid and invalid accounts; "
        "use generic 'if that account exists, we sent an email' messaging.",
        warning="Sends a few benign requests; no passwords are submitted.",
    ),
    RedTeamOp(
        id="cred_spray", name="Credential spraying / lockout test", team="red",
        category="initial_access", attack="T1110.003 — Password Spraying",
        attack_url="https://attack.mitre.org/techniques/T1110/003/",
        aggressiveness="moderate", executable=True, engine="in-process",
        summary=f"Capped (≤{AUTH_MAX_ATTEMPTS}) login attempts with DUMMY passwords to test lockout/throttle.",
        explanation=f"Authorized control test, NOT a brute-force. Sends at most "
        f"{AUTH_MAX_ATTEMPTS} login attempts against operator-supplied username(s) using a "
        "short list of obviously-fake passwords, then reports whether the app enforces "
        "account lockout, throttling/429, CAPTCHA, or MFA. Never tries real/leaked "
        "credentials and is hard-capped so it cannot itself become an attack. Params: "
        "`login_url`, `usernames`.",
        hardening="Enforce MFA, account lockout / exponential throttling, breached-password "
        "checks, CAPTCHA after N failures, and alert on spray patterns (many accounts, few "
        "passwords).",
        warning="Submits a few failed logins with FAKE passwords. This may lock the target "
        "account(s) if lockout is enabled — only run against accounts you own/authorize.",
    ),
    RedTeamOp(
        id="resilience_probe", name="Resilience & rate-limit probe", team="red",
        category="resilience", attack="T1499 — Endpoint Denial of Service",
        attack_url="https://attack.mitre.org/techniques/T1499/",
        aggressiveness="low", executable=True, engine="in-process",
        summary=f"Bounded burst (≤{RESILIENCE_MAX_REQUESTS} reqs) to check rate limiting / availability.",
        explanation=f"Sends a hard-capped burst of at most {RESILIENCE_MAX_REQUESTS} "
        f"requests at concurrency {RESILIENCE_CONCURRENCY}, measuring response times, error "
        "rate, and whether the target returns 429 / drops requests under light load. A "
        "resilience MEASUREMENT, not a flood.",
        hardening="Enforce per-IP and per-account rate limiting, deploy a WAF/CDN with DoS "
        "protection, enable autoscaling, set sane connection/timeout limits.",
        warning="Sends a brief, capped burst of requests. Only run against systems you own.",
    ),

    # ════════════════════════ RED — documented, WILL NOT execute ════════════════
    RedTeamOp(
        id="brute_force_heavy", name="High-volume credential brute-force", team="red",
        category="initial_access", attack="T1110.001 — Brute Force: Password Guessing",
        attack_url="https://attack.mitre.org/techniques/T1110/001/",
        aggressiveness="aggressive", executable=False, engine="simulated",
        summary="Large dictionary/credential-stuffing run against auth. Simulated only.",
        explanation="A real engagement might run hydra/medusa or a credential-stuffing list "
        "of thousands of passwords. Documented for the hardening narrative only.",
        hardening="MFA, lockout, breached-credential blocking, WAF bot rules, and anomaly "
        "alerting on auth failure spikes.",
        warning="Not executed by Temple Guard.",
        refusal="High-volume brute-force is an attack that locks out users and can breach "
        "accounts. We only run the bounded lockout test (cred_spray). Use an authorized "
        "lab + tool for the real thing.",
    ),
    RedTeamOp(
        id="exploit_known_cve", name="Exploit a known CVE (RCE/SQLi weaponized)", team="red",
        category="exploitation", attack="T1190 — Exploit Public-Facing Application",
        attack_url="https://attack.mitre.org/techniques/T1190/",
        aggressiveness="destructive", executable=False, engine="simulated",
        summary="Weaponized exploitation for code execution. Simulated only.",
        explanation="Detection of vulnerable components is covered by Nuclei/sqlmap. Actual "
        "weaponized exploitation (RCE, auth bypass, data tampering) is documented only.",
        hardening="Patch promptly, virtual-patch with a WAF, segment, and run least-privilege "
        "service accounts so a single bug isn't game-over.",
        warning="Not executed by Temple Guard.",
        refusal="Weaponized exploitation can damage or compromise the system. We detect "
        "vulnerabilities (Nuclei/sqlmap) but do not exploit them.",
    ),
    RedTeamOp(
        id="web_shell_upload", name="Web shell upload & persistence", team="red",
        category="persistence", attack="T1505.003 — Web Shell",
        attack_url="https://attack.mitre.org/techniques/T1505/003/",
        aggressiveness="destructive", executable=False, engine="simulated",
        summary="Plant a web shell for persistent access. Simulated only.",
        explanation="Documented for the defender narrative. Temple Guard never uploads "
        "shells or establishes persistence.",
        hardening="Disallow executable upload dirs, validate content types, run read-only "
        "web roots, and monitor for new files in served paths (FIM).",
        warning="Not executed by Temple Guard.",
        refusal="Establishing persistence/backdoors on a target is malicious; we will not.",
    ),
    RedTeamOp(
        id="volumetric_dos", name="Volumetric / flooding DoS", team="red", category="impact",
        attack="T1498 — Network Denial of Service",
        attack_url="https://attack.mitre.org/techniques/T1498/",
        aggressiveness="destructive", executable=False, engine="simulated",
        summary="Resource-exhausting flood. Simulated only — see resilience_probe instead.",
        explanation="A real flood (Slowloris, HTTP flood, amplification) degrades or downs "
        "the service. We only run the bounded, non-exhausting resilience_probe.",
        hardening="CDN/anti-DDoS, rate limiting, autoscaling, and connection/timeout caps.",
        warning="Not executed by Temple Guard.",
        refusal="Flooding is a denial-of-service attack that harms availability. We cap our "
        "resilience probe so it can never exhaust resources.",
    ),
    RedTeamOp(
        id="phishing_campaign", name="Phishing / payload delivery", team="red",
        category="initial_access", attack="T1566 — Phishing",
        attack_url="https://attack.mitre.org/techniques/T1566/",
        aggressiveness="aggressive", executable=False, engine="simulated",
        summary="Send credential-harvesting / malware lures. Simulated only.",
        explanation="Social-engineering campaigns target people and are documented only.",
        hardening="Security awareness training, DMARC/SPF/DKIM, attachment sandboxing, MFA, "
        "and reporting buttons.",
        warning="Not executed by Temple Guard.",
        refusal="Phishing targets and deceives people and can deliver malware; we won't "
        "generate or send lures.",
    ),
    RedTeamOp(
        id="lateral_movement", name="Lateral movement / privilege escalation", team="red",
        category="lateral_movement", attack="T1021 — Remote Services",
        attack_url="https://attack.mitre.org/techniques/T1021/",
        aggressiveness="destructive", executable=False, engine="simulated",
        summary="Pivot and escalate across hosts post-compromise. Simulated only.",
        explanation="Documented for the defender narrative; requires an existing foothold we "
        "never establish.",
        hardening="Network segmentation, least privilege, EDR, disable lateral SMB/RDP where "
        "unneeded, and tier admin accounts.",
        warning="Not executed by Temple Guard.",
        refusal="Lateral movement and privilege escalation deepen a compromise; out of scope.",
    ),
    RedTeamOp(
        id="data_exfiltration", name="Data exfiltration", team="red", category="exfiltration",
        attack="T1041 — Exfiltration Over C2 Channel",
        attack_url="https://attack.mitre.org/techniques/T1041/",
        aggressiveness="destructive", executable=False, engine="simulated",
        summary="Stage and extract sensitive data. Simulated only.",
        explanation="Documented for DLP/egress-monitoring narrative; never performed.",
        hardening="DLP, egress filtering, anomaly detection on outbound volume, and "
        "encryption + access logging on sensitive stores.",
        warning="Not executed by Temple Guard.",
        refusal="Exfiltrating data is theft; we will not stage or extract data.",
    ),

    # ════════════════════════ PURPLE — collaborative, executable ════════════════
    RedTeamOp(
        id="detection_validation", name="Detection validation (resilience)", team="purple",
        category="detection", attack="T1499 / Detection", attack_url="https://attack.mitre.org/",
        aggressiveness="low", executable=True, engine="in-process",
        summary="Run the bounded resilience probe and check whether defenses respond.",
        explanation="Runs the same hard-capped burst as the red resilience check, then "
        "evaluates whether the target visibly defended (rate limiting / 429 / WAF challenge). "
        "Purple-team: confirm controls actually fire.",
        hardening="If no defensive response was observed, add rate limiting + WAF and re-run "
        "to confirm detections and mitigations engage.",
        warning="Sends a brief, capped burst during an authorized window.",
    ),
    RedTeamOp(
        id="detection_replay", name="Auth-attack detection replay", team="purple",
        category="detection", attack="T1110 / Detection",
        attack_url="https://attack.mitre.org/techniques/T1110/",
        aggressiveness="low", executable=True, engine="in-process",
        summary="Run the capped lockout test, then assert whether defenses fired.",
        explanation="Executes the bounded cred_spray control test and explicitly grades the "
        "defensive response: did lockout/throttle/429/CAPTCHA appear? Purple-team validation "
        "that auth abuse is both prevented AND detected.",
        hardening="Wire failed-auth spikes to SIEM alerts; confirm lockout + alerting both "
        "trigger; tune thresholds.",
        warning="Submits a few FAKE-password logins (may lock authorized test accounts).",
    ),
    RedTeamOp(
        id="header_drift", name="Security-header drift check", team="purple",
        category="defense", attack="Config / Detection",
        attack_url="https://owasp.org/www-project-secure-headers/",
        aggressiveness="passive", executable=True, engine="in-process",
        summary="Re-read security headers and report drift from the hardened baseline.",
        explanation="Fetches the target and grades the full security-header set against the "
        "OWASP Secure Headers baseline so config regressions surface between assessments.",
        hardening="Manage headers as code at the edge; alert on drift; re-run after deploys.",
        warning="Read-only. Sends a single request.",
    ),

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
TEAMS = ["red", "purple", "blue", "soc"]


def all_ops() -> list[dict]:
    return [asdict(o) for o in CATALOG]


def ops_for_team(team: str) -> list[RedTeamOp]:
    return [o for o in CATALOG if o.team == team]


def executable_ops_for_team(team: str) -> list[RedTeamOp]:
    return [o for o in CATALOG if o.team == team and o.executable]


def get_op(op_id: str) -> RedTeamOp | None:
    return _BY_ID.get(op_id)
