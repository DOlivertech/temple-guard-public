"""Remediation knowledge base.

Maps a finding's `category` key to client-ready remediation guidance and the
compliance controls it satisfies. Both the real parsers and the simulation
generator pull from here so every finding ships with a fix.
"""
from __future__ import annotations

KB: dict[str, dict] = {
    "tls_weak_cipher": {
        "title": "Weak or deprecated TLS cipher suites enabled",
        "severity": "medium",
        "category": "tls_weak_cipher",
        "cvss": 5.3,
        "standard_refs": ["CIS 3.x", "PCI-DSS 4.2.1", "HIPAA 164.312(e)"],
        "description": "The service negotiates TLS versions or cipher suites "
        "(e.g. TLS 1.0/1.1, RC4, 3DES, CBC) considered weak by current guidance.",
        "remediation": "Disable TLS 1.0/1.1 and all RC4/3DES/CBC ciphers. Require "
        "TLS 1.2+ with forward-secrecy (ECDHE) AEAD suites. Re-test with "
        "`ssl-enum-ciphers`. Reissue certs with SHA-256+ and 2048-bit+ keys.",
    },
    "missing_security_headers": {
        "title": "Missing HTTP security headers",
        "severity": "low",
        "category": "missing_security_headers",
        "cvss": 3.1,
        "standard_refs": ["OWASP Top 10 A05", "OWASP ASVS 14.4"],
        "description": "Responses lack hardening headers such as "
        "Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, "
        "or X-Frame-Options.",
        "remediation": "Add CSP, HSTS (max-age>=31536000; includeSubDomains), "
        "X-Content-Type-Options: nosniff, and a frame-ancestors/X-Frame-Options "
        "policy at the edge (reverse proxy or app middleware).",
    },
    "sql_injection": {
        "title": "Potential SQL injection",
        "severity": "critical",
        "category": "sql_injection",
        "cvss": 9.8,
        "standard_refs": ["OWASP Top 10 A03", "OWASP WSTG-INPV-05", "PCI-DSS 6.2"],
        "description": "A parameter appears to influence backend SQL, allowing "
        "database read/write or authentication bypass.",
        "remediation": "Use parameterized queries / prepared statements everywhere; "
        "never concatenate user input into SQL. Apply least-privilege DB accounts "
        "and a WAF rule as defense in depth. Validate and allowlist input types.",
    },
    "xss_reflected": {
        "title": "Reflected cross-site scripting (XSS)",
        "severity": "high",
        "category": "xss_reflected",
        "cvss": 7.4,
        "standard_refs": ["OWASP Top 10 A03", "OWASP WSTG-INPV-01"],
        "description": "User-supplied input is reflected into a response without "
        "contextual output encoding, allowing script execution in the victim browser.",
        "remediation": "Apply context-aware output encoding, deploy a strict CSP, "
        "and sanitize/validate input. Set HttpOnly + SameSite on session cookies.",
    },
    "outdated_software": {
        "title": "Outdated server software with known CVEs",
        "severity": "high",
        "category": "outdated_software",
        "cvss": 7.5,
        "standard_refs": ["OWASP Top 10 A06", "NIST 800-115", "SOC 2 CC7.1"],
        "description": "A banner/version exposes software with publicly known "
        "vulnerabilities.",
        "remediation": "Patch to a supported, fixed release. Establish a vulnerability "
        "management SLA, subscribe to vendor advisories, and suppress version banners.",
    },
    "default_credentials": {
        "title": "Default or weak credentials accepted",
        "severity": "critical",
        "category": "default_credentials",
        "cvss": 9.1,
        "standard_refs": ["CIS 5.x", "OWASP Top 10 A07", "PCI-DSS 2.2"],
        "description": "A service accepts vendor-default or trivially guessable "
        "credentials.",
        "remediation": "Rotate all default credentials, enforce a strong password "
        "policy + MFA, and disable unused default accounts. Add lockout/rate limiting.",
    },
    "open_admin_interface": {
        "title": "Administrative interface exposed to untrusted network",
        "severity": "high",
        "category": "open_admin_interface",
        "cvss": 8.2,
        "standard_refs": ["CIS 9.x", "NIST 800-115", "SOC 2 CC6.6"],
        "description": "A management interface (SSH, RDP, DB, admin panel) is "
        "reachable from outside its intended trust boundary.",
        "remediation": "Restrict access via firewall/security-group allowlists, place "
        "behind a VPN/bastion, and require MFA. Remove public exposure entirely "
        "where possible.",
    },
    "directory_listing": {
        "title": "Directory listing / sensitive files exposed",
        "severity": "medium",
        "category": "directory_listing",
        "cvss": 5.3,
        "standard_refs": ["OWASP Top 10 A05", "OWASP WSTG-CONF-04"],
        "description": "The web server discloses directory contents or backup/config "
        "files.",
        "remediation": "Disable autoindex/directory listing, remove backup and "
        "config files from web roots, and return 404 for sensitive paths.",
    },
    "hardcoded_secret": {
        "title": "Hardcoded secret / credential in application binary",
        "severity": "high",
        "category": "hardcoded_secret",
        "cvss": 7.5,
        "standard_refs": ["OWASP Top 10 A07", "OWASP ASVS 2.10", "CIS 16.x"],
        "description": "A static string resembling a credential, API key, token, "
        "or private key was found embedded in the installer/binary.",
        "remediation": "Remove secrets from shipped artifacts. Load credentials at "
        "runtime from a secrets manager or OS keychain; never bake them into the "
        "build. Rotate any exposed secret immediately and add a build-time secret scanner.",
    },
    "exposed_endpoint": {
        "title": "Embedded backend endpoint / URL",
        "severity": "info",
        "category": "exposed_endpoint",
        "cvss": 2.0,
        "standard_refs": ["OWASP Top 10 A05", "NIST 800-115"],
        "description": "A hardcoded URL/endpoint was found in the binary — useful "
        "for mapping the app's attack surface (APIs, update servers, telemetry).",
        "remediation": "Confirm every embedded endpoint is intended, TLS-only, and "
        "access-controlled. Remove debug/staging endpoints from production builds.",
    },
    "unsigned_binary": {
        "title": "Installer/binary is unsigned or signature unverifiable",
        "severity": "medium",
        "category": "unsigned_binary",
        "cvss": 5.0,
        "standard_refs": ["OWASP Top 10 A08", "CIS 2.x", "SOC 2 CC6.8"],
        "description": "No verifiable code signature was detected, so tampering or "
        "supply-chain substitution can't be ruled out by the OS.",
        "remediation": "Code-sign and notarize releases (Authenticode on Windows, "
        "Developer ID + notarization on macOS, GPG/sigstore for Linux). Publish "
        "checksums and verify signatures in the updater.",
    },
    "vulnerable_dependency": {
        "title": "Bundled dependency with known vulnerabilities",
        "severity": "high",
        "category": "vulnerable_dependency",
        "cvss": 7.5,
        "standard_refs": ["OWASP Top 10 A06", "SOC 2 CC7.1"],
        "description": "A bundled library/manifest indicates an outdated component "
        "that may carry known CVEs.",
        "remediation": "Update bundled dependencies to patched versions, add SCA to "
        "CI, and ship an SBOM with each release.",
    },
    "info_disclosure": {
        "title": "Information disclosure in responses",
        "severity": "low",
        "category": "info_disclosure",
        "cvss": 3.7,
        "standard_refs": ["OWASP Top 10 A05", "SOC 2 CC6.1"],
        "description": "Verbose errors, stack traces, or internal hostnames leak in "
        "responses.",
        "remediation": "Return generic error pages, disable debug mode in production, "
        "and strip internal identifiers from headers and bodies.",
    },
}


def enrich(category: str, **overrides) -> dict:
    """Return a finding template for a category, with optional overrides."""
    base = dict(KB.get(category, {
        "title": overrides.get("title", "Security finding"),
        "severity": "info",
        "category": category,
        "description": "",
        "remediation": "Review and remediate per applicable standard.",
        "standard_refs": [],
    }))
    base.update({k: v for k, v in overrides.items() if v is not None})
    return base
