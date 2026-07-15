"""Audit-suite catalog.

A *standard* is a selectable button in the UI. Selecting it queues one or more
scan *modules* against the engagement's authorized targets. Keeping this as data
(not code) means new suites are added without touching the runner.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class SuiteModule:
    module: str                      # maps to a class in core/modules.py
    params: dict = field(default_factory=dict)


@dataclass
class Standard:
    id: str
    name: str
    framework: str
    category: str                    # web | network | config | compliance | redteam
    description: str
    modules: list[SuiteModule]
    references: list[str] = field(default_factory=list)
    # Whether this suite is implemented or a roadmap placeholder.
    available: bool = True


CATALOG: list[Standard] = [
    # ── OWASP ─────────────────────────────────────────────────────────────
    Standard(
        id="owasp_top10",
        name="OWASP Top 10 (Web)",
        framework="OWASP",
        category="web",
        description="Baseline web-app risk sweep aligned to the OWASP Top 10: "
        "injection, broken access control, misconfiguration, and known-CVE checks. "
        "Captures a browser screenshot of the target as report evidence.",
        modules=[
            SuiteModule("web_evidence"),
            SuiteModule("nuclei", {"severity": "medium,high,critical"}),
            SuiteModule("nikto"),
        ],
        references=["https://owasp.org/www-project-top-ten/"],
    ),
    Standard(
        id="nuclei_scan",
        name="Nuclei Vulnerability Scan",
        framework="OWASP",
        category="web",
        description="Template-based vulnerability scan (ProjectDiscovery Nuclei): "
        "CVEs, misconfigurations, exposures, default credentials, and injection "
        "checks. Broad CEH vulnerability-analysis coverage.",
        modules=[SuiteModule("nuclei", {"severity": "low,medium,high,critical"})],
        references=["https://github.com/projectdiscovery/nuclei"],
    ),
    Standard(
        id="sqli_audit",
        name="SQL Injection (sqlmap)",
        framework="OWASP",
        category="web",
        description="Automated SQL injection testing with sqlmap (CEH SQLi module). "
        "Crawls the target and tests parameters for injectable points.",
        modules=[SuiteModule("sqlmap")],
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
    ),
    Standard(
        id="full_recon",
        name="Full Recon Sweep",
        framework="CEH",
        category="recon",
        description="Footprinting + scanning sweep: subdomain enumeration, WAF "
        "fingerprinting, port/service scan, content discovery, and a template vuln "
        "scan. Maps the attack surface before deeper testing.",
        modules=[
            SuiteModule("subfinder"),
            SuiteModule("wafw00f"),
            SuiteModule("nmap", {"profile": "service-version"}),
            SuiteModule("ffuf"),
            SuiteModule("nuclei", {"severity": "medium,high,critical"}),
        ],
        references=["https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/"],
    ),
    Standard(
        id="wordpress_audit",
        name="WordPress Audit",
        framework="OWASP",
        category="web",
        description="WordPress-focused assessment: core/plugin/theme vulnerabilities "
        "and user enumeration (wpscan), plus content discovery and a browser evidence "
        "capture.",
        modules=[
            SuiteModule("web_evidence"),
            SuiteModule("wpscan"),
            SuiteModule("ffuf"),
        ],
        references=["https://wpscan.com/", "https://owasp.org/www-project-top-ten/"],
    ),
    Standard(
        id="tls_config_sslyze",
        name="TLS Config Scan (sslyze)",
        framework="PCI-DSS",
        category="compliance",
        description="Structured TLS configuration analysis (accepted protocols, cipher "
        "suites, certificate posture) via sslyze — a second engine alongside testssl.",
        modules=[SuiteModule("sslyze")],
        references=["https://github.com/nabla-c0d3/sslyze"],
    ),
    Standard(
        id="nmap_scan",
        name="Nmap Scan",
        framework="CEH",
        category="network",
        description="Run just an Nmap service/version scan against the scope and "
        "report open ports, services, and exposed admin interfaces.",
        modules=[SuiteModule("nmap", {"profile": "service-version"})],
        references=["https://nmap.org/"],
    ),
    Standard(
        id="nikto_scan",
        name="Nikto Web Scan",
        framework="CEH",
        category="web",
        description="Run just a comprehensive Nikto web-server scan (all test classes "
        "except DoS) and report misconfigurations, dangerous files, and outdated software.",
        modules=[SuiteModule("nikto")],
        references=["https://github.com/sullo/nikto"],
    ),
    Standard(
        id="osint_reconng",
        name="OSINT — recon-ng",
        framework="OSINT",
        category="recon",
        description="recon-ng OSINT sweep: subdomain discovery + whois points-of-contact "
        "(the HUMINT angle — names/emails exposed in domain registration).",
        modules=[SuiteModule("reconng")],
        references=["https://github.com/lanmaster53/recon-ng"],
    ),
    Standard(
        id="osint_spiderfoot",
        name="OSINT — SpiderFoot (HUMINT footprint)",
        framework="OSINT",
        category="recon",
        description="Automated OSINT footprint via SpiderFoot: subdomains, exposed emails, "
        "social accounts, breaches, and open services — where HUMINT leaves the org exposed.",
        modules=[SuiteModule("spiderfoot")],
        references=["https://www.spiderfoot.net/"],
    ),
    Standard(
        id="osint_harvester",
        name="OSINT — theHarvester",
        framework="OSINT",
        category="recon",
        description="Harvest exposed emails + subdomains from public sources (cert "
        "transparency, search engines, passive DNS) — the HUMINT email-exposure view.",
        modules=[SuiteModule("theharvester")],
        references=["https://github.com/laramies/theHarvester"],
    ),
    Standard(
        id="metasploit_vuln",
        name="Metasploit Vuln Scan",
        framework="CEH",
        category="network",
        description="Identify vulnerabilities with Metasploit's auxiliary scanner / check "
        "modules (e.g. MS17-010, Heartbleed, service versions) and report them. "
        "Detection-only — no exploitation is performed.",
        modules=[SuiteModule("metasploit")],
        references=["https://docs.metasploit.com/"],
    ),
    Standard(
        id="cve_scan",
        name="CVE Identification",
        framework="CEH",
        category="network",
        description="Map the target's exposed service versions to known, published CVEs "
        "using Nmap's `vuln` NSE scripts. Detection only — reports affected components + "
        "references; does not exploit them.",
        modules=[SuiteModule("cve_scan")],
        references=["https://nmap.org/nsedoc/categories/vuln.html"],
    ),
    Standard(
        id="owasp_wstg",
        name="OWASP WSTG (Web Security Testing Guide)",
        framework="OWASP",
        category="web",
        description="Deeper, methodology-driven web testing across authentication, "
        "session management, input validation, and business logic.",
        modules=[
            SuiteModule("web_evidence"),
            SuiteModule("nuclei", {"severity": "low,medium,high,critical"}),
            SuiteModule("nikto"),
        ],
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
    ),
    Standard(
        id="owasp_asvs",
        name="OWASP ASVS (Verification Standard)",
        framework="OWASP",
        category="web",
        description="Application Security Verification Standard L1/L2 control checks.",
        modules=[
            SuiteModule("nuclei", {"severity": "low,medium,high,critical"}),
            SuiteModule("nikto"),
        ],
        references=["https://owasp.org/www-project-application-security-verification-standard/"],
    ),
    Standard(
        id="web_evidence_capture",
        name="Web Evidence Capture (Playwright)",
        framework="OWASP",
        category="web",
        description="Drives a real browser to screenshot the target and verify "
        "security headers live. Produces visual evidence embedded in the client "
        "report — great for showing exactly what was assessed and what's exposed.",
        modules=[SuiteModule("web_evidence")],
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
    ),
    # ── PTES / NIST 800-115 ───────────────────────────────────────────────
    Standard(
        id="nist_800_115",
        name="NIST SP 800-115 Network Pentest",
        framework="NIST",
        category="network",
        description="Technical security testing per NIST 800-115: host discovery, "
        "port/service enumeration, and vulnerability identification.",
        modules=[
            SuiteModule("nmap", {"profile": "service-version", "scripts": "vuln"}),
        ],
        references=["https://csrc.nist.gov/pubs/sp/800/115/final"],
    ),
    Standard(
        id="ptes",
        name="PTES Penetration Test (Standard Flow)",
        framework="PTES",
        category="network",
        description="Penetration Testing Execution Standard flow: intelligence "
        "gathering, vulnerability analysis, and exploitation mapping.",
        modules=[
            SuiteModule("nmap", {"profile": "full", "scripts": "default,vuln"}),
            SuiteModule("nuclei", {"severity": "medium,high,critical"}),
            SuiteModule("nikto"),
        ],
        references=["http://www.pentest-standard.org/"],
    ),
    # ── CIS Benchmarks ────────────────────────────────────────────────────
    Standard(
        id="cis_benchmark",
        name="CIS Benchmark Config Audit",
        framework="CIS",
        category="config",
        description="Configuration hardening checks for exposed services against "
        "CIS Benchmarks (TLS, weak ciphers, default creds, dangerous defaults).",
        modules=[
            SuiteModule("nmap", {"profile": "config-audit", "scripts": "ssl-enum-ciphers,banner"}),
            SuiteModule("tls_audit"),
        ],
        references=["https://www.cisecurity.org/cis-benchmarks"],
    ),
    Standard(
        id="tls_crypto_audit",
        name="TLS / Crypto Audit",
        framework="CIS",
        category="config",
        description="Deep TLS/transport-security audit with testssl.sh: protocol "
        "versions, weak ciphers, certificate issues, and known TLS attacks "
        "(CEH cryptography; PCI-DSS 4.x / HIPAA transmission security).",
        modules=[SuiteModule("tls_audit")],
        references=["https://testssl.sh/"],
    ),
    # ── Regulatory / compliance ───────────────────────────────────────────
    Standard(
        id="pci_dss",
        name="PCI-DSS External Scan",
        framework="PCI-DSS",
        category="compliance",
        description="PCI-DSS Req. 11 style external vulnerability scan of the "
        "cardholder data environment perimeter.",
        modules=[
            SuiteModule("nmap", {"profile": "service-version", "scripts": "vuln"}),
            SuiteModule("tls_audit"),
            SuiteModule("nuclei", {"severity": "medium,high,critical"}),
        ],
        references=["https://www.pcisecuritystandards.org/"],
    ),
    Standard(
        id="hipaa",
        name="HIPAA Technical Safeguards",
        framework="HIPAA",
        category="compliance",
        description="Technical safeguard checks (§164.312): transmission security, "
        "access control, and audit-control exposure.",
        modules=[SuiteModule("nmap", {"profile": "service-version", "scripts": "ssl-enum-ciphers"}),
                 SuiteModule("tls_audit")],
        references=["https://www.hhs.gov/hipaa/for-professionals/security/"],
    ),
    Standard(
        id="soc2",
        name="SOC 2 Security Criteria",
        framework="SOC 2",
        category="compliance",
        description="Common Criteria (CC6/CC7) technical evidence: boundary "
        "protection, vulnerability management, and change exposure.",
        modules=[SuiteModule("nmap", {"profile": "service-version"}), SuiteModule("nikto")],
        references=["https://www.aicpa-cima.com/"],
    ),
    # ── Application analysis ──────────────────────────────────────────────
    Standard(
        id="app_static_analysis",
        name="App Static Analysis (containerized)",
        framework="OWASP MASVS",
        category="app",
        description="Spins up a container to fetch an app artifact (local path or "
        "installer URL) and statically dissect it: embedded secrets, endpoints, "
        "bundled dependencies, and code-signing. Pick the target OS per app target. "
        "Run it from an engagement's Audit Targets panel.",
        modules=[SuiteModule("app_analysis", {"os": "linux"})],
        references=["https://owasp.org/www-project-mobile-app-security/"],
    ),
    # ── Red team (roadmap placeholder) ────────────────────────────────────
    Standard(
        id="redteam_adversary",
        name="Red Team — Adversary Emulation (Coming Soon)",
        framework="MITRE ATT&CK",
        category="redteam",
        description="Full-scope adversary emulation: phishing, C2, lateral movement, "
        "and objective-based exploitation. Placeholder — not yet executable.",
        modules=[SuiteModule("redteam_placeholder")],
        references=["https://attack.mitre.org/"],
        available=False,
    ),
]

_BY_ID = {s.id: s for s in CATALOG}


def all_standards() -> list[dict]:
    from .modules import get_module  # lazy import to avoid a circular import
    out = []
    for s in CATALOG:
        d = asdict(s)
        warns: list[str] = []
        for sm in s.modules:
            try:
                w = getattr(get_module(sm.module), "warning", "")
            except Exception:  # noqa: BLE001
                w = ""
            if w and w not in warns:
                warns.append(w)
        d["warnings"] = warns      # distinct pre-flight warnings of this suite's tools
        out.append(d)
    return out


def get_standard(standard_id: str) -> Standard | None:
    return _BY_ID.get(standard_id)
