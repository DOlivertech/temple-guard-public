"""Playbooks — ordered, multi-step operations executed via the Kali container.

A playbook chains scan modules in a defined order (footprint → fingerprint →
scan → discover → vuln-scan), so each step runs only after the previous one
finishes. Every step spawns a labelled Kali container, so the run is visible
live in the Cluster view and on the per-attack dashboard.

Playbooks are pure data — add a new one here, no other code. Execution +
scope/auth gating is handled by `runner.enqueue_playbook` + `jobs.submit_playbook`.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class PlaybookStep:
    module: str                 # a registered scan module (modules._REGISTRY)
    label: str                  # short step name for the UI
    note: str = ""              # what this step does
    params: dict = field(default_factory=dict)


@dataclass
class Playbook:
    id: str
    name: str
    description: str
    category: str               # recon | web | network
    steps: list[PlaybookStep]


CATALOG: list[Playbook] = [
    Playbook(
        id="full_recon", name="Full Recon Sweep", category="recon",
        description="Footprint → fingerprint → scan → discover → vuln-scan, in order. "
        "Maps the attack surface end-to-end before any deeper testing.",
        steps=[
            PlaybookStep("subfinder", "Subdomain enum", "Passive subdomain discovery"),
            PlaybookStep("wafw00f", "WAF detection", "Fingerprint any WAF/CDN"),
            PlaybookStep("nmap", "Port & service scan", "Service/version scan", {"profile": "service-version"}),
            PlaybookStep("ffuf", "Content discovery", "Bounded directory brute-force"),
            PlaybookStep("nuclei", "Vuln templates", "Template vuln scan", {"severity": "medium,high,critical"}),
        ],
    ),
    Playbook(
        id="web_deep_dive", name="Web App Deep-Dive", category="web",
        description="Evidence → WAF → content discovery → web-server scan → template "
        "vulns → SQL injection. A thorough single-host web assessment.",
        steps=[
            PlaybookStep("web_evidence", "Screenshot + headers", "Visual + live header evidence"),
            PlaybookStep("wafw00f", "WAF detection", "Fingerprint any WAF/CDN"),
            PlaybookStep("ffuf", "Content discovery", "Bounded directory brute-force"),
            PlaybookStep("nikto", "Web server scan", "Misconfig + known issues"),
            PlaybookStep("nuclei", "Vuln templates", "Template vuln scan", {"severity": "low,medium,high,critical"}),
            PlaybookStep("sqlmap", "SQL injection", "Crawl + injectable-parameter test"),
        ],
    ),
    Playbook(
        id="network_enum", name="Network Enumeration", category="network",
        description="Port scan → SMB enumeration → TLS posture. For host/network "
        "targets rather than a single web app.",
        steps=[
            PlaybookStep("nmap", "Port & service scan", "Full service/version scan", {"profile": "service-version"}),
            PlaybookStep("enum4linux", "SMB enumeration", "Shares / users / OS"),
            PlaybookStep("tls_audit", "TLS posture", "Protocols + known TLS issues"),
        ],
    ),
    Playbook(
        id="humint_osint", name="HUMINT / OSINT Footprint", category="recon",
        description="Where does open-source intelligence leave the org exposed? "
        "recon-ng (subdomains + whois contacts) → SpiderFoot (emails, social, "
        "breaches, services). Run against a domain.",
        steps=[
            PlaybookStep("reconng", "recon-ng OSINT", "Subdomains + whois points-of-contact"),
            PlaybookStep("theharvester", "theHarvester", "Harvest emails + subdomains from public sources"),
            PlaybookStep("spiderfoot", "SpiderFoot footprint", "Emails, social, breaches, services"),
        ],
    ),
    Playbook(
        id="vuln_hunt", name="Vulnerability Hunt", category="network",
        description="Cross-image pipeline: Nmap (Kali) → Metasploit auxiliary scanners "
        "(its own image, detection-only) → Nuclei templates (Kali). Each step runs in "
        "the right container automatically.",
        steps=[
            PlaybookStep("nmap", "Port & service scan", "Service/version scan", {"profile": "service-version"}),
            PlaybookStep("metasploit", "Metasploit checks", "Auxiliary vuln-identification (no exploitation)"),
            PlaybookStep("nuclei", "Vuln templates", "Template vuln scan", {"severity": "medium,high,critical"}),
        ],
    ),
    Playbook(
        id="wordpress_pipeline", name="WordPress Pipeline", category="web",
        description="Evidence → wpscan → content discovery → vuln-scan. WordPress-"
        "focused, in order.",
        steps=[
            PlaybookStep("web_evidence", "Screenshot + headers", "Visual + live header evidence"),
            PlaybookStep("wpscan", "WordPress scan", "Core / plugins / users"),
            PlaybookStep("ffuf", "Content discovery", "Bounded directory brute-force"),
            PlaybookStep("nuclei", "Vuln templates", "Template vuln scan", {"severity": "medium,high,critical"}),
        ],
    ),
]

_BY_ID = {p.id: p for p in CATALOG}


def all_playbooks() -> list[dict]:
    from .modules import get_module  # lazy import to avoid a circular import
    out = []
    for p in CATALOG:
        d = asdict(p)
        warns: list[str] = []
        for step in p.steps:
            try:
                w = getattr(get_module(step.module), "warning", "")
            except Exception:  # noqa: BLE001
                w = ""
            if w and w not in warns:
                warns.append(w)
        d["warnings"] = warns       # distinct pre-flight warnings across the pipeline's tools
        out.append(d)
    return out


def get_playbook(pid: str) -> Playbook | None:
    return _BY_ID.get(pid)
