"""Control resolver.

Findings carry `standard_refs` like "OWASP Top 10 A03", "OWASP WSTG-INPV-05",
"PCI-DSS 6.2", "CIS 3.x", "NIST 800-115", "HIPAA 164.312(e)", "SOC 2 CC6.6".
This module parses those strings and resolves each to an authoritative,
linkable source on the web so evidence can point a client straight at the
control they're violating.

`resolve_refs()` is the single entry point used by the evidence + report layers.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

# OWASP Top 10 (2021) — per-category canonical pages.
_OWASP_TOP10 = {
    "A01": ("Broken Access Control", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    "A02": ("Cryptographic Failures", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "A03": ("Injection", "https://owasp.org/Top10/A03_2021-Injection/"),
    "A04": ("Insecure Design", "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
    "A05": ("Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "A06": ("Vulnerable and Outdated Components", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    "A07": ("Identification and Authentication Failures", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    "A08": ("Software and Data Integrity Failures", "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
    "A09": ("Security Logging and Monitoring Failures", "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    "A10": ("Server-Side Request Forgery", "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),
}

_FRAMEWORK_HOME = {
    "OWASP": "https://owasp.org/www-project-top-ten/",
    "OWASP WSTG": "https://owasp.org/www-project-web-security-testing-guide/",
    "OWASP ASVS": "https://owasp.org/www-project-application-security-verification-standard/",
    "NIST": "https://csrc.nist.gov/pubs/sp/800/115/final",
    "PCI-DSS": "https://www.pcisecuritystandards.org/document_library/",
    "HIPAA": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312",
    "CIS": "https://www.cisecurity.org/controls/cis-controls-list",
    "CIS Benchmark": "https://www.cisecurity.org/cis-benchmarks",
    "SOC 2": "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
}


@dataclass
class Control:
    ref: str             # the original string, e.g. "OWASP Top 10 A03"
    framework: str       # OWASP | OWASP WSTG | PCI-DSS | NIST | CIS | HIPAA | SOC 2 | Other
    control: str         # the specific clause, e.g. "A03" / "6.2" / "CC6.6"
    title: str           # human label, e.g. "Injection"
    url: str | None      # authoritative web link (None if unresolved)


def _owasp(ref: str) -> Control | None:
    m = re.search(r"top\s*10.*?(A\d{1,2})", ref, re.I)
    if m:
        code = "A" + m.group(1)[1:].zfill(2)
        title, url = _OWASP_TOP10.get(code, ("OWASP Top 10", _FRAMEWORK_HOME["OWASP"]))
        return Control(ref, "OWASP", code, title, url)
    m = re.search(r"wstg[-\s]?([A-Z]{3,4}[-\s]?\d{1,2})", ref, re.I)
    if m:
        return Control(ref, "OWASP WSTG", "WSTG-" + m.group(1).upper().replace(" ", "-"),
                       "Web Security Testing Guide", _FRAMEWORK_HOME["OWASP WSTG"])
    if re.search(r"wstg", ref, re.I):
        return Control(ref, "OWASP WSTG", "WSTG", "Web Security Testing Guide",
                       _FRAMEWORK_HOME["OWASP WSTG"])
    m = re.search(r"asvs\s*([\d.]+)?", ref, re.I)
    if m:
        return Control(ref, "OWASP ASVS", m.group(1) or "ASVS",
                       "Application Security Verification Standard", _FRAMEWORK_HOME["OWASP ASVS"])
    return None


def resolve(ref: str) -> Control:
    ref = (ref or "").strip()
    low = ref.lower()

    if "owasp" in low:
        c = _owasp(ref)
        if c:
            return c
        return Control(ref, "OWASP", ref, "OWASP", _FRAMEWORK_HOME["OWASP"])

    if "pci" in low:
        m = re.search(r"([\d.]+)", ref)
        return Control(ref, "PCI-DSS", m.group(1) if m else "PCI-DSS",
                       "Payment Card Industry DSS", _FRAMEWORK_HOME["PCI-DSS"])

    if "hipaa" in low or "164.312" in low:
        m = re.search(r"(164\.\d+\([a-z]\)|164\.\d+)", ref)
        return Control(ref, "HIPAA", m.group(1) if m else "164.312",
                       "HIPAA Security Rule — Technical Safeguards", _FRAMEWORK_HOME["HIPAA"])

    if "nist" in low:
        return Control(ref, "NIST", "SP 800-115",
                       "Technical Guide to Information Security Testing", _FRAMEWORK_HOME["NIST"])

    if "soc" in low:
        m = re.search(r"(CC\d(?:\.\d)?)", ref, re.I)
        return Control(ref, "SOC 2", m.group(1).upper() if m else "TSC",
                       "Trust Services Criteria", _FRAMEWORK_HOME["SOC 2"])

    if "cis" in low:
        m = re.search(r"([\d.]+x?)", ref)
        is_bench = "benchmark" in low
        key = "CIS Benchmark" if is_bench else "CIS"
        return Control(ref, key, m.group(1) if m else "CIS",
                       "CIS Benchmarks" if is_bench else "CIS Critical Security Controls",
                       _FRAMEWORK_HOME[key])

    return Control(ref, "Other", ref, ref, None)


def resolve_refs(refs: list[str] | None) -> list[dict]:
    return [asdict(resolve(r)) for r in (refs or []) if r]
