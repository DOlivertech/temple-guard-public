# wontdo.md — boundaries

Temple Guard is **defensive, authorized-testing** tooling. It is intentionally
**not** an offensive platform. The following are out of scope by design — the tool
does not build them as turnkey capabilities, and contributions that add them will
not be accepted here:

- **Exploitation for code execution / RCE** on live systems, and mass or
  internet-wide exploitation. (Temple Guard *detects* vulnerabilities — e.g. Nuclei,
  or sqlmap in detection mode — it does not weaponize them.)
- **High-volume credential brute-force / stuffing / password cracking** (online or
  offline).
- **Volumetric or application-layer DoS / flooding.**
- **Phishing, social engineering, or payload / malware delivery.**
- **Persistence, web-shell upload, lateral movement, privilege escalation, or data
  exfiltration.**
- **Command-and-control (C2) frameworks** and **detection / IDS / WAF evasion.**
- **Autonomous offensive automation** — wiring frameworks to *execute* attacks or
  ATT&CK techniques against targets.
- **Anything outside an authorized engagement's scope** or rules-of-engagement window.

What the platform *does* do: recon, vulnerability **detection**, web / app / API
auditing, OSINT exposure assessment, config & posture review, TLS / header / cookie
checks, SPF/DMARC validation, bounded SOC detection canaries, and client reporting —
all scope-gated to authorized targets.
