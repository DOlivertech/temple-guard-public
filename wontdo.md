# wontdo.md

Features planned or requested for Temple Guard that I will **not build, wire to run,
or document as shipped**. These stay `executable=False` (documented + simulated only).
"Bounded", "controlled", "read-only", "authorized", or "resilience testing" framing
does not change this — building the capability into the tool is the line.

## Red-team operations

- **High-volume credential brute-force** — `brute_force_heavy` · MITRE T1110.001
  Dictionary / credential-stuffing run against authentication (e.g. hydra).
  *(The capped, fake-password lockout test `cred_spray` is built and executable.)*

- **Weaponized CVE / RCE exploitation** — `exploit_known_cve` · MITRE T1190
  Running exploits against vulnerable components — incl. "controlled" / "read-only"
  exploitation and PoC execution.

- **CVE Discovery & Exploitation Chain — exploitation phase** — `cve_discovery_exploit` · MITRE T1190
  The "attempt exploitation" phase of the chain.
  *(The detection-only `cve_scan` module + "CVE Identification" standard are built.)*

- **Web shell upload & persistence** — `web_shell_upload` · MITRE T1505.003
  Uploading web shells / planting backdoors, even with "test payloads".

- **Volumetric / flooding DoS** — `volumetric_dos` · MITRE T1498
  Traffic floods, incl. "DDoS resilience testing" that generates flooding load.
  *(The hard-capped `resilience_probe` is built and executable.)*

- **Phishing / payload delivery** — `phishing_campaign` · MITRE T1566
- **Lateral movement / privilege escalation** — `lateral_movement` · MITRE T1021
- **Data exfiltration** — `data_exfiltration` · MITRE T1041

## General boundaries

- **Password cracking at scale** — offline cracking of captured hashes (hashcat / John)
  or large-scale online guessing.
- **Detection / IDS / WAF evasion** — techniques meant to defeat defensive monitoring.
- **Autonomous offensive automation** — wiring frameworks like PentAGI or Apache
  Caldera to *execute* attacks / ATT&CK techniques against targets. (Using Caldera for
  blue/purple **detection validation** only, scoped to a lab, is a separate question.)
- **Scope / authorization bypass** — running any tool outside the authorized scope or
  rules-of-engagement window.

The detection, posture, OSINT, reporting, and the explicitly-bounded probes
(`cred_spray`, `resilience_probe`, `cve_scan`, etc.) are the supported, executable side.
