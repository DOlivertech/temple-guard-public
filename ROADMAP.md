# Project Temple Guard — Roadmap / TODO

## ✅ Done
- Multi-tenant clients + engagements with authorization gating
- Selectable audit suites (OWASP, NIST/PTES, CIS, PCI/HIPAA/SOC 2)
- **Real Docker execution** — nmap / nikto / ZAP run in containers (images auto-pulled)
- **Real Kali instance spin-up** + in-browser remote shell (PTY over WebSocket)
- **Container Control Center** — grouped by client/engagement, live stats, live
  log streaming, in-app shell, and lifecycle controls (start/stop/restart/remove)
  individually and in bulk
- Scope enforcement + simulation fallback
- Topology graph, remediation reports, dashboard
- Electron desktop shell
- Temple Guard emblem logo

## 🚧 Cloud provisioning (in progress)
Interfaces in `backend/app/core/provisioner.py`. AWS scan path is implemented;
the rest is tracked here.

- [x] **AWS cloud-VM provisioner (scan path)** — launch ephemeral EC2 from a Kali
      AMI, run the tool via SSM RunShellScript, terminate. Gated on
      `TG_AWS_*` config + boto3 + credentials. *Untested without a live account.*
  - [ ] Bring-your-own-cloud: build the boto3 session from **assume-role** creds
        into the client's account (one-line swap in `_session()`)
  - [ ] Remote **shell/console** to a cloud instance over SSM (reuse terminal UI)
  - [ ] Auto-terminate on engagement close / TTL + cost tracking
  - [ ] GCP + Azure equivalents
- [ ] **Kubernetes job provisioner** — run each scan as an ephemeral Job/pod

## 🚧 Other backlog
- [x] **Global search** — clients, engagements, findings, assets, targets (sidebar)
- [x] **Client edit/delete + engagement scope edit** (inline, with cascade delete)
- [x] **Auto-incrementing authorization references** (`SOW-YEAR-INITIALS-NNN`)
- [x] **Postgres support + single-command Docker stack** (`./start.sh` →
      postgres + backend + frontend) with persistent volumes
- [x] **Backups** — `./backup.sh` (pg_dump) + restore; sync `backups/` to cloud
- [x] **Per-attack dashboard** — live status/elapsed, tools-run timeline, engaged
      container images (+ live logs), findings, topology map, and a **Stop** button
      that cancels queued scans and kills running containers (per-run labels)
- [x] **Async scan execution** — runs enqueue and execute in a background pool;
      the API returns immediately, status flows queued → running → completed, and
      live scan containers appear in the Control Center (stream their logs there)
- [x] **Web evidence capture (Playwright)** — real-browser screenshots + live
      header checks; evidence embeds in findings and the client report
- [x] **`install.sh`** — one-shot prerequisite installer (Docker, Python, Node,
      Playwright browser) for macOS + Debian/Ubuntu
- [x] **Evidence section** — classified findings (screenshot + what was found +
      what it violates), each control linked to its authoritative web source
      (OWASP/NIST/PCI/CIS/HIPAA/SOC 2), per-item permalinks; links surfaced in
      the engagement view and the client report too
- [x] **Audit targets (web & app)** — add a web URL or an app (path/installer +
      OS); a container spins up to fetch + attack/dissect it. Web tools auto-remap
      localhost → host.docker.internal. App = static analysis (secrets, endpoints,
      bundled deps, signing heuristics)
- [ ] **App dynamic detonation** — install + run + fuzz the app. Linux-feasible in
      a container; **Windows/macOS need OS-specific sandbox VMs** (big lift). Today
      app analysis is static-only.
- [ ] Dedicated per-scan live output streaming endpoint (today: via container logs)
- [x] **Blue / SOC team operations** — ATT&CK-mapped defensive catalog with full
      explanations + hardening; ROE-window + authorization-confirm gating; every op
      is bounded, read-only, and non-destructive (posture, TLS, cookies, security.txt,
      SPF/DMARC, SOC canary); runs on the per-attack dashboard
- [x] **Interactive report** — collapsible sections + Hardening section
- [ ] Real destructive execution (volumetric/L7 DoS) — intentionally NOT built;
      requires a DDoS-testing provider + dedicated authorization
- [ ] AuthN / RBAC / per-analyst audit logging
- [x] Server-side PDF export (`/api/engagements/{id}/report.pdf` via headless
      Chromium) + report header nav (home / back / print / download PDF)
- [ ] Report templating / branding (custom logo, cover page, per-client themes)
- [ ] Findings deduplication across scans
- [ ] Package desktop app with bundled Python backend (PyInstaller sidecar)
