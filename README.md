<div align="center">
  <img src="frontend/public/logo.svg" width="120" alt="Project Temple Guard" />

  # ⛨ Project Temple Guard

  **Authorized penetration-testing orchestration platform.**
  Run standards-driven security audits against authorized environments, spin up
  and manage Kali tooling, watch everything live, and hand clients a remediation
  report — many engagements at once.
</div>

<p align="center">
  <img src="docs/screenshots/dashboard.png" width="900" alt="Temple Guard operations dashboard" />
</p>

---

> ### ⚠️ Defensive & authorized use only
>
> This is a tool for defensive work only. It is intended to scan you or your friends
> OWN applications driven by ai or yourself. Be responsible with what you do and
> remember that AI is NOT a substitute for a good cyber security person and good
> practices. Enjoy 🛡️

Temple Guard enforces per-client authorization and per-engagement scope on **every**
scan — it refuses to touch a target that isn't in writing. Only point it at
environments you own or have explicit, documented permission to test.

---

## What it does

Temple Guard turns a pentest practice into a dashboard. You register a **client**,
open an **engagement** with an authorized scope, pick the **audit standards** you
want to run as buttons (OWASP, NIST, CIS, PCI/HIPAA/SOC 2…), point it at the
sandbox you've been granted, and run. It executes the right tools, collects
findings with remediation guidance, draws the topology, and generates a
client-ready report. You can do this for several clients simultaneously.

### Feature tour

| Feature | What it gives you |
|---|---|
| **Multi-tenant clients & engagements** | Each client carries an authorization status; each engagement carries an authorized scope, an auth reference, and a rules-of-engagement window. |
| **Selectable audit suites** | OWASP (Top 10 / WSTG / ASVS), PTES, NIST SP 800-115, CIS Benchmark, PCI-DSS, HIPAA, SOC 2 — single or multi-select. Adding a new suite is a data change, not a code change. |
| **Real tool execution (one Kali image)** | A broad CEH toolset runs from a single `templeguard/kali` toolbox container: `nmap` (scanning), **Nuclei** (template vuln scan, ~13k templates baked in), **Nikto** (comprehensive web scan), **sqlmap** (SQLi), **testssl** + **sslyze** (TLS/crypto), **subfinder** (subdomain enum), **wpscan** (WordPress), **ffuf** (content discovery), **wafw00f** (WAF detection), and **enum4linux-ng** (SMB enum). The same image boots the Kali consoles, so shells and scans share one toolset. Heavyweight **Metasploit** runs from its own `templeguard/metasploit` image for **detection-only** vuln identification (auxiliary scanners / checks — no exploitation). |
| **OSINT / HUMINT exposure** | Map where open-source intelligence leaves an org vulnerable: **recon-ng** (subdomains + whois points-of-contact), **SpiderFoot** (automated footprint — exposed emails, social accounts, breaches, services), and **PhoneInfoga** for phone-number OSINT (add a **phone target** and input a number → country, line type, and the public footprint an attacker could pivot on). Gated to authorized engagements — for assessing the client's *own* exposure. |
| **Single-tool workflows** | You don't have to run everything. Each tool is callable on its own: single-tool **standards** (Nmap Scan, Nikto Web Scan, OSINT — recon-ng / SpiderFoot, Metasploit Vuln Scan) and **playbooks** (HUMINT/OSINT Footprint, Vulnerability Hunt). Pick the exact workflow you want. |
| **Playbooks (orchestrated Kali pipelines)** | Ordered, multi-step operations that chain tools in sequence (footprint → fingerprint → scan → discover → vuln-scan). Each step runs in its own Kali container and only starts after the previous finishes; launching one opens the live attack dashboard while every step lights up as a node in the Cluster view. Ships with Full Recon, Web App Deep-Dive, Network Enumeration, WordPress, **HUMINT/OSINT Footprint**, and a cross-image **Vulnerability Hunt** (Nmap → Metasploit → Nuclei, each step in the right container) — adding one is a data change. |
| **API testing** | Add an API target → **discover endpoints** (OpenAPI/Swagger spec or common-path probing) → browse them as a **drill-down path tree**, select by level or method (each / all / batches), and fire **bounded** request bursts. Logs status + latency (avg/p95/max) per endpoint and flags slow endpoints, unauthenticated access, missing rate limiting, and verbose errors (OWASP API Security Top 10). Not a flood — hard-capped. |
| **Web evidence capture (Playwright)** | Drives a real browser to **screenshot** web targets and verify security headers live. Screenshots embed in findings and the client report — show clients exactly what was assessed and what's exposed. |
| **Audit targets — web, API, phone & app** | Add a target and Temple Guard spins up a container to go after it. **Web:** point at a URL (localhost included — auto-remapped to `host.docker.internal` for container tools). **API:** discover + test endpoints. **Phone:** input a number for OSINT. **App:** give a local path or installer URL + pick the OS; a container fetches and statically dissects the artifact (embedded secrets, endpoints, bundled deps, signing). |
| **Per-attack dashboard** | Every attack gets a live dashboard: status (running / completed / stopped), how long it's been running, the **tools run** with timestamps (click any tool for its live/stored logs), the **engaged container images** with live logs, the **findings**, a **topology map**, and a **Stop** button that kills the running containers on demand. |
| **Blue / SOC team ops** | A defensive team-operations catalog mapped to MITRE ATT&CK, each with a full explanation, hardening guidance, and a `script` / `img·kali` engine badge. Launches require an authorized engagement, respect the **rules-of-engagement window**, and need explicit confirmation. Every op is **bounded, read-only, and non-destructive** — security-header & TLS posture, cookie flags, security.txt / disclosure readiness, SPF/DMARC via real Kali tools, and a SOC detection canary. Runs use the same per-attack dashboard. |
| **Interactive report + hardening** | The report has collapsible finding sections (expand/collapse all) and a dedicated **Hardening** section. The PDF is rendered server-side. |
| **Simulation fallback** | No Docker? The same flow produces realistic synthetic findings so the whole app is demoable with zero infrastructure. |
| **Async, non-blocking scans** | Runs enqueue and execute on a background pool; the UI never blocks. Status flows queued → running → completed. |
| **Real Kali instances + remote shell** | Spin up a Kali container per engagement and get a live in-browser terminal (a real `root` shell). |
| **Container Control Center + Cluster view** | A Kubernetes-dashboard-style page: a **Cluster view** maps every container as a health-colored node tile grouped into client → engagement **namespaces**, with a control-plane summary bar (nodes, running, CPU avg + MEM peak gauges) and per-node CPU/MEM gauges; click a node to drill into live logs/shell. A **List** toggle gives the classic grouped view. Start/stop/restart/remove individually, per-namespace, or in bulk; auto-refreshes live. |
| **Topology view** | Client → engagement → discovered-asset graph; nodes colored by worst finding severity; filterable by client. |
| **Findings + remediation** | Every finding ships with severity, CVSS, the compliance controls it maps to, evidence, and a concrete fix. Triage state per finding (open / remediated / accepted risk / false positive). |
| **Evidence (classified & linked)** | A dedicated Evidence section alongside Reports. Every item is classified — screenshot, what was found, and **what it violates** — with each control linked to its **authoritative source on the web** (OWASP Top 10 pages, NIST 800-115, PCI-DSS, CIS, HIPAA §164.312, SOC 2 TSC). Every item has a stable permalink (`/evidence/{id}`). |
| **Client reports** | One click generates a printable HTML report (executive summary, risk breakdown, findings + remediation, methodology). Print → PDF for delivery. |
| **Cloud-VM provisioner (AWS)** | Optional: run scans on ephemeral EC2 instances via SSM. Gated on config + credentials. |
| **Desktop app** | Electron shell that boots everything and opens in a native window. |

---

## Screenshots

> The platform running in **simulation mode**. Every view is scope-gated to authorized targets.

### Operations dashboard
Live posture across every client — engagements, scans (running / queued), findings, open
criticals, risk distribution, and recent activity.

![Dashboard](docs/screenshots/dashboard.png)

### Clients & engagements
Multi-tenant: each **client** carries its own authorization status; each **engagement**
carries an authorized scope, an auth reference, and a rules-of-engagement window.

<table>
<tr>
<td width="50%"><img src="docs/screenshots/clients.png" alt="Clients"/></td>
<td width="50%"><img src="docs/screenshots/engagements.png" alt="Engagements"/></td>
</tr>
</table>

Open an engagement to pick **audit standards**, add **web / API / phone / app** targets,
set the **authorized scope** and **scan network**, and run — findings, discovered assets,
and the report all hang off it.

![Engagement detail](docs/screenshots/engagement-detail.png)

### Topology & the Container Control Center
Left: the client → engagement → discovered-asset graph, coloured by worst finding severity.
Right: a Kubernetes-style **Cluster view** of every scan / console container, grouped into
client → engagement **namespaces** with a control-plane summary bar and live CPU / MEM gauges.

<table>
<tr>
<td width="50%"><img src="docs/screenshots/topology.png" alt="Topology"/></td>
<td width="50%"><img src="docs/screenshots/control-center.png" alt="Container Control Center — Cluster view"/></td>
</tr>
</table>

### Live Kali shell · Blue / SOC team ops
Left: provision a container per engagement and **shell in live, from the browser**. Right:
the **Blue / SOC** defensive team-ops catalog — bounded, read-only posture and detection
checks (headers, TLS, cookies, security.txt, SPF/DMARC, a SOC detection canary).

<table>
<tr>
<td width="50%"><img src="docs/screenshots/consoles.png" alt="Live in-browser Kali shell"/></td>
<td width="50%"><img src="docs/screenshots/team-ops.png" alt="Blue / SOC team operations"/></td>
</tr>
</table>

### Playbooks — orchestrated Kali pipelines
Ordered, multi-step operations that chain tools in sequence (footprint → fingerprint → scan
→ discover → vuln-scan). Each step runs in its own container and lights up as a node in the
Cluster view.

![Playbooks](docs/screenshots/playbooks.png)

### Evidence & the client report
Left: a dedicated **Evidence** section — each item classified by what was found, the proof,
and the control it violates. Right: generate **client-ready reports** per engagement.

<table>
<tr>
<td width="50%"><img src="docs/screenshots/evidence.png" alt="Evidence"/></td>
<td width="50%"><img src="docs/screenshots/reports.png" alt="Reports"/></td>
</tr>
</table>

The rendered report — executive summary, risk breakdown, and every finding with remediation
and linked compliance controls (print → PDF, or download a server-rendered PDF):

![Client report](docs/screenshots/report.png)

📄 **[See a full example report (PDF)](docs/sample-report.pdf)** — generated from an
authorized simulation engagement.

---

## Architecture

```
┌─────────────────────────────┐         ┌──────────────────────────────────────┐
│  frontend/  (Next.js + TS)  │  HTTP   │  backend/  (FastAPI + SQLModel)       │
│  dashboard · topology       │ ──────▶ │  /api/*  REST + WebSockets            │
│  Control Center · consoles  │   WS    │                                       │
│  xterm.js terminals         │ ◀─────▶ │  core/standards   audit-suite catalog │
└─────────────────────────────┘         │  core/modules     scan tools + parse  │
                                        │  core/runner      orchestrate + scope │
   Next.js proxies /api → :8000         │  core/jobs        background executor │
                                        │  core/provisioner docker | aws | k8s   │
                                        │  core/kali        container management │
                                        │  core/shell       PTY/logs over WS     │
                                        │  core/reporting   HTML report           │
                                        └───────────────┬──────────────────────┘
                                                        │ docker run / exec
                                                        ▼
                                            Kali + tool containers
                                            (nmap, nikto, nuclei, shells)
```

The browser talks to a single origin — Next.js proxies `/api/*` to FastAPI.
WebSockets (shells, logs) connect directly to the backend (`ws://localhost:8000`).

**Stack:** Next.js 14 · TypeScript · Tailwind · React Flow · xterm.js ·
FastAPI · SQLModel/SQLite (Postgres-ready) · Docker · boto3.

---

## Command-line self-scan — `temple-guard`

Want a fast, read-only remediation report for **your own** app without standing up
the full platform? The bundled **`temple-guard`** CLI ([`cli/`](cli/)) runs bounded,
non-intrusive checks — security headers, TLS/certificate, cookie flags, information
disclosure, exposed sensitive files, risky HTTP methods, and SPF/DMARC email posture —
then prints a colourful report or writes HTML / PDF / markdown / JSON. With Docker it can
also merge real recon tools (whatweb, wafw00f, testssl, nmap, nuclei, nikto) into the same
report. Nothing it does exploits, floods, or brute-forces; a single `GET` per check (plus
one `OPTIONS`).

![temple-guard deep scan report](cli/docs/screenshots/cli-deep-scan.png)

### Install
`temple-guard` installs with **pipx** (isolated + on your PATH). Grab the wheel from
this repo's **Releases**, then:
```bash
pipx install ./temple_guard-0.5.1-py3-none-any.whl   # or, once on PyPI: pipx install temple-guard
```
New to pipx, or on **macOS / Windows**? [`cli/README.md`](cli/README.md) has the
per-platform setup (installing pipx, `ensurepath`).

### Use
```bash
temple-guard                                               # interactive, colourful session (all options)
temple-guard scan https://your-app.example.com             # colourful terminal report
temple-guard scan https://your-app.example.com -v          # verbose: each check + finding, live
temple-guard scan https://your-app.example.com --deep      # + Docker tools (whatweb, wafw00f, testssl, nmap, nuclei)
temple-guard scan https://your-app.example.com --dry-run   # list the checks, send nothing
temple-guard scan https://your-app.example.com -o report.html # collapsible HTML report (Print → PDF)
temple-guard scan https://your-app.example.com -o report.pdf  # branded PDF (also .md / .json)
temple-guard scan https://your-app.example.com --json      # machine-readable findings
```
It exits non-zero when a **HIGH** finding is present, so it drops straight into CI.
See [`cli/README.md`](cli/README.md) for the full reference.

> ⚠️ **Authorized use only** — scan apps you own or have explicit written
> permission to test.

---

## Quick start

Requirements: Python 3.10+, Node 18+, and (for real scans) Docker.

### Option A — one command, fully containerized (recommended)
```bash
cd temple-guard
./start.sh           # builds + runs Postgres + backend + frontend
```
Then open **http://localhost:3000**. The first run builds images (the backend
uses a Playwright base, ~2 GB pulled once). Data persists in Docker volumes —
see [Data & backups](#data--backups). Stop with `docker compose down`.

> The backend container mounts the host Docker socket so it can still spin up
> Kali / scanner / app-audit containers. On Docker Desktop this works out of the box.

### Option B — install prerequisites automatically (native)
```bash
cd temple-guard
./install.sh        # installs Docker Desktop, Python, Node, deps, Playwright browser
./run.sh            # launch API (:8000) + UI (:3000)
```
`install.sh` supports macOS (Homebrew) and Debian/Ubuntu (apt), is idempotent,
and sets up both apps. Then `./run.sh` seeds demo data and starts everything.

### Option C — manual (native)
```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m app.seed                 # demo clients / engagements / findings
uvicorn app.main:app --port 8000   # API → http://localhost:8000  (docs: /docs)

# Frontend (new terminal)
cd frontend
npm install
npm run dev                        # UI → http://localhost:3000
```

### Option D — desktop app
```bash
cd desktop && npm install && npm start   # native window; boots both servers
```

Open **http://localhost:3000**.

---

## How to use it

A typical engagement, start to finish:

1. **Add the client** (`Clients → + Add Client`). Set authorization to
   `authorized` once you have a signed scope — scans are blocked until you do.
2. **Create an engagement** (`Engagements → + New Engagement`):
   - Select **audit standards** (the suite buttons).
   - Enter the **authorized scope targets** (hostnames/IPs). Anything not listed
     is rejected at scan time.
   - Add an authorization reference and choose a provisioner (Docker today).
3. **Run the audit** — open the engagement and click **▶ Run Audit** (or pick a
   subset of standards first). Scans queue and run in the background.
4. **Watch it live** — the **Control Center** shows the running scan containers
   with live logs; the dashboard shows running/queued counts.
5. **Review findings** — expand each finding for evidence, mapped compliance
   controls, and remediation. Mark them remediated / accepted / false positive.
6. **See the topology** — the **Topology** page maps discovered assets, colored
   by worst severity, filterable by client.
7. **Generate the report** — **▤ Generate Report** on the engagement (or the
   Reports page). Opens printable HTML → Print to PDF for the client.

### Spinning up and using a Kali box
- **Kali Consoles** → pick an engagement → **⚡ Launch Kali**. A Kali container
  starts (image auto-pulls on first use) and a live `root` shell opens in-app.
- Manage every container from the **Control Center**: shell, logs, start, stop,
  restart, remove — per container, or in bulk by engagement / by client. Toggle
  **Showing all containers** to include non-Temple-Guard containers on the host.

---

## Execution modes

Set `TG_EXECUTION_MODE` (see [`.env.example`](.env.example)):

- **`docker`** *(default)* — real tools in ephemeral containers. Falls back to
  simulation automatically if Docker isn't reachable.
- **`simulation`** — realistic synthetic findings, no infrastructure. Great for
  demos, UI work, and report iteration. (The seed always uses this so the
  dashboard is populated regardless of mode.)

Scans run **asynchronously** on a pool sized by `TG_SCAN_CONCURRENCY` (default 4).

### Cloud-VM scans (AWS, optional)
Set an engagement's provisioner to `cloud_vm` and configure
`TG_AWS_REGION`, `TG_AWS_KALI_AMI`, `TG_AWS_SUBNET_ID` (+ AWS credentials;
`pip install boto3`). Scans then launch an ephemeral EC2 from your Kali AMI, run
the tool over SSM, and terminate it. **Disabled and inert unless fully
configured.** Bring-your-own-cloud (assume-role into the client's account) is a
small change in `CloudVMProvisioner._session()`.

### Scanning a client's private network (VPN)
By default scan containers run on Docker's isolated `bridge` network, so they
**can't see a VPN tunnel that only you have**. Each engagement has a **Scan
network** setting (on the engagement page, or `Engagement.scan_network`) that
controls the `docker run --network` for its scan containers:

| Value | Effect |
|---|---|
| `bridge` *(default)* | Isolated; `localhost` targets auto-remap to `host.docker.internal`. |
| `host` | Container shares the **engine host's** network namespace — including a VPN `tun`/`wg` interface and its routes. **Linux only.** No localhost remap. |
| `container:<name>` / a named network | Route scans through a **VPN sidecar** container or a custom network. Cross-platform. |

**The right setup depends on where the engine runs:**

- **Linux host on the VPN (recommended for VPN engagements).** Run the Temple
  Guard engine on a Linux box/jump host that holds the VPN connection, set the
  engagement's Scan network to **`host`**, and every scan container inherits the
  tunnel and reaches the client's private subnets. In-process modules
  (web-evidence, API test, team ops) already use the host's stack, so they work too.
- **macOS / Docker Desktop.** ⚠ Containers run inside Docker Desktop's Linux VM,
  which does **not** contain your Mac's VPN — so `--network host` shares the *VM's*
  network, not the Mac's. Options:
  1. **Full-tunnel corporate VPNs** often work as-is (Docker Desktop forwards
     container traffic through the Mac's stack). Try a scan first.
  2. **VPN sidecar (turnkey)** — see below. Works on macOS *and* Linux.
  3. **Run the engine on a Linux VM/jump host** that's on the VPN (option 1).

#### VPN sidecar — OpenVPN, WireGuard, or Tailscale
[`scripts/vpn-sidecar.sh`](scripts/vpn-sidecar.sh) runs your VPN *inside* a
container (reusing the `templeguard/kali` image — which ships `openvpn`,
`wireguard-tools`, and `tailscale`, so no extra image). Scan containers then share
its network namespace and route through the tunnel — so the VPN tech doesn't
matter, only that its client can run in a container:

```bash
scripts/vpn-sidecar.sh up ~/clients/acme/acme.ovpn        # OpenVPN  (auto-detected)
scripts/vpn-sidecar.sh up ~/clients/acme/wg.conf          # WireGuard — incl. Proton/Mullvad exports
scripts/vpn-sidecar.sh up tailscale tskey-auth-xxxx       # Tailscale (joins your tailnet)
scripts/vpn-sidecar.sh up tailscale tskey-auth-xxxx 100.x.y.z   # …via an exit node = carry ALL traffic

#    → ✓ tunnel up.  set the engagement's Scan network to:  container:tg-vpn
# then: engagement page → Scan network → ✎ edit → container:tg-vpn → Save → run your suites

scripts/vpn-sidecar.sh status   # tunnel state / address
scripts/vpn-sidecar.sh down     # tear it down when the engagement's over
```

What this does and doesn't cover:
- **OpenVPN / WireGuard** — any `.ovpn` or `.conf` you can export. **Proton VPN**
  and **Mullvad** both export WireGuard/OpenVPN configs, so they work via those.
- **Tailscale** — joins your tailnet with an auth key; with **`--exit-node`** it
  routes *all* the container's traffic through a node you pick (the closest thing
  to "just carry over my whole connection"). Tailscale also auto-picks up subnet
  routes (`--accept-routes`) advertised on the tailnet.
- **SSO/proprietary clients** (Cisco AnyConnect, Palo Alto GlobalProtect, the
  Proton *app* with its stealth protocol) **can't be containerized** — there's no
  config to hand a container. For those, run the engine on a **Linux jump host**
  that's already on the VPN (option 1) and use `host` networking.

> There is no single Docker flag that "inherits your Mac's whole connection" — on
> macOS the containers live in Docker Desktop's Linux VM, separate from macOS. The
> sidecar (VPN in a container) and the Linux-jump-host (`host` networking) are the
> two ways to truly route scans through your network path. `tg-vpn` is labelled
> `templeguard`, so it also appears as a node in the Cluster view. (Verified: a
> scan container launched with `--network container:tg-vpn` shares the sidecar's
> exact netns.)

> Only scan inside a client network you are **explicitly authorized** to test, and
> keep the engagement's scope + rules-of-engagement window accurate — the scope
> gate still applies to every target.

---

## Data & backups

The DB is **SQLite by default** (native runs) or **Postgres** (the Docker stack,
set via `TG_DATABASE_URL`). The Postgres data, captured evidence, and generated
reports each live in a named Docker volume, so they survive restarts.

```bash
./backup.sh                      # dump Postgres → backups/templeguard-<ts>.sql.gz
./backup.sh restore <file>       # restore a dump
```

Then sync `backups/` to the cloud whenever you want — no secrets manager required:

```bash
rclone copy backups remote:templeguard-backups
# or: aws s3 sync backups s3://my-bucket/templeguard-backups
```

To move an existing SQLite database to Postgres, point `TG_DATABASE_URL` at
Postgres and re-seed, or export/import per table — the schema is identical.

## Search

A global search box in the sidebar finds **clients, engagements, findings,
assets, and audit targets** as you type, with keyboard navigation — jump
straight to any of them.

![Global search](docs/screenshots/search.png)

## Managing clients & scope

- **Clients** page: add, **edit**, or **delete** a client (delete cascades its
  engagements + findings, with a confirm).
- **Engagement** page: the authorization reference auto-fills per client
  (`SOW-YEAR-INITIALS-NNN`), and the **authorized scope is editable inline** —
  chips with fuzzy autocomplete, plus the `*` wildcard.

## Safety model

1. **Client authorization gate** — a client must be `authorized` before any scan.
2. **Scope enforcement** — every target is checked against the engagement's
   `scope_targets`; out-of-scope targets are rejected (HTTP 422). Toggle with
   `TG_ENFORCE_SCOPE`.
3. **Rules-of-engagement** — engagements record `authorized_by` /
   `authorized_until` for the audit trail.
4. **Cloud is opt-in** — the AWS provisioner never launches anything unless you
   explicitly configure it.

---

## Extending

- **New audit suite** → append a `Standard` to
  [`core/standards.py`](backend/app/core/standards.py). It appears in the UI
  picker automatically and maps to existing modules.
- **New scan tool** → add a `ScanModule` subclass in
  [`core/modules.py`](backend/app/core/modules.py) (real command + parser +
  `simulate()`), and register it in `_REGISTRY`.
- **New playbook** → append a `Playbook` (ordered steps) to
  [`core/playbooks.py`](backend/app/core/playbooks.py). It runs its steps
  sequentially via Kali and shows up on the Playbooks page — data only.
- **New team op** → append a `RedTeamOp` (blue / SOC) to
  [`core/redteam.py`](backend/app/core/redteam.py) and add a bounded, read-only
  handler in `RedTeamModule`.
- **New provisioner (cloud/K8s)** → implement the `Provisioner` interface in
  [`core/provisioner.py`](backend/app/core/provisioner.py).

### Tools & frameworks you can pull in

Many CEH-standard tools are **already bundled** and wired as modules: in the
`templeguard/kali` image — `nmap`, `nikto`, `nuclei`, `sqlmap`, `testssl`,
`sslyze`, `subfinder`, `wpscan`, `ffuf`, `wafw00f`, `enum4linux-ng`, **recon-ng**,
**SpiderFoot**, **PhoneInfoga**, `theHarvester`, plus `gobuster`/`whatweb`/`dnsutils`;
and **Metasploit** (detection-only) in its own `templeguard/metasploit` image. To
add more, drop the package into [`docker/kali/Dockerfile`](backend/docker/kali/Dockerfile)
and add a `ScanModule` (`command()` starting with the binary, `parse()`,
`simulate()`) — or for any tool that ships as its own Docker image, set `image` to
that image (as Metasploit does). High-value tools **not yet wired**, by category:

| Category | Image / project | What it adds |
|---|---|---|
| More recon | `projectdiscovery/httpx`, `…/naabu`, `caffix/amass` | Probing, fast port scan, deeper attack-surface mapping |
| More fuzzing | `epi052/feroxbuster` | Recursive content discovery |
| Containers / IaC / SBOM | `aquasec/trivy` | Image, filesystem, IaC, and dependency CVE scanning |
| Secrets | `trufflesecurity/trufflehog`, `gitleaks/gitleaks` | Secret scanning (great for the app-audit path) |
| SAST | `returntocorp/semgrep` | Static analysis of source |
| Cloud posture | Prowler, ScoutSuite | AWS/Azure/GCP misconfig audits (pairs with the cloud-VM roadmap) |
| Kubernetes | `aquasec/kube-bench`, `aquasec/kube-hunter` | CIS k8s + cluster attack surface |

## Ethical boundaries — what Temple Guard won't ship

This platform is for **authorized** testing. The following are intentionally
**kept out of scope** — they're represented as documented + simulated
operations with hardening guidance. If your engagement authorizes them, keep them documented and simulated only:

- **Weaponized DoS** — volumetric (L3/L4) or application-layer (L7) flooders that
  saturate/exhaust a target. (The built-in resilience probe is hard-capped to
  ≤40 requests — a measurement, not a flood.)
- **Real exploitation that yields shells / RCE** on live systems, and any
  **mass-exploitation** or internet-wide scanning.
- **Credential brute-force / stuffing at scale** against live auth endpoints.
- **Live phishing / smishing delivery** (sending real lures to real people).
- **Malware, ransomware, droppers, persistence, rootkits**, and **AV/EDR/detection
  evasion** intended to defeat defenders.
- **Command-and-control (C2) frameworks and stealth/evasion tooling** aimed at
  non-consenting third parties.
- **Supply-chain compromise** tooling.
- **Destructive actions** on real systems (data deletion, defacement, lockout).
- Anything targeting hosts **outside an authorized engagement's scope**.

Everything else — recon, vuln scanning, web/app auditing, config/posture review,
bounded resilience checks, and the full reporting/hardening workflow — is fair
game and is what the platform is built to automate.

---

## Configuration

All backend settings are env vars prefixed `TG_` (see [`.env.example`](.env.example)).
Common ones:

| Var | Default | Purpose |
|---|---|---|
| `TG_EXECUTION_MODE` | `docker` | `docker` / `simulation` / `cloud_vm` / `k8s` |
| `TG_DATABASE_URL` | `sqlite:///./temple_guard.db` | e.g. `postgresql+psycopg2://temple:temple@postgres:5432/templeguard` |
| `TG_DB_PASSWORD` | `temple` | Postgres password for the Docker stack |
| `TG_SCAN_CONCURRENCY` | `4` | Max scans running at once |
| `TG_SCAN_TIMEOUT_SECONDS` | `900` | Per-scan timeout |
| `TG_ENFORCE_SCOPE` | `true` | Reject out-of-scope targets |
| `TG_AWS_REGION` / `TG_AWS_KALI_AMI` / `TG_AWS_SUBNET_ID` | — | Enable cloud-VM scans |

---

## Project layout

```
temple-guard/
├── backend/          FastAPI app
│   └── app/
│       ├── api/routes.py     all HTTP + WebSocket endpoints
│       ├── core/             standards, modules, runner, jobs, provisioner,
│       │                     kali, shell, reporting, remediation
│       ├── models.py         SQLModel tables
│       └── seed.py           demo data
├── frontend/         Next.js app (App Router)
│   ├── app/          dashboard, clients, engagements, topology,
│   │                 consoles, containers, reports, team-ops
│   ├── components/   Sidebar, Terminal, StandardsPicker, ui
│   └── lib/          api client + types
├── desktop/          Electron shell
├── run.sh            one-command local launcher
└── CLAUDE.md         guidance for AI agents working in this repo
```

Planned next: cloud shells / SSM consoles, a K8s provisioner, and RBAC / audit logging.

---

## License

Released under the [MIT License](LICENSE). This is **defensive tooling** — use it
only on systems you own or are explicitly authorized in writing to test.
