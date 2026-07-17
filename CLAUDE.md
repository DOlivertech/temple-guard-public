# CLAUDE.md — Project Temple Guard

Guidance for AI agents (Claude Code) working in this repository. Read this before
making changes.

## What this is

An **authorized** penetration-testing orchestration platform. Operators register
clients, open engagements with an authorized scope, select audit standards, and
run security scans (real tools in Docker, or a simulation fallback). The app
manages Kali containers, streams live shells/logs, draws topology, and generates
remediation reports.

**This is defensive/authorized security tooling.** Keep it that way: every
feature must preserve the authorization + scope guarantees below. Do not add
capabilities that bypass them, target third parties, or evade detection.

## Architecture at a glance

- `backend/` — FastAPI + SQLModel (SQLite by default, Postgres-ready). All
  endpoints (REST + WebSocket) live in `app/api/routes.py`.
- `frontend/` — Next.js 14 App Router, TypeScript, Tailwind, React Flow,
  xterm.js. Pages in `app/`, shared bits in `components/` and `lib/`.
- `desktop/` — Electron shell that boots both servers.
- `cli/` — a **standalone** `temple-guard` Python CLI (self-scan a web app you own; no
  backend/DB, no Docker for the core). Independent of everything above — its own section below.

Request flow: browser → Next.js (`/api/*` proxied to `:8000`) → FastAPI.
WebSockets (shells, logs) connect **directly** to the backend via
`lib/api.ts → wsUrl()` (`ws://localhost:8000`), because proxying WS through Next
is unreliable.

### Backend core modules (`backend/app/core/`)
| File | Responsibility |
|---|---|
| `standards.py` | Audit-suite catalog as **data** (`CATALOG`). Each `Standard` maps to one or more scan modules. New suite = new entry, no other code. |
| `modules.py` | Scan tools. **Containerized CLI tools all run in one image — `templeguard/kali:latest` (`KALI_IMAGE`, built from `backend/docker/kali/`)**: `nmap`, `nikto`, `nuclei` (template vuln scan, templates baked in), `tls_audit` (testssl), `sqlmap`. Each `command()` prepends the tool binary name (the image has no entrypoint). In-process tools (`runs_in_container=False`): `web_evidence` (Playwright screenshots + live header checks; findings may carry `_image` bytes persisted to `evidence_out/`, served at `/evidence-img/...`), `api_test` (httpx — discover + bounded API testing), `redteam_op`. Each tool has a real `command()`/`run_real()` + `parse()` **and** a `simulate()` fallback. Registered in `_REGISTRY`. (ZAP was retired — Java, not in Kali's repos — replaced by Nuclei across the OWASP/PCI suites.) |
| `runner.py` | Orchestration. `enqueue_standard()` (scope + queued rows), `enqueue_target()` (structured web/app/api targets → tool set; `TARGET_MODULES`), `execute_run()` (self-contained, runs one scan). `assert_in_scope()` is the scope gate. `_container_target()` remaps `localhost`→`host.docker.internal` for container modules (so local web apps are reachable; in-process modules like `web_evidence`/`api_test` keep `localhost`, gated by `module.runs_in_container`). Scan containers use the engagement's `scan_network` (`bridge` default / `host` / `container:<vpn>`) — the localhost remap is applied **only on `bridge`** (with `host`/VPN networking the container shares the host's loopback + routes, so targets pass through unchanged). |
| `modules.py` (app_analysis) | `AppAnalysisModule` spins up `templeguard/kali` (ships `file`/`strings`/`7z`/`unzip`/`curl`), fetches an app artifact (URL or mounted path), and statically dissects it. Static-only; does not execute the installer. |
| `modules.py` (api_test) | `ApiTestModule` + `discover_api_endpoints()`: discover an API's endpoints (OpenAPI/Swagger spec or common-path probing), then run **bounded** per-endpoint request bursts (httpx, in-process). Two endpoints drive the UI: `POST /targets/{id}/api/discover` and `POST /targets/{id}/api/test` (selected `[{method,path}]`). Frontend tester at `app/api-test/[id]`. |
| `jobs.py` | `ThreadPoolExecutor` background pool. `submit_runs()` is how the API kicks off async execution. |
| `provisioner.py` | `Provisioner` interface: `DockerProvisioner` (real), `CloudVMProvisioner` (AWS/boto3, gated), `K8sProvisioner` (placeholder). |
| `kali.py` | Docker container management: start/stop/restart/remove, list (label-filtered), stats, logs/shell commands. `label_run_args()` tags containers. |
| `shell.py` | WebSocket ↔ PTY bridge (`pty_bridge`), `stream_logs`, and an `emulated_shell` for no-Docker mode. |
| `remediation.py` | Knowledge base mapping a finding category → fix + compliance refs. Both real parsers and the simulator pull from here. |
| `controls.py` | Resolves a `standard_refs` string (e.g. "OWASP Top 10 A03", "PCI-DSS 6.2") to `{framework, control, title, url}` with an authoritative web link. Used by the Evidence endpoints (`/api/evidence`), the engagement detail payload, and the report. |
| `reporting.py` | Jinja2 HTML report. |

### Data model (`backend/app/models.py`)
`Client → Engagement → { Asset, ScanRun → Finding, ProvisionedInstance, Report }`.
`ScanRun.status`: `queued → running → completed | failed`.

## The `temple-guard` CLI (`cli/`)

A **standalone** Python CLI — independent of the platform above (no backend, no DB, no Docker
required for the core) — that scans a web app you own and prints or writes a remediation
report. Everything lives in `cli/`; it ships to end users via `pipx`.

- **Package `cli/temple_guard/`:** `cli.py` (Typer app, commands, interactive menu,
  `TOOL_GUIDE` guided prompts), `checks.py` (native read-only checks, `CHECK_PLAN`, `scan()`
  + progress events), `tools.py` (`TOOLS` registry of Docker-backed tools), `report.py`
  (terminal / Markdown / PDF / collapsible-HTML render), `monitor.py` (live btop-style
  multi-scan dashboard — concurrent scans via a thread pool + Rich `Live`). **The version
  lives in BOTH `cli/temple_guard/__init__.py` and `cli/pyproject.toml`** — bump them together.
- **Dev install:** `pipx install --force --editable cli` → the `temple-guard` command runs
  live from source. Deps: httpx · rich · typer · art · fpdf2 · dnspython · InquirerPy.
- **Native checks** (no Docker; one bounded request each): HTTPS/TLS + certificate, security
  headers, cookie flags, info disclosure, sensitive-path exposure (catch-all/SPA guard),
  HTTP methods, SPF/DMARC. `checks.scan(url, on_event=…)` streams `step`/`finding`/`clean`.
- **Docker tools** (`tools.py`; opt-in via `--deep` / `--tools` / `tool <name>`): each spins
  up a public per-tool image and merges findings into the same report —
  `whatweb, wafw00f, testssl, nmap, nuclei` (the `--deep` set) + `nikto` (opt-in). Entry
  points `run_tool` (parsed→findings), `run_raw` (full-flag passthrough), `kali_shell`. A
  `localhost` / `host.docker.internal` target resolves to the host's **numeric IPv4** (works
  around Docker-Desktop's dead IPv6 dual-stack); dry-run previews skip resolution. **Prereq =
  Docker running** (nothing to vendor — images are public, pulled on demand incl. `alpine` for
  the localhost remap). `temple-guard doctor [--pull]` verifies Docker + pre-pulls
  (`tools.defensive_images()`); every "Docker unavailable" path prints `tools.docker_hint()`
  (per-OS install/start guidance) and failed tool runs are classified via `tools._diagnose`
  (daemon-down · network/pull · image-unavailable · timeout).
- **UX:** bare `temple-guard` → a fuzzy, type-to-filter menu (InquirerPy; `TG_NO_FUZZY=1` for
  the numbered fallback). "Run a tool" is **guided** — options become numbered prompts /
  yes-no, the target is validated + normalized, and a "Run this?" confirm precedes execution.
  **Every** action has a `--dry-run`; `temple-guard update` self-updates from the git repo.
- **Monitor:** `temple-guard monitor <urls…>` (or the "Monitor" menu item) runs several scans
  concurrently in a live btop-style dashboard — animated progress, findings meter, live logs;
  `↑↓`/`jk` select, `s`/`r`/`n` stop/restart/new, `w` combined report, `Esc`/`Ctrl+C` leave
  (confirmation gate; `q` is inert). Arrow parsing handles ESC[A **and** ESC O A. Adding a target
  (`n`) picks **what runs against it** — native checks / deep / specific Docker tools
  (`monitor.DEEP_TOOLS` / `MONITOR_TOOLS`; `--deep` / `--tools` preload a profile); tool
  findings merge into the live counters + combined report. Non-TTY → headless run + summary.
- **Reports:** `-o report.{html,pdf,md,json}` — HTML is collapsible + Print-to-PDF, PDF via
  fpdf2 (no browser). README terminal screenshots live in `cli/docs/screenshots/`.
- **Extend:** a Docker tool = a `Tool(...)` in `tools.TOOLS` (image · `argv` builder ·
  `parse`→`[Finding]` · `what/usage/risk/flags`) + a `TOOL_GUIDE[name]` entry in `cli.py`;
  a native check = an entry in `CHECK_PLAN` + a check fn in `checks.py` (+ a `CAT_ICON` in
  `report.py` for a new category). Releasing: [AGENTS.md](AGENTS.md) → "Releasing".

## Non-negotiable invariants

1. **Scope enforcement.** Any path that scans a target must go through
   `assert_in_scope()` / `enqueue_standard()`. Never add a way to scan an
   arbitrary target. Out-of-scope → HTTP 422.
2. **Authorization gate.** `run_audit` refuses unless the client is `authorized`.
3. **Cloud is opt-in and inert by default.** `CloudVMProvisioner.available()`
   returns False unless `TG_AWS_*` config **and** credentials are present. **Do
   not** launch real EC2 instances during development/testing — the dev machine
   may have live AWS credentials. Leave `TG_AWS_*` unset.
4. **Container labels.** Temple-Guard containers carry `templeguard=true` +
   `tg.client` / `tg.engagement` / `tg.instance` / `tg.role`. The Control Center
   relies on these for grouping; keep them on anything you `docker run`.

## Deployment shapes

- **Native** (`run.sh`): SQLite, backend+frontend as host processes, direct Docker
  access for scans. Best for dev.
- **Containerized** (`start.sh` → `docker-compose.yml`): Postgres + backend +
  frontend, persistent volumes. The backend image is built on the Playwright/Python
  base (Chromium for web-evidence + PDF) and installs the Docker CLI; it mounts
  `/var/run/docker.sock` so it can still spin up scan/tool containers
  (docker-out-of-docker). `app/bootstrap.py` seeds only if the DB is empty.
- Postgres is selected purely via `TG_DATABASE_URL`; the SQLite-only migration
  helper (`_ensure_columns`) is skipped for Postgres (create_all covers it).

## Containers & images

(Mirrored in [AGENTS.md](AGENTS.md), which goes deeper.)

| Image | Built from | Use it for |
|---|---|---|
| **`templeguard/kali`** | `backend/docker/kali/Dockerfile` (`FROM kalilinux/kali-rolling`) | **Default for everything containerized.** All CLI scan tools (nmap, nikto, nuclei, sqlmap, testssl, sslyze, subfinder, wpscan, ffuf, wafw00f, enum4linux-ng, recon-ng, SpiderFoot, theHarvester, PhoneInfoga, …) + baked Nuclei templates + VPN clients. Also boots the Kali consoles and is the VPN sidecar. |
| **`templeguard/metasploit`** | `backend/docker/metasploit/Dockerfile` (`FROM templeguard/kali`) | Only the heavy Metasploit framework (detection-only). Layered on the Kali image so it shares every layer. |

- **Default to `templeguard/kali`.** Give a tool its own image only when it's too
  heavy to bake in (Metasploit is the one example), and build that image
  `FROM templeguard/kali:latest`. `install.sh` builds both.
- **In-process modules** (`web_evidence`, `api_test`, `redteam_op`) run in the
  backend process, not a container (`runs_in_container = False`).
- **A scan container =** `docker run --rm --network <scan_network> <labels>
  <module.image> <module.command(target)>` via `DockerProvisioner.run()`. `command()`
  starts with the binary name (the image has no entrypoint). Ephemeral (`--rm`).
- **Labels are mandatory** (invariant #4): `core/kali.py` `label_run_args()` /
  `_labels_args()` stamp `templeguard=true` + `tg.role/client/engagement/instance/run/target`.
- **`scan_network`** (per-engagement): `bridge` (default; localhost→`host.docker.internal`),
  `host` (inherit host stack + VPN, Linux), or `container:<vpn>` (VPN sidecar via
  `scripts/vpn-sidecar.sh`). Remap applies only on `bridge`.
- **Add a tool:** apt line in the Kali Dockerfile → rebuild
  (`docker build -t templeguard/kali:latest backend/docker/kali`) → confirm
  `docker run --rm templeguard/kali:latest which <tool>`.
- **Runtime management:** `core/kali.py` (start/stop/restart/remove, stats, logs,
  shell); `GET /containers` + `POST /containers/{ref}/{action}` + `/containers/bulk`;
  the Control Center page (Cluster + List views); consoles via
  `POST /engagements/{id}/instances`.

## Running & testing

```bash
# Backend
cd backend && source .venv/bin/activate
python -m app.seed                 # reset + populate demo data (idempotent)
uvicorn app.main:app --port 8000   # API; --reload optional

# Frontend
cd frontend && npm run dev         # :3000

# Type-check WITHOUT building (safe while dev server runs)
cd frontend && npx tsc --noEmit
```

Smoke endpoints: `GET /api/health`, `/api/dashboard`, `/api/standards`,
`/api/containers`, `/api/provisioners`. Interactive docs at `/docs`.

## Gotchas (learned the hard way)

- **Never run `npm run build` while `npm run dev` is running.** They share
  `.next/` and the build corrupts the dev server (`Cannot find module './###.js'`).
  To recover: stop dev, `rm -rf .next`, restart. For verification prefer
  `npx tsc --noEmit` + hitting routes, not a full build.
- **Pages using `useSearchParams` need a `<Suspense>` boundary** or production
  build fails (see `app/engagements/page.tsx`).
- **xterm CSS import** is declared in `frontend/types.d.ts` (`declare module
  "xterm/css/xterm.css"`) so TS doesn't choke.
- **All containerized scans use `templeguard/kali:latest`** — build it once
  (`docker build -t templeguard/kali:latest backend/docker/kali`, or run
  `./install.sh`). The first build is slow (pulls Kali, installs the toolset,
  bakes ~13k Nuclei templates) but every scan after is fast and offline. If a
  scan fails with "No such image", the toolbox hasn't been built yet.
- **SQLite under the concurrent scan pool** uses WAL + `busy_timeout` (set in
  `database.py`). If you add heavy concurrent writes, prefer Postgres
  (`TG_DATABASE_URL`).
- **WebSocket URLs bypass the Next proxy** — always build them with
  `wsUrl()` from `lib/api.ts`.
- **Evidence images are served at `/evidence-img`, NOT `/evidence`** — the latter
  is the Next page route (Evidence section). A Next rewrite proxies
  `/evidence-img/*` to the backend `StaticFiles` mount. Don't collapse them.

## Conventions

- Backend: type hints + `from __future__ import annotations`; keep endpoints in
  `routes.py`; business logic in `core/`. Env config via `pydantic-settings`
  (`config.py`, `TG_` prefix).
- Frontend: client components fetch with SWR + the `api()` / `fetcher` helpers in
  `lib/api.ts`; types in `lib/types.ts`; Tailwind utility classes + the small
  component set in `components/ui.tsx`. Dark "security console" aesthetic.
- Keep simulation and real paths in sync — when you add a real parser, add a
  matching `simulate()` so the no-Docker demo still works.

## Extending the platform (agent playbook)

How to add the three things you'll most often be asked for. **Every new feature
must preserve the invariants above** — scope gate, authorization gate, container
labels, non-destructive-by-default.

### Golden rules for any new attack/audit
1. **Never bypass scope/auth.** Anything that touches a target routes through
   `enqueue_standard()` / `enqueue_target()` → `assert_in_scope()`. Don't add a
   code path that scans an arbitrary host.
2. **Real + simulated stay in sync.** Every module needs both a real
   `command()`/`run_real()` + `parse()` **and** a `simulate()` that returns
   plausible findings, so the no-Docker demo and tests still work.
3. **Bounded & non-destructive.** Executable checks must be hard-capped (request
   counts, timeouts) and must not exploit, flood, persist, deceive people, or
   exfiltrate. Genuinely offensive techniques are *documented + simulated only*.
4. **Findings speak `remediation.py`.** Reuse `remediation.enrich(category, …)`
   where a category exists; new categories get a remediation + `standard_refs`
   so the Evidence/report control-linking works.

### Add a new audit suite (standard)
Pure data — usually no other code. In `core/standards.py`, append a `Standard`
to `CATALOG`: give it an `id`, `name`, `framework`, `category`, `description`,
`references`, and a `modules=[SuiteModule("<module_name>", {params})]` list. It
appears in the standards picker and runs automatically. (Example: `nuclei_scan`,
`tls_crypto_audit`.)

### Add a new scan tool (module)
In `core/modules.py`, subclass `ScanModule`:
- **Container tool (preferred):** set `image = KALI_IMAGE`. `command()` returns
  the argv **starting with the binary name** (the image has no entrypoint, e.g.
  `["nmap", "-sV", host]`). If the tool isn't already in the image, add it to
  `backend/docker/kali/Dockerfile` and rebuild (`docker build -t
  templeguard/kali:latest backend/docker/kali`). `parse(ExecResult, target)`
  turns stdout into `ModuleResult(findings=[…], assets=[…])`.
  - **Heavy tools get their own image — built `FROM templeguard/kali`.** If a tool
    is too large to bake into the shared image (e.g. Metasploit), give it a
    dedicated Dockerfile under `backend/docker/<tool>/` that starts
    `FROM templeguard/kali:latest` (so it reuses every Kali layer already on the
    host and adds ONLY its own packages — lower footprint than a second base), and
    set `image = "templeguard/<tool>:latest"` on the module (see `MetasploitModule`).
    Add the build to `install.sh` after the Kali build. Playbooks compose across
    images automatically — each step runs in its module's image.
- **In-process tool:** set `runs_in_container = False` and implement
  `run_real(self, provisioner, target, timeout, labels)` directly (httpx,
  Playwright, etc.). These keep `localhost` targets (not rewritten to
  `host.docker.internal`). Examples: `web_evidence`, `api_test`, `redteam_op`.
- Add a `simulate()`. Register the class in `_REGISTRY`. Wire it into a suite
  (`standards.py`) and/or a target kind (`TARGET_MODULES` in `runner.py`).
- The per-scan **execution badge** (`script` / `img·kali` / `simulated`) is
  derived automatically by `_execution_info()` in `routes.py` from
  `runs_in_container` + `image` + provisioner — no extra work needed.

### Add a Blue / SOC operation
1. In `core/redteam.py`, append a `RedTeamOp` to `CATALOG`. Set `team`
   (`blue` | `soc`), the MITRE `attack` / control mapping, `aggressiveness`
   (`passive` | `low`), `executable=True`, and `engine="in-process"` (a bounded
   httpx script) **or** `engine="kali"` (a real read-only tool in the Kali image
   via the provisioner). Every op here is bounded, read-only, and non-destructive.
2. Add a dispatch branch in `RedTeamModule._execute` (in `modules.py`) and a
   handler. In-process handlers take `(url, op, lines)`; Kali-engine handlers use
   `self._provisioner.run(KALI_IMAGE, [...], …)`. Emit `_ok_finding` /
   `_info_finding` helpers for clean passes.
3. Keep it bounded and non-destructive — no exploitation, brute-force, flooding,
   or offensive automation. This catalog is defensive-only.

### Add a Playbook (ordered multi-step pipeline)
Pure data — no other code. A playbook chains existing scan modules in order
(each step runs only after the previous finishes, in its own Kali container).
In `core/playbooks.py`, append a `Playbook` to `CATALOG` with `id`, `name`,
`description`, `category` (recon|web|network), and an ordered
`steps=[PlaybookStep("<module>", "<label>", "<note>", {params})]` list. Every
step's `module` must be registered in `modules._REGISTRY`. It shows up on the
Playbooks page automatically. Execution is generic:
`runner.enqueue_playbook()` scope-checks the target, anchors an `AuditTarget`
(so the per-attack dashboard shows the run live), and creates the step
`ScanRun`s in order; `jobs.submit_playbook()` runs them **sequentially** on one
worker. Launching redirects to `/attacks/{anchor_id}`, and each step appears as
a node in the Cluster view. Don't add destructive steps — playbooks compose the
same bounded modules as everything else.

### Verify before you hand off
- Backend: `python -c "from app.main import app"` (import sanity) and run the
  affected module against a safe target.
- Frontend: `npx tsc --noEmit` (never `npm run build` while dev server runs).
- Container tools: confirm the binary exists in the image
  (`docker run --rm templeguard/kali:latest which <tool>`).

## Status

Done: real Docker scans (one Kali toolbox image),
async execution, Kali instances + remote shell, Container Control Center, AWS scan
provisioner (gated), topology, reports + server-side PDF (Chromium), desktop shell,
API testing (discover + bounded request batches), bounded Blue/SOC team
execution. Next: cloud shells/SSM consoles, K8s provisioner, RBAC/audit logging.
