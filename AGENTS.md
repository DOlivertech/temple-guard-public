# AGENTS.md — Temple Guard

Working guide for AI agents. See [CLAUDE.md](CLAUDE.md) for the architecture map and
core-module table. This file goes deep on the two things asked about most —
**containers/images** and **playbooks** — and mirrors the invariants/gotchas.

## Non-negotiable invariants

1. **Scope enforcement.** Any path that scans a target goes through
   `assert_in_scope()` / `enqueue_standard()`. Never add a way to scan an arbitrary
   target. Out-of-scope → HTTP 422.
2. **Authorization gate.** Runs refuse unless the client is `authorized` and the
   engagement is inside its rules-of-engagement window.
3. **Cloud is opt-in and inert by default.** `CloudVMProvisioner` launches nothing
   unless `TG_AWS_*` + credentials are present. The dev machine may have live AWS
   creds — leave `TG_AWS_*` unset.
4. **Container labels.** Keep `templeguard=true` + `tg.client/engagement/instance/
   role/run/target` on anything you `docker run` — the Control Center groups by them.
5. **Non-destructive by default.** This is defensive tooling — no offensive
   techniques (exploitation, brute-force, flooding, C2). Intrusive scan tools carry
   a `warning`; keep `simulate()` in sync with every real parser. See
   [wontdo.md](wontdo.md).

---

## Containers & images

### What images exist — and what to use

| Image | Built from | Use it for |
|---|---|---|
| **`templeguard/kali`** | `backend/docker/kali/Dockerfile` (`FROM kalilinux/kali-rolling`) | **The default for everything containerized.** Every CLI scan tool (nmap, nikto, nuclei, sqlmap, testssl, sslyze, subfinder, wpscan, ffuf, wafw00f, enum4linux-ng, recon-ng, SpiderFoot, theHarvester, PhoneInfoga, gobuster, whatweb, dnsutils) + Nuclei templates baked in + the VPN clients (openvpn/wireguard/tailscale). It also boots the **Kali consoles** and doubles as the **VPN sidecar**. |
| **`templeguard/metasploit`** | `backend/docker/metasploit/Dockerfile` (`FROM templeguard/kali:latest`) | Only the heavy Metasploit framework (detection-only auxiliary scanners). Layered on the Kali image so it reuses every Kali layer and only adds msf — keeps the host footprint down. |

**Default to `templeguard/kali`.** Only give a tool its own image when it's too
heavy to bake into the shared one (Metasploit is the single example), and build that
image `FROM templeguard/kali:latest` so layers are shared. `install.sh` builds both.

In-process modules (`web_evidence`, `api_test`, `redteam_op`) run **in the backend
process, not a container** (`runs_in_container = False`) — they reach `localhost`
directly and need no image.

### How a scan container runs

`core/provisioner.py` → `DockerProvisioner.run()` executes:

```
docker run --rm --network <scan_network> <labels> <module.image> <module.command(target)>
```

- **`module.image`** picks the image (`KALI_IMAGE` for most; `templeguard/metasploit:latest`
  for the msf module).
- **`module.command()`** returns argv **starting with the binary name** — the image has
  no entrypoint (e.g. `["nmap", "-sV", host]`).
- Containers are **ephemeral** (`--rm`) — one per scan, torn down on completion.

### Labels — keep them

Anything you `docker run` for Temple Guard must carry the labels from
`core/kali.py` (`label_run_args()` for scans, `_labels_args()` for consoles):

```
templeguard=true  tg.role=<scan|kali|vpn>  tg.client=<id>  tg.engagement=<id>
tg.instance=<id>  tg.run=<id>  tg.target=<id>
```

The **Control Center / Cluster view** and bulk actions group and filter by these.
Drop them and the container becomes invisible to the UI and to cleanup.

### Network (`scan_network`) — incl. VPN

Per-engagement `Engagement.scan_network` controls `--network` for that engagement's
scan containers (editable on the engagement page):

- `bridge` (default) — isolated; `localhost` targets auto-remap to `host.docker.internal`.
- `host` — share the engine host's stack incl. a VPN tunnel (**Linux**); no localhost remap.
- `container:<name>` — route through a **VPN sidecar** (`scripts/vpn-sidecar.sh up …`,
  OpenVPN/WireGuard/Tailscale). The localhost remap is applied **only on `bridge`**.

### Adding a tool to the image

1. Add the package to the apt line in `backend/docker/kali/Dockerfile`.
2. Rebuild: `docker build -t templeguard/kali:latest backend/docker/kali`.
3. Confirm: `docker run --rm templeguard/kali:latest which <tool>`.
4. Write the `ScanModule` (`image = KALI_IMAGE`, `command()` starts with the binary).

Heavy tool → new `backend/docker/<tool>/Dockerfile` (`FROM templeguard/kali:latest`),
set `image = "templeguard/<tool>:latest"` on the module, and add the build to `install.sh`.

### Managing containers at runtime

- **Code:** `core/kali.py` — `start` / `stop` / `restart` / `remove`, `stats`, `logs`,
  `shell` (label-filtered). `kill_container()` / `kill_by_label()` for cleanup.
- **API:** `GET /containers`, `POST /containers/{ref}/{action}`, `POST /containers/bulk`,
  WS `/containers/{ref}/logs` and `/containers/{ref}/shell`.
- **UI:** Control Center page — **Cluster view** (namespace map, CPU/MEM gauges, drill
  into logs/shell) and **List view**; per-node and per-namespace actions.
- **Kali consoles:** `POST /engagements/{id}/instances` spins up a labelled long-lived
  `templeguard/kali` container with a live in-browser root shell.

---

## Playbooks — building & adding

A **playbook** chains scan modules in a fixed order; each step runs in its **own
container** and only starts after the previous one finishes. Adding one is a **pure
data change** — no other code.

### The recipe

In `backend/app/core/playbooks.py`, append a `Playbook` to `CATALOG`:

```python
Playbook(
    id="network_enum", name="Network Enumeration", category="network",   # recon | web | network
    description="Port scan → SMB enumeration → TLS posture.",
    steps=[
        PlaybookStep("nmap", "Port & service scan", "Service/version scan", {"profile": "service-version"}),
        PlaybookStep("enum4linux", "SMB enumeration", "Shares / users / OS"),
        PlaybookStep("tls_audit", "TLS posture", "Protocols + known TLS issues"),
    ],
),
```

`PlaybookStep(module, label, note="", params={})` — **`module` must be a key in
`modules._REGISTRY`.** `params` is passed straight to the module (same shape a
`SuiteModule` uses).

### How it executes (no code to write)

- `runner.enqueue_playbook(session, engagement, playbook_id, target)` scope-checks the
  target, anchors an `AuditTarget`, and creates the step `ScanRun`s **in order**.
- `jobs.submit_playbook(run_ids)` runs them **sequentially** on one worker (step N+1
  waits for N).
- Each step runs in **its module's image** — so a single playbook composes across
  `templeguard/kali` and `templeguard/metasploit` automatically (see the `vuln_hunt`
  playbook: nmap [kali] → metasploit [own image] → nuclei [kali]).

### Where it shows up

- `GET /api/playbooks` (each playbook now also returns `warnings` — the distinct
  pre-flight warnings of its tools) → the **Playbooks page**.
- Launching one returns the anchor `target_id`; the UI redirects to `/attacks/{id}`
  (the live per-attack dashboard), and every step appears as a node in the **Cluster
  view** as its container spins up and down.

### Rules

- Compose only the same **bounded, non-destructive** modules used elsewhere. Don't add
  a step that exploits, floods, or otherwise crosses [wontdo.md](wontdo.md).
- Order matters: footprint → fingerprint → scan → discover → vuln-scan.
- Intrusive steps carry a `warning` (surfaced per-playbook); passive ones don't.

---

## Adding a module / standard / team op

Summarized here; full recipes in **[CLAUDE.md → "Extending the platform"](CLAUDE.md)**:

- **Standard (audit suite):** append a `Standard` to `core/standards.py` (data only).
- **Scan module:** subclass `ScanModule` in `core/modules.py` (`image`, `command()`,
  `parse()`, `simulate()`), register in `_REGISTRY`. Set `warning` if it's intrusive.
- **Blue/SOC op:** append a `RedTeamOp` (blue/SOC) to `core/redteam.py` and add a
  bounded, read-only handler in `RedTeamModule._execute`. Defensive-only.

### Verify before handoff

```bash
cd backend && python -c "from app.main import app"     # import sanity
npx tsc --noEmit                                        # frontend (never `npm run build` over the dev server)
docker run --rm templeguard/kali:latest which <tool>   # container tools present
```

---

## Running & testing

```bash
# Backend
cd backend && source .venv/bin/activate
python -m app.seed                 # reset + populate demo data (idempotent)
uvicorn app.main:app --port 8000   # API; --reload optional

# Frontend
cd frontend && npm run dev         # :3000
cd frontend && npx tsc --noEmit    # type-check WITHOUT building (safe while dev runs)
```

Smoke endpoints: `GET /api/health`, `/api/dashboard`, `/api/standards`,
`/api/playbooks`, `/api/containers`, `/api/provisioners`. Interactive docs at `/docs`.

## Gotchas (learned the hard way)

- **Never run `npm run build` while `npm run dev` is running** — they share `.next/`
  and the build corrupts the dev server (`Cannot find module './###.js'`). Recover:
  stop dev, `rm -rf .next`, restart. Verify with `npx tsc --noEmit` + hitting routes.
- **All containerized scans use `templeguard/kali:latest`** — build it once
  (`./install.sh` or `docker build -t templeguard/kali:latest backend/docker/kali`).
  First build is slow (pulls Kali, installs the toolset, bakes ~13k Nuclei templates);
  every scan after is fast/offline. A scan failing with "No such image" = not built yet.
- **Pages using `useSearchParams` need a `<Suspense>` boundary** or the prod build fails.
- **xterm CSS import** is declared in `frontend/types.d.ts` so TS doesn't choke.
- **WebSocket URLs bypass the Next proxy** — build them with `wsUrl()` from `lib/api.ts`.
- **Evidence images serve at `/evidence-img`, NOT `/evidence`** (the latter is the Next
  page route); a rewrite proxies `/evidence-img/*` to the backend mount. Don't collapse them.
- **SQLite under the concurrent scan pool** uses WAL + `busy_timeout` (`database.py`);
  for heavy concurrent writes prefer Postgres (`TG_DATABASE_URL`).
- **Deleting a target cascades** its own scans + findings (by `target_id`); suite scans
  that merely share the hostname are preserved.

## The `temple-guard` CLI (`cli/`)

A self-contained CLI, **independent of the platform** (no backend/DB) — `pipx`-installable,
scans a web app you own. Full overview in [CLAUDE.md](CLAUDE.md) → "The `temple-guard` CLI".
Dev quick-reference:

- **Run from source:** `pipx install --force --editable cli` → `temple-guard`. Bump the
  version in **both** `cli/pyproject.toml` and `cli/temple_guard/__init__.py`. Byte-compile
  with `python -m py_compile cli/temple_guard/*.py`.
- **Layout:** `cli.py` (Typer commands + interactive menu + `TOOL_GUIDE` guided prompts),
  `checks.py` (`CHECK_PLAN` + `scan()` events), `tools.py` (`TOOLS`, `run_tool`/`run_raw`/
  `kali_shell`, host-IPv4 remap + dry-run command preview), `report.py` (render + HTML/PDF/MD),
  `monitor.py` (live btop-style dashboard — concurrent `checks.scan()` via a thread pool + Rich `Live`).
- **Add a Docker tool:** append a `Tool(...)` to `tools.TOOLS` (image, `argv` builder,
  `parse`→`[Finding]`, and the `what/usage/risk/flags` strings), add it to `DEFENSIVE` if it
  belongs under `--deep`, and add a `TOOL_GUIDE[name]` entry in `cli.py` for the guided flow.
  Confirm the image exists with a manual `docker run --rm <image> …` first.
- **Add a native check:** add `(category, name, desc)` to `CHECK_PLAN` and a check fn that
  emits findings via the `add`/`on_event` callback in `checks.py`; give a new category a
  `CAT_ICON` in `report.py`.
- **Verify:** `temple-guard tool <name> --dry-run <args>` builds the docker command without
  running it; a real tool / `--deep` run needs Docker. `temple-guard scan <url> --dry-run`
  lists the native checks.

## Releasing (`temple-guard` CLI)

Releases are tagged `vMAJOR.MINOR.PATCH` and published on GitHub Releases. **Every release
gets curated, human-readable notes — never auto-generated.** Steps:

1. Bump the version in **`cli/pyproject.toml`** and **`cli/temple_guard/__init__.py`**.
2. Add a dated section to **[CHANGELOG.md](CHANGELOG.md)** (Keep a Changelog format —
   `Added` / `Changed` / `Fixed`). This section *is* the release notes.
3. Build the artifacts: `cd cli && python -m build` → `dist/temple_guard-<v>-py3-none-any.whl`
   + `.tar.gz`.
4. Cut the release, using the CHANGELOG section as the notes (keep a short install + usage
   snippet at the top):
   ```bash
   gh release create v<v> cli/dist/temple_guard-<v>-* \
     --title "temple-guard v<v>" --notes-file <notes.md> --target main
   ```
5. `pipx install --force cli/dist/temple_guard-<v>-py3-none-any.whl` to update a local install,
   and bump the wheel version referenced in `README.md` + `cli/README.md`.
