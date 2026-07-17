# Changelog

All notable changes to Temple Guard and the `temple-guard` CLI are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/); releases are tagged
`vMAJOR.MINOR.PATCH` and published on GitHub Releases. **When cutting a release, use
that version's section below as the release notes** (see [AGENTS.md](AGENTS.md) → Releasing).

## [0.6.1] — 2026-07-17
### Changed
- **Monitor: manage targets from inside the dashboard.** Launching **Monitor** from the menu
  now opens the dashboard directly (empty) — press **`n`** to add one or more targets at any
  time (even while other scans run), instead of a prompt up front.
- **Actionable Docker errors.** Every "Docker unavailable" path now prints **what to do** (install
  Docker Desktop, or start it — per-OS guidance), and a failed tool run is **classified** —
  daemon-down · network/pull-failed · image-unavailable · timed-out — each with a targeted fix in
  the finding instead of a generic "did not complete".
- **New banner emblem.** The Temple Guard shield now carries a single **gold lightsaber** — a
  thick blade down the front of the guard mask, glowing tip up top, steel hilt below (replacing
  the old double-bladed saberstaff).
### Docs
- README now shows the **live monitor** in action, and the interactive Help lists `monitor` +
  `doctor`.
### Added
- **Combined monitor report.** Press **`w`** in the dashboard (or `temple-guard monitor
  <urls…> -o report.html`) to write **one** report across every scan — a summary table +
  per-target severity cards and findings, in `.html` / `.md` / `.json`.
- **Pick what runs against each target.** Adding a target in the dashboard (**`n`**) now asks
  what to run: **Native checks**, **Deep** (native + the Docker recon set — whatweb, wafw00f,
  testssl, nmap, nuclei), or **Pick tools…** (native + specific tools). Tool findings merge into
  the live counters and the combined report, and each row's **SCAN** column shows the chosen
  profile. For scripted runs, `temple-guard monitor <urls…> --deep` / `--tools nmap,nuclei`
  preload a profile onto the given targets.
- **`doctor` preflight.** `temple-guard doctor` verifies Docker is running and lists which tool
  images are present; `temple-guard doctor --pull` fetches the missing ones up front so the first
  deep scan runs immediately (also on the interactive menu). Nothing to build or vendor — the
  images are public and pulled on demand.
### Fixed
- **Arrow keys no longer quit the monitor.** The key reader used buffered `stdin.read(1)`, so an
  arrow's `ESC [ A` burst got split — the lone `ESC` read as "quit" while `[A` sat in Python's
  buffer where `select()` couldn't see it. It now reads the raw fd (`os.read`) and matches the
  whole sequence at once — both `ESC [ A` and application-cursor `ESC O A`; every other escape
  sequence is ignored, never a quit.
- **`s` / `r` always give feedback.** Pressing `s` on a scan that already finished (or `r` on one
  still running) now logs a clear reason instead of doing nothing silently.
- **`s` actually halts a running scan.** On a **deep** scan, stop used to only apply *between*
  tools — a long `testssl` / `nuclei` / `nmap` kept running for minutes. The tool runner is now
  cancellable: it names its container and `docker kill`s it through the daemon (a tool running as
  the container's PID 1 ignores a forwarded `SIGTERM`), so the scan stops in ~1–2s and leaves no
  container behind.
- **Leaving the monitor is now gated.** Quitting asks **"Quit the monitor?"** first — and warns
  when scans are still running (defaulting to *stay*). The only quit keys are **`Esc`** and
  **`Ctrl+C`**; **`q`** no longer exits (it hints to use Esc). A second `Ctrl+C` at the prompt
  force-quits.
- **Add-target prompt is now visible.** Pressing **`n`** (or **`w`**) opened a line prompt
  while the dashboard's single-key reader was still holding the terminal in no-echo `cbreak`
  mode *and* consuming stdin — so the target you typed was invisible and stray keystrokes
  could trigger dashboard actions. The reader now steps aside (restoring cooked/echo mode) for
  the duration of any prompt, then resumes single-key control.
- **Single-bladed saber.** The monitor's little lightsaber mark was a double-bladed saberstaff;
  it's now a single gold blade extending from a steel hilt.

## [0.6.0] — 2026-07-16
### Added
- **Live monitor** — `temple-guard monitor <urls…>` (or **Monitor** in the interactive menu)
  opens a **btop-style dashboard** that runs **several scans at once** and shows them live:
  animated progress bars, a findings-severity meter, an activity sparkline, a status panel,
  and a live log stream. **Stop / restart** individual scans and **queue new** ones (`s` /
  `r` / `n`) without leaving; **↑↓/jk** to select, **q / Esc** to quit. Real data only — each
  row is an actual `checks.scan()` in its own thread (`monitor.py`). No TTY → headless run +
  summary (for pipes / CI). No new dependency (built on Rich `Live`).

## [0.5.4] — 2026-07-16
### Changed
- **Clearer, consistent menu navigation.** Every interactive prompt now spells out its keys,
  and the two were swapped to match expectations: **Esc = back** (cancel the current
  menu/step) and **Ctrl+C = quit** (clean exit from anywhere). Menus show a visible
  **← Back** entry, the guided prompts take **`b` = back** (blank = back on text prompts), and
  the fuzzy picker footer reads "Esc = back · Ctrl+C = quit".

## [0.5.3] — 2026-07-16
### Fixed
- **Guided-tool target: validation + a clearer prompt.** The target prompt showed a dim
  "(your own / authorized)" reminder that read like a placeholder — so a stray "your own"
  could be entered and silently scanned as two bogus hosts. It's now a **format example**
  ("e.g. https://beta.example.com"), input is **validated** (empty / multi-token targets are
  rejected and re-asked) and **normalized** (a URL pasted into a host prompt reduces to the
  host; a bare domain gets `https://`, while `localhost` / `host:port` gets `http://`), and a
  **"Run this?"** confirmation now precedes execution. Same clearer prompt in the scan flow.

## [0.5.2] — 2026-07-16
### Changed
- **Guided "Run a tool" flow.** In the interactive menu, picking a tool now shows a brief
  explainer (what it is + its risks) and then asks the common options as **questions**
  (numbered choices / yes-no — aggression, ports, severity, timing…), assembling the command
  for you and showing it before it runs — instead of asking you to type raw flags. The
  `temple-guard tool <name>` CLI still prints the full flags reference for raw/scripted use.

## [0.5.1] — 2026-07-16
### Added
- **Fuzzy, type-to-filter menu** (fzy / fzf-style) for the interactive session — start
  typing to narrow the options, ↑↓ to move, enter to select (via InquirerPy). Falls back
  to the classic numbered menu when there's no fuzzy-capable TTY, or with `TG_NO_FUZZY=1`.
- **Dry-run for every action.** The interactive menu gained a **Dry-run toggle** that makes
  *all* actions preview-only, and `--dry-run` now works on the Docker actions too:
  `temple-guard tool <name> --dry-run <args>` and `temple-guard shell --dry-run` print the
  exact `docker run …` command and run nothing; `scan --deep --dry-run` lists each tool's
  command as well. Previews spin up **zero** containers (host-IP resolution is skipped).
### Fixed
- whatweb tech-fingerprint parsing dropped bare country-code / `RESERVED` fragments (a lone
  "ZZ") from the summary — minimal-tech apps now read "No tech stack fingerprinted" cleanly.
### Docs
- README now shows terminal screenshots (menu, scan, deep scan, tool explainer, dry-run),
  captured from real runs against a local app.

## [0.5.0] — 2026-07-16
### Added
- **Self-update** — `temple-guard update` pulls the newest source from the git repo and
  reinstalls (pipx- and pip-aware, and editable-aware); `temple-guard update --check` just
  reports whether a newer version exists. Added an **Update** entry to the interactive menu.
- **Three more Docker recon tools**, each merged into the same unified report: **`nikto`**
  (web-server misconfig / dangerous files / admin paths / outdated software), **`wafw00f`**
  (WAF/CDN fingerprint — flags apps with *no* WAF in front), and **`whatweb`** (tech-stack +
  software-version disclosure). `--deep` now runs the quick recon set
  (`whatweb, wafw00f, testssl, nmap, nuclei`); `nikto` is opt-in via `--tools nikto`
  because it's slow and noisy.
- **Per-tool explainers** — picking a tool (in the interactive menu, or `temple-guard tool
  <name>` with no arguments) now shows a panel with **what it is, how to use it, its risks,
  and the key flags** — including nmap's full usual argument set.
### Fixed
- **Docker → host connectivity on Docker Desktop.** `host.docker.internal` dual-stacks to an
  unreachable IPv6 (`fdXX::254`) alongside the good IPv4, so IPv6-preferring tools
  (whatweb/wafw00f) failed with "Network unreachable". temple-guard now resolves and pins the
  host's **numeric IPv4** for `localhost` / `host.docker.internal` targets.

## [0.4.1] — 2026-07-16
### Added
- **`temple-guard tool <name> [args…]`** — run a Docker tool with its **full argument set**,
  e.g. `temple-guard tool nmap -sV -p 1-1000 host.docker.internal` (or `tool nmap -h` for the
  tool's own help). `localhost` is auto-remapped to `host.docker.internal`. Added a
  **"Run a tool"** entry to the interactive menu.
### Fixed
- Corrected swapped description/category fields in the tool registry.

## [0.4.0] — 2026-07-16
### Added
- **Email-auth check (SPF / DMARC)** — a native DNS check (dnspython) for the target
  domain's SPF and DMARC posture (skipped for localhost / IPs). Closes the last easy
  Blue-team gap.
- **Docker-backed defensive tools** — `--deep` (or `--tools testssl,nmap,nuclei`) spins up
  each tool's own container, runs it against the target, and **merges its findings into the
  same report**: `testssl` (TLS posture), `nmap` (service / port exposure), `nuclei`
  (misconfiguration + exposure templates). `localhost` is reached via `host.docker.internal`;
  skipped cleanly when Docker isn't available.
- **`temple-guard shell`** — drop into an interactive Kali container shell.
- Interactive menu gained **Deep scan** and **Kali shell** entries.

## [0.3.3] — 2026-07-16
### Added
- **Animated progress bar** while a scan runs — a live bar fills as the checks complete
  (spinner · current check · count · elapsed time). With `-v`, each check and finding
  streams above the bar as it's discovered.

## [0.3.2] — 2026-07-16
### Added
- **Menu entry point** — bare `temple-guard` (interactive) now opens a menu of actions
  (Scan / Dry run / What it checks / Help) instead of jumping straight to a URL prompt.
### Changed
- **Redesigned the terminal banner emblem** to read more like the Temple Guard shield +
  hooded-mask + saberstaff logo.
- Install docs: added a per-OS **"command not found" / PATH** note (`pipx ensurepath` +
  restart your shell).

## [0.3.1] — 2026-07-16
### Added
- The **HTML report now embeds the Temple Guard shield logo** — in the nav bar and the banner.
### Fixed
- **Sensitive-path false positives on catch-all / SPA servers**: temple-guard probes a bogus
  path first and suppresses `/.git/config`, `/.env`, etc. findings when the server 200s
  everything (or serves an HTML page in place of the config file).

## [0.3.0] — 2026-07-16
### Added
- **CLI HTML report** (`temple-guard scan <url> -o report.html`) — a self-contained,
  **collapsible** report styled like the platform's: navy banner, risk-severity cards,
  per-finding cards (evidence + remediation), **Expand / Collapse all**, and a
  **Print / Save PDF** button that prints to a polished PDF straight from the browser.
- `-o / --report` now recognizes `.html` alongside `.pdf` / `.md` / `.json`, and the
  interactive session offers HTML as a save format.

## [0.2.0] — 2026-07-16
### Added
- **Verbose live output** (`-v` / `--verbose`) — streams each check and every finding
  as it runs, in colour.
- **Interactive session** — bare `temple-guard` (or `temple-guard interactive`) lists
  every check, then walks you through the target and options (dry-run, verbose, save format).
- **PDF report** (`-o report.pdf`) — a clean, branded PDF via `fpdf2` (self-contained,
  no browser needed).
### Changed
- `-o / --report` picks the output format from the file extension (`.pdf` / `.md` / `.json`).

## [0.1.0] — 2026-07-15
### Added
- Initial `temple-guard` CLI — bounded, read-only self-scan (security headers, TLS /
  certificate, cookie flags, info disclosure, exposed sensitive paths, risky HTTP methods)
  with a colourful terminal report, `--dry-run`, markdown output, and CI-friendly exit codes.
- Public release of the authorized penetration-testing orchestration platform.
