# temple-guard (CLI)

Scan a web app **you own** and get a remediation report — right in your terminal.
Bounded, read-only native checks (security headers, TLS/certificate, cookie flags, info
disclosure, exposed sensitive files, risky HTTP methods, SPF/DMARC email posture) — none
of which exploit, flood, or brute-force. Optionally, with **Docker**, it also runs real
defensive tools (`testssl`, `nmap`, `nuclei`, `nikto`, `wafw00f`, `whatweb`) and merges
their findings into the same report.

## Install

`temple-guard` is a self-contained Python CLI (Python 3.9+). The cleanest install is
with **[pipx](https://pipx.pypa.io/)** — it puts the tool in its own isolated
environment and on your PATH. Grab `temple_guard-<version>-py3-none-any.whl` from the
repo's **Releases**, then follow your platform:

### macOS
```bash
brew install pipx            # if you don't already have pipx
pipx ensurepath              # once — then open a new terminal

pipx install ./temple_guard-0.5.1-py3-none-any.whl
```

### Windows (PowerShell)
```powershell
py -m pip install --user pipx    # if you don't already have pipx
py -m pipx ensurepath            # once — then open a new terminal

pipx install .\temple_guard-0.5.1-py3-none-any.whl
```

### Linux / other
```bash
python3 -m pip install --user pipx && python3 -m pipx ensurepath
pipx install ./temple_guard-0.5.1-py3-none-any.whl
```

Once it's published to PyPI you'll be able to skip the wheel and just
`pipx install temple-guard`. Prefer not to use pipx? `pip install
./temple_guard-0.5.1-py3-none-any.whl` works too (ideally inside a virtualenv).

**Manage it:** `pipx uninstall temple-guard` · to **update**, see below.

## Updating

`temple-guard` isn't on PyPI, so `pipx upgrade` has nothing to fetch — the CLI updates
**itself from the git repo**:
```bash
temple-guard update            # pull the newest source and reinstall
temple-guard update --check    # just report whether a newer version exists
```
If you're running it from a local checkout it `git pull`s and reinstalls that; otherwise it
clones the public repo to `~/.local/share/temple-guard/repo`. (You can always reinstall a
wheel by hand instead: `pipx install --force ./temple_guard-<version>-py3-none-any.whl`.)

### `temple-guard: command not found`?
pipx installs the command into a user bin directory that must be on your **PATH**:
`~/.local/bin` (macOS / Linux) or `%USERPROFILE%\.local\bin` / the Python user `Scripts`
dir (Windows). `pipx ensurepath` (above) adds it — but you must then **open a new
terminal** (or `source ~/.zshrc` / `~/.bashrc`) for the change to take effect. Verify with
`pipx list` and `temple-guard version`.
> On zsh with `AUTO_CD` (e.g. oh-my-zsh), if PATH still isn't set, typing bare
> `temple-guard` may just `cd` into a same-named folder — that's the PATH, not the tool.

## Usage

**Interactive** — a colourful session with a **fuzzy, type-to-filter menu** (fzy/fzf-style:
start typing to narrow the options, ↑↓ to move, enter to pick). It walks you through the
target and options (verbose, save format), and a **Dry-run toggle** makes *every* action
preview-only:
```bash
temple-guard                 # bare command launches it — or: temple-guard interactive
```
> Prefer the classic numbered menu (no fuzzy)? Set `TG_NO_FUZZY=1`.

**Direct** — scan straight away:
```bash
temple-guard scan https://your-app.example.com                # colourful report
temple-guard scan https://your-app.example.com -v             # verbose: show each check + finding live
temple-guard scan https://your-app.example.com --dry-run      # list the checks, send nothing
temple-guard scan https://your-app.example.com -o report.html # collapsible HTML report (see formats below)
temple-guard scan https://your-app.example.com --json         # machine-readable findings
temple-guard version
```

`-o / --report` picks the format from the file **extension**:

| Extension | Output |
|---|---|
| `.html` | A **collapsible** report styled like the platform's — Expand/Collapse-all, and **Print → PDF** for a polished PDF |
| `.pdf`  | A clean, branded PDF (self-contained — no browser needed) |
| `.md`   | Markdown (table + evidence) |
| `.json` | Machine-readable findings |

`-v / --verbose` streams each check and every finding as it happens. The scan exits
non-zero when a **HIGH** finding is present, so it slots straight into CI.

## Deep scan — Docker tools (optional)

With **Docker** running, add real tool containers to any scan; their findings merge into
the same unified report:
```bash
temple-guard scan https://your-app.example.com --deep              # whatweb + wafw00f + testssl + nmap + nuclei
temple-guard scan https://your-app.example.com --tools nmap,nikto  # only the ones you name
```

| Tool | Image | What it adds |
|---|---|---|
| `whatweb` | `secsi/whatweb` | tech-stack fingerprint — server, framework, CMS, JS libs **+ versions** |
| `wafw00f` | `secsi/wafw00f` | whether a WAF/CDN fronts the app, and which one |
| `testssl` | `drwetter/testssl.sh` | deep TLS / crypto posture (protocols, ciphers, cert) |
| `nmap` | `instrumentisto/nmap` | open ports / exposed services **on the host** |
| `nuclei` | `projectdiscovery/nuclei` | misconfiguration + exposure templates (first run downloads templates) |
| `nikto` | `frapsoft/nikto` | web-server misconfig, dangerous files, admin paths, outdated software |

`--deep` runs the quick recon set (`whatweb, wafw00f, testssl, nmap, nuclei`); **`nikto` is
opt-in** via `--tools nikto` because it's slow and noisy. A `localhost` target is reached
from the container via the host's numeric IPv4 (auto-remapped). Heads-up: **`nmap` scans the
host's ports** (not just the one app), so it surfaces things like an exposed database. If
Docker isn't available the tools are skipped and the native checks still run.

### Run a tool with your own flags
`--deep` uses each tool's default command. To drive a tool with **its full argument set**,
use `temple-guard tool` — everything after the tool name is passed straight through:
```bash
temple-guard tool                       # list the tools
temple-guard tool nmap                  # explainer: what it is · how to use it · risks · flags
temple-guard tool nmap -sV -p 1-1000 host.docker.internal
temple-guard tool nmap -h               # nmap's own help / all options
temple-guard tool nikto -h http://host.docker.internal:8081
temple-guard tool wafw00f https://example.com
temple-guard tool whatweb https://example.com
temple-guard tool nuclei -u https://example.com -tags cve,exposure
```
Run `temple-guard tool <name>` with **no arguments** for a full explainer (what it is, how
to use it, its risks, and the key flags). `localhost` / `127.0.0.1` / `host.docker.internal`
is auto-remapped to the host's numeric IPv4 so the container reliably reaches your app. It
prints the tool's raw output. (Also available as "Run a tool" in the interactive menu.)

## Dry run — preview any action

**Every** action has a dry run: it prints exactly what *would* happen and runs nothing.
```bash
temple-guard scan <url> --dry-run          # list the native checks (sends nothing)
temple-guard scan <url> --deep --dry-run   # + the exact docker command for each tool
temple-guard tool nmap --dry-run <args>    # the docker command a tool run would execute
temple-guard shell --dry-run               # the shell container command
```
In the interactive menu, flip **Dry-run: ON** and every choice becomes preview-only.

## Interactive Kali shell
```bash
temple-guard shell             # drop into a Kali container (first run pulls ~1 GB); 'exit' to leave
temple-guard shell --dry-run   # just print the container command; start nothing
```

> ⚠️ **Authorized use only** — run this against applications you own or have explicit
> written permission to test.
