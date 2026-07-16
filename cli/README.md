# temple-guard (CLI)

Scan a web app **you own** and get a remediation report — right in your terminal.
Bounded, read-only native checks (security headers, TLS/certificate, cookie flags, info
disclosure, exposed sensitive files, risky HTTP methods, SPF/DMARC email posture) — none
of which exploit, flood, or brute-force. Optionally, with **Docker**, it also runs real
defensive tools (`testssl`, `nmap`, `nuclei`) and merges their findings into the same report.

## Install

`temple-guard` is a self-contained Python CLI (Python 3.9+). The cleanest install is
with **[pipx](https://pipx.pypa.io/)** — it puts the tool in its own isolated
environment and on your PATH. Grab `temple_guard-<version>-py3-none-any.whl` from the
repo's **Releases**, then follow your platform:

### macOS
```bash
brew install pipx            # if you don't already have pipx
pipx ensurepath              # once — then open a new terminal

pipx install ./temple_guard-0.4.0-py3-none-any.whl
```

### Windows (PowerShell)
```powershell
py -m pip install --user pipx    # if you don't already have pipx
py -m pipx ensurepath            # once — then open a new terminal

pipx install .\temple_guard-0.4.0-py3-none-any.whl
```

### Linux / other
```bash
python3 -m pip install --user pipx && python3 -m pipx ensurepath
pipx install ./temple_guard-0.4.0-py3-none-any.whl
```

Once it's published to PyPI you'll be able to skip the wheel and just
`pipx install temple-guard`. Prefer not to use pipx? `pip install
./temple_guard-0.4.0-py3-none-any.whl` works too (ideally inside a virtualenv).

**Manage it:** `pipx upgrade temple-guard` · `pipx uninstall temple-guard`.

### `temple-guard: command not found`?
pipx installs the command into a user bin directory that must be on your **PATH**:
`~/.local/bin` (macOS / Linux) or `%USERPROFILE%\.local\bin` / the Python user `Scripts`
dir (Windows). `pipx ensurepath` (above) adds it — but you must then **open a new
terminal** (or `source ~/.zshrc` / `~/.bashrc`) for the change to take effect. Verify with
`pipx list` and `temple-guard version`.
> On zsh with `AUTO_CD` (e.g. oh-my-zsh), if PATH still isn't set, typing bare
> `temple-guard` may just `cd` into a same-named folder — that's the PATH, not the tool.

## Usage

**Interactive** — a colourful session that lists every check, then walks you through
the target and options (dry-run, verbose, save format):
```bash
temple-guard                 # bare command launches it — or: temple-guard interactive
```

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
temple-guard scan https://your-app.example.com --deep         # testssl + nmap + nuclei
temple-guard scan https://your-app.example.com --tools nmap   # only the ones you name
```

| Tool | Image | What it adds |
|---|---|---|
| `testssl` | `drwetter/testssl.sh` | deep TLS / crypto posture (protocols, ciphers, cert) |
| `nmap` | `instrumentisto/nmap` | open ports / exposed services **on the host** |
| `nuclei` | `projectdiscovery/nuclei` | misconfiguration + exposure templates (first run downloads templates) |

A `localhost` target is reached from the container via `host.docker.internal`. Heads-up:
**`nmap` scans the host's ports** (not just the one app), so it surfaces things like an
exposed database. If Docker isn't available the tools are skipped and the native checks
still run.

## Interactive Kali shell
```bash
temple-guard shell        # drop into a Kali container (first run pulls ~1 GB); 'exit' to leave
```

> ⚠️ **Authorized use only** — run this against applications you own or have explicit
> written permission to test.
