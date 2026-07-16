# temple-guard (CLI)

Scan a web app **you own** and get a remediation report — right in your terminal.
Bounded, read-only checks (security headers, TLS/certificate, cookie flags, info
disclosure, exposed sensitive files, risky HTTP methods). Nothing here exploits,
floods, or brute-forces — one `GET` per check, plus a single `OPTIONS`.

## Install

`temple-guard` is a self-contained Python CLI (Python 3.9+). The cleanest install is
with **[pipx](https://pipx.pypa.io/)** — it puts the tool in its own isolated
environment and on your PATH. Grab `temple_guard-<version>-py3-none-any.whl` from the
repo's **Releases**, then follow your platform:

### macOS
```bash
brew install pipx            # if you don't already have pipx
pipx ensurepath              # once — then open a new terminal

pipx install ./temple_guard-0.1.0-py3-none-any.whl
```

### Windows (PowerShell)
```powershell
py -m pip install --user pipx    # if you don't already have pipx
py -m pipx ensurepath            # once — then open a new terminal

pipx install .\temple_guard-0.1.0-py3-none-any.whl
```

### Linux / other
```bash
python3 -m pip install --user pipx && python3 -m pipx ensurepath
pipx install ./temple_guard-0.1.0-py3-none-any.whl
```

Once it's published to PyPI you'll be able to skip the wheel and just
`pipx install temple-guard`. Prefer not to use pipx? `pip install
./temple_guard-0.1.0-py3-none-any.whl` works too (ideally inside a virtualenv).

**Manage it:** `pipx upgrade temple-guard` · `pipx uninstall temple-guard`.

## Usage
```bash
temple-guard scan https://your-app.example.com               # colourful terminal report
temple-guard scan https://your-app.example.com --dry-run     # list the checks, send nothing
temple-guard scan https://your-app.example.com -o report.md  # write a markdown report
temple-guard scan https://your-app.example.com --json        # machine-readable findings
temple-guard version
```
It exits non-zero when a **HIGH** finding is present, so it slots straight into CI.

> ⚠️ **Authorized use only** — run this against applications you own or have explicit
> written permission to test.
