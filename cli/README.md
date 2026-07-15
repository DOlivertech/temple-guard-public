# temple-guard (CLI)

Scan a web app **you own** and get a remediation report — right in your terminal.
Bounded, read-only checks (security headers, TLS/cert, cookie flags, info
disclosure, exposed sensitive files, risky HTTP methods). Nothing here exploits,
floods, or brute-forces.

```bash
pipx install temple-guard          # or: pip install temple-guard
temple-guard scan https://your-app.example.com
temple-guard scan https://your-app.example.com --dry-run     # show checks, send nothing
temple-guard scan https://your-app.example.com -o report.md  # write a markdown report
```

> Authorized use only — run this against applications you own or have explicit
> written permission to test.
