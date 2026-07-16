# Changelog

All notable changes to Temple Guard and the `temple-guard` CLI are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/); releases are tagged
`vMAJOR.MINOR.PATCH` and published on GitHub Releases. **When cutting a release, use
that version's section below as the release notes** (see [AGENTS.md](AGENTS.md) → Releasing).

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
- Sanitized public snapshot of the authorized penetration-testing orchestration platform.
