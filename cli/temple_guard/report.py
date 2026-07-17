"""Rendering — a colourful terminal report, live progress, markdown / HTML / PDF export."""
from __future__ import annotations

import base64
import html as _html
from datetime import datetime, timezone

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

from .checks import ScanResult

# brand chrome = blues + purples; severities keep their conventional colours
PURPLE = "#a855f7"
BLUE = "#38bdf8"
SEV_STYLE = {"high": "bold #f87171", "medium": "bold #fbbf24",
             "low": "#38bdf8", "info": "#94a3b8"}
SEV_LABEL = {"high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}
CAT_ICON = {"transport": "🔒", "headers": "📋", "cookies": "🍪",
            "disclosure": "📢", "exposure": "📂", "methods": "🔧",
            "email": "📧", "tls": "🔐", "ports": "🔌", "templates": "🎯",
            "web": "🌐", "waf": "🛡️", "tech": "🧩"}


def _summary_bar(result: ScanResult) -> Text:
    counts = result.by_severity
    t = Text()
    for sev in ("high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        t.append(f" {SEV_LABEL[sev]} {n} ", style=f"{SEV_STYLE[sev]} reverse" if n else "dim")
        t.append(" ")
    return t


def make_progress_reporter(console: Console):
    """Return an `on_event` callback for `checks.scan` that prints live, colourful
    per-check progress — what's running, and each finding as it surfaces."""
    def on_event(kind: str, **k) -> None:
        if kind == "step":
            icon = CAT_ICON.get(k.get("category"), "•")
            console.print(Text.assemble(
                ("  ▸ ", f"bold {BLUE}"),
                (f"{icon} {k['name']}", "bold white"),
                (f"   {k['desc']}", "dim")))
        elif kind == "finding":
            f = k["finding"]
            colour = SEV_STYLE[f.severity].split()[-1]
            console.print(Text.assemble(
                ("       ", ""),
                (f" {SEV_LABEL[f.severity]} ", f"{SEV_STYLE[f.severity]} reverse"),
                ("  ", ""), (f.title, colour)))
        elif kind == "clean":
            console.print(Text.assemble(("       ✓ ", "bold #4ade80"), ("clean", "#4ade80")))
        elif kind == "unreachable":
            console.print(Text.assemble(("  ✗ ", "bold #f87171"),
                          (f"could not reach {k['url']} — {k['error']}", "#f87171")))
    return on_event


def render(result: ScanResult, console: Console) -> None:
    title = Text.assemble(("temple-guard", f"bold {PURPLE}"), ("  ·  self-scan report", f"{BLUE}"))
    if not result.reachable:
        console.print(Panel(f"[bold #f87171]Could not reach[/] {result.url}\n[dim]{result.error}[/]",
                            title=title, border_style="#f87171"))
        return

    header = Group(
        Text.assemble(("Target  ", "dim"), (result.url, f"bold {BLUE}")),
        Text.assemble(("Status  ", "dim"), (str(result.status), "white"),
                      ("    Server  ", "dim"), (result.server or "—", "white")),
        Text.assemble(("Result  ", "dim"), (f"{len(result.findings)} findings   ", "white"), _summary_bar(result)),
    )
    console.print(Panel(header, title=title, border_style=PURPLE, padding=(1, 2)))

    if not result.findings:
        console.print(Panel("[bold #4ade80]✓ No issues found — nice.[/]", border_style="#4ade80"))
        return

    for f in result.findings:
        icon = CAT_ICON.get(f.category, "•")
        head = Text.assemble((f" {SEV_LABEL[f.severity]} ", f"{SEV_STYLE[f.severity]} reverse"),
                             ("  ", ""), (f"{icon} {f.title}", "bold white"))
        body = Group(
            Text.assemble(("evidence   ", "dim"), (f.evidence, "#cbd5e1")),
            Text.assemble(("remediate  ", f"dim {BLUE}"), (f.remediation, "#e2e8f0")),
        )
        console.print(Panel(body, title=head, title_align="left",
                            border_style=SEV_STYLE[f.severity].split()[-1], padding=(0, 1)))


def to_markdown(result: ScanResult) -> str:
    c = result.by_severity
    lines = [
        "# temple-guard — self-scan report",
        "",
        f"**Target:** `{result.url}`  ",
        f"**Status:** {result.status}  ·  **Server:** {result.server or '—'}  ",
        f"**Findings:** {len(result.findings)} "
        f"(🔴 {c['high']} high · 🟠 {c['medium']} medium · 🔵 {c['low']} low · ⚪ {c['info']} info)",
        "",
    ]
    if not result.reachable:
        return "\n".join(lines + [f"> Could not reach the target: {result.error}"])
    if not result.findings:
        return "\n".join(lines + ["✓ No issues found."])
    lines += ["| Severity | Finding | Remediation |", "|---|---|---|"]
    emoji = {"high": "🔴 High", "medium": "🟠 Medium", "low": "🔵 Low", "info": "⚪ Info"}
    for f in result.findings:
        rem = f.remediation.replace("|", "\\|")
        ttl = f.title.replace("|", "\\|")
        lines.append(f"| {emoji[f.severity]} | {ttl} | {rem} |")
    lines += ["", "<details><summary>Evidence</summary>", ""]
    for f in result.findings:
        lines.append(f"- **{f.title}** — `{f.evidence}`")
    lines += ["", "</details>", "",
              "_Generated by temple-guard — run only against apps you own or are authorized to test._"]
    return "\n".join(lines)


# --- PDF export -------------------------------------------------------------
_PDF_REPL = {"→": "->", "…": "...", "≥": ">=", "≤": "<=", "•": "-", "·": "-",
             "—": "-", "–": "-", "’": "'", "‘": "'", "“": '"', "”": '"',
             "🔴": "", "🟠": "", "🔵": "", "⚪": "", "✓": ""}


def _pt(s: str) -> str:
    """Down-convert to latin-1 so fpdf2 core fonts render it (no font files needed)."""
    for k, v in _PDF_REPL.items():
        s = s.replace(k, v)
    return s.encode("latin-1", "ignore").decode("latin-1")


def to_pdf(result: ScanResult, path: str) -> None:
    """Render a clean, branded PDF report. Pure-Python (fpdf2) — no browser needed."""
    from fpdf import FPDF  # lazy: only needed when a PDF is requested

    NAVY, PURP, BLU = (11, 17, 32), (168, 85, 247), (56, 189, 248)
    WHITE, DARK, GRAY, LIGHT = (255, 255, 255), (30, 41, 59), (100, 116, 139), (226, 232, 240)
    SEV = {"high": (248, 113, 113), "medium": (251, 191, 36),
           "low": (56, 189, 248), "info": (148, 163, 184)}

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    # header band
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 30, style="F")
    pdf.set_xy(14, 8)
    pdf.set_text_color(*PURP)
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 9, "TEMPLE GUARD")
    pdf.set_xy(14, 19)
    pdf.set_text_color(*BLU)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 5, "self-scan report")
    pdf.set_xy(pdf.l_margin, 38)

    if not result.reachable:
        pdf.set_text_color(*SEV["high"])
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 7, _pt(f"Could not reach {result.url}\n{result.error}"))
        pdf.output(path)
        return

    # meta
    pdf.set_text_color(*DARK)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 7, _pt(f"Target:  {result.url}"))
    pdf.set_text_color(*GRAY)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 5, _pt(f"Status {result.status}    Server {result.server or '-'}    "
                             f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}"))
    pdf.ln(2)

    # severity summary pills
    c = result.by_severity
    pdf.set_font("Helvetica", "B", 9)
    x, y = pdf.l_margin, pdf.get_y()
    for sev in ("high", "medium", "low", "info"):
        label = f"{SEV_LABEL[sev]} {c.get(sev, 0)}"
        w = pdf.get_string_width(label) + 8
        pdf.set_fill_color(*SEV[sev])
        pdf.set_text_color(*WHITE)
        pdf.set_xy(x, y)
        pdf.cell(w, 7, label, align="C", fill=True)
        x += w + 3
    pdf.set_xy(pdf.l_margin, y + 11)
    pdf.set_draw_color(*LIGHT)
    pdf.line(pdf.l_margin, pdf.get_y(), 210 - pdf.r_margin, pdf.get_y())
    pdf.ln(4)
    pdf.set_x(pdf.l_margin)

    if not result.findings:
        pdf.set_text_color(74, 222, 128)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "No issues found.")
        pdf.output(path)
        return

    pdf.set_text_color(*DARK)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 8, "Findings & remediation")
    pdf.ln(1)

    for f in result.findings:
        y = pdf.get_y()
        pdf.set_font("Helvetica", "B", 8)
        lbl = SEV_LABEL[f.severity]
        w = pdf.get_string_width(lbl) + 6
        pdf.set_fill_color(*SEV[f.severity])
        pdf.set_text_color(*WHITE)
        pdf.set_xy(pdf.l_margin, y)
        pdf.cell(w, 6, lbl, align="C", fill=True)
        pdf.set_text_color(*DARK)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_xy(pdf.l_margin + w + 3, y)
        pdf.multi_cell(0, 6, _pt(f.title))
        pdf.set_x(pdf.l_margin)
        pdf.set_text_color(*GRAY)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, _pt(f"Evidence:    {f.evidence}"))
        pdf.set_x(pdf.l_margin)
        pdf.set_text_color(*DARK)
        pdf.multi_cell(0, 5, _pt(f"Remediate:  {f.remediation}"))
        pdf.ln(3)

    pdf.set_xy(pdf.l_margin, -14)
    pdf.set_text_color(*GRAY)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(0, 5, _pt("Generated by temple-guard - run only against apps you own or are authorized to test."),
             align="C")
    pdf.output(path)


# --- HTML export (collapsible, styled like the platform report) -------------
_HTML_CSS = r"""
  body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#111827;margin:0;background:#f9fafb}
  .rnav{position:sticky;top:0;z-index:10;display:flex;gap:10px;align-items:center;background:#0b1120;color:#cbd5e1;padding:10px 24px;font-size:13px}
  .rnav .bmini{font-weight:700;color:#a855f7;letter-spacing:1px}
  .rnav button{color:#cbd5e1;background:transparent;border:1px solid #334155;border-radius:8px;padding:6px 12px;font-size:13px;cursor:pointer}
  .rnav button:hover{border-color:#38bdf8;color:#fff}
  .rnav .pdf{background:#38bdf8;color:#0b1120;border-color:#38bdf8;font-weight:600}
  .rnav .spacer{flex:1}
  .rnav .logo{height:20px;width:20px;vertical-align:middle}
  .banner .bhead{display:flex;align-items:center;gap:16px}
  .banner .blogo{height:54px;width:54px;flex:0 0 auto}
  .banner{background:#0f172a;color:#fff;padding:26px 48px}
  .banner .brand{letter-spacing:2px;font-size:12px;color:#93c5fd;text-transform:uppercase}
  .banner h1{font-size:23px;margin:6px 0 4px;color:#fff;word-break:break-all}
  .banner .bmeta{color:#cbd5e1;font-size:13px}
  .page{max-width:900px;margin:0 auto;padding:36px 48px;background:#fff}
  h2{font-size:18px;border-bottom:2px solid #e5e7eb;padding-bottom:6px;margin-top:30px}
  .muted{color:#6b7280}
  .summary{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}
  .card{border:1px solid #e5e7eb;border-radius:10px;padding:12px 18px;min-width:84px;text-align:center}
  .card .n{font-size:26px;font-weight:700}
  .card .cap{text-transform:uppercase;font-size:11px;color:#6b7280}
  .sev{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-size:12px;font-weight:600;text-transform:uppercase}
  details.finding{border:1px solid #e5e7eb;border-left:5px solid #ccc;border-radius:8px;margin:14px 0}
  details.finding>summary{list-style:none;cursor:pointer;padding:14px 16px;display:flex;align-items:center;gap:10px}
  details.finding>summary::-webkit-details-marker{display:none}
  details.finding>summary::before{content:"\25B8";color:#9ca3af}
  details.finding[open]>summary::before{content:"\25BE"}
  details.finding .fh{flex:1;font-size:15px;font-weight:600}
  details.finding .fbody{padding:0 16px 16px}
  .kv{margin:10px 0 4px}.kv b{color:#374151;font-size:13px}
  pre{background:#f3f4f6;padding:10px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-all;margin:4px 0}
  .rem{background:#ecfdf5;border:1px solid #a7f3d0;padding:10px 12px;border-radius:6px}
  .ok{color:#059669;font-weight:600;font-size:16px}
  .foot{color:#6b7280;font-size:12px;margin-top:30px}
  @media print{body{background:#fff}.page{padding:0}.rnav{display:none}}
"""

_LOGO_SVG = r'''<svg width="240" height="240" viewBox="0 0 240 240" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Temple Guard">
  <defs>
    <linearGradient id="tgShield" x1="0" y1="0" x2="0" y2="240" gradientUnits="userSpaceOnUse"><stop stop-color="#16233f"/><stop offset="1" stop-color="#0a1120"/></linearGradient>
    <linearGradient id="tgMask" x1="0" y1="40" x2="0" y2="210" gradientUnits="userSpaceOnUse"><stop stop-color="#f6e7c1"/><stop offset="0.55" stop-color="#d9c290"/><stop offset="1" stop-color="#a3884f"/></linearGradient>
    <linearGradient id="tgBlade" x1="0" y1="0" x2="0" y2="240" gradientUnits="userSpaceOnUse"><stop stop-color="#fff7cc"/><stop offset="0.5" stop-color="#ffd60a"/><stop offset="1" stop-color="#f59e0b"/></linearGradient>
    <radialGradient id="tgCore" cx="0.5" cy="0.5" r="0.5"><stop stop-color="#fffbe6"/><stop offset="1" stop-color="#ffd60a"/></radialGradient>
    <filter id="tgGlow" x="-60%" y="-30%" width="220%" height="160%"><feGaussianBlur stdDeviation="5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  </defs>
  <path d="M120 8 L210 40 V120 C210 178 172 214 120 232 C68 214 30 178 30 120 V40 Z" fill="url(#tgShield)" stroke="#38bdf8" stroke-opacity="0.55" stroke-width="3"/>
  <path d="M120 8 L210 40 V120 C210 178 172 214 120 232 C68 214 30 178 30 120 V40 Z" fill="none" stroke="#0ea5e9" stroke-opacity="0.12" stroke-width="9"/>
  <g filter="url(#tgGlow)"><rect x="116" y="22" width="8" height="64" rx="4" fill="url(#tgBlade)"/><rect x="116" y="170" width="8" height="48" rx="4" fill="url(#tgBlade)"/></g>
  <rect x="113" y="92" width="14" height="58" rx="3" fill="#1f2937" stroke="#475569" stroke-width="1.5"/>
  <rect x="111" y="100" width="18" height="5" rx="2" fill="#64748b"/><rect x="111" y="138" width="18" height="5" rx="2" fill="#64748b"/>
  <g>
    <path d="M120 44 C150 44 166 66 166 104 C166 150 146 184 120 198 C94 184 74 150 74 104 C74 66 90 44 120 44 Z" fill="url(#tgMask)" stroke="#7a652f" stroke-width="2"/>
    <path d="M120 48 L120 150" stroke="#8a7338" stroke-width="2.5" stroke-opacity="0.6"/>
    <path d="M92 96 C104 88 116 88 120 94 C124 88 136 88 148 96" fill="none" stroke="#7a652f" stroke-width="3" stroke-linecap="round"/>
    <path d="M96 104 L114 110 L114 116 L96 110 Z" fill="#1a1205"/><path d="M144 104 L126 110 L126 116 L144 110 Z" fill="#1a1205"/>
    <path d="M120 120 L131 156 C131 170 109 170 109 156 Z" fill="#caa75f" stroke="#7a652f" stroke-width="1.5"/>
  </g>
  <circle cx="120" cy="186" r="5" fill="url(#tgCore)" filter="url(#tgGlow)"/>
</svg>'''


def _logo_uri() -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(_LOGO_SVG.strip().encode("utf-8")).decode("ascii")


_HTML_NAV = ('<div class="rnav"><img class="logo" src="__LOGO__" alt="Temple Guard">'
             '<span class="bmini">temple-guard</span>'
             '<span class="spacer"></span>'
             "<button onclick=\"document.querySelectorAll('details.finding').forEach(function(d){d.open=true})\">Expand all</button>"
             "<button onclick=\"document.querySelectorAll('details.finding').forEach(function(d){d.open=false})\">Collapse all</button>"
             '<button class="pdf" onclick="window.print()">Print / Save PDF</button></div>')


def to_html(result: ScanResult) -> str:
    """A self-contained, collapsible HTML report — styled like the platform's report,
    and printable to a polished PDF straight from the browser (Print / Save PDF)."""
    colors = {"high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"}
    esc = _html.escape
    c = result.by_severity
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    logo = _logo_uri()
    nav = _HTML_NAV.replace("__LOGO__", logo)

    banner = (f'<div class="banner"><div class="bhead">'
              f'<img class="blogo" src="{logo}" alt="Temple Guard">'
              f'<div><div class="brand">Temple Guard &middot; Self-Scan Report</div>'
              f'<h1>{esc(result.url)}</h1>'
              f'<div class="bmeta">Status {esc(str(result.status))} &middot; '
              f'Server {esc(result.server or "-")} &middot; {gen}</div></div></div></div>')

    head = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>temple-guard - self-scan report</title><style>' + _HTML_CSS + '</style></head><body>')

    if not result.reachable:
        return (head + nav + banner +
                f'<div class="page"><p class="muted">Could not reach the target.</p>'
                f'<pre>{esc(result.error)}</pre></div></body></html>')

    risk = "".join(
        f'<div class="card" style="border-top:4px solid {colors[s]}">'
        f'<div class="n" style="color:{colors[s]}">{c.get(s, 0)}</div>'
        f'<div class="cap">{s}</div></div>'
        for s in ("high", "medium", "low", "info"))

    if result.findings:
        cards = "\n".join(
            f'<details class="finding" open style="border-left-color:{colors.get(f.severity, "#6b7280")}">'
            f'<summary><span class="fh">{i}. {esc(f.title)}</span>'
            f'<span class="sev" style="background:{colors.get(f.severity, "#6b7280")}">{esc(f.severity)}</span></summary>'
            f'<div class="fbody"><div class="kv"><b>Evidence</b></div><pre>{esc(f.evidence)}</pre>'
            f'<div class="kv"><b>Remediation</b></div><div class="rem">{esc(f.remediation)}</div></div></details>'
            for i, f in enumerate(result.findings, 1))
    else:
        cards = '<p class="ok">&#10003; No issues found &mdash; nice.</p>'

    summary_line = (f'{len(result.findings)} finding(s) from bounded, read-only checks '
                    '(security headers, TLS, cookies, information disclosure, sensitive paths, HTTP methods).')

    return (head + nav + banner +
            '<div class="page"><h2>Summary</h2>'
            f'<p class="muted">{summary_line}</p><div class="summary">{risk}</div>'
            '<h2>Findings &amp; Remediation</h2>' + cards +
            '<p class="foot">Generated by temple-guard &mdash; run only against apps you own or are authorized to test.</p>'
            '</div></body></html>')
