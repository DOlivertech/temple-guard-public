"""Client-facing report generation.

Produces a self-contained HTML report (printable to PDF from the browser) that
groups findings by severity, includes evidence, and gives remediation steps and
the compliance controls each finding maps to.
"""
from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone

from jinja2 import Environment, select_autoescape
from sqlmodel import Session, select

from ..config import settings
from ..models import Client, Engagement, Finding, ScanRun
from .controls import resolve_refs

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "reports_out")
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLOR = {
    "critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#2563eb", "info": "#6b7280",
}

# autoescape ON: finding title/evidence/description/remediation are raw tool/target
# output and must be HTML-escaped before rendering into the report + Playwright PDF.
_env = Environment(autoescape=select_autoescape(["html", "xml"]))
_TEMPLATE = _env.from_string(r"""
{% macro finding_card(f, idx, expand=True) %}
<details class="finding"{% if expand %} open{% endif %} style="border-left-color:{{ colors[f.severity] }}">
  <summary><span class="fh">{{ idx }}. {{ f.title }}</span>
    <span class="sev" style="background:{{ colors[f.severity] }}">{{ f.severity }}</span></summary>
  <div class="fbody">
    {% if f.cvss %}<div class="kv"><b>CVSS</b> {{ f.cvss }}</div>{% endif %}
    {% set ctrls = controls_by_id.get(f.id) %}
    {% if ctrls %}<div class="kv"><b>Violates</b>
      {% for c in ctrls %}{% if c.url %}<a href="{{ c.url }}" style="color:#2563eb;text-decoration:none">{{ c.framework }} {{ c.control }} ↗</a>{% else %}{{ c.ref }}{% endif %}{% if not loop.last %} · {% endif %}{% endfor %}
    </div>{% endif %}
    {% if f.description %}<p>{{ f.description }}</p>{% endif %}
    {% if f.evidence %}<div class="kv"><b>Evidence</b></div><pre>{{ f.evidence }}</pre>{% endif %}
    {% if f.evidence_path %}<div class="kv"><b>Captured screenshot</b></div>
      <img src="/evidence-img/{{ f.evidence_path }}" alt="evidence"
           style="max-width:100%;border:1px solid #e5e7eb;border-radius:6px;margin:6px 0" />{% endif %}
    <div class="kv"><b>{{ 'Hardening' if f.category == 'redteam' else 'Remediation' }}</b></div>
    <div class="rem">{{ f.remediation }}</div>
  </div>
</details>
{% endmacro %}
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{{ client.name }} — {{ engagement.name }} | Temple Guard Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; color:#111827; margin:0; background:#f9fafb; }
  .page { max-width: 900px; margin: 0 auto; padding: 48px; background:#fff; }
  h1 { font-size: 26px; margin:0 0 4px; }
  h2 { font-size:18px; border-bottom:2px solid #e5e7eb; padding-bottom:6px; margin-top:36px; }
  .muted { color:#6b7280; }
  .sev { display:inline-block; padding:2px 10px; border-radius:999px; color:#fff; font-size:12px; font-weight:600; text-transform:uppercase; }
  .summary { display:flex; gap:12px; flex-wrap:wrap; margin:20px 0; }
  .card { border:1px solid #e5e7eb; border-radius:10px; padding:14px 18px; min-width:90px; text-align:center; }
  .card .n { font-size:28px; font-weight:700; }
  details.finding { border:1px solid #e5e7eb; border-left:5px solid #ccc; border-radius:8px; margin:14px 0; }
  details.finding > summary { list-style:none; cursor:pointer; padding:14px 16px; display:flex; align-items:center; gap:10px; }
  details.finding > summary::-webkit-details-marker { display:none; }
  details.finding > summary::before { content:"\25B8"; color:#9ca3af; }
  details.finding[open] > summary::before { content:"\25BE"; }
  details.finding .fh { flex:1; font-size:16px; font-weight:600; }
  details.finding .fbody { padding:0 16px 16px; }
  .kv { margin:8px 0; }
  .kv b { display:inline-block; width:130px; color:#374151; }
  pre { background:#f3f4f6; padding:10px; border-radius:6px; overflow:auto; font-size:12px; white-space:pre-wrap; }
  .rem { background:#ecfdf5; border:1px solid #a7f3d0; padding:10px 12px; border-radius:6px; }
  .banner { background:#0f172a; color:#fff; padding:24px 48px; }
  .banner .brand { letter-spacing:2px; font-size:12px; color:#93c5fd; text-transform:uppercase; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  td,th { text-align:left; padding:6px 8px; border-bottom:1px solid #eee; }
  .rnav { position:sticky; top:0; z-index:10; display:flex; gap:10px; align-items:center;
          background:#0b1120; color:#cbd5e1; padding:10px 24px; font-size:13px; }
  .rnav a, .rnav button { color:#cbd5e1; background:transparent; border:1px solid #334155;
          border-radius:8px; padding:6px 12px; font-size:13px; cursor:pointer; text-decoration:none; }
  .rnav a:hover, .rnav button:hover { border-color:#38bdf8; color:#fff; }
  .rnav .spacer { flex:1; }
  .rnav .pdf { background:#38bdf8; color:#0b1120; border-color:#38bdf8; font-weight:600; }
  @media print { body{background:#fff} .page{padding:0} .rnav{display:none} }
</style></head>
<body>
<div class="rnav">
  <a href="{{ frontend_url }}/">⛨ Temple Guard</a>
  <a href="{{ frontend_url }}/engagements/{{ engagement.id }}">← Back to engagement</a>
  <a href="{{ frontend_url }}/reports">All reports</a>
  <span class="spacer"></span>
  <button onclick="document.querySelectorAll('details.finding').forEach(function(d){d.open=true})">Expand all</button>
  <button onclick="document.querySelectorAll('details.finding').forEach(function(d){d.open=false})">Collapse all</button>
  <button onclick="window.print()">🖨 Print</button>
  <a class="pdf" href="report.pdf">⬇ Download PDF</a>
</div>
<div class="banner">
  <div class="brand">Project Temple Guard · Authorized Security Assessment</div>
  <h1 style="color:#fff">{{ engagement.name }}</h1>
  <div class="muted" style="color:#cbd5e1">{{ client.name }}{% if client.industry %} · {{ client.industry }}{% endif %}</div>
</div>
<div class="page">
  <p class="muted">Generated {{ generated }} · Standards: {{ standards|join(', ') if standards else 'n/a' }}</p>
  <div class="kv"><b>Authorization</b> {{ engagement.authorization_ref or 'N/A' }}
    {% if engagement.authorized_by %}· approved by {{ engagement.authorized_by }}{% endif %}</div>
  <div class="kv"><b>Scope</b> {{ engagement.scope_targets|join(', ') }}</div>

  <h2>Executive Summary</h2>
  <p>This assessment executed {{ scan_count }} automated scan(s) and identified
     <b>{{ findings|length }}</b> finding(s) across the authorized scope. The table
     below summarizes risk by severity. Each finding includes evidence, affected
     assets, mapped compliance controls, and prioritized remediation guidance.</p>
  <div class="summary">
    {% for sev in severities %}
    <div class="card" style="border-top:4px solid {{ colors[sev] }}">
      <div class="n" style="color:{{ colors[sev] }}">{{ counts.get(sev, 0) }}</div>
      <div class="muted" style="text-transform:uppercase;font-size:11px">{{ sev }}</div>
    </div>{% endfor %}
  </div>

  <h2>Findings &amp; Remediation</h2>
  {# Large reports default collapsed; small ones stay expanded. Expand/Collapse-all still available. #}
  {% for f in findings %}{{ finding_card(f, loop.index, expand_all) }}
  {% else %}<p class="muted">No findings recorded.</p>{% endfor %}

  {% if hardening %}
  <h2>Hardening</h2>
  <p class="muted">Defensive posture checks assessed and how to harden against each.</p>
  {% for f in hardening %}{{ finding_card(f, loop.index, expand_all) }}{% endfor %}
  {% endif %}

  <h2>Methodology &amp; Scans Run</h2>
  <table><tr><th>Module</th><th>Standard</th><th>Target</th><th>Status</th><th>Mode</th></tr>
  {% for r in scans %}<tr><td>{{ r.module }}</td><td>{{ r.standard }}</td>
    <td>{{ r.target }}</td><td>{{ r.status }}</td><td>{{ r.provisioner }}</td></tr>{% endfor %}
  </table>
  <p class="muted" style="margin-top:30px;font-size:12px">
    Confidential. Prepared for {{ client.name }} under authorized engagement
    {{ engagement.authorization_ref or '' }}. Distribution restricted.</p>
</div></body></html>""")


def _severity_rank(f: Finding) -> int:
    return SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99


def build_report(session: Session, engagement: Engagement) -> tuple[str, dict]:
    client = session.get(Client, engagement.client_id)
    findings = session.exec(
        select(Finding).where(Finding.engagement_id == engagement.id)).all()
    findings = sorted(findings, key=lambda f: (_severity_rank(f), -(f.cvss or 0)))
    scans = session.exec(
        select(ScanRun).where(ScanRun.engagement_id == engagement.id)).all()
    counts = Counter(f.severity for f in findings)

    controls_by_id = {f.id: resolve_refs(f.standard_refs) for f in findings}
    main_findings = [f for f in findings if f.category != "redteam"]
    hardening = [f for f in findings if f.category == "redteam"]
    html = _TEMPLATE.render(
        client=client, engagement=engagement, findings=main_findings,
        hardening=hardening, scans=scans,
        expand_all=len(findings) <= 12,   # large reports default collapsed (total, not per-section)
        scan_count=len(scans), counts=counts, severities=SEVERITY_ORDER,
        colors=SEVERITY_COLOR, standards=engagement.standards,
        controls_by_id=controls_by_id, frontend_url=settings.frontend_url,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    summary = {
        "total": len(findings),
        "by_severity": dict(counts),
        "scans": len(scans),
    }
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, f"engagement_{engagement.id}.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return html, summary
