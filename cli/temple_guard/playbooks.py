"""Playbooks — ordered, defensive multi-step scans.

A playbook chains capabilities the CLI already exposes into a repeatable recipe and
runs them **in order** against ONE authorized target, merging every step's findings
into a single report. Nothing here is offensive: each step is a read-only native
check-set, a passive OSINT/recon tool, or a bounded Docker scan tool — just sequenced
(recon → web → TLS, etc.) so you don't have to remember the chain.

Each :class:`PlaybookStep` has a ``kind``:
  * ``"native"`` → the built-in read-only checks (:func:`checks.scan`)
  * ``"tool"``   → one Docker scan tool        (:func:`tools.run_tool`)
  * ``"recon"``  → one passive OSINT/recon tool (:func:`recon_tools.run_recon`)

Add a playbook = append a :class:`Playbook` to :data:`CATALOG`. No other code changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import checks


@dataclass
class PlaybookStep:
    kind: str                        # "native" | "tool" | "recon"
    ref: Optional[str] = None        # tool / recon key ("nmap", "theharvester"); None for native
    note: str = ""                   # short human description shown while it runs

    @property
    def label(self) -> str:
        return "native checks" if self.kind == "native" else (self.ref or self.kind)


@dataclass
class Playbook:
    id: str
    name: str
    description: str
    category: str                    # recon | web | network | tls | osint
    steps: List[PlaybookStep] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return " → ".join(s.label for s in self.steps)

    @property
    def needs_docker(self) -> bool:
        return any(s.kind in ("tool", "recon") for s in self.steps)


def _n(note: str = "") -> PlaybookStep:
    return PlaybookStep("native", None, note)


def _t(ref: str, note: str = "") -> PlaybookStep:
    return PlaybookStep("tool", ref, note)


def _r(ref: str, note: str = "") -> PlaybookStep:
    return PlaybookStep("recon", ref, note)


CATALOG: List[Playbook] = [
    Playbook(
        "recon-light", "Recon (light)",
        "Fast surface read — native checks, tech fingerprint, and WAF detection.",
        "recon",
        [_n("HTTPS/TLS, headers, cookies, info-leak, methods, SPF/DMARC"),
         _t("whatweb", "technology fingerprint"),
         _t("wafw00f", "WAF / proxy detection")],
    ),
    Playbook(
        "web-audit", "Web app audit",
        "Deeper web posture — native checks, fingerprint, Nikto misconfig, and Nuclei templates.",
        "web",
        [_n("baseline web posture"),
         _t("whatweb", "technology fingerprint"),
         _t("nikto", "web-server misconfiguration scan"),
         _t("nuclei", "templated known-issue checks")],
    ),
    Playbook(
        "tls-deep", "TLS / crypto deep-dive",
        "Certificate, protocol, and cipher review with testssl and SSLyze.",
        "tls",
        [_n("certificate + HSTS basics"),
         _t("testssl", "full TLS / cipher audit"),
         _r("sslyze", "protocol & cipher enumeration")],
    ),
    Playbook(
        "network-surface", "Network surface",
        "Service and version discovery, then the native web checks on what's exposed.",
        "network",
        [_t("nmap", "service / version discovery"),
         _n("web posture on the discovered surface")],
    ),
    Playbook(
        "osint-domain", "OSINT footprint (domain)",
        "Passive, public-source footprint — emails/hosts, subdomains, and a multi-source sweep.",
        "osint",
        [_r("theharvester", "emails / hosts / subdomains"),
         _r("subfinder", "passive subdomain enumeration"),
         _r("spiderfoot", "multi-source OSINT sweep")],
    ),
]

BY_ID = {p.id: p for p in CATALOG}


def get(pid: str) -> Optional[Playbook]:
    """Look up a playbook by id (or None)."""
    return BY_ID.get(pid)


def run_playbook(pb: Playbook, target: str, *, on_event: Optional[Callable] = None,
                 stop_event=None, timeout: Optional[int] = None,
                 tool_wrapper=None) -> checks.ScanResult:
    """Run every step of ``pb`` against ``target`` in order, merging findings into ONE
    :class:`checks.ScanResult`.

    ``on_event(kind, **data)`` mirrors :func:`checks.scan`'s protocol so the CLI's live
    reporter renders each step and finding as it happens:
      * ``("step", category=…, name=…, desc=…)`` before each tool/recon step
      * ``("finding", finding=Finding)`` per finding
      * ``("clean", category=…, name=…)`` for a step that surfaced nothing
    Native steps delegate straight to :func:`checks.scan`, so they emit their own
    per-check events. Honors ``stop_event`` (a ``threading.Event``) between steps.
    """
    def emit(kind: str, **kw) -> None:
        if on_event:
            on_event(kind, **kw)

    # Optional per-tool UI wrapper (e.g. a live spinner) injected by the CLI; a no-op otherwise.
    from contextlib import nullcontext
    wrap = tool_wrapper or (lambda *_a, **_k: nullcontext())

    # If any step needs Docker and it's unavailable, run natives and skip the rest cleanly.
    docker_ok = True
    if pb.needs_docker:
        from . import tools
        docker_ok, why = tools.docker_available()
        if not docker_ok:
            emit("step", category="scan", name=f"{pb.name}: Docker tools",
                 desc=f"skipped — {why}")

    result: Optional[checks.ScanResult] = None
    for step in pb.steps:
        if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
            break

        if step.kind == "native":
            native = checks.scan(target, on_event=on_event)
            if result is None:
                result = native
            else:
                result.findings.extend(native.findings)
            continue

        if not docker_ok:                       # tool/recon step but no Docker — already warned
            continue

        emit("step", category=("recon" if step.kind == "recon" else "scan"),
             name=step.label, desc=step.note)
        try:
            if step.kind == "recon":
                from . import recon_tools
                image = getattr(recon_tools.RECON_TOOLS.get(step.ref), "image", None)
                with wrap(step.label, image):
                    findings, _raw, _ok = recon_tools.run_recon(
                        step.ref, target, timeout=timeout, stop_event=stop_event)
            else:
                from . import tools
                image = getattr(tools.TOOLS.get(step.ref), "image", None)
                with wrap(step.label, image):
                    findings, _raw, _ok = tools.run_tool(
                        step.ref, target, timeout=timeout, stop_event=stop_event)
        except Exception as exc:                # noqa: BLE001 — one tool failing must not abort the chain
            findings = [checks.Finding(
                title=f"{step.label} did not complete",
                severity="info", category="scan",
                evidence=str(exc)[:200],
                remediation="Re-run this step on its own to see the full error.")]

        if result is None:
            result = checks.ScanResult(url=target, reachable=True)
        if findings:
            for f in findings:
                emit("finding", finding=f)
            result.findings.extend(findings)
        else:
            emit("clean", category="scan", name=step.label)

    if result is None:
        result = checks.ScanResult(url=target, reachable=True)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    result.findings.sort(key=lambda f: order.get(f.severity, 9))
    return result
