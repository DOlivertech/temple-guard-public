"""Scan orchestration.

Ties standards → modules → provisioner → findings, and enforces that we only
ever touch targets inside an engagement's authorized scope.

Two execution paths share the same per-scan logic:
  * enqueue_standard()  — create ScanRun rows as "queued" and return immediately
                          (the API submits these to the background executor)
  * run_standard()      — synchronous convenience used by the seed script
Both ultimately call execute_run(), which is self-contained (opens its own
session) so it is safe to run on a background worker thread.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone

from sqlmodel import Session, select

from ..config import settings
from ..database import engine
from ..models import Asset, AuditTarget, Engagement, Finding, ScanRun
from . import standards
from .kali import label_run_args
from .modules import get_module
from .provisioner import get_provisioner


class ScopeError(Exception):
    pass


def _now():
    return datetime.now(timezone.utc)


def _host(target: str) -> str:
    return re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]


def _container_target(target: str) -> str:
    """Docker containers can't reach the host's localhost — remap it so tools
    running in a container can still hit a locally-served app under audit."""
    return re.sub(r"\b(localhost|127\.0\.0\.1)\b", "host.docker.internal", target)


# Evidence (screenshots) live next to the app and are served at /evidence/...
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "evidence_out")


def _save_evidence(engagement_id: int, run_id: int, idx: int, image) -> str | None:
    if not image:
        return None
    rel = f"eng{engagement_id}/run{run_id}_{idx}.png"
    full = os.path.join(EVIDENCE_DIR, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as fh:
        fh.write(image)
    return rel


def assert_in_scope(engagement: Engagement, target: str) -> None:
    if not settings.enforce_scope:
        return
    scope = engagement.scope_targets or []
    if "*" in scope:            # wildcard scope — any target is authorized
        return
    allowed = {_host(t) for t in scope}
    if _host(target) not in allowed:
        raise ScopeError(
            f"Target '{target}' is not in the authorized scope for engagement "
            f"'{engagement.name}'. Authorized: {sorted(allowed) or 'none'}.")


def _decide_real(engagement: Engagement, force_simulation: bool) -> bool:
    if force_simulation:
        return False
    provisioner = get_provisioner(engagement.provisioner, settings.docker_network)
    return settings.execution_mode == "docker" and provisioner.available()


def enqueue_standard(session: Session, engagement: Engagement, standard_id: str,
                     targets: list[str] | None = None,
                     force_simulation: bool = False) -> list[ScanRun]:
    """Validate scope and create queued ScanRun rows (does not execute)."""
    std = standards.get_standard(standard_id)
    if std is None:
        raise ValueError(f"Unknown standard '{standard_id}'")

    targets = targets or engagement.scope_targets or []
    # '*' is an authorization wildcard, not a literal scannable host.
    targets = [t for t in targets if t != "*"]
    if not targets:
        raise ScopeError(
            "No concrete targets to scan. Scope is '*' (any) or empty — add web/app "
            "targets in the Audit Targets panel, or specify hosts to scan.")
    for t in targets:
        assert_in_scope(engagement, t)

    use_real = _decide_real(engagement, force_simulation)
    runs: list[ScanRun] = []
    for target in targets:
        for sm in std.modules:
            run = ScanRun(
                engagement_id=engagement.id,
                module=sm.module,
                standard=standard_id,
                target=target,
                status="queued",
                provisioner=engagement.provisioner if use_real else "simulation",
            )
            session.add(run)
            runs.append(run)
    session.commit()
    for r in runs:
        session.refresh(r)
    return runs


# Default tool set per target kind. Web tools hit the URL; app tools dissect the
# artifact. web_evidence runs in-process (reaches localhost); nikto/app_analysis
# run in containers.
TARGET_MODULES = {
    "web": ["web_evidence", "nikto"],
    "app": ["app_analysis"],
    "redteam": ["redteam_op"],
    "api": ["api_test"],
    "phone": ["phoneinfoga"],
}


def enqueue_target(session: Session, engagement: Engagement, target) -> list[ScanRun]:
    """Queue the right tools for a structured target (web / app / api / red-team /
    phone). Scope-gated like enqueue_standard — a target's value must be authorized
    in the engagement scope (invariant #1), so no path can scan an out-of-scope host."""
    assert_in_scope(engagement, target.value)
    use_real = _decide_real(engagement, False)
    modules = TARGET_MODULES.get(target.kind, ["web_evidence"])
    if target.kind == "app":
        params = {"os": target.os} if target.os else {}
    elif target.kind == "redteam":
        params = {"operation": target.operation, "team": target.team,
                  **(target.extra or {})}  # e.g. login_url, usernames for cred tests
    elif target.kind == "api":
        params = {"endpoints": (target.extra or {}).get("discovered", [])}
    else:
        params = {}
    runs: list[ScanRun] = []
    for m in modules:
        run = ScanRun(
            engagement_id=engagement.id, module=m,
            standard=f"target:{target.kind}", target=target.value, status="queued",
            provisioner=engagement.provisioner if use_real else "simulation",
            params=params, target_id=target.id,
        )
        session.add(run)
        runs.append(run)
    session.commit()
    for r in runs:
        session.refresh(r)
    return runs


def enqueue_playbook(session: Session, engagement: Engagement, playbook_id: str,
                     target_value: str):
    """Validate scope, anchor a target, and create the playbook's step ScanRuns in
    order (does not execute — caller submits them sequentially)."""
    from . import playbooks
    pb = playbooks.get_playbook(playbook_id)
    if pb is None:
        raise ValueError(f"Unknown playbook '{playbook_id}'")
    target_value = (target_value or "").strip()
    if not target_value or target_value == "*":
        raise ScopeError("Provide a concrete target host/URL for the playbook.")
    assert_in_scope(engagement, target_value)

    # Anchor target so the existing per-attack dashboard shows the pipeline live.
    anchor = AuditTarget(engagement_id=engagement.id, kind="web", value=target_value,
                         label=f"▦ {pb.name}", last_status="running")
    session.add(anchor)
    session.commit()
    session.refresh(anchor)

    use_real = _decide_real(engagement, False)
    runs: list[ScanRun] = []
    for step in pb.steps:
        run = ScanRun(
            engagement_id=engagement.id, module=step.module,
            standard=f"playbook:{playbook_id}", target=target_value, status="queued",
            provisioner=engagement.provisioner if use_real else "simulation",
            params=step.params or {}, target_id=anchor.id,
        )
        session.add(run)
        runs.append(run)
    session.commit()
    for r in runs:
        session.refresh(r)
    return anchor, runs


def _upsert_asset(session: Session, engagement_id: int, data: dict) -> Asset | None:
    if not data:
        return None
    key_ip, key_host = data.get("ip"), data.get("hostname")
    existing = None
    if key_ip or key_host:
        stmt = select(Asset).where(Asset.engagement_id == engagement_id)
        for a in session.exec(stmt).all():
            if (key_ip and a.ip == key_ip) or (key_host and a.hostname == key_host):
                existing = a
                break
    if existing:
        if data.get("open_ports"):
            existing.open_ports = data["open_ports"]
        if data.get("os"):
            existing.os = data["os"]
        session.add(existing)
        return existing
    asset = Asset(
        engagement_id=engagement_id,
        ip=key_ip,
        hostname=key_host,
        asset_type=data.get("asset_type", "host"),
        os=data.get("os"),
        open_ports=data.get("open_ports", []),
    )
    session.add(asset)
    session.flush()
    return asset


def execute_run(run_id: int) -> None:
    """Run a single queued ScanRun to completion. Self-contained (own session)."""
    with Session(engine) as session:
        run = session.get(ScanRun, run_id)
        if not run or run.status not in ("queued", "running"):
            return
        engagement = session.get(Engagement, run.engagement_id)
        if not engagement:
            return

        run.status = "running"
        run.started_at = _now()
        session.add(run)
        session.commit()

        std = standards.get_standard(run.standard)
        sm = next((m for m in std.modules if m.module == run.module), None) if std else None
        params = run.params or (sm.params if sm else {})
        module = get_module(run.module, params)
        use_real = run.provisioner != "simulation"

        try:
            if use_real:
                network = engagement.scan_network or settings.docker_network
                provisioner = get_provisioner(engagement.provisioner, network)
                labels = label_run_args(engagement.client_id, engagement.id, role="scan",
                                        run_id=run.id, target_id=run.target_id)
                # On the default bridge, container tools can't reach host localhost —
                # remap to host.docker.internal. With host/VPN networking the container
                # shares the host's loopback + routes (incl. the VPN), so keep as-is.
                scan_target = run.target
                if getattr(module, "runs_in_container", True) and network == "bridge":
                    scan_target = _container_target(run.target)
                result = module.run_real(provisioner, scan_target,
                                         settings.scan_timeout_seconds, labels)
            else:
                result = module.simulate(run.target)

            # If the attack was stopped while this scan ran, honor it (don't
            # overwrite the stopped state with completed/failed).
            session.refresh(run)
            if run.status in ("stopped", "cancelled"):
                run.finished_at = _now()
                session.add(run)
                session.commit()
                return

            run.raw_output = result.raw_output
            run.instance_ref = result.instance_ref
            run.status = "completed" if result.ok else "failed"
            run.error = result.error
            run.finished_at = _now()

            asset = None
            for adata in result.assets:
                asset = _upsert_asset(session, engagement.id, adata)
            for i, f in enumerate(result.findings):
                evidence_path = _save_evidence(engagement.id, run.id, i, f.get("_image"))
                session.add(Finding(
                    engagement_id=engagement.id,
                    scan_run_id=run.id,
                    asset_id=asset.id if asset else None,
                    title=f.get("title", "Finding"),
                    severity=f.get("severity", "info"),
                    category=f.get("category"),
                    standard_refs=f.get("standard_refs", []),
                    cvss=f.get("cvss"),
                    description=f.get("description"),
                    evidence=f.get("evidence"),
                    evidence_path=evidence_path,
                    remediation=f.get("remediation"),
                ))
        except Exception as exc:  # noqa: BLE001
            run.status = "failed"
            run.error = str(exc)
            run.finished_at = _now()
        session.add(run)
        session.commit()


def run_standard(session: Session, engagement: Engagement, standard_id: str,
                 targets: list[str] | None = None,
                 force_simulation: bool = False) -> list[ScanRun]:
    """Synchronous: enqueue then execute each run inline (used by the seed)."""
    runs = enqueue_standard(session, engagement, standard_id, targets, force_simulation)
    for r in runs:
        execute_run(r.id)
    for r in runs:
        session.refresh(r)
    return runs
