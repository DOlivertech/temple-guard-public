"""HTTP API for Temple Guard."""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone

from fastapi import (APIRouter, Depends, HTTPException, Request, Response,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import HTMLResponse
from sqlalchemy import or_
from sqlmodel import Session, delete, select

from ..config import settings
from ..core import modules as modules_mod
from ..core import playbooks as playbooks_mod
from ..core import redteam as redteam_mod
from ..core import standards as standards_mod
from ..core.controls import resolve_refs
from ..core.kali import kali_manager, kill_container
from ..core.provisioner import get_provisioner
from ..core.jobs import submit_playbook, submit_runs
from ..core.reporting import build_report
from ..core.runner import (ScopeError, assert_in_scope, enqueue_playbook,
                           enqueue_standard, enqueue_target)
from ..core.shell import emulated_shell, pty_bridge, stream_logs
from ..database import engine, get_session
from ..models import (Asset, AuditTarget, Client, Engagement, Finding,
                      ProvisionedInstance, Report, ScanRun)
from ..schemas import (ApiTestRequest, BulkContainerAction, ClientCreate,
                       ClientUpdate, EngagementCreate, EngagementUpdate,
                       FindingUpdate, InstanceCreate, PlaybookRunRequest,
                       RunRequest, TargetCreate)
from ..utils import slugify

router = APIRouter()


# ── Meta / health ─────────────────────────────────────────────────────────
@router.get("/health")
def health():
    docker = get_provisioner("docker").available()
    return {
        "status": "ok",
        "app": settings.app_name,
        "execution_mode": settings.execution_mode,
        "docker_available": docker,
        "enforce_scope": settings.enforce_scope,
    }


@router.get("/standards")
def list_standards():
    return standards_mod.all_standards()


@router.get("/redteam/operations")
def redteam_operations():
    return redteam_mod.all_ops()


@router.get("/search")
def search(q: str = "", session: Session = Depends(get_session)):
    """Global search across clients, engagements, findings, assets, and targets."""
    q = q.strip()
    if len(q) < 1:
        return {"query": q, "count": 0, "results": []}
    like = f"%{q}%"
    out: list[dict] = []

    for c in session.exec(select(Client).where(Client.name.ilike(like))).all():
        out.append({"type": "client", "id": c.id, "title": c.name,
                    "subtitle": c.industry or c.authorization_status,
                    "href": f"/engagements?client={c.id}"})
    for e in session.exec(select(Engagement).where(or_(
            Engagement.name.ilike(like),
            Engagement.authorization_ref.ilike(like)))).all():
        out.append({"type": "engagement", "id": e.id, "title": e.name,
                    "subtitle": e.authorization_ref or e.status,
                    "href": f"/engagements/{e.id}"})
    for f in session.exec(select(Finding).where(
            Finding.title.ilike(like)).limit(40)).all():
        out.append({"type": "finding", "id": f.id, "title": f.title,
                    "subtitle": f.severity, "href": f"/evidence/{f.id}"})
    for a in session.exec(select(Asset).where(or_(
            Asset.hostname.ilike(like), Asset.ip.ilike(like))).limit(20)).all():
        out.append({"type": "asset", "id": a.id, "title": a.hostname or a.ip or "asset",
                    "subtitle": a.asset_type, "href": "/topology"})
    for t in session.exec(select(AuditTarget).where(
            AuditTarget.value.ilike(like)).limit(20)).all():
        out.append({"type": "target", "id": t.id, "title": t.value,
                    "subtitle": t.kind, "href": f"/engagements/{t.engagement_id}"})

    return {"query": q, "count": len(out), "results": out[:60]}


# ── Clients ───────────────────────────────────────────────────────────────
@router.get("/clients")
def list_clients(session: Session = Depends(get_session)):
    clients = session.exec(select(Client)).all()
    out = []
    for c in clients:
        engs = session.exec(select(Engagement).where(Engagement.client_id == c.id)).all()
        finding_count = 0
        for e in engs:
            finding_count += len(session.exec(
                select(Finding).where(Finding.engagement_id == e.id)).all())
        out.append({**c.model_dump(), "engagement_count": len(engs),
                    "finding_count": finding_count})
    return out


@router.post("/clients")
def create_client(body: ClientCreate, session: Session = Depends(get_session)):
    client = Client(**body.model_dump(), slug=slugify(body.name))
    session.add(client)
    session.commit()
    session.refresh(client)
    return client


def _client_initials(name: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", name or "")
    if not words:
        return "XX"
    if len(words) == 1:
        return words[0][:2].upper()
    return "".join(w[0] for w in words[:4]).upper()


@router.get("/clients/{client_id}/next-auth-ref")
def next_auth_ref(client_id: int, session: Session = Depends(get_session)):
    """Suggest the next authorization reference: SOW-<year>-<initials>-<NNN>.

    Increments from the client's highest existing reference; a brand-new client
    starts at 001.
    """
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(404, "client not found")
    initials = _client_initials(client.name)
    year = datetime.now().year
    engs = session.exec(select(Engagement).where(
        Engagement.client_id == client_id)).all()
    max_n = 0
    for e in engs:
        if e.authorization_ref:
            m = re.search(r"-(\d+)\s*$", e.authorization_ref)
            if m:
                max_n = max(max_n, int(m.group(1)))
    return {"auth_ref": f"SOW-{year}-{initials}-{max_n + 1:03d}",
            "initials": initials, "next_seq": max_n + 1}


@router.get("/clients/{client_id}/scope-suggestions")
def scope_suggestions(client_id: int, session: Session = Depends(get_session)):
    """Distinct hosts/URLs already associated with a client — for scope autocomplete."""
    engs = session.exec(select(Engagement).where(
        Engagement.client_id == client_id)).all()
    eng_ids = [e.id for e in engs]
    hosts: set[str] = set()
    for e in engs:
        hosts.update(e.scope_targets or [])
    if eng_ids:
        for a in session.exec(select(Asset).where(Asset.engagement_id.in_(eng_ids))).all():
            if a.hostname:
                hosts.add(a.hostname)
            if a.ip:
                hosts.add(a.ip)
        for t in session.exec(select(AuditTarget).where(
                AuditTarget.engagement_id.in_(eng_ids))).all():
            hosts.add(t.value)
    hosts.discard("*")
    return sorted(hosts)


@router.patch("/clients/{client_id}")
def update_client(client_id: int, body: ClientUpdate,
                  session: Session = Depends(get_session)):
    c = session.get(Client, client_id)
    if not c:
        raise HTTPException(404, "client not found")
    data = body.model_dump(exclude_none=True)
    for k, v in data.items():
        setattr(c, k, v)
    if "name" in data:
        c.slug = slugify(data["name"])
    session.add(c)
    session.commit()
    session.refresh(c)
    return c


def _delete_engagement_children(session: Session, eng_id: int) -> None:
    for model in (Finding, ScanRun, Asset, AuditTarget, ProvisionedInstance, Report):
        session.exec(delete(model).where(model.engagement_id == eng_id))


@router.delete("/clients/{client_id}")
def delete_client(client_id: int, session: Session = Depends(get_session)):
    c = session.get(Client, client_id)
    if not c:
        return {"ok": True, "deleted_engagements": 0}
    engs = session.exec(select(Engagement).where(
        Engagement.client_id == client_id)).all()
    for e in engs:
        _delete_engagement_children(session, e.id)
        session.delete(e)
    session.delete(c)
    session.commit()
    return {"ok": True, "deleted_engagements": len(engs)}


@router.get("/clients/{client_id}")
def get_client(client_id: int, session: Session = Depends(get_session)):
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(404, "client not found")
    engs = session.exec(select(Engagement).where(Engagement.client_id == client_id)).all()
    return {**client.model_dump(), "engagements": [e.model_dump() for e in engs]}


# ── Engagements ───────────────────────────────────────────────────────────
@router.get("/engagements")
def list_engagements(client_id: int | None = None, session: Session = Depends(get_session)):
    stmt = select(Engagement)
    if client_id:
        stmt = stmt.where(Engagement.client_id == client_id)
    engs = session.exec(stmt).all()
    out = []
    for e in engs:
        findings = session.exec(select(Finding).where(Finding.engagement_id == e.id)).all()
        client = session.get(Client, e.client_id)
        out.append({
            **e.model_dump(),
            "client_name": client.name if client else None,
            "findings_by_severity": dict(Counter(f.severity for f in findings)),
            "finding_count": len(findings),
        })
    return out


@router.post("/engagements")
def create_engagement(body: EngagementCreate, session: Session = Depends(get_session)):
    if not session.get(Client, body.client_id):
        raise HTTPException(404, "client not found")
    eng = Engagement(**body.model_dump())
    session.add(eng)
    session.commit()
    session.refresh(eng)
    return eng


@router.get("/engagements/{eng_id}")
def get_engagement(eng_id: int, session: Session = Depends(get_session)):
    eng = session.get(Engagement, eng_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    client = session.get(Client, eng.client_id)
    findings = session.exec(select(Finding).where(Finding.engagement_id == eng_id)).all()
    scans = session.exec(select(ScanRun).where(ScanRun.engagement_id == eng_id)).all()
    assets = session.exec(select(Asset).where(Asset.engagement_id == eng_id)).all()
    return {
        **eng.model_dump(),
        "client_name": client.name if client else None,
        "findings": [{**f.model_dump(), "controls": resolve_refs(f.standard_refs)}
                     for f in findings],
        "scans": [s.model_dump() for s in scans],
        "assets": [a.model_dump() for a in assets],
        "findings_by_severity": dict(Counter(f.severity for f in findings)),
    }


@router.patch("/engagements/{eng_id}")
def update_engagement(eng_id: int, body: EngagementUpdate,
                      session: Session = Depends(get_session)):
    e = session.get(Engagement, eng_id)
    if not e:
        raise HTTPException(404, "engagement not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(e, k, v)
    session.add(e)
    session.commit()
    session.refresh(e)
    return e


@router.delete("/engagements/{eng_id}")
def delete_engagement(eng_id: int, session: Session = Depends(get_session)):
    e = session.get(Engagement, eng_id)
    if not e:
        return {"ok": True}
    _delete_engagement_children(session, eng_id)
    session.delete(e)
    session.commit()
    return {"ok": True}


@router.post("/engagements/{eng_id}/run")
def run_audit(eng_id: int, body: RunRequest, session: Session = Depends(get_session)):
    eng = session.get(Engagement, eng_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    client = session.get(Client, eng.client_id)
    if client and client.authorization_status != "authorized":
        raise HTTPException(
            403, f"client '{client.name}' is not authorized (status="
                 f"{client.authorization_status}). Cannot run scans.")

    selected = body.standards or eng.standards
    if not selected:
        raise HTTPException(400, "no standards selected")

    eng.status = "active"
    session.add(eng)
    session.commit()

    all_runs = []
    try:
        for std_id in selected:
            std = standards_mod.get_standard(std_id)
            if std and not std.available:
                continue  # skip roadmap placeholders
            runs = enqueue_standard(session, eng, std_id, body.targets)
            all_runs.extend(runs)
    except ScopeError as exc:
        raise HTTPException(422, str(exc))

    # Execute in the background; respond immediately so audits never block.
    run_ids = [r.id for r in all_runs]
    submit_runs(run_ids)
    return {"engagement_id": eng_id, "queued": len(run_ids),
            "run_ids": run_ids, "status": "queued"}


# ── Audit targets (web addresses & apps) ──────────────────────────────────
@router.get("/engagements/{eng_id}/targets")
def list_targets(eng_id: int, session: Session = Depends(get_session)):
    rows = session.exec(select(AuditTarget).where(
        AuditTarget.engagement_id == eng_id)).all()
    scans = session.exec(select(ScanRun).where(ScanRun.engagement_id == eng_id)).all()
    out = []
    for t in rows:
        mine = [s for s in scans if s.target == t.value]
        if any(s.status in ("queued", "running") for s in mine):
            status = "running"
        elif mine:
            status = "completed"
        else:
            status = t.last_status or "idle"
        d = t.model_dump()
        d["last_status"] = status
        d["finding_count"] = None
        out.append(d)
    return out


@router.post("/engagements/{eng_id}/targets")
def create_target(eng_id: int, body: TargetCreate,
                  session: Session = Depends(get_session)):
    if not session.get(Engagement, eng_id):
        raise HTTPException(404, "engagement not found")
    if body.kind not in ("web", "app", "redteam", "api", "phone"):
        raise HTTPException(400, "kind must be 'web', 'app', 'redteam', 'api', or 'phone'")
    if body.kind == "redteam" and not redteam_mod.get_op(body.operation or ""):
        raise HTTPException(400, f"unknown team operation '{body.operation}'")
    t = AuditTarget(engagement_id=eng_id, kind=body.kind, value=body.value.strip(),
                    os=body.os, operation=body.operation, team=body.team,
                    extra=body.extra or {}, label=body.label, last_status="idle")
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


@router.delete("/targets/{target_id}")
def delete_target(target_id: int, session: Session = Depends(get_session)):
    t = session.get(AuditTarget, target_id)
    if not t:
        return {"ok": True, "killed": 0}
    # Stop any in-flight test first so we never orphan running containers.
    runs = session.exec(select(ScanRun).where(or_(
        ScanRun.target_id == target_id,
        ScanRun.target_id.is_(None) & (ScanRun.engagement_id == t.engagement_id)
        & (ScanRun.target == t.value),
    ))).all()
    killed = 0
    for c in _attack_containers(t, [r.id for r in runs]):
        if kill_container(c["id"]):
            killed += 1
    # Cascade-delete only scans this target OWNS (linked by target_id) + their
    # findings, so nothing is orphaned. Scans merely matched by value (target_id
    # NULL — e.g. a suite run against the same host) belong to the engagement: just
    # stop them if they're in flight, never delete.
    owned = [r for r in runs if r.target_id == target_id]
    owned_ids = [r.id for r in owned]
    findings_deleted = 0
    if owned_ids:
        for f in session.exec(select(Finding).where(
                Finding.scan_run_id.in_(owned_ids))).all():
            session.delete(f)
            findings_deleted += 1
    for r in owned:
        session.delete(r)
    for r in runs:
        if r.target_id != target_id and r.status in ("queued", "running"):
            r.status = "stopped"
            r.error = "target deleted"
            r.finished_at = datetime.now(timezone.utc)
            session.add(r)
    session.delete(t)
    session.commit()
    return {"ok": True, "killed": killed, "scans_deleted": len(owned),
            "findings_deleted": findings_deleted}


@router.get("/playbooks")
def list_playbooks():
    """Catalog of ordered, multi-step Kali pipelines."""
    return playbooks_mod.all_playbooks()


@router.post("/engagements/{eng_id}/playbooks/{playbook_id}/run")
def run_playbook(eng_id: int, playbook_id: str, body: PlaybookRunRequest,
                 session: Session = Depends(get_session)):
    """Launch a playbook: anchor a target and run its steps in order (each step a
    Kali container). Returns the anchor target_id to watch on the attack dashboard."""
    eng = session.get(Engagement, eng_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    client = session.get(Client, eng.client_id)
    if client and client.authorization_status != "authorized":
        raise HTTPException(403, f"client '{client.name}' is not authorized")
    if eng.authorized_until and \
            datetime.now(eng.authorized_until.tzinfo) > eng.authorized_until:
        raise HTTPException(422, "Outside the authorized rules-of-engagement window.")
    try:
        anchor, runs = enqueue_playbook(session, eng, playbook_id, body.target)
    except ScopeError as e:
        raise HTTPException(422, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    eng.status = "active"
    session.add(eng)
    session.commit()
    submit_playbook([r.id for r in runs])
    return {"target_id": anchor.id, "playbook": playbook_id,
            "steps": len(runs), "run_ids": [r.id for r in runs]}


def _execution_info(r) -> dict:
    """Where/how a scan ran — powers the 'script vs container image' UI label.
    engine ∈ {container, in-process, simulated}; image set only for containers."""
    if r.provisioner == "simulation":
        return {"engine": "simulated", "label": "Simulated — no execution", "image": None}
    if r.module == "redteam_op":
        op = redteam_mod.get_op((r.params or {}).get("operation", ""))
        if op and op.engine == "kali":
            return {"engine": "container", "image": modules_mod.KALI_IMAGE,
                    "label": f"Kali container · {modules_mod.KALI_IMAGE}"}
        if op and not op.executable:
            return {"engine": "simulated", "image": None, "label": "Documented — not executed"}
        return {"engine": "in-process", "image": None, "label": "In-process script — no container"}
    mod = modules_mod.get_module(r.module, r.params or {})
    if getattr(mod, "runs_in_container", True):
        return {"engine": "container", "image": mod.image, "label": f"Container · {mod.image}"}
    return {"engine": "in-process", "image": None, "label": "In-process script — no container"}


def _attack_containers(t: AuditTarget, run_ids: list[int]) -> list[dict]:
    """Scan containers engaged in this attack — precise (tg.run / tg.target) plus a
    legacy fallback for containers started before per-run labels existed."""
    if not kali_manager.available():
        return []
    out = []
    for c in kali_manager.list_containers():
        if c.get("role") != "scan":
            continue
        if c.get("target_id") == t.id or c.get("run_id") in run_ids:
            out.append(c)
        elif (c.get("run_id") is None and c.get("target_id") is None
              and c.get("engagement_id") == t.engagement_id and c.get("state") == "running"):
            out.append(c)
    return out


@router.get("/targets/{target_id}")
def get_target(target_id: int, session: Session = Depends(get_session)):
    t = session.get(AuditTarget, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    eng = session.get(Engagement, t.engagement_id)
    return {**t.model_dump(),
            "engagement_name": eng.name if eng else None,
            "client_id": eng.client_id if eng else None}


@router.post("/targets/{target_id}/api/discover")
def api_discover(target_id: int, session: Session = Depends(get_session)):
    """Discover an API's endpoints (OpenAPI/Swagger or common-path probing)."""
    from ..core.modules import discover_api_endpoints
    t = session.get(AuditTarget, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    base = t.value if re.match(r"^https?://", t.value) else f"http://{t.value}"
    eps = discover_api_endpoints(base.rstrip("/"))
    t.extra = {**(t.extra or {}), "discovered": eps}
    session.add(t)
    session.commit()
    return {"base": base, "count": len(eps), "endpoints": eps}


@router.post("/targets/{target_id}/api/test")
def api_test_selected(target_id: int, body: ApiTestRequest,
                      session: Session = Depends(get_session)):
    """Run a bounded API test against a selected set of {method, path} endpoints."""
    t = session.get(AuditTarget, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    eng = session.get(Engagement, t.engagement_id)
    client = session.get(Client, eng.client_id) if eng else None
    if client and client.authorization_status != "authorized":
        raise HTTPException(403, f"client '{client.name}' is not authorized")
    if eng and eng.authorized_until and \
            datetime.now(eng.authorized_until.tzinfo) > eng.authorized_until:
        raise HTTPException(422, "Outside the authorized rules-of-engagement window.")
    try:                                          # scope gate (invariant #1)
        assert_in_scope(eng, t.value)
    except ScopeError as e:
        raise HTTPException(422, str(e))

    selected = body.endpoints or (t.extra or {}).get("discovered") or []
    run = ScanRun(engagement_id=t.engagement_id, module="api_test",
                  standard="target:api", target=t.value, status="queued",
                  target_id=t.id, provisioner="inprocess",
                  params={"endpoints": selected})
    session.add(run)
    session.commit()
    session.refresh(run)
    t.last_status = "running"
    eng.status = "active"
    session.add_all([t, eng])
    session.commit()
    submit_runs([run.id])
    return {"target_id": target_id, "run_id": run.id, "tested": len(selected)}


def _duration(start, end) -> float | None:
    if not start:
        return None
    end = end or datetime.now(start.tzinfo)
    try:
        return round((end - start).total_seconds(), 1)
    except Exception:
        return None


@router.get("/targets/{target_id}/attack")
def target_attack(target_id: int, session: Session = Depends(get_session)):
    """Everything about one attack: status, timeline, engaged containers,
    findings, and discovered assets (for the per-attack dashboard)."""
    t = session.get(AuditTarget, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    eng = session.get(Engagement, t.engagement_id)
    client = session.get(Client, eng.client_id) if eng else None

    runs = session.exec(select(ScanRun).where(or_(
        ScanRun.target_id == target_id,
        ScanRun.target_id.is_(None) & (ScanRun.engagement_id == t.engagement_id)
        & (ScanRun.target == t.value),
    ))).all()
    run_ids = [r.id for r in runs]
    active = [r for r in runs if r.status in ("queued", "running")]
    started = min([r.started_at for r in runs if r.started_at], default=None)
    finished = (max([r.finished_at for r in runs if r.finished_at], default=None)
                if runs and not active else None)
    if active:
        overall = "running"
    elif any(r.status == "stopped" for r in runs):
        overall = "stopped"
    elif runs:
        overall = "completed"
    else:
        overall = "idle"

    scans = [{
        "id": r.id, "module": r.module, "status": r.status, "target": r.target,
        "provisioner": r.provisioner, "instance_ref": r.instance_ref,
        "execution": _execution_info(r),
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "duration_s": _duration(r.started_at, r.finished_at),
        "error": r.error,
    } for r in sorted(runs, key=lambda r: r.id)]

    # Live containers engaged in this attack.
    containers = _attack_containers(t, run_ids)

    # Findings produced by this attack's scans.
    findings = []
    if run_ids:
        for f in session.exec(select(Finding).where(
                Finding.scan_run_id.in_(run_ids))).all():
            findings.append({**f.model_dump(),
                             "controls": resolve_refs(f.standard_refs)})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), -(f.get("cvss") or 0)))

    assets = []
    if eng:
        host = re.sub(r"^https?://", "", t.value).split("/")[0].split(":")[0]
        for a in session.exec(select(Asset).where(
                Asset.engagement_id == eng.id)).all():
            if a.hostname == host or (a.hostname and host in a.hostname) or a.ip == host \
                    or t.kind == "app":
                assets.append(a.model_dump())

    return {
        "target": t.model_dump(),
        "engagement_id": t.engagement_id, "engagement_name": eng.name if eng else None,
        "client_name": client.name if client else None,
        "status": overall, "active_count": len(active),
        "started_at": started.isoformat() if started else None,
        "finished_at": finished.isoformat() if finished else None,
        "duration_s": _duration(started, finished),
        "scans": scans, "containers": containers, "findings": findings,
        "assets": assets,
        "findings_by_severity": dict(Counter(f["severity"] for f in findings)),
    }


@router.post("/targets/{target_id}/stop")
def stop_target(target_id: int, session: Session = Depends(get_session)):
    """Stop a running attack: cancel queued scans and kill their containers."""
    t = session.get(AuditTarget, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    runs = session.exec(select(ScanRun).where(or_(
        ScanRun.target_id == target_id,
        ScanRun.target_id.is_(None) & (ScanRun.engagement_id == t.engagement_id)
        & (ScanRun.target == t.value),
    ))).all()
    run_ids = [r.id for r in runs]
    killed = 0
    # Kill every container engaged in this attack (precise + legacy).
    for c in _attack_containers(t, run_ids):
        if kill_container(c["id"]):
            killed += 1
    for r in runs:
        if r.status in ("queued", "running"):
            r.status = "stopped"
            r.error = "stopped by operator"
            r.finished_at = datetime.now(timezone.utc)
            session.add(r)
    t.last_status = "stopped"
    session.add(t)
    session.commit()
    return {"target_id": target_id, "stopped_scans":
            len([r for r in runs if r.status == "stopped"]), "containers_killed": killed}


@router.post("/targets/{target_id}/run")
def run_target(target_id: int, session: Session = Depends(get_session)):
    t = session.get(AuditTarget, target_id)
    if not t:
        raise HTTPException(404, "target not found")
    eng = session.get(Engagement, t.engagement_id)
    client = session.get(Client, eng.client_id) if eng else None
    if client and client.authorization_status != "authorized":
        raise HTTPException(403, f"client '{client.name}' is not authorized")
    # Rules-of-engagement window: refuse to launch outside the authorized period.
    if eng and eng.authorized_until:
        now = datetime.now(eng.authorized_until.tzinfo)
        if now > eng.authorized_until:
            raise HTTPException(
                422, f"Outside the authorized window (rules of engagement ended "
                     f"{eng.authorized_until.isoformat()}). Update the engagement's "
                     "authorized_until to proceed.")

    # Scope gate (invariant #1) — enqueue_target raises if the target is out of scope;
    # do this BEFORE marking the target running so a rejected target stays idle.
    try:
        runs = enqueue_target(session, eng, t)
    except ScopeError as e:
        raise HTTPException(422, str(e))

    eng.status = "active"
    t.last_status = "running"
    session.add_all([eng, t])
    session.commit()

    submit_runs([r.id for r in runs])
    return {"target_id": target_id, "kind": t.kind, "queued": len(runs),
            "run_ids": [r.id for r in runs]}


# ── Findings ──────────────────────────────────────────────────────────────
@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, session: Session = Depends(get_session)):
    """A scan run incl. its raw output — used for the per-tool log view."""
    s = session.get(ScanRun, scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    return {**s.model_dump(), "execution": _execution_info(s)}


@router.get("/engagements/{eng_id}/findings")
def list_findings(eng_id: int, session: Session = Depends(get_session)):
    return session.exec(select(Finding).where(Finding.engagement_id == eng_id)).all()


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingUpdate,
                   session: Session = Depends(get_session)):
    f = session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(f, k, v)
    session.add(f)
    session.commit()
    session.refresh(f)
    return f


# ── Topology ──────────────────────────────────────────────────────────────
@router.get("/topology")
def topology(client_id: int | None = None, engagement_id: int | None = None,
             session: Session = Depends(get_session)):
    """Graph of clients → engagements → assets for the topology view."""
    nodes, edges = [], []
    clients = session.exec(select(Client)).all()
    if client_id:
        clients = [c for c in clients if c.id == client_id]

    for c in clients:
        nodes.append({"id": f"client-{c.id}", "type": "client", "label": c.name,
                      "status": c.authorization_status})
        engs = session.exec(select(Engagement).where(Engagement.client_id == c.id)).all()
        for e in engs:
            if engagement_id and e.id != engagement_id:
                continue
            nodes.append({"id": f"eng-{e.id}", "type": "engagement", "label": e.name,
                          "status": e.status, "client_id": c.id})
            edges.append({"source": f"client-{c.id}", "target": f"eng-{e.id}"})
            assets = session.exec(select(Asset).where(Asset.engagement_id == e.id)).all()
            for a in assets:
                findings = session.exec(
                    select(Finding).where(Finding.asset_id == a.id)).all()
                sev = Counter(f.severity for f in findings)
                worst = next((s for s in ["critical", "high", "medium", "low", "info"]
                              if sev.get(s)), None)
                nodes.append({
                    "id": f"asset-{a.id}", "type": "asset",
                    "label": a.hostname or a.ip or f"asset-{a.id}",
                    "asset_type": a.asset_type, "worst_severity": worst,
                    "open_ports": a.open_ports, "engagement_id": e.id,
                    "finding_count": len(findings), "x": a.x, "y": a.y,
                })
                edges.append({"source": f"eng-{e.id}", "target": f"asset-{a.id}"})
    return {"nodes": nodes, "edges": edges}


# ── Reports ───────────────────────────────────────────────────────────────
@router.post("/engagements/{eng_id}/report")
def generate_report(eng_id: int, session: Session = Depends(get_session)):
    eng = session.get(Engagement, eng_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    _, summary = build_report(session, eng)
    report = Report(engagement_id=eng_id,
                    title=f"{eng.name} Security Assessment",
                    fmt="html", path=f"reports_out/engagement_{eng_id}.html",
                    summary=summary)
    session.add(report)
    session.commit()
    session.refresh(report)
    return report


@router.get("/engagements/{eng_id}/report", response_class=HTMLResponse)
def view_report(eng_id: int, session: Session = Depends(get_session)):
    eng = session.get(Engagement, eng_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    html, _ = build_report(session, eng)
    return HTMLResponse(html)


@router.get("/engagements/{eng_id}/report.pdf")
def report_pdf(eng_id: int, request: Request, session: Session = Depends(get_session)):
    eng = session.get(Engagement, eng_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    build_report(session, eng)  # ensure latest HTML exists
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise HTTPException(501, "PDF export needs playwright "
                                 "(pip install playwright && playwright install chromium)")
    base = str(request.base_url).rstrip("/")
    url = f"{base}/api/engagements/{eng_id}/report"
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(args=["--no-sandbox", "--disable-gpu"])
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            pdf = page.pdf(format="A4", print_background=True,
                           margin={"top": "12mm", "bottom": "12mm",
                                   "left": "10mm", "right": "10mm"})
            browser.close()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"PDF render failed: {exc}")
    fname = f"temple-guard-{slugify(eng.name)}.pdf"
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@router.get("/reports")
def list_reports(session: Session = Depends(get_session)):
    return session.exec(select(Report)).all()


# ── Evidence ──────────────────────────────────────────────────────────────
def _evidence_item(session: Session, f: Finding,
                   cache: dict | None = None) -> dict:
    cache = cache if cache is not None else {}
    eng = cache.setdefault(("eng", f.engagement_id),
                           session.get(Engagement, f.engagement_id))
    client = None
    if eng:
        client = cache.setdefault(("client", eng.client_id),
                                  session.get(Client, eng.client_id))
    scan = session.get(ScanRun, f.scan_run_id) if f.scan_run_id else None
    return {
        "id": f.id,
        "title": f.title,                       # what was found
        "severity": f.severity,
        "category": f.category,
        "cvss": f.cvss,
        "description": f.description,
        "evidence": f.evidence,                 # raw evidence text
        "evidence_path": f.evidence_path,        # screenshot, if any
        "has_screenshot": bool(f.evidence_path),
        "remediation": f.remediation,
        "status": f.status,
        "engagement_id": f.engagement_id,
        "engagement_name": eng.name if eng else None,
        "client_id": eng.client_id if eng else None,
        "client_name": client.name if client else None,
        "module": scan.module if scan else None,
        "standard": scan.standard if scan else None,
        "target": scan.target if scan else None,
        "controls": resolve_refs(f.standard_refs),  # what it violates, linked
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


@router.get("/evidence")
def list_evidence(client_id: int | None = None, engagement_id: int | None = None,
                  severity: str | None = None, has_screenshot: bool | None = None,
                  session: Session = Depends(get_session)):
    stmt = select(Finding)
    if engagement_id:
        stmt = stmt.where(Finding.engagement_id == engagement_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    findings = session.exec(stmt).all()

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 9), -(f.cvss or 0)))

    cache: dict = {}
    items = [_evidence_item(session, f, cache) for f in findings]
    if client_id:
        items = [i for i in items if i["client_id"] == client_id]
    if has_screenshot is not None:
        items = [i for i in items if i["has_screenshot"] == has_screenshot]

    sev_counts = Counter(i["severity"] for i in items)
    fw_counts = Counter(c["framework"] for i in items for c in i["controls"])
    return {
        "count": len(items),
        "with_screenshots": len([i for i in items if i["has_screenshot"]]),
        "by_severity": dict(sev_counts),
        "by_framework": dict(fw_counts),
        "items": items,
    }


@router.get("/evidence/{finding_id}")
def get_evidence(finding_id: int, session: Session = Depends(get_session)):
    f = session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "evidence item not found")
    return _evidence_item(session, f)


# ── Kali instances + remote shell ─────────────────────────────────────────
@router.get("/instances")
def list_instances(engagement_id: int | None = None,
                   session: Session = Depends(get_session)):
    stmt = select(ProvisionedInstance)
    if engagement_id:
        stmt = stmt.where(ProvisionedInstance.engagement_id == engagement_id)
    rows = session.exec(stmt).all()
    # Refresh live status from Docker for real instances.
    for r in rows:
        if r.provider == "docker" and r.ref:
            r.status = "running" if kali_manager.is_running(r.ref) else "stopped"
    return [r.model_dump() for r in rows]


@router.post("/engagements/{eng_id}/instances")
def start_instance(eng_id: int, body: InstanceCreate,
                   session: Session = Depends(get_session)):
    eng = session.get(Engagement, eng_id)
    if not eng:
        raise HTTPException(404, "engagement not found")
    image = body.image or settings.docker_kali_image
    inst = ProvisionedInstance(engagement_id=eng_id, provider="docker",
                               image=image, status="pending")
    session.add(inst)
    session.commit()
    session.refresh(inst)

    if not kali_manager.available():
        inst.status = "error"
        session.add(inst)
        session.commit()
        raise HTTPException(
            422, "Docker is not available — cannot provision a Kali instance. "
                 "Install/start Docker, or use the simulated console.")

    name = f"tg-kali-eng{eng_id}-i{inst.id}"
    ok, ref = kali_manager.start(name, image, client_id=eng.client_id,
                                 engagement_id=eng_id, instance_id=inst.id)
    inst.ref = ref if ok else None
    inst.status = "running" if ok else "error"
    session.add(inst)
    session.commit()
    session.refresh(inst)
    if not ok:
        raise HTTPException(500, f"failed to start instance: {ref}")
    return inst


@router.post("/instances/{instance_id}/stop")
def stop_instance(instance_id: int, session: Session = Depends(get_session)):
    inst = session.get(ProvisionedInstance, instance_id)
    if not inst:
        raise HTTPException(404, "instance not found")
    if inst.ref:
        kali_manager.stop(inst.ref)
    inst.status = "stopped"
    session.add(inst)
    session.commit()
    return inst


@router.websocket("/instances/{instance_id}/shell")
async def instance_shell(websocket: WebSocket, instance_id: int):
    await websocket.accept()
    with Session(engine) as session:
        inst = session.get(ProvisionedInstance, instance_id)
    use_real = bool(
        inst and inst.provider == "docker" and inst.ref
        and kali_manager.available() and kali_manager.is_running(inst.ref))
    try:
        if use_real:
            banner = (f"\x1b[1;36m⛨ Temple Guard — connected to {inst.image}\x1b[0m"
                      f" \x1b[2m({inst.ref})\x1b[0m\r\n\r\n")
            await pty_bridge(websocket, kali_manager.shell_command(inst.ref), banner)
        else:
            await emulated_shell(websocket)
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass


# ── Container control center ──────────────────────────────────────────────
_ACTIONS = {
    "start": lambda r: kali_manager.start_container(r),
    "stop": lambda r: kali_manager.stop_container(r),
    "restart": lambda r: kali_manager.restart_container(r),
    "remove": lambda r: kali_manager.remove_container(r),
}


def _decorate_containers(session: Session, rows: list[dict]) -> list[dict]:
    """Attach client/engagement names from the DB to each container."""
    client_names: dict[int, str] = {}
    eng_names: dict[int, str] = {}
    for c in rows:
        cid, eid = c.get("client_id"), c.get("engagement_id")
        if cid and cid not in client_names:
            obj = session.get(Client, cid)
            client_names[cid] = obj.name if obj else f"client {cid}"
        if eid and eid not in eng_names:
            obj = session.get(Engagement, eid)
            eng_names[eid] = obj.name if obj else f"engagement {eid}"
        c["client_name"] = client_names.get(cid)
        c["engagement_name"] = eng_names.get(eid)
    return rows


@router.get("/containers")
def list_containers(all: bool = False, session: Session = Depends(get_session)):
    if not kali_manager.available():
        return {"docker_available": False, "containers": []}
    rows = kali_manager.list_containers(include_all=all)
    running = [c["name"] for c in rows if c["state"] == "running"]
    stats = kali_manager.stats(running) if running else {}
    for c in rows:
        c["stats"] = stats.get(c["name"])
    return {"docker_available": True,
            "containers": _decorate_containers(session, rows)}


@router.post("/containers/{ref}/{action}")
def container_action(ref: str, action: str):
    if action not in _ACTIONS:
        raise HTTPException(400, f"unknown action '{action}'")
    if not kali_manager.available():
        raise HTTPException(422, "Docker is not available")
    ok = _ACTIONS[action](ref)
    if not ok:
        raise HTTPException(500, f"failed to {action} container {ref}")
    return {"ref": ref, "action": action, "ok": True}


@router.post("/containers/bulk")
def container_bulk(body: BulkContainerAction):
    if body.action not in _ACTIONS:
        raise HTTPException(400, f"unknown action '{body.action}'")
    if not kali_manager.available():
        raise HTTPException(422, "Docker is not available")
    rows = kali_manager.list_containers()
    targets = [
        c for c in rows
        if (body.engagement_id and c.get("engagement_id") == body.engagement_id)
        or (body.client_id and c.get("client_id") == body.client_id)
    ]
    results = [{"name": c["name"], "ok": _ACTIONS[body.action](c["id"])} for c in targets]
    return {"action": body.action, "count": len(results), "results": results}


@router.websocket("/containers/{ref}/logs")
async def container_logs(websocket: WebSocket, ref: str):
    await websocket.accept()
    if not kali_manager.available():
        await websocket.send_text("Docker not available.\r\n")
        await websocket.close()
        return
    try:
        await stream_logs(websocket, kali_manager.logs_command(ref))
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass


@router.websocket("/containers/{ref}/shell")
async def container_shell(websocket: WebSocket, ref: str):
    await websocket.accept()
    use_real = kali_manager.available() and kali_manager.is_running(ref)
    try:
        if use_real:
            banner = f"\x1b[1;36m⛨ Temple Guard — {ref}\x1b[0m\r\n\r\n"
            await pty_bridge(websocket, kali_manager.shell_command(ref), banner)
        else:
            await emulated_shell(websocket)
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass


# ── Dashboard ─────────────────────────────────────────────────────────────
@router.get("/dashboard")
def dashboard(session: Session = Depends(get_session)):
    clients = session.exec(select(Client)).all()
    engs = session.exec(select(Engagement)).all()
    findings = session.exec(select(Finding)).all()
    scans = session.exec(select(ScanRun)).all()
    return {
        "clients": len(clients),
        "engagements": len(engs),
        "active_engagements": len([e for e in engs if e.status == "active"]),
        "scans": len(scans),
        "scans_running": len([s for s in scans if s.status == "running"]),
        "scans_queued": len([s for s in scans if s.status == "queued"]),
        "findings": len(findings),
        "findings_by_severity": dict(Counter(f.severity for f in findings)),
        "open_critical": len([f for f in findings
                              if f.severity == "critical" and f.status == "open"]),
        "recent_scans": [s.model_dump() for s in sorted(
            scans, key=lambda s: s.created_at, reverse=True)[:8]],
    }


# ── Provisioning (status + placeholder controls) ──────────────────────────
@router.get("/provisioners")
def provisioners():
    cloud_ok = get_provisioner("cloud_vm").available()
    return [
        {"name": "docker", "available": get_provisioner("docker").available(),
         "label": "Local Docker", "status": "ready"},
        {"name": "cloud_vm", "available": cloud_ok,
         "label": "Cloud VM (AWS EC2 via SSM)",
         "status": "ready" if cloud_ok else "needs config",
         "note": "Configured" if cloud_ok else
                 "Set TG_AWS_REGION / TG_AWS_KALI_AMI / TG_AWS_SUBNET_ID + creds "
                 "(install boto3). Bring-your-own-cloud via assume-role."},
        {"name": "k8s", "available": False, "label": "Kubernetes Jobs",
         "status": "placeholder", "note": "Roadmap — high-concurrency ephemeral pods."},
    ]
