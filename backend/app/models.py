"""Database models for Temple Guard.

The domain hierarchy:

    Client ─┬─ Engagement ─┬─ Asset (topology node)
            │              ├─ ScanRun ── Finding
            │              ├─ ProvisionedInstance
            │              └─ Report
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column
from sqlalchemy.types import JSON
from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Client(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    slug: str = Field(index=True)
    contact_email: Optional[str] = None
    industry: Optional[str] = None
    # Authorization is first-class: we never test a client without a signed scope.
    authorization_status: str = Field(default="pending")  # pending | authorized | revoked
    scope_notes: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


class Engagement(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    client_id: int = Field(foreign_key="client.id", index=True)
    name: str
    status: str = Field(default="draft")  # draft | active | completed | archived
    # Selected standards suites, e.g. ["owasp_top10", "nist_800_115"].
    standards: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    # Authorized scope — scans refuse to touch anything not listed here.
    scope_targets: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    authorization_ref: Optional[str] = None     # ticket / contract id
    authorized_by: Optional[str] = None          # client signatory
    authorized_until: Optional[datetime] = None  # rules-of-engagement window
    provisioner: str = Field(default="docker")   # docker | cloud_vm | k8s
    # Docker network for this engagement's scan containers. "bridge" (isolated,
    # default), "host" (inherit the engine host's stack incl. a VPN — Linux), or a
    # custom value like "container:<vpn>" / a named network to route via a VPN sidecar.
    scan_network: str = Field(default="bridge")
    created_at: datetime = Field(default_factory=utcnow)


class AuditTarget(SQLModel, table=True):
    """A structured thing to audit: a web address, or an app to detonate.

    web : value = URL (http/https)
    app : value = local path OR installer download URL; os picks the runtime
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    kind: str = Field(default="web")        # web | app | redteam | api
    value: str                               # URL or path/installer link
    os: Optional[str] = None                 # app only: linux | windows | macos
    operation: Optional[str] = None          # redteam only: catalog op id
    team: Optional[str] = None               # redteam only: red | purple | blue
    # api only: {"endpoints": [...], "discover": bool}
    extra: dict = Field(default_factory=dict, sa_column=Column(JSON))
    label: Optional[str] = None
    last_status: Optional[str] = None        # idle | running | completed | failed
    created_at: datetime = Field(default_factory=utcnow)


class Asset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    hostname: Optional[str] = None
    ip: Optional[str] = None
    asset_type: str = Field(default="host")  # host | web | db | network | cloud | unknown
    os: Optional[str] = None
    open_ports: list[dict] = Field(default_factory=list, sa_column=Column(JSON))
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    # Topology layout coordinates (set by UI; null => auto-layout).
    x: Optional[float] = None
    y: Optional[float] = None
    created_at: datetime = Field(default_factory=utcnow)


class ScanRun(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    module: str                       # nmap | nikto | zap_baseline | app_analysis | ...
    standard: Optional[str] = None    # suite that triggered it
    target: str
    target_id: Optional[int] = Field(default=None, index=True)  # AuditTarget link
    # Module params for target-driven runs (e.g. {"os": "windows"}); falls back
    # to the standard's SuiteModule params when absent.
    params: dict = Field(default_factory=dict, sa_column=Column(JSON))
    status: str = Field(default="queued")  # queued | running | completed | failed
    provisioner: str = Field(default="docker")
    instance_ref: Optional[str] = None     # container id / vm id / pod name
    raw_output: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    scan_run_id: Optional[int] = Field(default=None, foreign_key="scanrun.id", index=True)
    asset_id: Optional[int] = Field(default=None, foreign_key="asset.id")
    title: str
    severity: str = Field(default="info")  # critical | high | medium | low | info
    category: Optional[str] = None
    standard_refs: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    cvss: Optional[float] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    # Relative path to a Playwright-captured screenshot, served at /evidence/...
    evidence_path: Optional[str] = None
    remediation: Optional[str] = None
    status: str = Field(default="open")  # open | remediated | accepted_risk | false_positive
    created_at: datetime = Field(default_factory=utcnow)


class ProvisionedInstance(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    provider: str = Field(default="docker")  # docker | cloud_vm | k8s
    image: Optional[str] = None
    ref: Optional[str] = None
    status: str = Field(default="pending")  # pending | running | stopped | error
    region: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


class Report(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    title: str
    fmt: str = Field(default="html")  # html | pdf
    path: Optional[str] = None
    summary: dict = Field(default_factory=dict, sa_column=Column(JSON))
    generated_at: datetime = Field(default_factory=utcnow)
