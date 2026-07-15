"""Request/response schemas (kept separate from table models)."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ClientCreate(BaseModel):
    name: str
    contact_email: Optional[str] = None
    industry: Optional[str] = None
    authorization_status: str = "pending"
    scope_notes: Optional[str] = None


class EngagementCreate(BaseModel):
    client_id: int
    name: str
    standards: list[str] = []
    scope_targets: list[str] = []
    authorization_ref: Optional[str] = None
    authorized_by: Optional[str] = None
    authorized_until: Optional[datetime] = None
    provisioner: str = "docker"
    scan_network: str = "bridge"


class RunRequest(BaseModel):
    standards: Optional[list[str]] = None   # defaults to engagement.standards
    targets: Optional[list[str]] = None     # defaults to engagement.scope_targets


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None


class InstanceCreate(BaseModel):
    image: Optional[str] = None   # defaults to configured Kali image


class ClientUpdate(BaseModel):
    name: Optional[str] = None
    contact_email: Optional[str] = None
    industry: Optional[str] = None
    authorization_status: Optional[str] = None
    scope_notes: Optional[str] = None


class EngagementUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    standards: Optional[list[str]] = None
    scope_targets: Optional[list[str]] = None
    authorization_ref: Optional[str] = None
    authorized_by: Optional[str] = None
    scan_network: Optional[str] = None


class TargetCreate(BaseModel):
    kind: str                       # web | app | redteam | api
    value: str                      # URL, app path/installer URL, or redteam target host
    os: Optional[str] = None        # app only: linux | windows | macos
    operation: Optional[str] = None  # redteam only: catalog op id
    team: Optional[str] = None       # redteam only: red | purple | blue
    extra: Optional[dict] = None     # api only: {endpoints, discover}
    label: Optional[str] = None


class ApiTestRequest(BaseModel):
    endpoints: Optional[list[dict]] = None   # [{method, path}] selected subset


class PlaybookRunRequest(BaseModel):
    target: str                              # concrete in-scope host/URL


class BulkContainerAction(BaseModel):
    action: str                          # start | stop | restart | remove
    client_id: Optional[int] = None      # target all containers for a client
    engagement_id: Optional[int] = None  # ...or an engagement
