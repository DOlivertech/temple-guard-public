"""Seed demo data so the dashboard is populated on first launch.

Run:  python -m app.seed
Safe to re-run — it clears and recreates the demo rows.
"""
from __future__ import annotations

from sqlmodel import Session, delete, select

from .database import engine, init_db
from .models import (Asset, Client, Engagement, Finding, ProvisionedInstance,
                     Report, ScanRun)
from .core.runner import run_standard


def reset(session: Session) -> None:
    for model in (Finding, ScanRun, Asset, ProvisionedInstance, Report, Engagement, Client):
        session.exec(delete(model))
    session.commit()


def seed() -> None:
    init_db()
    with Session(engine) as session:
        reset(session)

        acme = Client(name="Acme FinTech", slug="acme-fintech",
                      contact_email="security@acme.example", industry="Financial Services",
                      authorization_status="authorized",
                      scope_notes="Signed SOW #2026-114. External perimeter + web app.")
        globex = Client(name="Globex Health", slug="globex-health",
                        contact_email="ciso@globex.example", industry="Healthcare",
                        authorization_status="authorized",
                        scope_notes="HIPAA assessment. Sandbox env only.")
        initech = Client(name="Initech (Prospect)", slug="initech",
                         industry="SaaS", authorization_status="pending",
                         scope_notes="Awaiting signed authorization.")
        session.add_all([acme, globex, initech])
        session.commit()
        for c in (acme, globex, initech):
            session.refresh(c)

        e1 = Engagement(client_id=acme.id, name="Acme Q2 External Pentest",
                        status="draft", standards=["owasp_top10", "nist_800_115", "pci_dss"],
                        scope_targets=["sandbox.acme.example", "api.sandbox.acme.example"],
                        authorization_ref="SOW-2026-114", authorized_by="J. Reyes, CISO",
                        provisioner="docker")
        e2 = Engagement(client_id=globex.id, name="Globex HIPAA Technical Audit",
                        status="draft", standards=["hipaa", "cis_benchmark"],
                        scope_targets=["portal.sandbox.globex.example"],
                        authorization_ref="HIPAA-2026-07", authorized_by="M. Tan",
                        provisioner="docker")
        session.add_all([e1, e2])
        session.commit()
        for e in (e1, e2):
            session.refresh(e)

        # Seed demo findings via simulation (targets are placeholders), so the
        # dashboard is populated regardless of the live execution mode.
        for std in e1.standards:
            run_standard(session, e1, std, force_simulation=True)
        for std in e2.standards:
            run_standard(session, e2, std, force_simulation=True)

        findings = session.exec(select(Finding)).all()
        print(f"Seeded {session.exec(select(Client)).all().__len__()} clients, "
              f"2 engagements, {len(findings)} findings.")


if __name__ == "__main__":
    seed()
