"""First-boot helper for the containerized stack.

Creates tables and seeds demo data only if the database is empty, so restarts
never clobber real data. Run: python -m app.bootstrap
"""
from __future__ import annotations

from sqlmodel import Session, select

from .database import engine, init_db
from .models import Client


def seed_if_empty() -> None:
    init_db()
    with Session(engine) as session:
        if session.exec(select(Client)).first():
            print("Temple Guard: database already initialized — skipping seed.")
            return
    print("Temple Guard: empty database — seeding demo data…")
    from .seed import seed
    seed()


if __name__ == "__main__":
    seed_if_empty()
