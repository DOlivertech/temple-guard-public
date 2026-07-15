"""Database engine + session helpers."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

from .config import settings

_is_sqlite = settings.database_url.startswith("sqlite")
connect_args = {"check_same_thread": False} if _is_sqlite else {}
engine = create_engine(settings.database_url, echo=False, connect_args=connect_args)

if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        # WAL + a busy timeout let the background scan pool write concurrently
        # without tripping "database is locked".
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()


def init_db() -> None:
    # Import models so SQLModel.metadata is populated before create_all.
    from . import models  # noqa: F401

    SQLModel.metadata.create_all(engine)
    _ensure_columns()


def _ensure_columns() -> None:
    """Tiny additive migration: add columns introduced after a DB was created.

    Works on SQLite and Postgres (uses the SQLAlchemy inspector) so neither needs
    a full migration tool for additive changes.
    """
    from sqlalchemy import inspect, text
    additive = {
        "finding": [("evidence_path", "VARCHAR")],
        "scanrun": [("params", "JSON"), ("target_id", "INTEGER")],
        "audittarget": [("operation", "VARCHAR"), ("team", "VARCHAR"), ("extra", "JSON")],
        "engagement": [("scan_network", "VARCHAR")],
    }
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table, cols in additive.items():
            try:
                existing = {c["name"] for c in inspector.get_columns(table)}
            except Exception:
                continue
            for name, coltype in cols:
                if name not in existing:
                    conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {coltype}'))


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
