"""Background scan executor.

Scans shell out to Docker (blocking subprocess), so a thread pool is the right
tool: the API enqueues ScanRun rows and submits their ids here, returning
immediately. The UI then polls scan status (queued → running → completed).

Concurrency is bounded so a burst of audits doesn't fork hundreds of containers
at once. For multi-node scale this is where a real queue (Celery/RQ/Arq) or the
K8s job backend slots in — same enqueue/execute seam.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from ..config import settings
from .runner import execute_run

log = logging.getLogger("temple_guard.jobs")

_executor = ThreadPoolExecutor(
    max_workers=settings.scan_concurrency, thread_name_prefix="tg-scan")


def submit_run(run_id: int) -> None:
    """Queue a single ScanRun for background execution."""
    _executor.submit(_safe_execute, run_id)


def submit_runs(run_ids: list[int]) -> None:
    for rid in run_ids:
        submit_run(rid)


def submit_playbook(run_ids: list[int]) -> None:
    """Run a playbook's steps in ORDER — one worker executes them sequentially so
    step N+1 starts only after step N completes (each spawns its own container)."""
    _executor.submit(_run_sequential, list(run_ids))


def _run_sequential(run_ids: list[int]) -> None:
    for rid in run_ids:
        _safe_execute(rid)


def _safe_execute(run_id: int) -> None:
    try:
        execute_run(run_id)
    except Exception:  # noqa: BLE001
        log.exception("scan run %s failed in background", run_id)
