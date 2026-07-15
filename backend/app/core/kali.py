"""Docker container management for Temple Guard.

Containers are labelled (`templeguard=true` + `tg.client` / `tg.engagement` /
`tg.instance` / `tg.role`) so the control center can group, filter, and act on
them by client, by engagement, or individually — Docker-Desktop style.

The same manager backs:
  * long-lived Kali instances you shell into
  * (labelled) ephemeral scan containers, so live scans appear in the UI

A future cloud-VM / K8s backend implements the same surface for remote hosts.
"""
from __future__ import annotations

import json
import shutil
import subprocess

LABEL = "templeguard=true"


def _labels_args(client_id=None, engagement_id=None, instance_id=None,
                 role="kali", run_id=None, target_id=None) -> list[str]:
    args = ["--label", LABEL, "--label", f"tg.role={role}"]
    if client_id is not None:
        args += ["--label", f"tg.client={client_id}"]
    if engagement_id is not None:
        args += ["--label", f"tg.engagement={engagement_id}"]
    if instance_id is not None:
        args += ["--label", f"tg.instance={instance_id}"]
    if run_id is not None:
        args += ["--label", f"tg.run={run_id}"]
    if target_id is not None:
        args += ["--label", f"tg.target={target_id}"]
    return args


def label_run_args(client_id=None, engagement_id=None, role="scan",
                   run_id=None, target_id=None) -> list[str]:
    """Label args for `docker run` so ephemeral scans show in the control center
    and can be tracked/stopped per scan-run and per target."""
    return _labels_args(client_id, engagement_id, None, role, run_id, target_id)


def kill_by_label(label: str) -> int:
    """Force-kill running containers matching a label (e.g. 'tg.run=42'). Returns count."""
    ids = subprocess.run(["docker", "ps", "-q", "--filter", f"label={label}"],
                         capture_output=True, text=True).stdout.split()
    for cid in ids:
        subprocess.run(["docker", "kill", cid], capture_output=True)
    return len(ids)


def kill_container(ref: str) -> bool:
    return subprocess.run(["docker", "kill", ref], capture_output=True).returncode == 0


class KaliManager:
    """Lifecycle + introspection for Temple Guard Docker containers."""

    # ── availability ────────────────────────────────────────────────────
    def available(self) -> bool:
        if not shutil.which("docker"):
            return False
        try:
            return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
        except Exception:
            return False

    # ── create ──────────────────────────────────────────────────────────
    def start(self, name: str, image: str, client_id=None, engagement_id=None,
              instance_id=None) -> tuple[bool, str]:
        """Start a detached, idling container we can `docker exec` into."""
        existing = subprocess.run(["docker", "ps", "-aq", "-f", f"name=^{name}$"],
                                  capture_output=True, text=True)
        if existing.stdout.strip():
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        cmd = ["docker", "run", "-d", "--name", name, "--hostname", name,
               *_labels_args(client_id, engagement_id, instance_id, "kali"),
               image, "sleep", "infinity"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return False, proc.stderr.strip() or "failed to start container"
        return True, proc.stdout.strip()[:12]

    # ── lifecycle ───────────────────────────────────────────────────────
    def stop_container(self, ref: str) -> bool:
        return subprocess.run(["docker", "stop", "-t", "5", ref],
                              capture_output=True).returncode == 0

    def start_container(self, ref: str) -> bool:
        return subprocess.run(["docker", "start", ref], capture_output=True).returncode == 0

    def restart_container(self, ref: str) -> bool:
        return subprocess.run(["docker", "restart", "-t", "5", ref],
                              capture_output=True).returncode == 0

    def remove_container(self, ref: str) -> bool:
        return subprocess.run(["docker", "rm", "-f", ref], capture_output=True).returncode == 0

    # Back-compat: callers that "stop" an instance remove it entirely.
    def stop(self, ref: str) -> bool:
        return self.remove_container(ref)

    def is_running(self, ref: str) -> bool:
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", ref],
                           capture_output=True, text=True)
        return r.stdout.strip() == "true"

    # ── introspection ───────────────────────────────────────────────────
    def list_containers(self, include_all: bool = False) -> list[dict]:
        """Temple-Guard-labelled containers, or every container if include_all."""
        cmd = ["docker", "ps", "-a", "--format", "{{json .}}"]
        if not include_all:
            cmd[3:3] = ["--filter", f"label={LABEL}"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        out = []
        for line in proc.stdout.splitlines():
            try:
                c = json.loads(line)
            except ValueError:
                continue
            labels = _parse_labels(c.get("Labels", ""))
            managed = labels.get("templeguard") == "true"
            out.append({
                "id": (c.get("ID") or "")[:12],
                "name": c.get("Names", ""),
                "image": c.get("Image", ""),
                "state": c.get("State", ""),          # running | exited | created
                "status": c.get("Status", ""),        # "Up 3 minutes"
                "created": c.get("CreatedAt", ""),
                "ports": c.get("Ports", ""),
                "managed": managed,
                "client_id": _to_int(labels.get("tg.client")),
                "engagement_id": _to_int(labels.get("tg.engagement")),
                "instance_id": _to_int(labels.get("tg.instance")),
                "run_id": _to_int(labels.get("tg.run")),
                "target_id": _to_int(labels.get("tg.target")),
                "role": labels.get("tg.role", "external" if not managed else "kali"),
            })
        return out

    def stats(self, refs: list[str]) -> dict[str, dict]:
        """One-shot CPU/mem stats for the given refs, keyed by name."""
        if not refs:
            return {}
        proc = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}", *refs],
            capture_output=True, text=True, timeout=15)
        out = {}
        for line in proc.stdout.splitlines():
            try:
                s = json.loads(line)
            except ValueError:
                continue
            out[s.get("Name", "")] = {
                "cpu": s.get("CPUPerc", ""),
                "mem": s.get("MemUsage", ""),
                "mem_pct": s.get("MemPerc", ""),
            }
        return out

    def logs_command(self, ref: str, tail: int = 300) -> list[str]:
        return ["docker", "logs", "-f", "--tail", str(tail), ref]

    def shell_command(self, ref: str) -> list[str]:
        return ["docker", "exec", "-it", ref,
                "/bin/sh", "-c", "exec /bin/bash 2>/dev/null || exec /bin/sh"]


def _parse_labels(raw: str) -> dict:
    out = {}
    for part in raw.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


kali_manager = KaliManager()
