"""Runtime configuration for Temple Guard.

Everything is environment-overridable so the same image runs on a laptop
(SQLite + simulation) or in the cloud (Postgres + real Docker/K8s runners).
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TG_", env_file=".env", extra="ignore")

    app_name: str = "Project Temple Guard"
    database_url: str = "sqlite:///./temple_guard.db"

    # Execution mode controls how scan modules actually run:
    #   "docker"     -> shell out to local Docker (kali / tool images)  [default]
    #   "simulation" -> generate realistic synthetic findings (zero-config demo)
    #   "cloud_vm"   -> PLACEHOLDER: provision ephemeral cloud instances
    #   "k8s"        -> PLACEHOLDER: run each scan as a Kubernetes job
    # Falls back to simulation automatically if Docker is unavailable.
    execution_mode: str = "docker"

    # Docker settings (used when execution_mode == "docker")
    docker_kali_image: str = "templeguard/kali:latest"
    docker_network: str = "bridge"
    scan_timeout_seconds: int = 900
    # Max scans executing concurrently in the background pool.
    scan_concurrency: int = 4

    # ── AWS cloud-VM provisioner (optional; off unless configured) ─────────
    aws_region: str = ""
    aws_kali_ami: str = ""           # AMI id of a Kali (or tools) image
    aws_subnet_id: str = ""
    aws_security_group_id: str = ""
    aws_instance_type: str = "t3.medium"
    aws_key_name: str = ""           # optional SSH key pair
    aws_iam_instance_profile: str = ""  # needed for SSM-based command exec

    # Safety: refuse to scan anything outside an engagement's authorized scope.
    enforce_scope: bool = True

    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    # Where the Temple Guard UI lives (used for the report's "home" link).
    frontend_url: str = "http://localhost:3000"

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
