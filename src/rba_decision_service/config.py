"""Runtime settings (env / .env)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "rba-decision-service"
    host: str = "0.0.0.0"
    port: int = 8000

    redis_url: str = "redis://localhost:6379/0"
    redis_key_prefix: str = "rba:profile:"
    # ADR-0042: the deployment's learned-login counts (profile-service writes).
    redis_population_key: str = "rba:population"
    # sync: update Redis after each decision (Phase 3 thin slice).
    # none: read-only (Phase 4 profile-service owns writes).
    profile_write_mode: Literal["sync", "none"] = "sync"

    database_url: str = (
        "postgresql+psycopg://rba:rba@localhost:5432/rba_decision"
    )
    # When true, use in-memory SQLite (unit tests / no Docker).
    use_memory_db: bool = False
    # C-4: create tables and seed policies at startup (compose, k3d, tests).
    # Off where `python -m rba_decision_service.init` runs as a Job first.
    init_on_startup: bool = True

    # Tenant policies live in Postgres (ADR-0033). On startup, any tenant
    # without a row is seeded from this directory; existing rows are never
    # overwritten, so an operator's edit survives a restart.
    policy_seed_dir: Path = Field(default=_REPO_ROOT / "config" / "policies")
    # How stale a replica's copy of a policy may be after another replica
    # writes it.
    policy_cache_seconds: float = 5.0
    freeman_artifact_path: Path = Field(
        default=_REPO_ROOT / "artifacts" / "freeman-0.4.0.json"
    )
    # Supervised second opinion (ADR-0027). Missing file → Freeman only.
    logreg_artifact_path: Path = Field(
        default=_REPO_ROOT / "artifacts" / "logreg-0.2.0.json"
    )
    supervised_escalation_enabled: bool = True

    # Failed logins in the last 24h at/above these → REAUTHENTICATE, then BLOCK.
    failed_login_burst_threshold: int = 3
    failed_login_lockout_threshold: int = 10


@lru_cache
def get_settings() -> Settings:
    return Settings()
