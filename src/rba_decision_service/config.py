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
    # sync: update Redis after each decision (Phase 3 thin slice).
    # none: read-only (Phase 4 profile-service owns writes).
    profile_write_mode: Literal["sync", "none"] = "sync"

    database_url: str = (
        "postgresql+psycopg://rba:rba@localhost:5432/rba_decision"
    )
    # When true, use in-memory SQLite (unit tests / no Docker).
    use_memory_db: bool = False

    policy_config_path: Path = Field(
        default=_REPO_ROOT / "config" / "policy-config.yaml"
    )
    freeman_artifact_path: Path = Field(
        default=_REPO_ROOT / "artifacts" / "freeman-0.1.0.json"
    )

    # Soft rule: failed logins in the last 24h at/above this → extra reason.
    failed_login_burst_threshold: int = 3


@lru_cache
def get_settings() -> Settings:
    return Settings()
