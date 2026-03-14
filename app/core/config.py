from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINELSYNC_",
        env_file=".env",
        extra="ignore",
    )

    db_path: str = Field(default="./sentinelsync.db")
    log_level: str = Field(default="INFO")
    max_input_chars: int = Field(default=200_000, ge=10_000, le=2_000_000)

    tcp_probe_timeout: int = Field(default=5, ge=1, le=30)
    tcp_probe_banner_bytes: int = Field(default=64, ge=0, le=512)
    allow_public_probes: bool = Field(default=False)

    urlhaus_auth_key: str = Field(default="")
    cache_ttl_ok: int = Field(default=3600)
    cache_ttl_error: int = Field(default=300)

    max_workers: int = Field(default=4, ge=1, le=8)
    max_probe_ports: int = Field(default=10, ge=1, le=50)


settings = Settings()

# ── backwards-compat module-level aliases ─────────────────────────────────────
# test_guardrails.py does: from app.core.config import ALLOW_PUBLIC_PROBES
# The original guardrails.py does the same. These aliases preserve that import
# while the real value still lives in settings (env-overridable, validated).
TCP_PROBE_TIMEOUT: int = settings.tcp_probe_timeout
TCP_PROBE_BANNER_BYTES: int = settings.tcp_probe_banner_bytes
ALLOW_PUBLIC_PROBES: bool = settings.allow_public_probes