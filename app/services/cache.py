from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from app.db.repo import CacheRepo

log = logging.getLogger("sentinelsync.cache")


@dataclass
class CacheEntry:
    key: str
    value: str
    expires_at: datetime


class CacheService:
    """
    Simple TTL-based cache backed by the ``cache_entries`` SQLite table.

    Design notes:
    - ``get`` returns None on miss *and* on expiry — callers treat both the same.
    - ``set`` always upserts (overwrites stale entries for the same key).
    - All ``expires_at`` comparisons use timezone-aware UTC datetimes.
    """

    def __init__(self, repo: CacheRepo) -> None:
        self.repo = repo

    def get(self, key: str, now: datetime) -> Any | None:
        """Return cached value or None on miss / expiry."""
        entry = self.repo.get_cache_entry(key)
        if entry is None:
            return None

        # Normalise to UTC-aware regardless of what SQLite stored
        expires_at = (
            entry.expires_at.replace(tzinfo=UTC)
            if entry.expires_at.tzinfo is None
            else entry.expires_at
        )

        if expires_at <= now:
            log.debug(f"cache expired key={key}")
            return None

        try:
            return json.loads(entry.value)
        except json.JSONDecodeError:
            log.warning(f"cache corrupt key={key} — treating as miss")
            return None

    def set(self, key: str, value: Any, ttl_seconds: int, now: datetime) -> None:
        """Store *value* under *key* with a TTL relative to *now*."""
        expires_at = now + timedelta(seconds=ttl_seconds)
        value_str = json.dumps(value)
        self.repo.upsert_cache_entry(key, value_str, expires_at)
        log.debug(f"cache set key={key} ttl={ttl_seconds}s expires={expires_at.isoformat()}")