import json
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from app.db.models import CacheEntry
from app.db.repo import CacheRepo
from app.services.cache import CacheService


@pytest.fixture
def mock_repo():
    return Mock(spec=CacheRepo)


@pytest.fixture
def cache_service(mock_repo):
    return CacheService(mock_repo)


def test_get_cache_miss(mock_repo, cache_service):
    mock_repo.get_cache_entry.return_value = None
    now = datetime.now(UTC)
    result = cache_service.get("abc", now)
    assert result is None
    mock_repo.get_cache_entry.assert_called_once_with("abc")


def test_get_cache_hit(mock_repo, cache_service):
    value = {"key": "value"}
    expires_at = datetime.now(UTC) + timedelta(hours=1)
    entry = CacheEntry(key="abc", value=json.dumps(value), expires_at=expires_at)
    mock_repo.get_cache_entry.return_value = entry
    now = datetime.now(UTC)
    result = cache_service.get("abc", now)
    assert result == value


def test_get_cache_expired(mock_repo, cache_service):
    value = {"key": "value"}
    expires_at = datetime.now(UTC) - timedelta(hours=1)  # expired
    entry = CacheEntry(key="abc", value=json.dumps(value), expires_at=expires_at)
    mock_repo.get_cache_entry.return_value = entry
    now = datetime.now(UTC)
    result = cache_service.get("abc", now)
    assert result is None


def test_set_cache(mock_repo, cache_service):
    value = {"key": "value"}
    ttl_seconds = 3600
    now = datetime(2026, 3, 9, 12, 0, 0, tzinfo=UTC)
    expected_expires_at = now + timedelta(seconds=ttl_seconds)
    cache_service.set("abc", value, ttl_seconds, now)
    mock_repo.upsert_cache_entry.assert_called_once_with("abc", json.dumps(value), expected_expires_at)