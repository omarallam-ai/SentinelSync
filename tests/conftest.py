from __future__ import annotations

"""
pytest conftest — shared fixtures.

The key fix: session.py uses _ENGINE and _SessionLocal (underscore prefix),
NOT engine / SessionLocal. Patching the wrong names with raising=False
silently does nothing — tests end up hitting the real sentinelsync.db.

Correct approach: patch get_session on the api_main module directly,
which is where routes.py imports and uses it.
"""

import contextlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.api.routes as api_main
from app.db.models import Base


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # Fresh in-memory-equivalent DB per test (tmp_path is unique per test)
    db_path = tmp_path / "test.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    @contextlib.contextmanager
    def test_get_session():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    # Patch get_session where routes.py imported it — this is the only
    # patch that actually works. The session_mod._ENGINE patch does nothing
    # because routes.py already captured get_session at import time.
    monkeypatch.setattr(api_main, "get_session", test_get_session)

    return TestClient(api_main.app)