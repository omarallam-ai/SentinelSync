from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings


def build_engine() -> Engine:
    # sqlite+pysqlite works on Windows without extra drivers
    url = f"sqlite+pysqlite:///{settings.db_path}"
    return create_engine(url, future=True)


_ENGINE = build_engine()
_SessionLocal = sessionmaker(bind=_ENGINE, autoflush=False, autocommit=False, future=True)

""""
def get_session() -> Iterator[Session]:
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
"""


@contextmanager
def get_session() -> Iterator[Session]:
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()