from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Base
from app.db.repo import IOCRepo


def test_repo_upsert_dedupes(tmp_path):
    db_path = tmp_path / "t.db"
    engine = create_engine(f"sqlite+pysqlite:///{db_path}", future=True)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, future=True)

    with SessionLocal() as db:
        repo = IOCRepo(db)
        rows = [
            {"ioc_type": "ip", "raw": "8.8.8.8", "normalized": "8.8.8.8", "source": "test"},
            {"ioc_type": "ip", "raw": "8.8.8.8", "normalized": "8.8.8.8", "source": "test"},
        ]
        res = repo.upsert_many(rows)
        assert res.inserted == 1
        assert res.deduped == 1
        assert len(repo.list_iocs(limit=10)) == 1