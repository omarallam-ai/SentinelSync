from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import CacheEntry, IOCModel, Probe, ReportModel


# ── IOC ───────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class InsertResult:
    inserted: int
    deduped: int
    ids: list[int]


class IOCRepo:
    def __init__(self, db: Session) -> None:
        self.db = db

    def init_db(self) -> None:
        from app.db.models import Base
        from app.db.session import _ENGINE
        Base.metadata.create_all(bind=_ENGINE)

    def upsert_many(self, rows: list[dict]) -> InsertResult:
        inserted = 0
        deduped = 0
        ids: list[int] = []

        for r in rows:
            model = IOCModel(
                ioc_type=r["ioc_type"],
                raw=r["raw"],
                normalized=r["normalized"],
                source=r.get("source", "cli"),
                score=int(r.get("score", 0)),
                score_reasons=json.dumps(r.get("score_reasons", [])),
            )
            self.db.add(model)
            try:
                self.db.commit()
                self.db.refresh(model)
                inserted += 1
                ids.append(model.id)
            except IntegrityError:
                self.db.rollback()
                deduped += 1

        return InsertResult(inserted=inserted, deduped=deduped, ids=ids)

    def list_iocs(self, limit: int = 100) -> list[IOCModel]:
        stmt = select(IOCModel).order_by(IOCModel.id.desc()).limit(limit)
        return list(self.db.execute(stmt).scalars().all())

    def get_by_id(self, ioc_id: int) -> IOCModel | None:
        stmt = select(IOCModel).where(IOCModel.id == ioc_id)
        return self.db.execute(stmt).scalars().first()

    def get_ioc(self, ioc_id: int) -> IOCModel | None:
        try:
            return self.get_by_id(int(ioc_id))
        except (ValueError, TypeError):
            return None

    def get_by_normalized(self, ioc_type: str, normalized: str) -> IOCModel | None:
        """Find an existing IOC by type + normalized value. Used by enrichment services."""
        stmt = select(IOCModel).where(
            IOCModel.ioc_type == ioc_type,
            IOCModel.normalized == normalized,
        )
        return self.db.execute(stmt).scalars().first()

    def save_enrichment(self, ioc_id: int, enrichment: dict, now: datetime) -> None:
        """
        Merge enrichment data into the ioc row's enrichment_json field.
        Accumulates across multiple enrichment runs rather than overwriting.
        """
        ioc = self.db.get(IOCModel, ioc_id)
        if ioc is None:
            return
        existing: dict = {}
        if ioc.enrichment_json:
            try:
                existing = json.loads(ioc.enrichment_json)
            except json.JSONDecodeError:
                existing = {}
        existing.update(enrichment)
        ioc.enrichment_json = json.dumps(existing)
        ioc.last_enriched_at = now
        self.db.add(ioc)
        self.db.commit()


# ── Cache ─────────────────────────────────────────────────────────────────────

class CacheRepo:
    def __init__(self, db: Session) -> None:
        self.db = db

    def init_db(self) -> None:
        from app.db.models import Base
        from app.db.session import _ENGINE
        Base.metadata.create_all(bind=_ENGINE)

    def get_cache_entry(self, key: str) -> CacheEntry | None:
        stmt = select(CacheEntry).where(CacheEntry.key == key)
        return self.db.execute(stmt).scalar_one_or_none()

    def upsert_cache_entry(self, key: str, value: str, expires_at: datetime) -> None:
        entry = self.get_cache_entry(key)
        if entry:
            entry.value = value
            entry.expires_at = expires_at
        else:
            entry = CacheEntry(key=key, value=value, expires_at=expires_at)
            self.db.add(entry)
        self.db.commit()


# ── Probe ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class InsertProbeResult:
    probe_id: int


class ProbeRepo:
    def __init__(self, db: Session) -> None:
        self.db = db

    def init_db(self) -> None:
        from app.db.models import Base
        from app.db.session import _ENGINE
        Base.metadata.create_all(bind=_ENGINE)

    def save_probe_result(self, result: dict) -> InsertProbeResult:
        probe = Probe(
            ip=result["ip"],
            port=result["port"],
            status=result["status"],
            banner=result.get("banner"),
            created_at=datetime.now(UTC),
        )
        self.db.add(probe)
        self.db.commit()
        self.db.refresh(probe)
        return InsertProbeResult(probe_id=probe.id)

    def list_probes(self, limit: int = 100) -> list[Probe]:
        stmt = select(Probe).order_by(Probe.id.desc()).limit(limit)
        return list(self.db.execute(stmt).scalars().all())

    def get_probe(self, probe_id: int) -> Probe | None:
        stmt = select(Probe).where(Probe.id == probe_id)
        return self.db.execute(stmt).scalar_one_or_none()


# ── Report ────────────────────────────────────────────────────────────────────

class ReportRepo:
    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, title: str, markdown: str, params: dict) -> ReportModel:
        row = ReportModel(
            title=title,
            params_json=json.dumps(params),
            markdown=markdown,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def get_by_id(self, report_id: int) -> ReportModel | None:
        stmt = select(ReportModel).where(ReportModel.id == report_id)
        return self.db.execute(stmt).scalars().first()

    def list_reports(self, limit: int = 50) -> list[ReportModel]:
        stmt = select(ReportModel).order_by(ReportModel.id.desc()).limit(limit)
        return list(self.db.execute(stmt).scalars().all())