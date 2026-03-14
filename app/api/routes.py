from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import configure_logging_api, set_correlation_id
from app.db.repo import IOCRepo, ProbeRepo, ReportRepo
from app.db.session import get_session
from app.services.ingest import ingest_text
from app.services.probe_tcp import probe_tcp

configure_logging_api(settings.log_level)
log = logging.getLogger("sentinelsync.api")

app = FastAPI(title="SentinelSync", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _create_tables() -> None:
    """Create all tables on startup so cache_entries etc. always exist."""
    with get_session() as db:
        IOCRepo(db).init_db()


@app.middleware("http")
async def _correlation_middleware(request: Request, call_next) -> Response:
    cid = request.headers.get("X-Correlation-ID") or uuid.uuid4().hex
    set_correlation_id(cid)
    response: Response = await call_next(request)
    response.headers["X-Correlation-ID"] = cid
    return response


# ── serialisers ───────────────────────────────────────────────────────────────

def _ioc_to_dict(ioc) -> dict:
    return {
        "id": ioc.id,
        "ioc_type": ioc.ioc_type,
        "raw": ioc.raw,
        "normalized": ioc.normalized,
        "source": ioc.source,
        "score": ioc.score,
        "score_reasons": ioc.score_reasons,
        "enrichment_json": ioc.enrichment_json,
        "last_enriched_at": str(ioc.last_enriched_at) if ioc.last_enriched_at else None,
        "created_at": str(ioc.created_at),
    }


def _probe_to_dict(p) -> dict:
    return {
        "id": p.id,
        "ip": p.ip,
        "port": p.port,
        "status": p.status,
        "banner": p.banner,
        "created_at": str(p.created_at),
    }


def _report_to_dict(row) -> dict:
    return {
        "report_id": row.id,
        "title": row.title,
        "created_at": str(row.created_at),
    }


# ── health ────────────────────────────────────────────────────────────────────

@app.get("/")
async def read_root() -> dict:
    return {"welcome to": "SentinelSync"}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


# ── IOC endpoints — specific paths BEFORE /{ioc_id} ──────────────────────────

@app.post("/iocs/ingest")
def ingest_iocs(text: Optional[str] = None, file: Optional[Path] = None) -> dict:
    cid = set_correlation_id()
    log.info(f"start ingest cid={cid}")

    if (text is None) == (file is None):
        raise HTTPException(status_code=400, detail="Provide exactly one of text or file")

    try:
        raw = text if text is not None else Path(file).read_text(encoding="utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to read file")

    with get_session() as db:
        repo = IOCRepo(db)
        repo.init_db()
        ing = ingest_text(raw, source="api")
        res = repo.upsert_many(ing.rows)

    return {"extracted": ing.extracted, "inserted": res.inserted, "deduped": res.deduped}


@app.post("/iocs/score")
def score_iocs(limit: int = 500) -> dict:
    from app.core.scoring import score_all
    with get_session() as db:
        results = score_all(db, limit=limit)
    return {"scored": len(results), "results": [{"ioc_id": r.ioc_id, "score": r.score} for r in results]}


@app.get("/iocs")
def list_iocs(limit: int = 100, ioc_type: Optional[str] = None, min_score: Optional[int] = None) -> list:
    with get_session() as db:
        iocs = IOCRepo(db).list_iocs(limit=limit)
    if ioc_type:
        iocs = [i for i in iocs if i.ioc_type == ioc_type]
    if min_score is not None:
        iocs = [i for i in iocs if i.score >= min_score]
    return [_ioc_to_dict(i) for i in iocs]


@app.get("/iocs/{ioc_id}")
def get_ioc(ioc_id: str) -> dict:
    with get_session() as db:
        ioc = IOCRepo(db).get_ioc(ioc_id)
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    return _ioc_to_dict(ioc)


# ── enrichment endpoints ──────────────────────────────────────────────────────

@app.post("/enrich/urlhaus")
def enrich_urlhaus_api(url: str, auth_key: str = "") -> dict:
    from app.services.enrich_urlhaus import enrich_urlhaus
    return enrich_urlhaus(url, auth_key)


@app.post("/enrich/ip")
def enrich_ip_api(ip: str) -> dict:
    from app.services.enrich_ip import enrich_ip
    return enrich_ip(ip)


# ── probe endpoints ───────────────────────────────────────────────────────────

@app.post("/probes")
def run_probe(ip: str, port: int) -> dict:
    try:
        return probe_tcp(ip, port)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/probes")
def list_probes(limit: int = 100) -> list:
    with get_session() as db:
        return [_probe_to_dict(p) for p in ProbeRepo(db).list_probes(limit=limit)]


@app.get("/probes/{probe_id}")
def get_probe_result(probe_id: int) -> dict:
    with get_session() as db:
        result = ProbeRepo(db).get_probe(probe_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Probe result not found")
    return _probe_to_dict(result)


# ── report endpoints ──────────────────────────────────────────────────────────

@app.post("/reports")
def create_report(title: str = "Threat Intel Report", limit: int = 200) -> dict:
    """Generate and persist a report. Returns report_id + markdown."""
    from app.services.report import generate_report
    with get_session() as db:
        markdown = generate_report(db, title=title, limit=limit)
        row = ReportRepo(db).save(title=title, markdown=markdown, params={"limit": limit})
    log.info(f"report created id={row.id} title={title!r}")
    return {"report_id": row.id, "title": row.title, "markdown": markdown}


@app.get("/reports/{report_id}")
def get_report(report_id: int) -> dict:
    with get_session() as db:
        row = ReportRepo(db).get_by_id(report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"report_id": row.id, "title": row.title, "markdown": row.markdown,
            "created_at": str(row.created_at)}


@app.get("/reports")
def list_reports(limit: int = 50) -> list:
    with get_session() as db:
        rows = ReportRepo(db).list_reports(limit=limit)
    return [_report_to_dict(r) for r in rows]