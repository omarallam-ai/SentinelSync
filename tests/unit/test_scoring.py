from __future__ import annotations

"""
tests/unit/test_scoring.py

Tests the scoring service against a real in-memory SQLite DB.
Enrichment is stored in ioc.enrichment_json — no separate enrichments table.
"""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Base, IOCModel, Probe
from app.core.scoring import ScoreResult, score_ioc, score_all


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/score_test.db", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        yield session


def _make_ioc(db, ioc_type="ip", normalized="1.2.3.4", source="test",
              score=0, enrichment=None) -> IOCModel:
    ioc = IOCModel(
        ioc_type=ioc_type,
        raw=normalized,
        normalized=normalized,
        source=source,
        score=score,
        enrichment_json=json.dumps(enrichment) if enrichment else None,
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


def _add_probe(db, ip: str, port: int, status: str, banner: str | None = None) -> None:
    p = Probe(ip=ip, port=port, status=status, banner=banner)
    db.add(p)
    db.commit()


# ── no enrichment ─────────────────────────────────────────────────────────────

def test_score_zero_with_no_enrichment_no_probe(db):
    ioc = _make_ioc(db, "ip", "10.0.0.1")
    result = score_ioc(db, ioc)
    assert result.score == 0
    assert any("No enrichment" in r for r in result.reasons)


# ── URLhaus rules via enrichment_json ─────────────────────────────────────────

def test_score_urlhaus_listed_adds_points(db):
    ioc = _make_ioc(db, "url", "http://evil.com/", enrichment={
        "urlhaus_status": "ok",
        "urlhaus_threat": "malware_download",
        "urlhaus_tags": ["exe", "malware"],
    })
    result = score_ioc(db, ioc)
    assert result.score >= 40
    assert any("URLhaus listed" in r for r in result.reasons)


def test_score_urlhaus_threat_adds_extra_points(db):
    ioc = _make_ioc(db, "url", "http://bad.com/x", enrichment={
        "urlhaus_status": "ok",
        "urlhaus_threat": "malware_download",
    })
    result = score_ioc(db, ioc)
    assert result.score >= 60   # listed (40) + threat (20)
    assert any("threat" in r for r in result.reasons)


def test_score_urlhaus_not_found_adds_nothing(db):
    ioc = _make_ioc(db, "url", "http://clean.com/", enrichment={
        "urlhaus_status": "no_results",
    })
    result = score_ioc(db, ioc)
    assert result.score == 0


def test_score_urlhaus_host_listed(db):
    ioc = _make_ioc(db, "ip", "1.2.3.4", enrichment={
        "urlhaus_host_status": "ok",
        "urlhaus_host_urls_count": 3,
    })
    result = score_ioc(db, ioc)
    assert result.score >= 40
    assert any("URLhaus host listed" in r for r in result.reasons)


# ── geo enrichment ────────────────────────────────────────────────────────────

def test_score_geo_enrichment_adds_points(db):
    ioc = _make_ioc(db, "ip", "185.220.101.47", enrichment={
        "country": "Germany",
        "org": "AS51396 Chaos Computer Club",
        "sources": ["ip-api.com"],
    })
    result = score_ioc(db, ioc)
    assert result.score >= 5
    assert any("Geo" in r for r in result.reasons)


# ── probe rules ───────────────────────────────────────────────────────────────

def test_score_open_port_adds_points(db):
    ioc = _make_ioc(db, "ip", "192.168.1.5")
    _add_probe(db, "192.168.1.5", 80, "open")
    result = score_ioc(db, ioc)
    assert result.score >= 15
    assert any("Open port" in r for r in result.reasons)


def test_score_suspicious_port_adds_extra(db):
    ioc = _make_ioc(db, "ip", "192.168.1.6")
    _add_probe(db, "192.168.1.6", 4444, "open")
    result = score_ioc(db, ioc)
    assert result.score >= 25   # open_port (15) + suspicious_port (10)
    assert any("Suspicious port" in r for r in result.reasons)


def test_score_closed_probe_adds_nothing(db):
    ioc = _make_ioc(db, "ip", "192.168.1.7")
    _add_probe(db, "192.168.1.7", 80, "closed")
    result = score_ioc(db, ioc)
    assert result.score == 0


# ── hash baseline ─────────────────────────────────────────────────────────────

def test_score_hash_gets_baseline(db):
    ioc = _make_ioc(db, "hash_sha256", "a" * 64)
    result = score_ioc(db, ioc)
    assert result.score == 5
    assert any("SHA-256" in r for r in result.reasons)


# ── score clamped ─────────────────────────────────────────────────────────────

def test_score_clamped_to_100(db):
    ioc = _make_ioc(db, "url", "http://very-evil.com/", enrichment={
        "urlhaus_status": "ok",
        "urlhaus_threat": "malware_download",
        "urlhaus_tags": ["ransomware"],
        "country": "RU",
        "org": "Bad Hosting",
    })
    _add_probe(db, "http://very-evil.com/", 4444, "open")
    result = score_ioc(db, ioc)
    assert 0 <= result.score <= 100


# ── score written back to DB ──────────────────────────────────────────────────

def test_score_written_back_to_ioc_row(db):
    ioc = _make_ioc(db, "ip", "192.168.2.1")
    _add_probe(db, "192.168.2.1", 22, "open")
    result = score_ioc(db, ioc)

    db.expire(ioc)
    db.refresh(ioc)
    assert ioc.score == result.score
    assert json.loads(ioc.score_reasons) == result.reasons


# ── score_all ─────────────────────────────────────────────────────────────────

def test_score_all_scores_every_ioc(db):
    for i in range(3):
        _make_ioc(db, "ip", f"10.0.0.{i + 1}")
    results = score_all(db, limit=10)
    assert len(results) == 3
    assert all(isinstance(r, ScoreResult) for r in results)