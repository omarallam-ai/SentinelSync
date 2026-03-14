from __future__ import annotations

"""
tests/unit/test_report.py

Tests the report generator. Enrichment is stored in ioc.enrichment_json.
"""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Base, IOCModel, Probe
from app.services.report import generate_report


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/report_test.db", future=True)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, future=True)
    with Session() as session:
        yield session


def _make_ioc(db, ioc_type="ip", normalized="1.2.3.4", score=0,
              reasons=None, enrichment=None) -> IOCModel:
    from datetime import UTC, datetime
    ioc = IOCModel(
        ioc_type=ioc_type,
        raw=normalized,
        normalized=normalized,
        source="test",
        score=score,
        score_reasons=json.dumps(reasons or []),
        enrichment_json=json.dumps(enrichment) if enrichment else None,
        last_enriched_at=datetime.now(UTC) if enrichment else None,
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


def test_report_empty_db(db):
    md = generate_report(db, title="Empty Report")
    assert "# Empty Report" in md
    assert "**Total IOCs:** 0" in md


def test_report_contains_normalized_value(db):
    _make_ioc(db, "ip", "192.168.99.99", score=20)
    md = generate_report(db, title="Case X")
    assert "192.168.99.99" in md
    assert "Case X" in md


def test_report_shows_enrichment_country(db):
    _make_ioc(db, "ip", "45.33.32.156", score=5, enrichment={
        "country": "US",
        "org": "AS63949 Linode",
        "sources": ["ip-api.com"],
    })
    md = generate_report(db, title="R")
    assert "country" in md
    assert "US" in md


def test_report_shows_urlhaus_threat(db):
    _make_ioc(db, "url", "http://evil.com/", score=60, enrichment={
        "urlhaus_status": "ok",
        "urlhaus_threat": "malware_download",
    })
    md = generate_report(db, title="R")
    assert "malware_download" in md


def test_report_shows_probe_data(db):
    ioc = _make_ioc(db, "ip", "10.0.0.5", score=15)
    p = Probe(ip="10.0.0.5", port=22, status="open", banner="SSH-2.0-test")
    db.add(p)
    db.commit()
    md = generate_report(db, title="R")
    assert "22" in md
    assert "open" in md


def test_report_sorts_by_score_descending(db):
    _make_ioc(db, "ip", "10.0.0.1", score=10)
    _make_ioc(db, "ip", "10.0.0.2", score=80)
    _make_ioc(db, "ip", "10.0.0.3", score=50)
    md = generate_report(db, title="R")
    pos_high = md.find("10.0.0.2")
    pos_mid  = md.find("10.0.0.3")
    pos_low  = md.find("10.0.0.1")
    assert pos_high < pos_mid < pos_low


def test_report_severity_labels(db):
    _make_ioc(db, "ip", "10.0.1.1", score=75)
    _make_ioc(db, "ip", "10.0.1.2", score=50)
    _make_ioc(db, "ip", "10.0.1.3", score=10)
    _make_ioc(db, "ip", "10.0.1.4", score=0)
    md = generate_report(db, title="R")
    assert "🔴 HIGH"   in md
    assert "🟡 MEDIUM" in md
    assert "🟢 LOW"    in md
    assert "⚪ NONE"   in md


def test_report_enriched_checkmark_in_table(db):
    _make_ioc(db, "ip", "10.0.2.1", enrichment={"country": "US"})
    _make_ioc(db, "ip", "10.0.2.2")  # no enrichment
    md = generate_report(db, title="R")
    assert "✓" in md   # enriched IOC
    assert "–" in md   # un-enriched IOC