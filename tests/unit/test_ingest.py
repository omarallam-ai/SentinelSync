import pytest

from app.services.ingest import ingest_text


def test_ingest_text_builds_rows():
    text = "ip 1.2.3.4 and https://example.com/a"
    res = ingest_text(text, source="cli")
    assert res.extracted >= 2
    assert all("ioc_type" in r and "raw" in r and "normalized" in r for r in res.rows)


def test_ingest_rejects_too_large(monkeypatch):
    from app.core import config

    monkeypatch.setattr(config.settings, "max_input_chars", 10)
    with pytest.raises(ValueError):
        ingest_text("x" * 11, source="cli")