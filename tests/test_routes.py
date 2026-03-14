from __future__ import annotations

from pathlib import Path


# ---------- Basic API ----------

def test_root_ok(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"welcome to": "SentinelSync"}


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# ---------- /iocs (list) ----------

def test_list_iocs_empty_initially(client):
    r = client.get("/iocs")
    assert r.status_code == 200
    assert r.json() == []


def test_ingest_then_list_returns_rows(client):
    r1 = client.post("/iocs/ingest", params={"text": "8.8.8.8 http://example.com"})
    assert r1.status_code == 200, r1.text
    r2 = client.get("/iocs", params={"limit": 100})
    assert r2.status_code == 200
    assert len(r2.json()) >= 1


def test_list_respects_limit(client):
    client.post("/iocs/ingest", params={"text": "8.8.8.8 1.1.1.1 http://a.com http://b.com"})
    r = client.get("/iocs", params={"limit": 1})
    assert r.status_code == 200
    assert len(r.json()) <= 1


# ---------- /iocs/ingest ----------

def test_ingest_rejects_missing_both(client):
    r = client.post("/iocs/ingest")
    assert r.status_code == 400
    assert r.json()["detail"] == "Provide exactly one of text or file"


def test_ingest_rejects_both_text_and_file(client, tmp_path: Path):
    p = tmp_path / "a.txt"
    p.write_text("hello", encoding="utf-8")
    r = client.post("/iocs/ingest", params={"text": "abc", "file": str(p)})
    assert r.status_code == 400
    assert r.json()["detail"] == "Provide exactly one of text or file"


def test_ingest_file_read_failure_returns_400(client, tmp_path: Path):
    d = tmp_path / "dir"
    d.mkdir()
    r = client.post("/iocs/ingest", params={"file": str(d)})
    assert r.status_code == 400
    assert r.json()["detail"] == "Failed to read file"


def test_ingest_text_returns_counts(client):
    sample = "8.8.8.8 http://example.com d41d8cd98f00b204e9800998ecf8427e"
    r = client.post("/iocs/ingest", params={"text": sample})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body.keys()) == {"extracted", "inserted", "deduped"}
    assert body["extracted"] >= 1


def test_ingest_dedupes_on_second_run(client):
    sample = "8.8.8.8 http://example.com"
    r1 = client.post("/iocs/ingest", params={"text": sample})
    b1 = r1.json()
    r2 = client.post("/iocs/ingest", params={"text": sample})
    b2 = r2.json()
    assert b2["inserted"] <= b1["inserted"]
    assert b2["deduped"] >= 0


# ---------- SQL injection ----------

def test_sql_injection_payload_does_not_break_db(client):
    payload = "1'); DROP TABLE iocs; -- http://example.com 8.8.8.8"
    r1 = client.post("/iocs/ingest", params={"text": payload})
    assert r1.status_code == 200, r1.text
    r2 = client.get("/iocs")
    assert r2.status_code == 200
    assert isinstance(r2.json(), list)


def test_sql_injection_like_limit_rejected(client):
    r = client.get("/iocs", params={"limit": "1; DROP TABLE iocs; --"})
    assert r.status_code == 422


# ---------- /iocs/score ----------

def test_score_endpoint_empty_db_returns_zero(client):
    r = client.post("/iocs/score")
    assert r.status_code == 200
    assert r.json()["scored"] == 0


def test_score_endpoint_after_ingest(client):
    client.post("/iocs/ingest", params={"text": "8.8.8.8 http://example.com"})
    r = client.post("/iocs/score")
    assert r.status_code == 200
    body = r.json()
    assert body["scored"] >= 1
    assert all("score" in item for item in body["results"])


# ---------- /reports ----------

def test_create_report_returns_markdown(client):
    client.post("/iocs/ingest", params={"text": "8.8.8.8 http://evil.com"})
    r = client.post("/reports", params={"title": "Test Report"})
    assert r.status_code == 200
    body = r.json()
    assert "report_id" in body
    assert "markdown" in body
    assert "Test Report" in body["markdown"]


def test_get_report_by_id(client):
    client.post("/iocs/ingest", params={"text": "1.2.3.4"})
    r1 = client.post("/reports", params={"title": "Case 001"})
    rid = r1.json()["report_id"]
    r2 = client.get(f"/reports/{rid}")
    assert r2.status_code == 200
    assert r2.json()["title"] == "Case 001"


def test_get_report_not_found(client):
    r = client.get("/reports/99999")
    assert r.status_code == 404


def test_list_reports(client):
    client.post("/reports", params={"title": "R1"})
    client.post("/reports", params={"title": "R2"})
    r = client.get("/reports")
    assert r.status_code == 200
    assert len(r.json()) >= 2