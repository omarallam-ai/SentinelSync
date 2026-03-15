# SentinelSync

> A defensive threat intelligence pipeline for SOC-style IOC triage — built for Windows.

---

## Overview

SentinelSync turns raw text — phishing emails, alert logs, ticket notes — into a structured, scored, and explainable threat intelligence snapshot. It extracts indicators of compromise (IPs, domains, URLs, SHA-256 hashes), enriches them using two public threat intelligence sources, optionally runs safe TCP connect probes under strict guardrails, scores everything using deterministic rules, and generates a clean Markdown report. The entire pipeline runs locally on Windows with SQLite — no Docker, no cloud, no paid APIs required.

Built across 7 milestones to demonstrate production-grade engineering discipline: clean architecture, structured logging with correlation IDs, TTL caching, retry/backoff, multiprocessing, and full CI with security scanning.

---

## Features

- **IOC Extraction** — regex-based extraction of IPs, domains, URLs, and SHA-256 hashes from any raw text, with false-positive filtering for file extensions falsely matched as domains (`dropper.exe`, `gate.php`, etc.)
- **Dual Enrichment Sources** — ip-api.com for geolocation/ASN (no key needed) and URLhaus abuse.ch for malicious URL/host intelligence (host endpoint is public)
- **Inline Enrichment Storage** — enrichment data is stored directly on the IOC row (`enrichment_json`) — no separate joins needed, no orphaned records
- **Deterministic Scoring** — explainable rules produce a 0–100 score with human-readable reasons persisted to the DB; same data always produces same score
- **Safe TCP Probing** — connect-only probes with strict RFC-1918 allowlist; public IPs blocked by default; hard caps on ports and workers
- **TTL Cache** — all external API calls are cached in SQLite to prevent re-querying the same indicators
- **Multiprocessing Pipeline** — parallel enrichment and probing via `multiprocessing.Pool` with graceful Ctrl-C shutdown
- **Markdown Reports** — severity-labelled (🔴🟡🟢⚪) reports with enrichment data, score reasons, and probe results per IOC
- **REST API** — FastAPI with correlation ID middleware, structured JSON logging, and proper route ordering
- **Full Test Suite** — unit tests, integration tests, mocked network calls; no test touches a real network or real DB

---

## Requirements

- **Python** 3.11+
- **OS** Windows 10/11 (also works on Linux/macOS)

```
typer>=0.12
fastapi>=0.111
uvicorn>=0.30
pydantic>=2.7
pydantic-settings>=2.3
requests>=2.32
beautifulsoup4>=4.12
sqlalchemy>=2.0
```

Dev dependencies: `pytest`, `httpx`, `ruff`, `bandit`, `pip-audit`

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/omarallam-ai/SentinelSync.git
cd sentinelsync

# 2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 3. Install the package and all dependencies
pip install -e ".[dev]"

# 4. Create your environment file
copy .env.example .env
```

`.env.example`:
```
SENTINELSYNC_DB_PATH=./sentinelsync.db
SENTINELSYNC_LOG_LEVEL=INFO
SENTINELSYNC_URLHAUS_AUTH_KEY=        # optional — get free key at urlhaus.abuse.ch
```

---

## Quick Start

```bash
# Extract and store IOCs from a text file
sentinelsync ingest --file sample_alert.txt

# Or paste raw text directly
sentinelsync ingest --text "Suspicious IP 185.220.101.47 contacted http://malware-cdn.biz/payload.exe"

# Enrich stored IOCs (ip-api.com + URLhaus host lookup)
sentinelsync enrich --limit 50 --workers 2

# Score all IOCs using enrichment + probe data
sentinelsync score

# Generate a Markdown threat intel report
sentinelsync report --title "Case 2024-001" --out report.md

# Start the REST API
sentinelsync serve --port 8000
```

**Example output after enrichment and scoring:**

```
Scored:  14
High:    1
Medium:  2
Low:     6
```

**Example report excerpt:**

```markdown
| # | Type   | Normalized              | Score      | Enriched | Source |
|---|--------|-------------------------|------------|----------|--------|
| 1 | `url`  | `http://malware-cdn.biz`| 60 🟡 MEDIUM | ✓      | cli    |
| 2 | `ip`   | `185.220.101.47`        | 20 🟢 LOW  | ✓        | cli    |
| 3 | `hash_sha256` | `deadbeef...`    | 5 🟢 LOW   | –        | cli    |
```

---

## REST API

Start the server with `sentinelsync serve`, then open `http://127.0.0.1:8000/docs` for the interactive Swagger UI.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/iocs/ingest` | Extract and store IOCs from raw text or file |
| `GET` | `/iocs` | List stored IOCs (filter by type, min score) |
| `GET` | `/iocs/{id}` | Get a single IOC with full enrichment data |
| `POST` | `/iocs/score` | Score all IOCs from stored enrichment |
| `POST` | `/enrich/ip` | Enrich a single IP directly |
| `POST` | `/enrich/urlhaus` | Enrich a single URL directly |
| `POST` | `/probes` | Run a safe TCP probe on an IP |
| `POST` | `/reports` | Generate and persist a Markdown report |
| `GET` | `/reports/{id}` | Retrieve a previously generated report |
| `GET` | `/health` | Health check |

```bash
# Example: ingest via API
curl -X POST "http://127.0.0.1:8000/iocs/ingest?text=8.8.8.8%20http://evil.com"

# Example: get scored IOCs above threshold
curl "http://127.0.0.1:8000/iocs?min_score=20"
```

---

## Architecture

```
Raw text / file
    │
    ▼
INGEST  →  EXTRACT (regex + fake-TLD filter)
    │
    ▼
NORMALIZE  →  DEDUPLICATE  →  SQLite (iocs table)
    │
    ▼
ENRICH  →  ip-api.com (geo/ASN) + URLhaus (threat intel)
           └─ stored in iocs.enrichment_json (inline, no extra table)
           └─ cached in cache_entries (TTL-based)
    │
    ▼
PROBE  →  TCP connect-only (RFC-1918 only by default)
          └─ stored in probes table
    │
    ▼
SCORE  →  deterministic rules → score + reasons written to iocs row
    │
    ▼
REPORT  →  Markdown with severity labels, enrichment, probe results
```

**Database schema (3 tables):**

| Table | Purpose |
|-------|---------|
| `iocs` | Indicators + inline enrichment + scores |
| `cache_entries` | TTL cache for external API calls |
| `probes` | TCP probe results |

---

## Technical Highlights

### Security Guardrails
- Public IP probing blocked by default; requires explicit opt-in via `SENTINELSYNC_ALLOW_PUBLIC_PROBES=true`
- Hard caps on worker count (max 8) and probe ports (max 10) — enforced in code, not just docs
- No credentials ever hardcoded; all keys come from `.env` via Pydantic Settings
- Log injection prevention — newlines escaped, field length capped at 2000 chars

### Engineering Practices
- **Structured logging** — JSON log lines with correlation IDs per request/command, propagated through multiprocessing workers
- **Retry + backoff** — all HTTP calls use `urllib3.Retry` with exponential backoff and 429 Retry-After handling
- **Idempotent DB init** — `Base.metadata.create_all()` called on every code path that touches the DB, so enrichment works from a cold start without a prior ingest
- **Enrichment merging** — `save_enrichment()` merges new data with existing `enrichment_json` rather than overwriting, so multiple enrichment passes accumulate
- **False-positive filtering** — domain regex filters out 40+ file extensions (`exe`, `dll`, `php`, `pdf`, ...) that look like TLDs but aren't
- **Deterministic scoring** — rules applied in fixed order; same DB state always produces same score; reasons persisted alongside score for audit trail

### Testing
```bash
# Run all tests
pytest -q

# Run with coverage
pytest --cov=app --cov-report=term-missing

# Security scan
bandit -r app -q

# Dependency audit
pip-audit
```

- Unit tests for extraction, normalization, scoring, caching, pipeline orchestration
- Integration tests for all API endpoints using `TestClient` with isolated in-memory DB per test
- All network calls mocked — no test requires internet access
- Pipeline tests verify multiprocessing behaviour, worker caps, and graceful Ctrl-C handling

---

## Engineering Decisions

**Why store enrichment inline on the IOC row instead of a separate table?**
A separate `enrichments` table introduced a subtle bug: `upsert_many()` silently failed on duplicate IOCs and returned `ids=[]`, so the foreign key was never set and enrichment rows were never saved. Storing enrichment as a JSON blob directly on the IOC row eliminates the join, eliminates the orphan-record problem, and makes the scoring service a simple `json.loads(ioc.enrichment_json)` — no query needed.

**Why deterministic scoring over ML?**
For a defensive triage tool, reproducibility and auditability matter more than precision. An analyst needs to know *why* an indicator scored 60, not just that it did. Every rule produces a human-readable reason string that's persisted alongside the score, making results explainable and debuggable.

**Why multiprocessing instead of async?**
The enrichment pipeline makes blocking HTTP calls to external APIs. `asyncio` would require async-compatible HTTP clients and async SQLAlchemy throughout. `multiprocessing.Pool` lets each worker use standard `requests` and its own SQLite session — simpler, safer on Windows (spawn model), and gets real parallelism for CPU-bound normalization work too.

---

## Project Structure

```
sentinelsync/
├── app/
│   ├── api/
│   │   └── routes.py          # FastAPI endpoints
│   ├── cli/
│   │   └── main.py            # Typer CLI commands
│   ├── core/
│   │   ├── config.py          # Pydantic Settings
│   │   ├── guardrails.py      # Probe safety enforcement
│   │   ├── http.py            # Hardened HTTP client
│   │   ├── logging.py         # Structured JSON logging
│   │   └── scoring.py         # Deterministic scoring rules
│   ├── db/
│   │   ├── models.py          # SQLAlchemy models (iocs, cache_entries, probes)
│   │   ├── repo.py            # Repository pattern
│   │   └── session.py         # Engine + session factory
│   ├── domain/
│   │   └── types.py           # IOCType enum
│   └── services/
│       ├── cache.py           # TTL cache service
│       ├── enrich_ip.py       # IP enrichment (ip-api + URLhaus host)
│       ├── enrich_urlhaus.py  # URL/domain enrichment (URLhaus)
│       ├── extract.py         # IOC extraction with fake-TLD filter
│       ├── ingest.py          # Text ingestion pipeline
│       ├── normalize.py       # Canonical form normalisation
│       ├── pipeline.py        # Multiprocessing orchestration
│       ├── probe_tcp.py       # Safe TCP connect probe
│       └── report.py          # Markdown report generator
└── tests/
    ├── unit/                  # Pure unit tests (no network, no real DB)
    └── test_routes.py         # API integration tests
```

---

## Author

Built as a portfolio project demonstrating SOC-adjacent engineering: defensive tooling, clean architecture, and production-grade practices on a Windows-first stack.

---

## Methodology Note

All data enrichment, URL/IP investigations, and threat analysis were performed manually using SentinelSync. AI assistance was used only to plan the project, write tests, add comments, and produce well-structured, polished documentation.
