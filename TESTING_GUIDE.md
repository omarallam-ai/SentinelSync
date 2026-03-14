# SentinelSync — Manual Testing Guide

Run every command from the root of your project (`SentinelSync/`).
The commands go in order — each step builds on the previous one.

---

## Setup (do this once)

```bash
pip install -e ".[dev]"
```

Create a `.env` file if you don't have one:

```
SENTINELSYNC_DB_PATH=./test-run.db
SENTINELSYNC_LOG_LEVEL=INFO
```

---

## Step 1 — Ingest from text directly

```bash
sentinelsync ingest --text "Suspicious IP 185.220.101.47 contacted http://malware-cdn.biz/payload/dropper.exe and domain evil-phish.net hash 3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c"
```

**Expected output:**
```
Extracted: 5
Inserted:  5
Deduped:   0
```

---

## Step 2 — Ingest from a file

Save `sample_threat_data.txt` somewhere, then:

```bash
sentinelsync ingest --file sample_threat_data.txt
```

**Expected output:**
```
Extracted: ~18
Inserted:  ~13   (some already exist from Step 1 → deduped)
Deduped:   ~5
```

Run it **again immediately** to confirm deduplication works:

```bash
sentinelsync ingest --file sample_threat_data.txt
```

**Expected:** `Inserted: 0  Deduped: ~13` — nothing new added.

---

## Step 3 — Score all IOCs (before enrichment)

```bash
sentinelsync score --limit 100
```

**Expected output:**
```
Scored:  13
High:    0
Medium:  0
Low:     0
```

All scores are 0 because there's no enrichment data yet. Hash IOCs get 5.

---

## Step 4 — Enrich a single URL manually (URLhaus live test)

This makes a real network call to abuse.ch. Most URLs in the sample are
fictional and will return "not found" — that's correct behaviour.

```bash
sentinelsync enrich --url "http://malware-cdn.biz/payload/dropper.exe"
```

**Expected:** JSON response with `query_status: "no_results"` or `"ok"` if
the URL happens to be in URLhaus. Either is a passing result.

---

## Step 5 — Enrich all IOCs via pipeline

```bash
sentinelsync enrich --limit 50 --workers 2
```

**Expected:**
```
Enriching 13/13...
Processed:  13
URLhaus OK: 0-2   (most fictional URLs return not_found)
IP OK:      3-5   (ip-api.com returns geo data for public IPs)
Errors:     0
```

If you see errors, check your internet connection. Private IPs (10.x, 192.168.x)
are skipped for external lookup — that's correct.

---

## Step 6 — Score again after enrichment

```bash
sentinelsync score --limit 100
```

**Expected:** Scores are now non-zero for IOCs that had enrichment data.
Hash IOCs all score 5 (baseline). Public IPs with ip-api data may score
higher if probe data is also present.

---

## Step 7 — Probe internal IPs (safe — RFC1918 only by default)

```bash
sentinelsync probe --ip 127.0.0.1 --port 80
```

**Expected:**
```json
{
  "ip": "127.0.0.1",
  "port": 80,
  "status": "closed",
  "banner": null
}
```

Try a port that's actually open on your machine:

```bash
sentinelsync probe --ip 127.0.0.1 --port 8000
```

If your FastAPI server is running (see Step 10), this will show `"status": "open"`.

---

## Step 8 — Try probing a public IP (should be blocked)

```bash
sentinelsync probe --ip 8.8.8.8 --port 53
```

**Expected error:**
```
Error: Public probing is disabled. Target '8.8.8.8' ...
```

To enable it (only for testing):

```bash
# Windows
set SENTINELSYNC_ALLOW_PUBLIC_PROBES=true
sentinelsync probe --ip 8.8.8.8 --port 53

# Then disable again
set SENTINELSYNC_ALLOW_PUBLIC_PROBES=false
```

---

## Step 9 — Generate a Markdown report

```bash
sentinelsync report --title "Case 2024-0314 Phishing" --out report.md
```

**Expected:**
```
Report saved to DB (id=1)
Written to: report.md
```

Open `report.md` and verify:
- Header with title and timestamp
- Summary table with all IOCs, scores, severity labels (🔴🟡🟢⚪)
- Per-IOC detail with enrichment data and probe results

---

## Step 10 — Start the API server

```bash
sentinelsync serve --port 8000
```

Open your browser to `http://127.0.0.1:8000/docs` — you'll see the full
interactive Swagger UI with all endpoints.

---

## Step 11 — Test the API with curl

Open a **second terminal** with the server running.

**Health check:**
```bash
curl http://127.0.0.1:8000/health
```
Expected: `{"status":"ok"}`

**Ingest via API:**
```bash
curl -X POST "http://127.0.0.1:8000/iocs/ingest?text=Test+IP+1.2.3.4+and+http://test.com"
```
Expected: `{"extracted":3,"inserted":2,"deduped":0}`

**List IOCs:**
```bash
curl "http://127.0.0.1:8000/iocs?limit=5"
```

**Score via API:**
```bash
curl -X POST "http://127.0.0.1:8000/iocs/score"
```

**Generate report via API:**
```bash
curl -X POST "http://127.0.0.1:8000/reports?title=API+Report"
```

**Get report by ID:**
```bash
curl "http://127.0.0.1:8000/reports/1"
```

---

## Step 12 — Run the full test suite

```bash
pytest -q
```

**Expected: all green.** You should see approximately 40+ tests passing.

To run only a specific group:

```bash
pytest tests/unit/test_scoring.py -v
pytest tests/unit/test_report.py -v
pytest tests/test_routes.py -v
```

---

## What to look for in `report.md`

| Section | What it proves |
|---|---|
| `**Total IOCs:**` header | Report generated successfully |
| `🔴 HIGH` rows | URLhaus matched + threat field set |
| `🟢 LOW` rows | Hash baseline scored, no enrichment hits |
| `⚪ NONE` rows | Private IPs, no data |
| Enrichment block | URLhaus / ip-api data persisted correctly |
| Probe block | TCP connect results stored correctly |
| Score reasons | Deterministic, human-readable, explains each point |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ImportError: cannot import name 'EnrichmentModel'` | Replace `models.py` with the M7 version |
| `PydanticSerializationError` | Replace `routes.py` with the M7 version |
| `Public probing is disabled` on private IP | Your IP resolved to a public address — check the IP is actually RFC1918 |
| `Extracted: 0` on ingest | Text has no recognisable IOCs — try pasting the sample data |
| `Errors: N` on enrich | Network issue or ip-api.com rate limit — wait 60s and retry |
| DB already exists from old schema | Delete `test-run.db` and re-run `ingest` |
