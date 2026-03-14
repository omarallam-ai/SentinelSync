from __future__ import annotations

"""
Deterministic, explainable IOC scoring.

Reads enrichment data from ioc.enrichment_json (stored inline on the IOC row)
and probe results from the probes table. No separate enrichments table.

Rules fire in a fixed order — same DB state always produces same score.
Score + reasons are written back to ioc.score and ioc.score_reasons.
"""

import json
import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import IOCModel, Probe

log = logging.getLogger("sentinelsync.scoring")


@dataclass
class ScoreResult:
    ioc_id: int
    score: int
    reasons: list[str] = field(default_factory=list)


# ── scoring rules ─────────────────────────────────────────────────────────────
# Each rule receives the parsed enrichment dict and/or probe list.
# Returns (points, reason_string | None).  reason=None means rule did not fire.

def _rule_urlhaus_listed(enrichment: dict) -> tuple[int, str | None]:
    """+40 if URLhaus confirmed the indicator is listed (query_status=ok)."""
    if enrichment.get("urlhaus_status") == "ok":
        tags = enrichment.get("urlhaus_tags") or []
        tag_str = ", ".join(tags) if tags else "no tags"
        return 40, f"URLhaus listed (tags: {tag_str})"
    # Also handle host-endpoint format (urlhaus_host_status)
    if enrichment.get("urlhaus_host_status") == "ok":
        count = enrichment.get("urlhaus_host_urls_count", 0)
        return 40, f"URLhaus host listed ({count} malicious URL(s) known)"
    return 0, None


def _rule_urlhaus_threat(enrichment: dict) -> tuple[int, str | None]:
    """+20 if URLhaus threat field is non-empty (e.g. 'malware_download')."""
    threat = enrichment.get("urlhaus_threat") or ""
    if threat:
        return 20, f"URLhaus threat: {threat}"
    return 0, None


def _rule_geo_enriched(enrichment: dict) -> tuple[int, str | None]:
    """
    +5 if geolocation data is present (IP was successfully looked up).
    Informational only — just confirms the IP is reachable and public.
    """
    if enrichment.get("country") or enrichment.get("org"):
        country = enrichment.get("country", "unknown")
        org = enrichment.get("org", "unknown")
        return 5, f"Geo: {country} / {org}"
    return 0, None


def _rule_open_port_found(probes: list[Probe]) -> tuple[int, str | None]:
    """+15 if any probe found an open port."""
    open_ports = [p.port for p in probes if p.status == "open"]
    if open_ports:
        ports_str = ", ".join(str(p) for p in sorted(open_ports))
        return 15, f"Open port(s) detected: {ports_str}"
    return 0, None


def _rule_suspicious_port(probes: list[Probe]) -> tuple[int, str | None]:
    """+10 if a commonly-abused port is open (4444, 1337, 8888, 31337, ...)."""
    suspicious = {4444, 1337, 8888, 31337, 9999, 6666, 6667}
    found = [p.port for p in probes if p.status == "open" and p.port in suspicious]
    if found:
        return 10, f"Suspicious port(s) open: {', '.join(str(p) for p in sorted(found))}"
    return 0, None


def _rule_hash_ioc(ioc: IOCModel) -> tuple[int, str | None]:
    """+5 baseline for any SHA-256 hash indicator."""
    if ioc.ioc_type == "hash_sha256":
        return 5, "SHA-256 hash indicator (baseline)"
    return 0, None


def _rule_no_enrichment(ioc: IOCModel) -> tuple[int, str | None]:
    """Informational — records when the IOC has never been enriched (0 pts)."""
    if not ioc.enrichment_json:
        return 0, "No enrichment data available"
    return 0, None


# ── public API ────────────────────────────────────────────────────────────────

def score_ioc(db: Session, ioc: IOCModel) -> ScoreResult:
    """
    Score a single IOC from its enrichment_json and probe rows.
    Writes score + reasons back to the DB row.
    """
    # Parse inline enrichment data
    enrichment: dict = {}
    if ioc.enrichment_json:
        try:
            enrichment = json.loads(ioc.enrichment_json)
        except json.JSONDecodeError:
            log.warning(f"score_ioc: corrupt enrichment_json for ioc_id={ioc.id}")

    # Fetch probe rows for this IOC's normalized value
    probes = list(
        db.execute(
            select(Probe).where(Probe.ip == ioc.normalized)
        ).scalars().all()
    )

    total = 0
    reasons: list[str] = []

    # Explicit dispatch — each rule gets exactly what it needs
    for rule, args in [
        (_rule_urlhaus_listed,  (enrichment,)),
        (_rule_urlhaus_threat,  (enrichment,)),
        (_rule_geo_enriched,    (enrichment,)),
        (_rule_open_port_found, (probes,)),
        (_rule_suspicious_port, (probes,)),
        (_rule_hash_ioc,        (ioc,)),
        (_rule_no_enrichment,   (ioc,)),
    ]:
        pts, reason = rule(*args)  # type: ignore[call-arg]
        if reason:
            reasons.append(reason)
        total += pts

    final_score = max(0, min(100, total))

    ioc.score = final_score
    ioc.score_reasons = json.dumps(reasons)
    db.add(ioc)
    db.commit()

    log.info(f"scored ioc_id={ioc.id} score={final_score} reasons={len(reasons)}")
    return ScoreResult(ioc_id=ioc.id, score=final_score, reasons=reasons)


def score_all(db: Session, limit: int = 500) -> list[ScoreResult]:
    """Score all IOCs in the DB up to *limit*. Returns list of ScoreResult."""
    iocs = list(db.execute(select(IOCModel).limit(limit)).scalars().all())
    results = [score_ioc(db, ioc) for ioc in iocs]
    log.info(f"score_all done count={len(results)}")
    return results