from __future__ import annotations

"""
Markdown threat intel report generator.

Reads enrichment from ioc.enrichment_json (stored inline on IOC row).
Reads probe data from the probes table.
No separate enrichments table needed.
"""

import json
import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import IOCModel, Probe

log = logging.getLogger("sentinelsync.report")


def _fmt_score(score: int) -> str:
    if score >= 70:
        return f"{score} 🔴 HIGH"
    if score >= 40:
        return f"{score} 🟡 MEDIUM"
    if score > 0:
        return f"{score} 🟢 LOW"
    return f"{score} ⚪ NONE"


def _ioc_table(iocs: list[IOCModel]) -> str:
    rows = [
        "| # | Type | Normalized | Score | Enriched | Source |",
        "|---|------|------------|-------|----------|--------|",
    ]
    for i, ioc in enumerate(iocs, 1):
        enriched = "✓" if ioc.last_enriched_at else "–"
        rows.append(
            f"| {i} | `{ioc.ioc_type}` | `{ioc.normalized}` "
            f"| {_fmt_score(ioc.score)} | {enriched} | {ioc.source} |"
        )
    return "\n".join(rows)


def _enrichment_section(ioc: IOCModel) -> str:
    """Render enrichment data stored in ioc.enrichment_json."""
    if not ioc.enrichment_json:
        return "_No enrichment data._\n"

    try:
        data = json.loads(ioc.enrichment_json)
    except json.JSONDecodeError:
        return "_Enrichment data corrupt._\n"

    if not data:
        return "_No enrichment data._\n"

    lines = []

    # ── geolocation fields ────────────────────────────────────────────────
    for key in ("country", "org", "isp", "asn"):
        val = data.get(key)
        if val:
            lines.append(f"- **{key}:** `{val}`")

    # ── URLhaus URL endpoint fields ───────────────────────────────────────
    if data.get("urlhaus_status"):
        lines.append(f"- **URLhaus status:** `{data['urlhaus_status']}`")
    if data.get("urlhaus_threat"):
        lines.append(f"- **URLhaus threat:** `{data['urlhaus_threat']}`")
    tags = data.get("urlhaus_tags") or []
    if tags:
        lines.append(f"- **URLhaus tags:** {', '.join(f'`{t}`' for t in tags)}")

    # ── URLhaus host endpoint fields ──────────────────────────────────────
    if data.get("urlhaus_host_status"):
        lines.append(f"- **URLhaus host status:** `{data['urlhaus_host_status']}`")
    count = data.get("urlhaus_host_urls_count")
    if count is not None:
        lines.append(f"- **URLhaus malicious URLs on host:** {count}")

    # ── sources ───────────────────────────────────────────────────────────
    sources = data.get("sources") or []
    if sources:
        lines.append(f"- **Sources:** {', '.join(sources)}")

    if not lines:
        return "_Enrichment present but no displayable fields._\n"

    ts = ioc.last_enriched_at.strftime("%Y-%m-%d %H:%M UTC") if ioc.last_enriched_at else "unknown"
    lines.append(f"- **Last enriched:** {ts}")

    return "\n".join(lines) + "\n"


def _probe_section(db: Session, ioc: IOCModel) -> str:
    probes = list(
        db.execute(
            select(Probe).where(Probe.ip == ioc.normalized)
        ).scalars().all()
    )
    if not probes:
        return "_No probe data._\n"

    lines = []
    for p in probes:
        banner = f" — banner: `{p.banner[:60]}`" if p.banner else ""
        lines.append(f"- Port **{p.port}**: `{p.status}`{banner}")
    return "\n".join(lines) + "\n"


def generate_report(db: Session, title: str, limit: int = 200) -> str:
    """
    Generate a Markdown threat intel report from DB contents.
    Reads enrichment from ioc.enrichment_json, probes from probes table.
    """
    iocs = list(
        db.execute(
            select(IOCModel)
            .order_by(IOCModel.score.desc(), IOCModel.id.desc())
            .limit(limit)
        ).scalars().all()
    )

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    high   = [i for i in iocs if i.score >= 70]
    medium = [i for i in iocs if 40 <= i.score < 70]
    low    = [i for i in iocs if 0 < i.score < 40]
    none_  = [i for i in iocs if i.score == 0]

    lines: list[str] = [
        f"# {title}",
        "",
        f"**Generated:** {now}  ",
        f"**Total IOCs:** {len(iocs)}  ",
        f"**High:** {len(high)} | **Medium:** {len(medium)} | **Low:** {len(low)} | **None:** {len(none_)}",
        "",
        "---",
        "",
    ]

    if iocs:
        lines += ["## Summary", "", _ioc_table(iocs), "", "---", ""]

    lines += ["## IOC Detail", ""]

    for ioc in iocs:
        reasons: list[str] = []
        try:
            reasons = json.loads(ioc.score_reasons) if ioc.score_reasons else []
        except json.JSONDecodeError:
            pass

        lines += [
            f"### `{ioc.normalized}` ({ioc.ioc_type})",
            "",
            f"- **Score:** {_fmt_score(ioc.score)}",
            f"- **Source:** {ioc.source}",
            f"- **Raw:** `{ioc.raw}`",
            f"- **First seen:** {ioc.created_at.strftime('%Y-%m-%d %H:%M UTC') if ioc.created_at else 'unknown'}",
            "",
        ]

        if reasons:
            lines.append("**Score reasons:**")
            for r in reasons:
                lines.append(f"- {r}")
            lines.append("")

        lines += ["**Enrichment:**", ""]
        lines.append(_enrichment_section(ioc))

        lines += ["**Probe results:**", ""]
        lines.append(_probe_section(db, ioc))
        lines += ["---", ""]

    return "\n".join(lines)