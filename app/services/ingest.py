from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings
from app.services.extract import extract_iocs
from app.services.normalize import normalize


@dataclass(frozen=True)
class IngestResult:
    extracted: int
    rows: list[dict]

def ingest_text(text: str, source: str) -> IngestResult:
    if len(text) > settings.max_input_chars:
        raise ValueError(f"Input too large. Max chars = {settings.max_input_chars}")

    extracted = extract_iocs(text)
    rows: list[dict] = []

    for item in extracted:
        norm = normalize(item.ioc_type, item.raw)
        rows.append(
            {
                "ioc_type": item.ioc_type.value,
                "raw": item.raw,
                "normalized": norm,
                "source": source,
            }
        )

    return IngestResult(extracted=len(extracted), rows=rows)