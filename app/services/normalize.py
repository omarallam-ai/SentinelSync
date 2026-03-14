from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from app.domain.types import IOCType


def normalize(ioc_type: IOCType, raw: str) -> str:
    raw = raw.strip()

    if ioc_type == IOCType.ip:
        return raw

    if ioc_type == IOCType.hash_sha256:
        return raw.lower()

    if ioc_type == IOCType.domain:
        return raw.strip(".").lower()

    if ioc_type == IOCType.url:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()
        path = parts.path or "/"
        # drop fragment, keep query (often important)
        return urlunsplit((scheme, netloc, path, parts.query, ""))

    return raw