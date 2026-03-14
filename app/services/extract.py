from __future__ import annotations

import re
from dataclasses import dataclass

from app.domain.types import IOCType

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,63})\b")

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"]+\b", re.IGNORECASE)

_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# File extensions that the domain regex falsely matches.
# These are NOT valid domain TLDs — filter them out.
_FAKE_TLDS = {
    "exe", "dll", "php", "asp", "aspx", "jsp", "py", "rb", "sh", "bat",
    "ps1", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "gz", "tar", "7z",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp",
    "mp3", "mp4", "avi", "mov", "mkv",
    "bin", "dat", "log", "txt", "csv", "json", "xml", "html", "htm",
    "css", "js", "ts", "go", "rs", "c", "cpp", "h",
}


@dataclass(frozen=True)
class ExtractedIOC:
    ioc_type: IOCType
    raw: str


def _is_fake_domain(candidate: str) -> bool:
    """Return True if the candidate looks like a filename, not a real domain."""
    tld = candidate.rsplit(".", 1)[-1].lower()
    return tld in _FAKE_TLDS


def extract_iocs(text: str) -> list[ExtractedIOC]:
    found: list[ExtractedIOC] = []

    # URLs first — domains inside URLs are captured here, not again below
    url_spans: list[tuple[int, int]] = []
    for m in _URL_RE.finditer(text):
        found.append(ExtractedIOC(IOCType.url, m.group(0)))
        url_spans.append((m.start(), m.end()))

    for m in _IP_RE.finditer(text):
        found.append(ExtractedIOC(IOCType.ip, m.group(0)))

    for m in _SHA256_RE.finditer(text):
        found.append(ExtractedIOC(IOCType.hash_sha256, m.group(0)))

    # Domains last — skip anything inside a URL span and skip fake TLDs
    for m in _DOMAIN_RE.finditer(text):
        # Skip if this match is inside a URL already captured
        in_url = any(s <= m.start() and m.end() <= e for s, e in url_spans)
        if in_url:
            continue
        candidate = m.group(0)
        if _is_fake_domain(candidate):
            continue
        found.append(ExtractedIOC(IOCType.domain, candidate))

    return found