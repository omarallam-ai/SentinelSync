from __future__ import annotations

from enum import StrEnum


class IOCType(StrEnum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash_sha256 = "hash_sha256"