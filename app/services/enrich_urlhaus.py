from __future__ import annotations

"""
URLhaus enrichment service.

Routes:
  Full URLs  → /v1/url/  (needs auth key)
  IPs/domains → /v1/host/ (public, no auth)

Saves enrichment into iocs.enrichment_json.
"""

import ipaddress
import logging
from datetime import UTC, datetime

from app.core.http import query_urlhaus_host, query_urlhaus_url
from app.db.repo import CacheRepo, IOCRepo
from app.db.session import get_session
from app.domain.types import IOCType
from app.services.cache import CacheService
from app.services.normalize import normalize

log = logging.getLogger("sentinelsync.enrich_urlhaus")


def _ioc_type_for(indicator: str) -> tuple[str, str]:
    """Return (ioc_type, normalized) for the indicator."""
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url", normalize(IOCType.url, indicator)
    try:
        ipaddress.ip_address(indicator)
        return "ip", indicator
    except ValueError:
        return "domain", normalize(IOCType.domain, indicator)


def enrich_urlhaus(indicator: str, auth_key: str = "") -> dict:
    """
    Enrich a URL, IP, or domain via URLhaus.
    Saves enrichment into the existing ioc row.
    """
    if not auth_key:
        try:
            from app.core.config import settings
            auth_key = settings.urlhaus_auth_key or ""
        except Exception:
            auth_key = ""

    ioc_type_str, normalized_val = _ioc_type_for(indicator)
    is_url = ioc_type_str == "url"

    cache_key = f"urlhaus:{'url' if is_url else 'host'}:{indicator}"
    now = datetime.now(UTC)

    with get_session() as db:
        # Ensure all tables exist before any DB operation
        IOCRepo(db).init_db()

        cache = CacheService(CacheRepo(db))
        cached = cache.get(cache_key, now)
        if cached is not None:
            log.debug(f"urlhaus cache hit {indicator}")
            cached["from_cache"] = True
            return cached

        # API call
        if is_url:
            api_response = query_urlhaus_url(indicator, auth_key)
        else:
            api_response = query_urlhaus_host(indicator)

        api_response["from_cache"] = False

        if "error" in api_response:
            cache.set(cache_key, api_response, 300, now)
            log.warning(f"urlhaus error {indicator}: {api_response['error']}")
            return api_response

        status = api_response.get("query_status", "")
        ttl = 3600 if status == "ok" else 300

        # Find or create IOC, then save enrichment
        repo = IOCRepo(db)
        ioc = repo.get_by_normalized(ioc_type_str, normalized_val)
        if ioc is None:
            insert = repo.upsert_many([{
                "ioc_type": ioc_type_str,
                "raw": indicator,
                "normalized": normalized_val,
                "source": "urlhaus",
            }])
            ioc_id = insert.ids[0] if insert.ids else None
        else:
            ioc_id = ioc.id

        if ioc_id:
            enrichment_data = {
                "urlhaus_status": status,
                "urlhaus_threat": api_response.get("threat"),
                "urlhaus_tags": api_response.get("tags"),
                "urlhaus_url_status": api_response.get("url_status"),
                "urlhaus_date_added": api_response.get("date_added"),
            }
            repo.save_enrichment(ioc_id, enrichment_data, now)
            log.info(f"urlhaus saved enrichment ioc_id={ioc_id} status={status} {indicator}")

        cache.set(cache_key, api_response, ttl, now)
        return api_response