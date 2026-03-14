from __future__ import annotations

"""
IP address enrichment service.

Saves enrichment data directly into iocs.enrichment_json.
Uses ip-api.com (geo) and URLhaus /v1/host/ (threat intel).
"""

import ipaddress
import logging
from datetime import UTC, datetime

from app.core.config import settings
from app.core.http import fetch_ip_metadata, query_urlhaus_host
from app.db.repo import CacheRepo, IOCRepo
from app.db.session import get_session
from app.services.cache import CacheService

log = logging.getLogger("sentinelsync.enrich_ip")


def _parse_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(ip_str.strip())


def enrich_ip(ip_str: str) -> dict:
    """
    Enrich an IP address indicator via ip-api.com and URLhaus /v1/host/.
    Saves results into iocs.enrichment_json on the existing IOC row.
    Results are cached in cache_entries.
    """
    try:
        ip_obj = _parse_ip(ip_str)
    except ValueError as exc:
        return {"error": f"Invalid IP address: {exc}"}

    cache_key = f"enrich_ip:{ip_str}"
    now = datetime.now(UTC)

    with get_session() as db:
        # Ensure all tables exist — enrichment can be called before any ingest
        IOCRepo(db).init_db()

        cache = CacheService(CacheRepo(db))
        cached = cache.get(cache_key, now)
        if cached is not None:
            log.debug(f"enrich_ip cache hit ip={ip_str}")
            cached["from_cache"] = True
            return cached

        skip_external = (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
        )

        result: dict = {
            "ip": ip_str,
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_reserved": ip_obj.is_reserved,
            "is_link_local": ip_obj.is_link_local,
            "isp": None,
            "asn": None,
            "org": None,
            "country": None,
            "urlhaus_host_status": None,
            "urlhaus_host_urls_count": None,
            "sources": [],
            "from_cache": False,
        }

        if not skip_external:
            # ip-api.com geolocation (no auth required)
            metadata = fetch_ip_metadata(ip_str)
            if "error" not in metadata:
                result.update({
                    "asn": metadata.get("asn"),
                    "org": metadata.get("org"),
                    "country": metadata.get("country"),
                    "isp": metadata.get("isp"),
                })
                result["sources"].append("ip-api.com")
            else:
                log.warning(f"enrich_ip ip-api failed ip={ip_str}: {metadata['error']}")

            # URLhaus /v1/host/ (no auth needed)
            uh_resp = query_urlhaus_host(ip_str)
            if "error" not in uh_resp:
                result["urlhaus_host_status"] = uh_resp.get("query_status")
                urls = uh_resp.get("urls") or []
                result["urlhaus_host_urls_count"] = len(urls)
                result["sources"].append("urlhaus-host")
            else:
                log.debug(f"enrich_ip urlhaus-host failed ip={ip_str}: {uh_resp.get('error')}")

        # Find existing IOC or create it, then save enrichment into its row
        repo = IOCRepo(db)
        ioc = repo.get_by_normalized("ip", ip_str)
        if ioc is None:
            insert = repo.upsert_many(
                [{"ioc_type": "ip", "raw": ip_str, "normalized": ip_str, "source": "enrich_ip"}]
            )
            ioc_id = insert.ids[0] if insert.ids else None
        else:
            ioc_id = ioc.id

        if ioc_id:
            repo.save_enrichment(ioc_id, result, now)
            log.info(f"enrich_ip saved ioc_id={ioc_id} ip={ip_str} private={skip_external}")
        else:
            log.warning(f"enrich_ip could not resolve ioc_id for ip={ip_str}")

        cache.set(cache_key, result, settings.cache_ttl_ok, now)
        return result