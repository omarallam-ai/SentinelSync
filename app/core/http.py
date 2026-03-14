
from __future__ import annotations

__authkey = "e44e82ef72e9724e664c4b2163092fb5d2da9a361f1f7c96"


"""
Hardened HTTP client utilities.

- Separate connect and read timeouts (never a single integer).
- Exponential backoff on transient errors (5xx, network).
- 429 Rate-Limit detection with Retry-After respect.
- No hardcoded credentials.
- Errors returned as {"error": "..."} dicts.
"""

import logging
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("sentinelsync.http")

_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 10

_RETRY_POLICY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["GET", "POST"],
    raise_on_status=False,
)


def _build_session() -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=_RETRY_POLICY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers["User-Agent"] = "SentinelSync/1.0"
    return session


_SESSION = _build_session()


def _handle_429(response: requests.Response, attempt: int) -> None:
    retry_after = response.headers.get("Retry-After")
    try:
        wait = float(retry_after) if retry_after else 2 ** attempt
    except ValueError:
        wait = 2 ** attempt
    wait = min(wait, 60)
    log.warning(f"rate limited (429) — sleeping {wait:.1f}s (attempt {attempt})")
    time.sleep(wait)


def get_json(
    url: str,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: tuple[int, int] = (_CONNECT_TIMEOUT, _READ_TIMEOUT),
    max_attempts: int = 3,
) -> dict:
    for attempt in range(1, max_attempts + 1):
        try:
            resp = _SESSION.get(url, params=params, headers=headers, timeout=timeout)
            if resp.status_code == 429:
                _handle_429(resp, attempt)
                continue
            resp.raise_for_status()
            if not resp.text.strip():
                return {"error": "empty response"}
            return resp.json()
        except requests.RequestException as exc:
            log.warning(f"GET {url} attempt {attempt} failed: {exc}")
            if attempt == max_attempts:
                return {"error": str(exc)}
            time.sleep(2 ** (attempt - 1))
    return {"error": "max retries exceeded"}


def post_form(
    url: str,
    data: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: tuple[int, int] = (_CONNECT_TIMEOUT, _READ_TIMEOUT),
    max_attempts: int = 3,
) -> dict:
    for attempt in range(1, max_attempts + 1):
        try:
            resp = _SESSION.post(url, data=data, headers=headers, timeout=timeout)
            if resp.status_code == 429:
                _handle_429(resp, attempt)
                continue
            resp.raise_for_status()
            if not resp.text.strip():
                return {"error": "empty response"}
            return resp.json()
        except requests.RequestException as exc:
            log.warning(f"POST {url} attempt {attempt} failed: {exc}")
            if attempt == max_attempts:
                return {"error": str(exc)}
            time.sleep(2 ** (attempt - 1))
    return {"error": "max retries exceeded"}


def query_urlhaus_url(url: str, auth_key: str = "") -> dict:
    """URLhaus /v1/url/ — for full URL indicators. Requires auth key."""
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    headers: dict[str, str] = {}
    if auth_key:
        headers["Auth-Key"] = auth_key
    return post_form(api_url, data={"url": url}, headers=headers)


def query_urlhaus_host(host: str, auth_key: str = "") -> dict:
    """URLhaus /v1/host/ — for IP and domain indicators. No auth needed."""
    api_url = "https://urlhaus-api.abuse.ch/v1/host/"
    headers: dict[str, str] = {}
    if auth_key:
        headers["Auth-Key"] = auth_key
    return post_form(api_url, data={"host": host}, headers=headers)


def query_urlhaus(url: str, auth_key: str = "") -> dict:
    """Backwards-compat alias → query_urlhaus_url."""
    return query_urlhaus_url(url, auth_key)


def fetch_ip_metadata(ip_str: str) -> dict:
    """ip-api.com geolocation — free, no key required."""
    resp = get_json(f"http://ip-api.com/json/{ip_str}")
    if "error" in resp:
        return resp
    return {
        "country": resp.get("country"),
        "org": resp.get("org"),
        "isp": resp.get("isp"),
        "asn": resp.get("as"),
    }