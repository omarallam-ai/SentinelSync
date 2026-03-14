from __future__ import annotations

"""
Safe TCP connect-only probe with banner grab and DB persistence.
"""

import logging
import socket

from app.core.config import settings
from app.core.guardrails import validate_target
from app.db.repo import ProbeRepo
from app.db.session import get_session

log = logging.getLogger("sentinelsync.probe_tcp")

_HTTP_PORTS = {80, 443, 8000, 8080, 8443}


def probe_tcp(ip: str, port: int, *, db: object = None) -> dict:
    """
    Attempt a TCP connection to *ip*:*port* and optionally grab a banner.

    Args:
        ip:   Target hostname or IP string.
        port: TCP port number.
        db:   Ignored — accepted so existing tests can pass ``db=None``
              without breaking. DB access uses its own session internally.

    Returns:
        dict with keys: ip, port, status ("open"|"closed"), banner (str|None).

    Raises:
        ValueError: if the target is blocked by guardrails.
    """
    validate_target(ip)

    result: dict = {"ip": ip, "port": port, "status": "closed", "banner": None}

    try:
        with socket.create_connection((ip, port), timeout=settings.tcp_probe_timeout) as sock:
            result["status"] = "open"
            try:
                sock.settimeout(1)
                if port in _HTTP_PORTS:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = sock.recv(settings.tcp_probe_banner_bytes)
                if raw:
                    result["banner"] = raw.decode(errors="ignore")
            except OSError:
                pass
    except OSError:
        result["status"] = "closed"

    # Persist to DB (non-fatal)
    try:
        with get_session() as sess:
            ProbeRepo(sess).save_probe_result(result)
    except Exception as exc:  # noqa: BLE001
        log.warning(f"probe_tcp DB persist failed ip={ip} port={port}: {exc}")

    log.info(f"probe_tcp done ip={ip} port={port} status={result['status']}")
    return result