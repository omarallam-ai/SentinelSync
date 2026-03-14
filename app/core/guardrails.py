from __future__ import annotations

"""
Probe guardrails — enforced before any socket.connect() call.

Rules:
- By default only RFC-1918 private ranges and loopback are allowed.
- Public targets require ``SENTINELSYNC_ALLOW_PUBLIC_PROBES=true`` in env.
- Domains are resolved to check if the resulting IP is allowed.
- All validation raises ``ValueError`` with a clear message on rejection.
"""

import ipaddress
import logging
import socket

log = logging.getLogger("sentinelsync.guardrails")

# ── RFC-1918 private + loopback + link-local ranges ──────────────────────────
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 ULA
]


def _is_private(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if address falls in any private/loopback/link-local range."""
    return any(addr in net for net in _PRIVATE_NETWORKS)


def validate_target(target: str) -> bool:
    """
    Validate that *target* (IP string or hostname) is allowed to be probed.

    Raises:
        ValueError: if the target is not permitted under current settings.

    Returns:
        True when the target is allowed.
    """
    # Import here to avoid circular import at module load time
    from app.core.config import settings

    # Resolve hostname → IP so the IP-range check always applies
    try:
        resolved = socket.gethostbyname(target)
        addr = ipaddress.ip_address(resolved)
    except (socket.gaierror, ValueError) as exc:
        raise ValueError(f"Cannot resolve target '{target}': {exc}") from exc

    if _is_private(addr):
        log.debug(f"validate_target: {target} ({addr}) is private — allowed")
        return True

    if settings.allow_public_probes:
        log.warning(
            f"validate_target: probing public target {target} ({addr}) "
            "because SENTINELSYNC_ALLOW_PUBLIC_PROBES=true"
        )
        return True

    raise ValueError(
        f"Public probing is disabled. Target '{target}' resolves to {addr} "
        "(a public IP). Set SENTINELSYNC_ALLOW_PUBLIC_PROBES=true to enable."
    )