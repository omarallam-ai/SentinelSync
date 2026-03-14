from __future__ import annotations

import pytest

from app.core.guardrails import validate_target


def test_private_ip_allowed():
    assert validate_target("192.168.1.1") is True


def test_loopback_allowed():
    assert validate_target("127.0.0.1") is True


def test_link_local_allowed():
    assert validate_target("169.254.1.1") is True


def test_public_ip_denied_by_default():
    """Public IPs must be blocked when allow_public_probes=False (the default)."""
    # The original test did:  ALLOW_PUBLIC_PROBES = False  ← this is a local
    # variable assignment, it does NOT change the module constant.
    # Correct approach: patch settings.allow_public_probes via monkeypatch.
    import app.core.config as cfg
    original = cfg.settings.allow_public_probes
    cfg.settings.allow_public_probes = False
    try:
        with pytest.raises(ValueError, match="Public probing is disabled"):
            validate_target("8.8.8.8")
    finally:
        cfg.settings.allow_public_probes = original


def test_public_ip_allowed_when_flag_set():
    import app.core.config as cfg
    original = cfg.settings.allow_public_probes
    cfg.settings.allow_public_probes = True
    try:
        assert validate_target("8.8.8.8") is True
    finally:
        cfg.settings.allow_public_probes = original