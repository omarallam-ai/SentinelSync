from __future__ import annotations

from unittest.mock import MagicMock, patch

from app.services.probe_tcp import probe_tcp


def test_open_port_detected():
    """probe_tcp returns status=open and captures the banner."""

    class FakeSocket:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, x):
            pass
        def recv(self, x):
            return b"SSH-2.0-OpenSSH_8.9"

    with (
        patch("socket.create_connection", return_value=FakeSocket()),
        patch("app.services.probe_tcp.get_session") as mock_sess,
    ):
        # Make DB persistence a no-op
        mock_db = MagicMock()
        mock_db.__enter__ = MagicMock(return_value=mock_db)
        mock_db.__exit__ = MagicMock(return_value=False)
        mock_sess.return_value = mock_db

        result = probe_tcp("192.168.1.10", 22)   # no db= kwarg — probe_tcp manages its own session

    assert result["status"] == "open"
    assert result["banner"] == "SSH-2.0-OpenSSH_8.9"
    assert result["ip"] == "192.168.1.10"
    assert result["port"] == 22


def test_closed_port_detected():
    """probe_tcp returns status=closed when connection is refused."""
    import socket

    with (
        patch("socket.create_connection", side_effect=ConnectionRefusedError),
        patch("app.services.probe_tcp.get_session") as mock_sess,
    ):
        mock_db = MagicMock()
        mock_db.__enter__ = MagicMock(return_value=mock_db)
        mock_db.__exit__ = MagicMock(return_value=False)
        mock_sess.return_value = mock_db

        result = probe_tcp("192.168.1.10", 9999)

    assert result["status"] == "closed"
    assert result["banner"] is None


def test_public_ip_raises_value_error():
    """probe_tcp raises ValueError for public IPs when probing is disabled."""
    import app.core.config as cfg
    original = cfg.settings.allow_public_probes
    cfg.settings.allow_public_probes = False
    try:
        import pytest
        with pytest.raises(ValueError):
            probe_tcp("8.8.8.8", 80)
    finally:
        cfg.settings.allow_public_probes = original