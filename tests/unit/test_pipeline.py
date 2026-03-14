"""
tests/unit/test_pipeline.py

All network and DB calls are mocked — no real sockets, no real HTTP, no SQLite.

Patch targets use the module where the name is LOOKED UP, not where it's defined.
Since pipeline.py now imports get_session and IOCRepo at module level, the
correct patch paths are "app.services.pipeline.get_session" etc.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.services.pipeline import PipelineResult, run_enrich_pipeline, run_probe_pipeline


# ── helpers ───────────────────────────────────────────────────────────────────

def _fake_ioc(ioc_id: int, ioc_type: str = "ip", normalized: str = "1.2.3.4") -> MagicMock:
    m = MagicMock()
    m.id = ioc_id
    m.ioc_type = ioc_type
    m.normalized = normalized
    return m


def _mock_db_with_iocs(iocs: list, mock_sess, mock_repo_cls) -> None:
    """Wire get_session + IOCRepo to return the given ioc list."""
    mock_db = MagicMock()
    mock_db.__enter__ = MagicMock(return_value=mock_db)
    mock_db.__exit__ = MagicMock(return_value=False)
    mock_sess.return_value = mock_db
    mock_repo = MagicMock()
    mock_repo.list_iocs.return_value = iocs
    mock_repo_cls.return_value = mock_repo


# ── enrich pipeline ───────────────────────────────────────────────────────────

class TestEnrichPipeline:
    def test_empty_iocs_returns_zero_result(self):
        with (
            patch("app.services.pipeline.get_session") as ms,
            patch("app.services.pipeline.IOCRepo") as mr,
        ):
            _mock_db_with_iocs([], ms, mr)
            result = run_enrich_pipeline(limit=10, workers=2)

        assert result.processed == 0
        assert result.errors == 0
        assert result.urlhaus_ok == 0

    def test_workers_capped_at_settings_max(self):
        captured: list[int] = []

        def fake_pool(processes, initializer):
            captured.append(processes)
            pool = MagicMock()
            pool.imap_unordered.return_value = iter([])
            return pool

        with (
            patch("app.services.pipeline.get_session") as ms,
            patch("app.services.pipeline.IOCRepo") as mr,
            patch("app.services.pipeline.multiprocessing.Pool", side_effect=fake_pool),
            patch("app.services.pipeline._capped_workers", return_value=4),
        ):
            _mock_db_with_iocs([_fake_ioc(1)], ms, mr)
            run_enrich_pipeline(limit=10, workers=999)

        assert captured and captured[0] == 4

    def test_counts_urlhaus_and_ip_ok_correctly(self):
        fake_results = [
            {"ioc_id": 1, "urlhaus": "ok", "ip": "ok", "error": None},
            {"ioc_id": 2, "urlhaus": "not_found", "ip": "ok", "error": None},
            {"ioc_id": 3, "urlhaus": "skip", "ip": "skip", "error": "timeout"},
        ]

        with (
            patch("app.services.pipeline.get_session") as ms,
            patch("app.services.pipeline.IOCRepo") as mr,
            patch("app.services.pipeline.multiprocessing.Pool") as mp,
        ):
            _mock_db_with_iocs([_fake_ioc(i) for i in [1, 2, 3]], ms, mr)
            pool = MagicMock()
            pool.imap_unordered.return_value = iter(fake_results)
            mp.return_value = pool

            result = run_enrich_pipeline(limit=10, workers=2)

        assert result.processed == 3
        assert result.urlhaus_ok == 1
        assert result.ip_ok == 2
        assert result.errors == 1

    def test_progress_callback_called_once_per_ioc(self):
        calls: list[tuple[int, int]] = []
        fake_results = [
            {"ioc_id": 1, "urlhaus": "ok", "ip": "skip", "error": None},
            {"ioc_id": 2, "urlhaus": "ok", "ip": "skip", "error": None},
        ]

        with (
            patch("app.services.pipeline.get_session") as ms,
            patch("app.services.pipeline.IOCRepo") as mr,
            patch("app.services.pipeline.multiprocessing.Pool") as mp,
        ):
            _mock_db_with_iocs([_fake_ioc(1), _fake_ioc(2)], ms, mr)
            pool = MagicMock()
            pool.imap_unordered.return_value = iter(fake_results)
            mp.return_value = pool

            run_enrich_pipeline(
                limit=10, workers=2, progress_cb=lambda d, t: calls.append((d, t))
            )

        assert calls == [(1, 2), (2, 2)]

    def test_keyboard_interrupt_returns_partial_result(self):
        with (
            patch("app.services.pipeline.get_session") as ms,
            patch("app.services.pipeline.IOCRepo") as mr,
            patch("app.services.pipeline.multiprocessing.Pool") as mp,
        ):
            _mock_db_with_iocs([_fake_ioc(1), _fake_ioc(2)], ms, mr)
            pool = MagicMock()

            def _raise_after_one(fn, ids):
                yield {"ioc_id": 1, "urlhaus": "ok", "ip": "skip", "error": None}
                raise KeyboardInterrupt

            pool.imap_unordered.side_effect = _raise_after_one
            mp.return_value = pool

            result = run_enrich_pipeline(limit=10, workers=2)

        assert result.processed == 1
        pool.terminate.assert_called_once()
        pool.join.assert_called_once()


# ── probe pipeline ────────────────────────────────────────────────────────────

class TestProbePipeline:
    def test_skips_hash_and_url_iocs(self):
        submitted_ids: list[int] = []

        with (
            patch("app.services.pipeline.get_session") as ms,
            patch("app.services.pipeline.IOCRepo") as mr,
            patch("app.services.pipeline.multiprocessing.Pool") as mp,
        ):
            _mock_db_with_iocs(
                [
                    _fake_ioc(1, "ip"),
                    _fake_ioc(2, "hash_sha256"),
                    _fake_ioc(3, "url"),
                    _fake_ioc(4, "domain", "evil.com"),
                ],
                ms, mr,
            )
            pool = MagicMock()

            def _capture(fn, args_list):
                for ioc_id, ports in args_list:
                    submitted_ids.append(ioc_id)
                return iter([
                    {"ioc_id": 1, "open_ports": [80], "error": None},
                    {"ioc_id": 4, "open_ports": [], "error": None},
                ])

            pool.imap_unordered.side_effect = _capture
            mp.return_value = pool

            result = run_probe_pipeline(ports=[80, 443], limit=10, workers=2)

        assert set(submitted_ids) == {1, 4}
        assert result.processed == 2
        assert result.probes_open == 1

    def test_ports_capped_at_settings_max_probe_ports(self):
        captured_ports: list[list[int]] = []

        with (
            patch("app.services.pipeline.get_session") as ms,
            patch("app.services.pipeline.IOCRepo") as mr,
            patch("app.services.pipeline.multiprocessing.Pool") as mp,
            patch("app.services.pipeline._capped_workers", return_value=2),
        ):
            # Patch settings inside run_probe_pipeline's local import
            import app.core.config as cfg_mod
            orig = cfg_mod.settings.max_probe_ports
            cfg_mod.settings.max_probe_ports = 3

            _mock_db_with_iocs([_fake_ioc(1, "ip")], ms, mr)
            pool = MagicMock()

            def _capture(fn, args_list):
                for _, ports in args_list:
                    captured_ports.append(list(ports))
                return iter([{"ioc_id": 1, "open_ports": [], "error": None}])

            pool.imap_unordered.side_effect = _capture
            mp.return_value = pool

            run_probe_pipeline(ports=list(range(50)), limit=10, workers=2)
            cfg_mod.settings.max_probe_ports = orig  # restore

        assert all(len(p) <= 3 for p in captured_ports)

    def test_empty_iocs_returns_zero_result(self):
        with (
            patch("app.services.pipeline.get_session") as ms,
            patch("app.services.pipeline.IOCRepo") as mr,
        ):
            _mock_db_with_iocs([], ms, mr)
            result = run_probe_pipeline(ports=[80], limit=10, workers=2)

        assert result.processed == 0
        assert result.probes_open == 0

    def test_error_in_worker_increments_error_count(self):
        with (
            patch("app.services.pipeline.get_session") as ms,
            patch("app.services.pipeline.IOCRepo") as mr,
            patch("app.services.pipeline.multiprocessing.Pool") as mp,
        ):
            _mock_db_with_iocs([_fake_ioc(1, "ip"), _fake_ioc(2, "ip")], ms, mr)
            pool = MagicMock()
            pool.imap_unordered.return_value = iter([
                {"ioc_id": 1, "open_ports": [], "error": "guardrail blocked"},
                {"ioc_id": 2, "open_ports": [443], "error": None},
            ])
            mp.return_value = pool

            result = run_probe_pipeline(ports=[443], limit=10, workers=2)

        assert result.processed == 2
        assert result.errors == 1
        assert result.probes_open == 1