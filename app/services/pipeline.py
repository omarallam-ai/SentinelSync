from __future__ import annotations

"""
Multiprocessing pipeline — Milestone 6.

TESTABILITY RULE: ``get_session`` and ``IOCRepo`` are imported at module level
so ``patch("app.services.pipeline.get_session")`` works in unit tests.
When these were imported only inside function bodies the names didn't exist in
the module namespace and patch() raised AttributeError.
"""

import logging
import multiprocessing
import signal
from collections.abc import Callable
from dataclasses import dataclass, field

# Module-level — required for patch() to intercept these in tests
from app.db.repo import IOCRepo
from app.db.session import get_session

log = logging.getLogger("sentinelsync.pipeline")


@dataclass
class PipelineResult:
    processed: int = 0
    urlhaus_ok: int = 0
    crtsh_ok: int = 0
    ip_ok: int = 0
    probes_open: int = 0
    errors: int = 0
    details: list[dict] = field(default_factory=list)


def _init_worker() -> None:
    """Ignore SIGINT in workers so only the parent handles Ctrl-C."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _enrich_worker(ioc_id: int) -> dict:
    """Enrich one IOC. Module-level required for pickle on Windows spawn."""
    result: dict = {"ioc_id": ioc_id, "urlhaus": "skip", "ip": "skip", "error": None}
    try:
        from app.db.repo import IOCRepo
        from app.db.session import get_session
        with get_session() as db:
            ioc = IOCRepo(db).get_by_id(ioc_id)
        if ioc is None:
            result["error"] = "ioc_not_found"
            return result
        if ioc.ioc_type in ("url", "domain", "ip"):
            from app.services.enrich_urlhaus import enrich_urlhaus
            resp = enrich_urlhaus(ioc.normalized)
            result["urlhaus"] = "ok" if resp.get("query_status") == "ok" else "not_found"
        if ioc.ioc_type == "ip":
            from app.services.enrich_ip import enrich_ip
            resp = enrich_ip(ioc.normalized)
            result["ip"] = "ok" if "error" not in resp else "error"
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        log.warning(f"_enrich_worker ioc_id={ioc_id} error: {exc}")
    return result


def _probe_worker(args: tuple[int, list[int]]) -> dict:
    """Probe one IOC across ports. Module-level required for pickle."""
    ioc_id, ports = args
    result: dict = {"ioc_id": ioc_id, "open_ports": [], "error": None}
    try:
        from app.db.repo import IOCRepo
        from app.db.session import get_session
        with get_session() as db:
            ioc = IOCRepo(db).get_by_id(ioc_id)
        if ioc is None:
            result["error"] = "ioc_not_found"
            return result
        from app.services.probe_tcp import probe_tcp
        for port in ports:
            try:
                pr = probe_tcp(ioc.normalized, port)
                if pr["status"] == "open":
                    result["open_ports"].append(port)
            except ValueError as exc:
                log.warning(f"_probe_worker blocked ioc_id={ioc_id}: {exc}")
                result["error"] = str(exc)
                break
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        log.warning(f"_probe_worker ioc_id={ioc_id} error: {exc}")
    return result


def _capped_workers(requested: int) -> int:
    from app.core.config import settings
    return min(requested, settings.max_workers)


def run_enrich_pipeline(
    limit: int = 200,
    workers: int = 4,
    progress_cb: Callable[[int, int], None] | None = None,
) -> PipelineResult:
    n_workers = _capped_workers(workers)
    result = PipelineResult()

    with get_session() as db:
        iocs = IOCRepo(db).list_iocs(limit=limit)

    ioc_ids = [ioc.id for ioc in iocs]
    total = len(ioc_ids)
    if not ioc_ids:
        log.info("enrich_pipeline: no IOCs to process")
        return result

    log.info(f"enrich_pipeline start total={total} workers={n_workers}")
    pool = multiprocessing.Pool(processes=n_workers, initializer=_init_worker)
    try:
        for i, r in enumerate(pool.imap_unordered(_enrich_worker, ioc_ids), 1):
            result.processed += 1
            if r.get("error"):
                result.errors += 1
            if r.get("urlhaus") == "ok":
                result.urlhaus_ok += 1
            if r.get("ip") == "ok":
                result.ip_ok += 1
            result.details.append(r)
            if progress_cb:
                progress_cb(i, total)
    except KeyboardInterrupt:
        log.warning("enrich_pipeline: interrupted — terminating workers")
        pool.terminate()
        pool.join()
        return result
    else:
        pool.close()
        pool.join()

    log.info(f"enrich_pipeline done processed={result.processed} errors={result.errors}")
    return result


def run_probe_pipeline(
    ports: list[int],
    limit: int = 200,
    workers: int = 4,
    progress_cb: Callable[[int, int], None] | None = None,
) -> PipelineResult:
    from app.core.config import settings
    n_workers = _capped_workers(workers)
    capped_ports = ports[: settings.max_probe_ports]
    result = PipelineResult()

    with get_session() as db:
        all_iocs = IOCRepo(db).list_iocs(limit=limit)

    probeables = [ioc for ioc in all_iocs if ioc.ioc_type in ("ip", "domain")]
    total = len(probeables)
    if not probeables:
        log.info("probe_pipeline: no probeable IOCs")
        return result

    log.info(f"probe_pipeline start total={total} workers={n_workers} ports={capped_ports}")
    args = [(ioc.id, capped_ports) for ioc in probeables]
    pool = multiprocessing.Pool(processes=n_workers, initializer=_init_worker)
    try:
        for i, r in enumerate(pool.imap_unordered(_probe_worker, args), 1):
            result.processed += 1
            if r.get("error"):
                result.errors += 1
            result.probes_open += len(r.get("open_ports", []))
            result.details.append(r)
            if progress_cb:
                progress_cb(i, total)
    except KeyboardInterrupt:
        log.warning("probe_pipeline: interrupted — terminating workers")
        pool.terminate()
        pool.join()
        return result
    else:
        pool.close()
        pool.join()

    log.info(f"probe_pipeline done processed={result.processed} open={result.probes_open}")
    return result