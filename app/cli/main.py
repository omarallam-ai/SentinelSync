from __future__ import annotations

"""
SentinelSync CLI — Typer-based.

Commands:  ingest · enrich · probe · score · report · serve

Windows guard: the ``if __name__ == "__main__"`` block at the bottom
prevents worker processes from re-executing CLI commands on import.
"""

import json
import logging
from pathlib import Path
from typing import Optional

import typer

from app.core.config import settings
from app.core.logging import configure_logging_cli, set_correlation_id

app = typer.Typer(add_completion=False, help="SentinelSync — defensive IOC triage pipeline")


@app.callback()
def _startup() -> None:
    configure_logging_cli(settings.log_level)


# ── ingest ────────────────────────────────────────────────────────────────────

@app.command()
def ingest(
    text: Optional[str] = typer.Option(None, "--text", help="Raw text to parse for IOCs"),
    file: Optional[Path] = typer.Option(None, "--file", exists=True, help="File to parse"),
    source: str = typer.Option("cli", "--source", help="Source label stored in DB"),
) -> None:
    """Extract, normalise, and store IOCs from raw text or a file."""
    from app.db.repo import IOCRepo
    from app.db.session import get_session
    from app.services.ingest import ingest_text

    cid = set_correlation_id()
    log = logging.getLogger("sentinelsync")
    log.info(f"start ingest cid={cid}")

    if (text is None) == (file is None):
        raise typer.BadParameter("Provide exactly one of --text or --file")

    raw = text if text is not None else file.read_text(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

    with get_session() as db:
        repo = IOCRepo(db)
        repo.init_db()
        ing = ingest_text(raw, source=source)
        res = repo.upsert_many(ing.rows)

    typer.echo(f"Extracted: {ing.extracted}")
    typer.echo(f"Inserted:  {res.inserted}")
    typer.echo(f"Deduped:   {res.deduped}")


# ── enrich ────────────────────────────────────────────────────────────────────

@app.command()
def enrich(
    limit: int = typer.Option(200, "--limit", help="Max IOCs to enrich"),
    workers: int = typer.Option(4, "--workers", help="Parallel worker processes"),
    url: Optional[str] = typer.Option(None, "--url", help="Single URL to enrich directly"),
    ip: Optional[str] = typer.Option(None, "--ip", help="Single IP to enrich directly"),
    auth_key: Optional[str] = typer.Option(None, "--auth-key", help="URLhaus auth key override"),
) -> None:
    """Enrich stored IOCs via URLhaus + ip-api (parallel). Or enrich a single --url/--ip."""
    cid = set_correlation_id()
    log = logging.getLogger("sentinelsync")

    if url is not None and ip is None:
        from app.services.enrich_urlhaus import enrich_urlhaus
        result = enrich_urlhaus(url, auth_key or "")
        typer.echo(json.dumps(result, indent=2))
        return

    if ip is not None and url is None:
        from app.services.enrich_ip import enrich_ip
        result = enrich_ip(ip)
        typer.echo(json.dumps(result, indent=2))
        return

    if url is not None and ip is not None:
        raise typer.BadParameter("Provide at most one of --url or --ip")

    from app.services.pipeline import run_enrich_pipeline

    def _progress(done: int, total: int) -> None:
        typer.echo(f"\rEnriching {done}/{total}...", nl=False)

    r = run_enrich_pipeline(limit=limit, workers=workers, progress_cb=_progress)
    typer.echo("")
    typer.echo(f"Processed:  {r.processed}")
    typer.echo(f"URLhaus OK: {r.urlhaus_ok}")
    typer.echo(f"IP OK:      {r.ip_ok}")
    typer.echo(f"Errors:     {r.errors}")


# ── probe ─────────────────────────────────────────────────────────────────────

@app.command()
def probe(
    ports: str = typer.Option("80,443", "--ports", help="Comma-separated port list"),
    workers: int = typer.Option(4, "--workers", help="Parallel worker processes"),
    limit: int = typer.Option(200, "--limit", help="Max IOCs to probe"),
    ip: Optional[str] = typer.Option(None, "--ip", help="Single IP for immediate probe"),
    port: Optional[int] = typer.Option(None, "--port", help="Port for single --ip probe"),
) -> None:
    """TCP connect probe stored IOCs in parallel. Or probe a single --ip --port."""
    cid = set_correlation_id()
    log = logging.getLogger("sentinelsync")

    if ip is not None:
        if port is None:
            raise typer.BadParameter("--port is required with --ip")
        from app.services.probe_tcp import probe_tcp
        try:
            result = probe_tcp(ip, port)
            typer.echo(json.dumps(result, indent=2))
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        return

    from app.services.pipeline import run_probe_pipeline

    port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    if not port_list:
        raise typer.BadParameter("No valid port numbers in --ports")

    def _progress(done: int, total: int) -> None:
        typer.echo(f"\rProbing {done}/{total}...", nl=False)

    r = run_probe_pipeline(ports=port_list, limit=limit, workers=workers, progress_cb=_progress)
    typer.echo("")
    typer.echo(f"Processed:  {r.processed}")
    typer.echo(f"Open ports: {r.probes_open}")
    typer.echo(f"Errors:     {r.errors}")


# ── score ─────────────────────────────────────────────────────────────────────

@app.command()
def score(
    limit: int = typer.Option(500, "--limit", help="Max IOCs to score"),
) -> None:
    """Score stored IOCs using enrichment + probe data. Writes scores to DB."""
    from app.core.scoring import score_all
    from app.db.session import get_session

    cid = set_correlation_id()
    log = logging.getLogger("sentinelsync")
    log.info(f"start score cid={cid} limit={limit}")

    with get_session() as db:
        results = score_all(db, limit=limit)

    high   = sum(1 for r in results if r.score >= 70)
    medium = sum(1 for r in results if 40 <= r.score < 70)
    low    = sum(1 for r in results if 0 < r.score < 40)

    typer.echo(f"Scored:  {len(results)}")
    typer.echo(f"High:    {high}")
    typer.echo(f"Medium:  {medium}")
    typer.echo(f"Low:     {low}")


# ── report ────────────────────────────────────────────────────────────────────

@app.command()
def report(
    title: str = typer.Option("Threat Intel Report", "--title", help="Report title"),
    out: Optional[Path] = typer.Option(None, "--out", help="Write Markdown to this file"),
    limit: int = typer.Option(200, "--limit", help="Max IOCs to include"),
) -> None:
    """Generate a Markdown threat intel report and save to DB (+ optional file)."""
    from app.db.repo import ReportRepo
    from app.db.session import get_session
    from app.services.report import generate_report

    cid = set_correlation_id()
    log = logging.getLogger("sentinelsync")
    log.info(f"start report cid={cid} title={title!r}")

    with get_session() as db:
        markdown = generate_report(db, title=title, limit=limit)
        row = ReportRepo(db).save(title=title, markdown=markdown, params={"limit": limit})

    typer.echo(f"Report saved to DB (id={row.id})")

    if out:
        out.write_text(markdown, encoding="utf-8")
        typer.echo(f"Written to: {out}")
    else:
        typer.echo(markdown)


# ── serve ─────────────────────────────────────────────────────────────────────

@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port_: int = typer.Option(8000, "--port"),
) -> None:
    """Run the FastAPI server locally."""
    import uvicorn
    typer.echo(f"Starting SentinelSync API on http://{host}:{port_}")
    uvicorn.run("app.api.routes:app", host=host, port=port_, reload=False)


# ── Windows multiprocessing guard ─────────────────────────────────────────────

if __name__ == "__main__":
    app()