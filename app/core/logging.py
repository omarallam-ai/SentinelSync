from __future__ import annotations

import json
import logging
import os
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")


def set_correlation_id(value: str | None = None) -> str:
    cid = value or uuid.uuid4().hex
    _correlation_id.set(cid)
    return cid


def get_correlation_id() -> str:
    cid = _correlation_id.get()
    return cid or set_correlation_id()


class JsonFormatter(logging.Formatter):
    """Structured JSON log line — safe against log injection via newline escape."""

    def format(self, record: logging.LogRecord) -> str:
        # Sanitise: collapse newlines so one log record = one JSON line
        msg = record.getMessage().replace("\n", "\\n").replace("\r", "\\r")
        # Cap field length to prevent log bloat from malicious input
        msg = msg[:2000]

        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": msg,
            "correlation_id": get_correlation_id(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str, *, json_format: bool = True) -> None:
    """
    Single configure function used by both CLI and API.
    Clears existing handlers on every call so repeated invocations
    (tests, reload) never accumulate duplicate handlers.

    Args:
        level: Log level string, e.g. "INFO", "DEBUG".
        json_format: If True use structured JSON (API default).
                     If False use plain text (friendlier for CLI interactive use).
    """
    root = logging.getLogger()
    root.handlers.clear()          # ← was commented out; causes duplicate lines
    root.setLevel(level.upper())

    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(JsonFormatter())
    root.addHandler(handler)

    logging.getLogger("sqlalchemy.engine").setLevel(
        os.getenv("SQLALCHEMY_LOG_LEVEL", "WARNING")
    )


# Convenience aliases so existing call-sites don't need to change
def configure_logging_cli(level: str) -> None:
    configure_logging(level, json_format=False)


def configure_logging_api(level: str) -> None:
    configure_logging(level, json_format=True)