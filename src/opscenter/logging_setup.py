"""Structured logging with automatic secret redaction."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from opscenter.security import redact

_RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON with secrets redacted."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = redact(value) if isinstance(value, str) else value
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, ensure_ascii=False)


class RedactingTextFormatter(logging.Formatter):
    """Human-readable formatter that still redacts secrets."""

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def configure_logging(level: str = "INFO", *, json_output: bool = True) -> None:
    """Configure the ``opscenter`` logger tree.

    Calling this repeatedly replaces the previously installed handler, so it is
    safe to invoke from both the CLI and test fixtures.
    """
    logger = logging.getLogger("opscenter")
    logger.setLevel(level)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        JsonFormatter()
        if json_output
        else RedactingTextFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a logger namespaced under ``opscenter``."""
    return logging.getLogger(name if name.startswith("opscenter") else f"opscenter.{name}")
