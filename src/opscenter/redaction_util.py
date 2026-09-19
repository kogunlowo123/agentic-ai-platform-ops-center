"""Helpers for producing safe, bounded error text."""

from __future__ import annotations

from opscenter.security import redact


def safe_message(exc: BaseException, limit: int = 300) -> str:
    """A short, redacted description of ``exc`` suitable for reports and logs."""
    return redact(f"{type(exc).__name__}: {exc}")[:limit]
