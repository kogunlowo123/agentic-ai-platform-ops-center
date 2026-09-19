"""Telemetry ingestion: validate, derive signals, price, and persist. Raw text is never stored."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from opscenter.errors import IngestError
from opscenter.models import IngestReport, LLMEvent, StoredEvent
from opscenter.pricing import PriceCatalog
from opscenter.security import redact, salted_hash
from opscenter.signals import derive_signals
from opscenter.store import EventStore

_BATCH = 1000
_MAX_ERRORS = 20


def to_stored(event: LLMEvent, *, salt: str, catalog: PriceCatalog) -> StoredEvent:
    """Convert an incoming event to its stored form.

    Text fields are consumed to compute signals and then discarded. The user id is replaced by a
    salted hash. Cost is taken from the event when present, otherwise computed from the catalog.
    """
    cost = event.cost_usd
    if cost is None:
        cost = catalog.cost(event.model, event.input_tokens, event.output_tokens)
    return StoredEvent(
        event_id=event.event_id,
        timestamp=event.timestamp,
        app=event.app,
        environment=event.environment,
        model=event.model,
        provider=event.provider,
        prompt_id=event.prompt_id,
        prompt_version=event.prompt_version,
        input_tokens=event.input_tokens,
        output_tokens=event.output_tokens,
        latency_ms=event.latency_ms,
        status=event.status,
        error_type=event.error_type,
        user_hash=salted_hash(event.user_id, salt) if event.user_id else None,
        cost_usd=cost,
        signals=derive_signals(event, salt=salt),
        tags=event.tags,
    )


def ingest_lines(
    lines: Iterable[str],
    store: EventStore,
    *,
    salt: str,
    catalog: PriceCatalog,
    max_line_bytes: int = 200_000,
    max_lines: int = 2_000_000,
) -> IngestReport:
    """Ingest JSON Lines telemetry. Bad lines are counted and described, never fatal.

    Error messages carry the line number and the validation problem, never the line's content.
    """
    report = IngestReport()
    batch: list[StoredEvent] = []

    def flush() -> None:
        if batch:
            stored = store.insert(batch)
            report.accepted += stored
            report.duplicates += len(batch) - stored
            batch.clear()

    def reject(number: int, reason: str) -> None:
        report.rejected += 1
        if len(report.errors) < _MAX_ERRORS:
            report.errors.append(f"line {number}: {redact(reason)[:200]}")

    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        report.lines += 1
        if report.lines > max_lines:
            raise IngestError(f"input exceeds the limit of {max_lines} lines")
        if len(raw.encode("utf-8", errors="replace")) > max_line_bytes:
            reject(number, f"line exceeds {max_line_bytes} bytes")
            continue
        try:
            event = LLMEvent.model_validate(json.loads(raw))
        except json.JSONDecodeError:
            reject(number, "not valid JSON")
            continue
        except ValidationError as exc:
            first = exc.errors()[0]
            reject(number, f"{'.'.join(str(p) for p in first['loc'])}: {first['msg']}")
            continue
        stored = to_stored(event, salt=salt, catalog=catalog)
        if stored.cost_usd is None:
            report.unpriced += 1
        batch.append(stored)
        if len(batch) >= _BATCH:
            flush()
    flush()
    return report


def ingest_file(
    path: Path,
    store: EventStore,
    *,
    salt: str,
    catalog: PriceCatalog,
    max_line_bytes: int = 200_000,
    max_lines: int = 2_000_000,
) -> IngestReport:
    """Ingest a JSON Lines file. Raises :class:`IngestError` if it cannot be read."""
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return ingest_lines(
                handle,
                store,
                salt=salt,
                catalog=catalog,
                max_line_bytes=max_line_bytes,
                max_lines=max_lines,
            )
    except OSError as exc:
        raise IngestError(f"cannot read {path}: {exc.strerror or exc}") from exc
