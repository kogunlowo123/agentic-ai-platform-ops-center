"""Event store over SQLite."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from opscenter.db import Database
from opscenter.errors import StoreError
from opscenter.models import Signals, StoredEvent


def to_epoch(moment: datetime) -> float:
    """UTC epoch seconds for ``moment`` (naive values are treated as UTC)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def from_epoch(value: float) -> datetime:
    """UTC datetime for epoch seconds."""
    return datetime.fromtimestamp(value, tz=timezone.utc)


class EventStore:
    """Persists :class:`StoredEvent` rows and answers time-window queries."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def insert(self, events: list[StoredEvent]) -> int:
        """Insert events, ignoring ids that already exist. Returns the number newly stored."""
        rows = [
            (
                e.event_id,
                to_epoch(e.timestamp),
                e.app,
                e.environment,
                e.model,
                e.provider,
                e.prompt_id,
                e.prompt_version,
                e.input_tokens,
                e.output_tokens,
                e.latency_ms,
                e.status,
                e.error_type,
                e.user_hash,
                e.cost_usd,
                e.signals.model_dump_json(),
                json.dumps(e.tags),
            )
            for e in events
        ]
        try:
            with self._db.transaction() as conn:
                before = conn.total_changes
                conn.executemany(
                    "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
                )
                return conn.total_changes - before
        except sqlite3.Error as exc:
            raise StoreError(f"cannot store events: {exc}") from exc

    @staticmethod
    def _row(row: sqlite3.Row) -> StoredEvent:
        return StoredEvent(
            event_id=row["event_id"],
            timestamp=from_epoch(row["ts"]),
            app=row["app"],
            environment=row["environment"],
            model=row["model"],
            provider=row["provider"],
            prompt_id=row["prompt_id"],
            prompt_version=row["prompt_version"],
            input_tokens=row["input_tokens"],
            output_tokens=row["output_tokens"],
            latency_ms=row["latency_ms"],
            status=row["status"],
            error_type=row["error_type"],
            user_hash=row["user_hash"],
            cost_usd=row["cost_usd"],
            signals=Signals.model_validate_json(row["signals"]),
            tags=json.loads(row["tags"]),
        )

    def query(
        self,
        start: datetime,
        end: datetime,
        *,
        app: str | None = None,
        environment: str | None = None,
    ) -> list[StoredEvent]:
        """Events with ``start <= timestamp < end``, oldest first."""
        sql = "SELECT * FROM events WHERE ts >= ? AND ts < ?"
        params: list[object] = [to_epoch(start), to_epoch(end)]
        if app is not None:
            sql += " AND app = ?"
            params.append(app)
        if environment is not None:
            sql += " AND environment = ?"
            params.append(environment)
        sql += " ORDER BY ts, event_id"
        try:
            return [self._row(r) for r in self._db.conn.execute(sql, params).fetchall()]
        except sqlite3.Error as exc:
            raise StoreError(f"cannot query events: {exc}") from exc

    def count(self) -> int:
        """Total number of stored events."""
        return int(self._db.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def time_range(self) -> tuple[datetime, datetime] | None:
        """Earliest and latest event timestamps, or ``None`` when empty."""
        row = self._db.conn.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
        if row[0] is None:
            return None
        return from_epoch(row[0]), from_epoch(row[1])
