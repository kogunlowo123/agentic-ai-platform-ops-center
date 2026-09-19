"""SQLite connection and schema shared by the event store, alerts, evaluations and registry."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from opscenter.errors import StoreError

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    app TEXT NOT NULL,
    environment TEXT NOT NULL,
    model TEXT NOT NULL,
    provider TEXT NOT NULL,
    prompt_id TEXT,
    prompt_version TEXT,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    latency_ms REAL NOT NULL,
    status TEXT NOT NULL,
    error_type TEXT,
    user_hash TEXT,
    cost_usd REAL,
    signals TEXT NOT NULL,
    tags TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_app_ts ON events (app, ts);

CREATE TABLE IF NOT EXISTS alerts (
    fingerprint TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    app TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    occurrences INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS eval_runs (
    run_id TEXT PRIMARY KEY,
    suite TEXT NOT NULL,
    target TEXT NOT NULL,
    ts REAL NOT NULL,
    pass_rate REAL NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_eval_suite_ts ON eval_runs (suite, target, ts);

CREATE TABLE IF NOT EXISTS models (
    name TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL,
    review_due TEXT,
    notes TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS prompt_versions (
    prompt_id TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    author TEXT NOT NULL,
    approved_by TEXT,
    created_at REAL NOT NULL,
    PRIMARY KEY (prompt_id, version)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail TEXT NOT NULL
);
"""


class Database:
    """A SQLite database with the ops-center schema applied.

    Use ``":memory:"`` for an ephemeral database. All statements in this package use bound
    parameters; no value is ever interpolated into SQL.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = str(path)
        try:
            if self._path != ":memory:":
                Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self._path)
            self.conn.row_factory = sqlite3.Row
            if self._path != ":memory:":
                self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(_SCHEMA)
            self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self.conn.commit()
        except (OSError, sqlite3.Error) as exc:
            raise StoreError(f"cannot open database {self._path}: {exc}") from exc

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Commit on success, roll back on any exception."""
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def close(self) -> None:
        """Close the connection."""
        self.conn.close()
