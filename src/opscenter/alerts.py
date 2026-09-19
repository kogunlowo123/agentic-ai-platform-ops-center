"""Alert lifecycle (open, acknowledged, resolved) and delivery sinks."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import SecretStr

from opscenter.db import Database
from opscenter.errors import OpscenterError, ProviderError, RegistryError
from opscenter.logging_setup import get_logger
from opscenter.models import Alert, AlertRecord, Severity
from opscenter.providers.http import JsonClient
from opscenter.security import redact
from opscenter.store import from_epoch, to_epoch

_log = get_logger("alerts")


def fingerprint(agent: str, app: str, key: str) -> str:
    """Stable identity of an alert across runs."""
    return hashlib.sha256(f"{agent}|{app}|{key}".encode()).hexdigest()[:16]


class AlertManager:
    """Persists alerts and tracks their lifecycle across supervisor runs.

    * An alert seen again keeps its ``first_seen`` and increments ``occurrences``.
    * An acknowledged alert stays acknowledged while it keeps firing.
    * An open or acknowledged alert that stops firing is marked resolved (only for agents that ran
      successfully, so an agent failure never silently resolves its alerts).
    * A resolved alert that fires again reopens.
    """

    def __init__(self, db: Database, clock: Callable[[], datetime] | None = None) -> None:
        self._db = db
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _record(row: sqlite3.Row) -> AlertRecord:
        base = Alert.model_validate_json(row["payload"])
        return AlertRecord(
            **base.model_dump(),
            status=row["status"],
            first_seen=from_epoch(row["first_seen"]),
            last_seen=from_epoch(row["last_seen"]),
            occurrences=row["occurrences"],
        )

    def sync(
        self, alerts: list[Alert], now: datetime, ran_agents: set[str]
    ) -> tuple[list[AlertRecord], list[AlertRecord]]:
        """Reconcile ``alerts`` with stored state.

        Returns ``(records, newly_active)``: the records for the current alerts, and the subset that
        is new or has reopened (what a notifier should send).
        """
        stamp = to_epoch(now)
        newly: set[str] = set()
        current = {a.fingerprint for a in alerts}
        with self._db.transaction() as conn:
            for alert in alerts:
                row = conn.execute(
                    "SELECT * FROM alerts WHERE fingerprint = ?", (alert.fingerprint,)
                ).fetchone()
                payload = alert.model_dump_json()
                if row is None:
                    conn.execute(
                        "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (
                            alert.fingerprint,
                            alert.agent,
                            alert.app,
                            alert.severity.value,
                            alert.title,
                            payload,
                            "open",
                            stamp,
                            stamp,
                            1,
                        ),
                    )
                    newly.add(alert.fingerprint)
                    continue
                status = row["status"]
                if status == "resolved":
                    status = "open"
                    newly.add(alert.fingerprint)
                conn.execute(
                    "UPDATE alerts SET severity=?, title=?, payload=?, status=?, last_seen=?, "
                    "occurrences=occurrences+1 WHERE fingerprint=?",
                    (alert.severity.value, alert.title, payload, status, stamp, alert.fingerprint),
                )
            stale = conn.execute(
                "SELECT fingerprint, agent FROM alerts WHERE status IN ('open','acked')"
            ).fetchall()
            for row in stale:
                if row["agent"] in ran_agents and row["fingerprint"] not in current:
                    conn.execute(
                        "UPDATE alerts SET status='resolved' WHERE fingerprint=?",
                        (row["fingerprint"],),
                    )
        records = {r.fingerprint: r for r in self.list()}
        return (
            [records[a.fingerprint] for a in alerts],
            [records[f] for f in newly if f in records],
        )

    def list(self, status: str | None = None) -> list[AlertRecord]:
        """Stored alerts, most severe and most recent first."""
        sql = "SELECT * FROM alerts"
        params: tuple[str, ...] = ()
        if status:
            sql += " WHERE status = ?"
            params = (status,)
        rows = self._db.conn.execute(sql, params).fetchall()
        records = [self._record(r) for r in rows]
        return sorted(
            records, key=lambda a: (-a.severity.rank, -a.last_seen.timestamp(), a.fingerprint)
        )

    def acknowledge(self, fingerprint_prefix: str, actor: str) -> AlertRecord:
        """Acknowledge the open alert whose fingerprint starts with ``fingerprint_prefix``."""
        matches = [r for r in self.list("open") if r.fingerprint.startswith(fingerprint_prefix)]
        if len(matches) != 1:
            raise RegistryError(
                f"{len(matches)} open alerts match '{fingerprint_prefix}'; give a longer prefix"
                if matches
                else f"no open alert matches '{fingerprint_prefix}'"
            )
        target = matches[0]
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE alerts SET status='acked' WHERE fingerprint=?", (target.fingerprint,)
            )
            conn.execute(
                "INSERT INTO audit_log (ts, actor, action, subject, detail) VALUES (?,?,?,?,?)",
                (to_epoch(self._clock()), actor, "alert.ack", target.fingerprint, target.title),
            )
        return target.model_copy(update={"status": "acked"})


@runtime_checkable
class AlertSink(Protocol):
    """Delivers new alerts somewhere."""

    def send(self, alerts: list[AlertRecord]) -> None:
        """Deliver ``alerts``."""


class FileSink:
    """Appends alerts as JSON Lines."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def send(self, alerts: list[AlertRecord]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            for alert in alerts:
                handle.write(redact(alert.model_dump_json()) + "\n")


class WebhookSink:
    """POSTs alerts as JSON to a webhook URL (kept secret, since it often embeds a token)."""

    def __init__(self, client: JsonClient, url: SecretStr) -> None:
        self._client = client
        self._url = url

    def send(self, alerts: list[AlertRecord]) -> None:
        payload = {
            "alerts": [
                {
                    "severity": a.severity.value,
                    "app": a.app,
                    "title": a.title,
                    "detail": a.detail,
                    "recommendation": a.recommendation,
                    "fingerprint": a.fingerprint,
                }
                for a in alerts
            ]
        }
        self._client.request(
            "POST", self._url.get_secret_value(), json=json.loads(redact(json.dumps(payload)))
        )


def deliver(sinks: list[AlertSink], alerts: list[AlertRecord]) -> list[str]:
    """Send ``alerts`` (high severity and above are delivered) to every sink.

    A failing sink never stops the others or the run. Returns descriptions of failures.
    """
    urgent = [a for a in alerts if a.severity.rank >= Severity.HIGH.rank]
    failures: list[str] = []
    if not urgent:
        return failures
    for sink in sinks:
        try:
            sink.send(urgent)
        except (ProviderError, OSError, OpscenterError) as exc:
            _log.warning("alert delivery failed", extra={"sink": type(sink).__name__})
            failures.append(f"{type(sink).__name__}: {redact(str(exc))[:200]}")
    return failures
