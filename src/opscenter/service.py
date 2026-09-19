"""Application service: ingestion, reporting and evaluation behind one facade."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from opscenter.agents import AnalysisContext, Supervisor
from opscenter.alerts import AlertManager
from opscenter.config import AppConfig, Settings
from opscenter.db import Database
from opscenter.errors import OpscenterError
from opscenter.evals import EvalRepo, EvalRun, EvalSuite, run_suite
from opscenter.models import IngestReport, LLMEvent, OpsReport
from opscenter.pricing import PriceCatalog
from opscenter.providers.llm import LLMClient
from opscenter.registry import Registry
from opscenter.store import EventStore
from opscenter.telemetry import ingest_file, ingest_lines, to_stored

_DURATION = re.compile(r"^(\d+)([mhdw])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_duration(text: str) -> timedelta:
    """Parse ``90m``, ``24h``, ``7d`` or ``2w`` into a timedelta."""
    match = _DURATION.match(text.strip())
    if not match or int(match.group(1)) == 0:
        raise OpscenterError(f"invalid duration {text!r}; use forms like 90m, 24h, 7d, 2w")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


class OpsService:
    """Facade used by the CLI and library callers."""

    def __init__(
        self,
        settings: Settings,
        db: Database,
        store: EventStore,
        registry: Registry,
        alerts: AlertManager,
        evals: EvalRepo,
        catalog: PriceCatalog,
        apps: dict[str, AppConfig],
        supervisor: Supervisor,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.store = store
        self.registry = registry
        self.alerts = alerts
        self.evals = evals
        self.catalog = catalog
        self.apps = apps
        self._supervisor = supervisor
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def close(self) -> None:
        """Close the database connection. Safe to call more than once."""
        self.db.close()

    def __enter__(self) -> OpsService:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def ingest_file(self, path: Path) -> IngestReport:
        """Ingest a JSON Lines telemetry file."""
        return ingest_file(
            path,
            self.store,
            salt=self.settings.hash_salt.get_secret_value(),
            catalog=self.catalog,
            max_line_bytes=self.settings.max_line_bytes,
            max_lines=self.settings.max_lines,
        )

    def ingest_events(self, events: list[LLMEvent]) -> IngestReport:
        """Ingest already-parsed events (used by the simulator and the router)."""
        return ingest_lines(
            (e.model_dump_json(exclude_none=True) for e in events),
            self.store,
            salt=self.settings.hash_salt.get_secret_value(),
            catalog=self.catalog,
        )

    def store_event(self, event: LLMEvent) -> None:
        """Store one event directly (router telemetry hook)."""
        self.store.insert(
            [
                to_stored(
                    event, salt=self.settings.hash_salt.get_secret_value(), catalog=self.catalog
                )
            ]
        )

    def report(
        self, *, window: timedelta, baseline: timedelta, now: datetime | None = None
    ) -> OpsReport:
        """Analyse the last ``window`` against the ``baseline`` period that precedes it."""
        end = now or self._clock()
        start = end - window
        base_end, base_start = start, start - baseline
        upper = end + timedelta(microseconds=1)
        ctx = AnalysisContext(
            events=self.store.query(start, upper),
            baseline=self.store.query(base_start, base_end),
            window=(start, end),
            baseline_window=(base_start, base_end),
            apps=self.apps,
            thresholds=self.settings.thresholds,
            catalog=self.catalog,
            registry=self.registry,
            evals=self.evals,
            now=end,
        )
        return self._supervisor.run(ctx)

    def run_eval(self, suite: EvalSuite, client: LLMClient, *, target: str) -> EvalRun:
        """Run ``suite`` against ``client`` and store the result."""
        run = run_suite(suite, client, target=target, clock=self._clock)
        self.evals.save(run)
        return run
