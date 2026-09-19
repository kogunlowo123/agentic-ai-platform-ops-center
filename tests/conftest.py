"""Shared fixtures and builders."""

from __future__ import annotations

import contextlib
import random
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from opscenter.agents import AnalysisContext
from opscenter.alerts import AlertManager
from opscenter.config import AppConfig, Settings, Thresholds
from opscenter.db import Database
from opscenter.evals import EvalRepo
from opscenter.models import Signals, StoredEvent
from opscenter.pricing import ModelPrice, PriceCatalog
from opscenter.providers.http import JsonClient
from opscenter.registry import Registry
from opscenter.store import EventStore

NOW = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIGS = REPO_ROOT / "configs"

CATALOG = PriceCatalog(
    {
        "small-model": ModelPrice(input_per_mtok=0.5, output_per_mtok=1.5),
        "large-model": ModelPrice(input_per_mtok=3.0, output_per_mtok=15.0),
    }
)


@dataclass
class Env:
    """In-memory database and the repositories built on it."""

    db: Database
    store: EventStore
    registry: Registry
    alerts: AlertManager
    evals: EvalRepo


@pytest.fixture(autouse=True)
def _close_databases(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Close every SQLite connection a test opens, so none leak."""
    opened: list[Database] = []
    original = Database.__init__

    def tracking(self: Database, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(Database, "__init__", tracking)
    yield
    for db in opened:
        with contextlib.suppress(Exception):
            db.close()


@pytest.fixture
def env() -> Env:
    db = Database(":memory:")
    return Env(
        db, EventStore(db), Registry(db, lambda: NOW), AlertManager(db, lambda: NOW), EvalRepo(db)
    )


def make_event(
    when: datetime | None = None,
    *,
    app: str = "app",
    model: str = "small-model",
    signals: dict[str, Any] | None = None,
    **kw: Any,
) -> StoredEvent:
    """A stored event with sensible defaults."""
    data: dict[str, Any] = {
        "event_id": f"e{random.random()}",
        "timestamp": when or NOW - timedelta(hours=1),
        "app": app,
        "environment": "prod",
        "model": model,
        "input_tokens": 500,
        "output_tokens": 100,
        "latency_ms": 800.0,
        "status": "ok",
        "cost_usd": 0.001,
        "signals": Signals(**(signals or {})),
    }
    data.update(kw)
    return StoredEvent.model_validate(data)


def many(count: int, factory: Callable[[int], StoredEvent]) -> list[StoredEvent]:
    """``count`` events built by ``factory(index)`` with unique ids."""
    events = []
    for i in range(count):
        event = factory(i)
        events.append(
            event.model_copy(update={"event_id": f"{event.app}-{event.model}-{i}-{id(event)}"})
        )
    return events


def make_ctx(
    env: Env,
    events: Iterable[StoredEvent],
    baseline: Iterable[StoredEvent] = (),
    *,
    apps: dict[str, AppConfig] | None = None,
    thresholds: Thresholds | None = None,
    catalog: PriceCatalog | None = None,
    window_days: float = 1.0,
    baseline_days: float = 6.0,
) -> AnalysisContext:
    """An analysis context ending at :data:`NOW`."""
    start = NOW - timedelta(days=window_days)
    return AnalysisContext(
        events=list(events),
        baseline=list(baseline),
        window=(start, NOW),
        baseline_window=(start - timedelta(days=baseline_days), start),
        apps=apps or {},
        thresholds=thresholds or Thresholds(),
        catalog=catalog if catalog is not None else CATALOG,
        registry=env.registry,
        evals=env.evals,
        now=NOW,
    )


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    """Settings that ignore the developer's environment and write only under ``tmp_path``."""
    base: dict[str, object] = {
        "db_path": tmp_path / "ops.db",
        "retry_min_wait": 0.0,
        "retry_max_wait": 0.0,
        "log_level": "CRITICAL",
        "hash_salt": "test-salt",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def json_client(
    handler: Callable[[httpx.Request], httpx.Response], attempts: int = 2
) -> JsonClient:
    """A JsonClient backed by an in-process mock transport."""
    return JsonClient(
        httpx.Client(transport=httpx.MockTransport(handler)),
        attempts=attempts,
        min_wait=0.0,
        max_wait=0.0,
    )


class FakeLLM:
    """Scripted chat client."""

    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
