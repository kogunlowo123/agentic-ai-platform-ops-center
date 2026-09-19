"""Shared context and helpers for specialist agents."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from opscenter.alerts import fingerprint
from opscenter.config import AppConfig, Thresholds
from opscenter.evals import EvalRepo
from opscenter.models import AgentResult, Alert, Severity, StoredEvent
from opscenter.pricing import PriceCatalog
from opscenter.registry import Registry


@dataclass
class AnalysisContext:
    """Everything an agent needs to analyse one window against its baseline."""

    events: list[StoredEvent]
    baseline: list[StoredEvent]
    window: tuple[datetime, datetime]
    baseline_window: tuple[datetime, datetime]
    apps: dict[str, AppConfig]
    thresholds: Thresholds
    catalog: PriceCatalog
    registry: Registry
    evals: EvalRepo
    now: datetime

    def app_config(self, app: str) -> AppConfig:
        """Configuration for ``app`` (defaults when not configured)."""
        return self.apps.get(app, AppConfig())

    @property
    def window_days(self) -> float:
        return (self.window[1] - self.window[0]).total_seconds() / 86400

    @property
    def baseline_days(self) -> float:
        return (self.baseline_window[1] - self.baseline_window[0]).total_seconds() / 86400


def by_app(events: list[StoredEvent]) -> dict[str, list[StoredEvent]]:
    """Group events by application, keeping event order."""
    grouped: dict[str, list[StoredEvent]] = defaultdict(list)
    for event in events:
        grouped[event.app].append(event)
    return dict(sorted(grouped.items()))


def make_alert(
    agent: str,
    severity: Severity,
    title: str,
    detail: str,
    *,
    key: str,
    app: str = "",
    evidence: dict[str, Any] | None = None,
    recommendation: str = "",
) -> Alert:
    """Build an :class:`Alert` with a stable fingerprint from ``agent``, ``app`` and ``key``."""
    return Alert(
        fingerprint=fingerprint(agent, app, key),
        agent=agent,
        severity=severity,
        title=title,
        detail=detail,
        app=app,
        evidence=evidence or {},
        recommendation=recommendation,
    )


@runtime_checkable
class SpecialistAgent(Protocol):
    """An agent that analyses a window of telemetry and returns findings and metrics."""

    name: str

    def analyze(self, ctx: AnalysisContext) -> AgentResult:
        """Analyse ``ctx``."""
