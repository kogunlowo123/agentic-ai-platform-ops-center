"""Supervisor agent: runs the specialists, isolates their failures, and merges their findings."""

from __future__ import annotations

import math

from opscenter._version import __version__
from opscenter.agents.base import AnalysisContext, SpecialistAgent, make_alert
from opscenter.alerts import AlertManager, AlertSink, deliver
from opscenter.logging_setup import get_logger
from opscenter.models import AgentResult, Alert, AlertRecord, AppHealth, OpsReport, Severity
from opscenter.redaction_util import safe_message

_log = get_logger("supervisor")
_HEALTH_DECAY = 60.0


def _score(penalty: int) -> int:
    return round(100 * math.exp(-penalty / _HEALTH_DECAY))


def compute_health(apps: dict[str, int], alerts: list[AlertRecord]) -> tuple[list[AppHealth], int]:
    """Per-app health scores and an overall score from the open alerts.

    Only open alerts count; acknowledged ones are known and being handled. ``apps`` maps each app to
    its event count. Alerts without an app are platform-level and scale the overall score.
    """
    open_alerts = [a for a in alerts if a.status == "open"]
    health: list[AppHealth] = []
    for app, events in sorted(apps.items()):
        mine = [a for a in open_alerts if a.app == app]
        counts = {sev.value: sum(1 for a in mine if a.severity is sev) for sev in Severity}
        health.append(
            AppHealth(
                app=app,
                score=_score(sum(a.severity.penalty for a in mine)),
                open_alerts=counts,
                events=events,
            )
        )
    platform_penalty = sum(a.severity.penalty for a in open_alerts if not a.app)
    base = sum(h.score for h in health) / len(health) if health else 100.0
    return health, round(base * math.exp(-platform_penalty / _HEALTH_DECAY))


class Supervisor:
    """Coordinates specialist agents and produces the :class:`OpsReport`."""

    def __init__(
        self,
        agents: list[SpecialistAgent],
        alert_manager: AlertManager,
        sinks: list[AlertSink] | None = None,
    ) -> None:
        self._agents = agents
        self._alerts = alert_manager
        self._sinks = sinks or []

    def run(self, ctx: AnalysisContext) -> OpsReport:
        """Run every agent against ``ctx`` and build the report.

        One agent failing does not stop the others: its error is recorded on its result and raised as
        a high-severity alert, and its previously open alerts are left as they were.
        """
        results: list[AgentResult] = []
        alerts: list[Alert] = []
        succeeded: set[str] = set()
        for agent in self._agents:
            try:
                result = agent.analyze(ctx)
                succeeded.add(agent.name)
            except Exception as exc:
                message = safe_message(exc)
                _log.error("agent failed", extra={"agent": agent.name, "error": message})
                result = AgentResult(name=agent.name, error=message)
                result.alerts.append(
                    make_alert(
                        "supervisor",
                        Severity.HIGH,
                        f"Analysis agent failed: {agent.name}",
                        f"The {agent.name} agent raised an error, so its checks did not run: {message}",
                        key=f"agent-failure-{agent.name}",
                        recommendation="Check the logs and the input data; alerts from this agent were not updated.",
                    )
                )
            results.append(result)
            alerts.extend(result.alerts)

        unique: dict[str, Alert] = {}
        for alert in alerts:
            kept = unique.get(alert.fingerprint)
            if kept is None or alert.severity.rank > kept.severity.rank:
                unique[alert.fingerprint] = alert
        ordered = sorted(unique.values(), key=lambda a: (-a.severity.rank, a.app, a.title))

        records, newly = self._alerts.sync(ordered, ctx.now, succeeded | {"supervisor"})
        failures = deliver(self._sinks, newly)
        for failure in failures:
            _log.warning("alert sink failure", extra={"detail": failure})

        app_events: dict[str, int] = {}
        for event in ctx.events:
            app_events[event.app] = app_events.get(event.app, 0) + 1
        health, overall = compute_health(app_events, records)
        return OpsReport(
            tool_version=__version__,
            generated_at=ctx.now,
            window_start=ctx.window[0],
            window_end=ctx.window[1],
            baseline_start=ctx.baseline_window[0],
            baseline_end=ctx.baseline_window[1],
            events_analyzed=len(ctx.events),
            baseline_events=len(ctx.baseline),
            results=results,
            alerts=records,
            health=health,
            overall_health=overall,
            summary=self._summary(ctx, records, health, overall),
        )

    @staticmethod
    def _summary(
        ctx: AnalysisContext, alerts: list[AlertRecord], health: list[AppHealth], overall: int
    ) -> str:
        active = [a for a in alerts if a.status != "resolved"]
        open_alerts = [a for a in active if a.status == "open"]
        counts = ", ".join(
            f"{n} {sev.value}"
            for sev in Severity
            if (n := sum(1 for a in open_alerts if a.severity is sev))
        )
        text = (
            f"Analysed {len(ctx.events)} events across {len(health)} applications. "
            f"Platform health {overall}/100 with {len(open_alerts)} open alerts"
            + (f" ({counts})." if counts else ".")
        )
        if health:
            worst = min(health, key=lambda h: h.score)
            text += f" Weakest application: {worst.app} ({worst.score}/100)."
        top = [a for a in open_alerts if a.severity.rank >= Severity.HIGH.rank][:3]
        if top:
            text += (
                " Top issues: "
                + "; ".join(a.title + (f" [{a.app}]" if a.app else "") for a in top)
                + "."
            )
        return text
