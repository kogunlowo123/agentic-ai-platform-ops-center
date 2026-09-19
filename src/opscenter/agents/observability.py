"""Observability agent: availability, latency and error-budget burn against each app's SLO."""

from __future__ import annotations

from typing import Any

from opscenter.agents.base import AnalysisContext, by_app, make_alert
from opscenter.models import AgentResult, Alert, Severity, StoredEvent
from opscenter.stats import percentile

_LATENCY_HIGH_FACTOR = 1.5
_SPIKE_MIN_DELTA = 0.02


def _row(events: list[StoredEvent]) -> dict[str, Any]:
    ok = [e.latency_ms for e in events if e.status == "ok"] or [e.latency_ms for e in events]
    failed = sum(e.failed for e in events)
    return {
        "requests": len(events),
        "error_rate": round(failed / len(events), 4),
        "p50_ms": round(percentile(ok, 0.5), 1),
        "p95_ms": round(percentile(ok, 0.95), 1),
        "p99_ms": round(percentile(ok, 0.99), 1),
        "input_tokens": sum(e.input_tokens for e in events),
        "output_tokens": sum(e.output_tokens for e in events),
    }


class ObservabilityAgent:
    """Computes request metrics and raises SLO alerts."""

    name = "observability"

    def analyze(self, ctx: AnalysisContext) -> AgentResult:
        t = ctx.thresholds
        alerts: list[Alert] = []
        apps: dict[str, Any] = {}
        models: list[dict[str, Any]] = []
        baseline = by_app(ctx.baseline)

        for app, events in by_app(ctx.events).items():
            cfg = ctx.app_config(app)
            row = _row(events)
            apps[app] = row
            for model in sorted({e.model for e in events}):
                models.append(
                    {"app": app, "model": model, **_row([e for e in events if e.model == model])}
                )
            if len(events) < t.min_samples:
                continue

            error_rate = row["error_rate"]
            budget = 1.0 - cfg.slo_availability
            burn = error_rate / budget
            if error_rate > 0 and burn >= t.burn_high:
                severity = Severity.CRITICAL if burn >= t.burn_critical else Severity.HIGH
                alerts.append(
                    make_alert(
                        self.name,
                        severity,
                        f"Error budget burning at {burn:.1f}x",
                        f"{app} error rate is {error_rate:.2%} against an SLO of {cfg.slo_availability:.2%} "
                        f"availability ({row['requests']} requests).",
                        key="error-budget",
                        app=app,
                        evidence={
                            "error_rate": error_rate,
                            "burn_rate": round(burn, 2),
                            "slo": cfg.slo_availability,
                        },
                        recommendation="Check recent deploys, provider status and the error_type breakdown; "
                        "consider failing over to a secondary model.",
                    )
                )
            if row["p95_ms"] > cfg.slo_p95_ms:
                severity = (
                    Severity.HIGH
                    if row["p95_ms"] >= _LATENCY_HIGH_FACTOR * cfg.slo_p95_ms
                    else Severity.MEDIUM
                )
                alerts.append(
                    make_alert(
                        self.name,
                        severity,
                        "p95 latency above SLO",
                        f"{app} p95 latency is {row['p95_ms']:.0f} ms against a target of {cfg.slo_p95_ms:.0f} ms.",
                        key="latency-p95",
                        app=app,
                        evidence={"p95_ms": row["p95_ms"], "slo_p95_ms": cfg.slo_p95_ms},
                        recommendation="Inspect the per-model latency table; route latency-sensitive traffic "
                        "to a faster model or reduce prompt size.",
                    )
                )
            base_events = baseline.get(app, [])
            if len(base_events) >= t.min_samples:
                base_rate = _row(base_events)["error_rate"]
                if (
                    error_rate >= t.error_spike_ratio * max(base_rate, 0.001)
                    and error_rate - base_rate >= _SPIKE_MIN_DELTA
                ):
                    alerts.append(
                        make_alert(
                            self.name,
                            Severity.HIGH,
                            "Error rate spike versus baseline",
                            f"{app} error rate rose from {base_rate:.2%} to {error_rate:.2%}.",
                            key="error-spike",
                            app=app,
                            evidence={"baseline_error_rate": base_rate, "error_rate": error_rate},
                            recommendation="Correlate the onset with deployments, prompt changes and provider incidents.",
                        )
                    )
        return AgentResult(name=self.name, alerts=alerts, metrics={"apps": apps, "models": models})
