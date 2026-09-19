"""Drift agent: distribution shift in traffic, latency, cost, quality and model mix."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from opscenter.agents.base import AnalysisContext, by_app, make_alert
from opscenter.models import AgentResult, Alert, Severity, StoredEvent
from opscenter.stats import category_counts, ks_two_sample, psi, psi_categorical

_KS_P = 0.01

_NUMERIC: dict[str, Callable[[StoredEvent], float | None]] = {
    "input_chars": lambda e: float(e.signals.in_chars) if e.signals.in_chars else None,
    "output_chars": lambda e: float(e.signals.out_chars) if e.signals.out_chars else None,
    "input_tokens": lambda e: float(e.input_tokens),
    "output_tokens": lambda e: float(e.output_tokens),
    "latency_ms": lambda e: e.latency_ms if e.status == "ok" else None,
    "cost_usd": lambda e: e.cost_usd,
    "grounding": lambda e: e.signals.grounding,
}
_CATEGORICAL: dict[str, Callable[[StoredEvent], str | None]] = {
    "model": lambda e: e.model,
    "prompt_version": lambda e: f"{e.prompt_id}@{e.prompt_version}" if e.prompt_id else None,
}

_GUIDANCE = {
    "input_tokens": "Inputs are changing size; check for prompt template changes or new upstream context.",
    "input_chars": "User inputs are changing; check for a new user segment, integration or attack.",
    "latency_ms": "Latency distribution moved; check provider status and model mix.",
    "cost_usd": "Per-request cost moved; check model mix and token volume.",
    "grounding": "Answer grounding moved; check retrieval and recent prompt or model changes.",
    "model": "Traffic is being served by different models than the baseline; confirm this was intended.",
    "prompt_version": "Different prompt versions are serving traffic; confirm the rollout was intended.",
}


def _shares(values: list[str]) -> dict[str, float]:
    """Share of each category, so windows of different lengths can be compared."""
    return {k: round(v / len(values), 3) for k, v in sorted(category_counts(values).items())}


class DriftAgent:
    """Compares each app's current window with its baseline using PSI and the KS test."""

    name = "drift"

    def analyze(self, ctx: AnalysisContext) -> AgentResult:
        t = ctx.thresholds
        alerts: list[Alert] = []
        rows: list[dict[str, Any]] = []
        baseline = by_app(ctx.baseline)

        for app, current in by_app(ctx.events).items():
            base = baseline.get(app, [])
            if len(current) < t.drift_min_samples or len(base) < t.drift_min_samples:
                continue
            for feature, getter in _NUMERIC.items():
                a = [num for e in base if (num := getter(e)) is not None]
                b = [num for e in current if (num := getter(e)) is not None]
                if len(a) < t.drift_min_samples or len(b) < t.drift_min_samples:
                    continue
                score = psi(a, b)
                d, p = ks_two_sample(a, b)
                rows.append(
                    {
                        "app": app,
                        "feature": feature,
                        "psi": round(score, 4),
                        "ks_d": round(d, 4),
                        "ks_p": round(p, 6),
                    }
                )
                if score >= t.psi_moderate and p < _KS_P:
                    alerts.append(
                        self._alert(
                            app,
                            feature,
                            score,
                            t.psi_significant,
                            {"ks_d": round(d, 3), "ks_p": round(p, 6)},
                        )
                    )
            for feature, cat in _CATEGORICAL.items():
                a_cat = [name for e in base if (name := cat(e)) is not None]
                b_cat = [name for e in current if (name := cat(e)) is not None]
                if len(a_cat) < t.drift_min_samples or len(b_cat) < t.drift_min_samples:
                    continue
                score = psi_categorical(category_counts(a_cat), category_counts(b_cat))
                rows.append(
                    {
                        "app": app,
                        "feature": feature,
                        "psi": round(score, 4),
                        "ks_d": None,
                        "ks_p": None,
                    }
                )
                if score >= t.psi_moderate:
                    alerts.append(
                        self._alert(
                            app,
                            feature,
                            score,
                            t.psi_significant,
                            {
                                "baseline_share": _shares(a_cat),
                                "current_share": _shares(b_cat),
                            },
                        )
                    )
        rows.sort(key=lambda r: -r["psi"])
        return AgentResult(name=self.name, alerts=alerts, metrics={"features": rows})

    def _alert(
        self, app: str, feature: str, score: float, significant: float, extra: dict[str, Any]
    ) -> Alert:
        severity = Severity.HIGH if score >= significant else Severity.MEDIUM
        return make_alert(
            self.name,
            severity,
            f"Drift in {feature}",
            f"{app} {feature} distribution differs from baseline (PSI {score:.2f}).",
            key=f"drift-{feature}",
            app=app,
            evidence={"psi": round(score, 3), **extra},
            recommendation=_GUIDANCE.get(feature, "Investigate what changed."),
        )
