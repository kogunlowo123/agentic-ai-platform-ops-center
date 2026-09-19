"""Quality agent: grounding (hallucination risk) on RAG traffic and evaluation regressions."""

from __future__ import annotations

from typing import Any

from opscenter.agents.base import AnalysisContext, by_app, make_alert
from opscenter.evals import compare_runs
from opscenter.models import AgentResult, Alert, Severity
from opscenter.stats import mean

_LOW_GROUNDING = 0.5
_LOW_SHARE_LIMIT = 0.10


class QualityAgent:
    """Watches answer grounding and evaluation results."""

    name = "quality"

    def analyze(self, ctx: AnalysisContext) -> AgentResult:
        t = ctx.thresholds
        alerts: list[Alert] = []
        grounding: dict[str, Any] = {}

        for app, events in by_app(ctx.events).items():
            scores = [e.signals.grounding for e in events if e.signals.grounding is not None]
            if not scores:
                continue
            avg = mean(scores)
            low_share = sum(1 for s in scores if s < _LOW_GROUNDING) / len(scores)
            grounding[app] = {
                "samples": len(scores),
                "mean": round(avg, 4),
                "share_below_0_5": round(low_share, 4),
            }
            if len(scores) < t.min_samples:
                continue
            cfg = ctx.app_config(app)
            if avg < cfg.min_grounding:
                alerts.append(
                    make_alert(
                        self.name,
                        Severity.HIGH,
                        "Answer grounding below target",
                        f"{app} mean grounding is {avg:.2f} against a target of {cfg.min_grounding:.2f} "
                        f"({len(scores)} RAG responses); answers increasingly contain claims absent from the "
                        "retrieved context.",
                        key="grounding-mean",
                        app=app,
                        evidence={
                            "mean": round(avg, 3),
                            "target": cfg.min_grounding,
                            "samples": len(scores),
                        },
                        recommendation="Inspect retrieval quality and recent prompt or model changes; run the "
                        "app's evaluation suite.",
                    )
                )
            elif low_share > _LOW_SHARE_LIMIT:
                alerts.append(
                    make_alert(
                        self.name,
                        Severity.MEDIUM,
                        "Many poorly grounded answers",
                        f"{low_share:.0%} of {app} responses have grounding below {_LOW_GROUNDING}.",
                        key="grounding-tail",
                        app=app,
                        evidence={"share_below": round(low_share, 3)},
                        recommendation="Sample the low-scoring responses for hallucinated content.",
                    )
                )

        eval_rows: list[dict[str, Any]] = []
        for suite, target in ctx.evals.suites():
            runs = ctx.evals.history(suite, target, limit=2)
            if not runs:
                continue
            latest = runs[0]
            row: dict[str, Any] = {"suite": suite, "target": target, "pass_rate": latest.pass_rate}
            if len(runs) == 2:
                diff = compare_runs(runs[1], latest)
                row["delta"] = diff.pass_rate_delta
                if diff.pass_rate_delta <= -t.eval_drop:
                    alerts.append(
                        make_alert(
                            self.name,
                            Severity.HIGH,
                            f"Evaluation regression in {suite}",
                            f"Pass rate for {target} fell from {runs[1].pass_rate:.0%} to {latest.pass_rate:.0%}.",
                            key=f"eval-regression-{suite}-{target}",
                            evidence={
                                "newly_failing": diff.newly_failing,
                                "delta": diff.pass_rate_delta,
                            },
                            recommendation="Review the newly failing cases before promoting this model or prompt.",
                        )
                    )
            eval_rows.append(row)

        alerts.extend(self._stale_evals(ctx))
        return AgentResult(
            name=self.name, alerts=alerts, metrics={"grounding": grounding, "evals": eval_rows}
        )

    @staticmethod
    def _stale_evals(ctx: AnalysisContext) -> list[Alert]:
        alerts: list[Alert] = []
        for app in sorted({e.app for e in ctx.events}):
            suite = ctx.app_config(app).eval_suite
            if not suite:
                continue
            last = ctx.evals.latest_time(suite)
            age_days = (ctx.now - last).total_seconds() / 86400 if last else None
            if age_days is None or age_days > ctx.thresholds.eval_max_age_days:
                alerts.append(
                    make_alert(
                        "quality",
                        Severity.LOW,
                        f"Evaluation suite {suite} is stale",
                        f"{app} expects regular runs of {suite}; "
                        + (
                            "it has never run."
                            if age_days is None
                            else f"the last run was {age_days:.0f} days ago."
                        ),
                        key=f"eval-stale-{suite}",
                        app=app,
                        evidence={
                            "suite": suite,
                            "age_days": None if age_days is None else round(age_days, 1),
                        },
                        recommendation="Schedule `opsctl eval run` so regressions are caught between releases.",
                    )
                )
        return alerts
