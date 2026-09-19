"""Cost agent: spend attribution, budget and spike alerts, and savings opportunities."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from opscenter.agents.base import AnalysisContext, by_app, make_alert
from opscenter.models import AgentResult, Alert, Severity, StoredEvent

_DOWNSHIFT_MAX_AVG_OUTPUT = 150
_DOWNSHIFT_MAX_ERROR_RATE = 0.02
_DOWNSHIFT_PRICE_RATIO = 0.5
_MIN_WINDOW_DAYS_FOR_BUDGETS = 0.5
_SPIKE_HIGH_FACTOR = 2.5


def _cost(events: list[StoredEvent]) -> float:
    return sum(e.cost_usd or 0.0 for e in events)


class CostAgent:
    """Attributes spend and flags anomalies and opportunities."""

    name = "cost"

    def analyze(self, ctx: AnalysisContext) -> AgentResult:
        t = ctx.thresholds
        alerts: list[Alert] = []
        apps: dict[str, Any] = {}
        models: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"calls": 0, "cost_usd": 0.0, "input_tokens": 0, "output_tokens": 0}
        )
        prompts: dict[str, float] = defaultdict(float)
        baseline = by_app(ctx.baseline)
        days = max(ctx.window_days, 1e-9)

        for event in ctx.events:
            entry = models[event.model]
            entry["calls"] += 1
            entry["cost_usd"] += event.cost_usd or 0.0
            entry["input_tokens"] += event.input_tokens
            entry["output_tokens"] += event.output_tokens
            if event.prompt_id:
                prompts[f"{event.prompt_id}@{event.prompt_version or '?'}"] += event.cost_usd or 0.0

        for app, events in by_app(ctx.events).items():
            cfg = ctx.app_config(app)
            total = _cost(events)
            daily = total / days
            apps[app] = {
                "cost_usd": round(total, 4),
                "daily_usd": round(daily, 4),
                "calls": len(events),
            }

            unpriced = sorted({e.model for e in events if e.cost_usd is None})
            if unpriced:
                count = sum(1 for e in events if e.cost_usd is None)
                alerts.append(
                    make_alert(
                        self.name,
                        Severity.MEDIUM,
                        "Usage without pricing",
                        f"{app} made {count} calls with models missing from the price catalog: {', '.join(unpriced)}.",
                        key="unpriced",
                        app=app,
                        evidence={"models": unpriced, "calls": count},
                        recommendation="Add these models to the pricing file so their spend is counted.",
                    )
                )

            if ctx.window_days >= _MIN_WINDOW_DAYS_FOR_BUDGETS:
                if cfg.daily_budget_usd and daily > cfg.daily_budget_usd:
                    alerts.append(
                        make_alert(
                            self.name,
                            Severity.HIGH
                            if daily > 1.5 * cfg.daily_budget_usd
                            else Severity.MEDIUM,
                            "Daily budget exceeded",
                            f"{app} averages ${daily:,.2f} per day against a budget of ${cfg.daily_budget_usd:,.2f}.",
                            key="daily-budget",
                            app=app,
                            evidence={
                                "daily_usd": round(daily, 2),
                                "budget_usd": cfg.daily_budget_usd,
                            },
                            recommendation="Review the model and prompt cost tables and the savings opportunities below.",
                        )
                    )
                if cfg.monthly_budget_usd and daily * 30 > cfg.monthly_budget_usd:
                    alerts.append(
                        make_alert(
                            self.name,
                            Severity.HIGH,
                            "Projected monthly spend over budget",
                            f"At ${daily:,.2f} per day, {app} is projected to spend ${daily * 30:,.0f} "
                            f"this month against ${cfg.monthly_budget_usd:,.0f}.",
                            key="monthly-budget",
                            app=app,
                            evidence={
                                "projected_usd": round(daily * 30, 2),
                                "budget_usd": cfg.monthly_budget_usd,
                            },
                            recommendation="Reduce spend or raise the budget deliberately.",
                        )
                    )

            base_events = baseline.get(app, [])
            base_daily = _cost(base_events) / max(ctx.baseline_days, 1e-9)
            if (
                base_events
                and base_daily > 0
                and daily >= t.cost_spike_ratio * base_daily
                and daily - base_daily >= t.cost_spike_min_usd
            ):
                ratio = daily / base_daily
                alerts.append(
                    make_alert(
                        self.name,
                        Severity.HIGH if ratio >= _SPIKE_HIGH_FACTOR else Severity.MEDIUM,
                        f"Cost spike: {ratio:.1f}x baseline",
                        f"{app} daily spend rose from ${base_daily:,.2f} to ${daily:,.2f}.",
                        key="cost-spike",
                        app=app,
                        evidence={
                            "baseline_daily_usd": round(base_daily, 2),
                            "daily_usd": round(daily, 2),
                        },
                        recommendation="Compare model mix, input token size and request volume with the baseline.",
                    )
                )
            alerts.extend(self._cache_opportunity(ctx, app, events))

        alerts.extend(self._downshift_opportunities(ctx))
        total = sum(v["cost_usd"] for v in models.values())
        return AgentResult(
            name=self.name,
            alerts=alerts,
            metrics={
                "total_usd": round(total, 4),
                "apps": apps,
                "models": {
                    k: {**v, "cost_usd": round(v["cost_usd"], 4)} for k, v in sorted(models.items())
                },
                "prompts": {
                    k: round(v, 4) for k, v in sorted(prompts.items(), key=lambda kv: -kv[1])
                },
            },
        )

    def _cache_opportunity(
        self, ctx: AnalysisContext, app: str, events: list[StoredEvent]
    ) -> list[Alert]:
        hashed = [e for e in events if e.signals.input_hash]
        if len(hashed) < ctx.thresholds.min_samples:
            return []
        counts = Counter(e.signals.input_hash for e in hashed)
        duplicates = len(hashed) - len(counts)
        ratio = duplicates / len(hashed)
        if ratio < ctx.thresholds.duplicate_ratio:
            return []
        seen: set[str | None] = set()
        repeat_cost = 0.0
        for event in hashed:
            if event.signals.input_hash in seen:
                repeat_cost += event.cost_usd or 0.0
            seen.add(event.signals.input_hash)
        return [
            make_alert(
                self.name,
                Severity.INFO,
                "Caching opportunity: repeated inputs",
                f"{ratio:.0%} of {app} requests repeat an earlier input in this window; "
                f"those repeats cost ${repeat_cost:,.2f}.",
                key="cache-opportunity",
                app=app,
                evidence={
                    "duplicate_ratio": round(ratio, 3),
                    "repeat_cost_usd": round(repeat_cost, 4),
                },
                recommendation="Consider response caching for identical inputs. The estimate assumes a cached "
                "answer is acceptable; check freshness and personalisation requirements first.",
            )
        ]

    def _downshift_opportunities(self, ctx: AnalysisContext) -> list[Alert]:
        alerts: list[Alert] = []
        for app, events in by_app(ctx.events).items():
            for model in sorted({e.model for e in events}):
                current = ctx.catalog.get(model)
                subset = [e for e in events if e.model == model]
                if current is None or len(subset) < ctx.thresholds.min_samples:
                    continue
                avg_out = sum(e.output_tokens for e in subset) / len(subset)
                error_rate = sum(e.failed for e in subset) / len(subset)
                if avg_out > _DOWNSHIFT_MAX_AVG_OUTPUT or error_rate > _DOWNSHIFT_MAX_ERROR_RATE:
                    continue
                cheaper = [
                    (name, ctx.catalog.get(name))
                    for name in ctx.catalog.models()
                    if name != model
                    and (price := ctx.catalog.get(name)) is not None
                    and price.blended() <= _DOWNSHIFT_PRICE_RATIO * current.blended()
                ]
                if not cheaper:
                    continue
                name, price = min(cheaper, key=lambda item: item[1].blended() if item[1] else 0.0)
                assert price is not None
                savings = sum(
                    (e.cost_usd or 0.0) - price.cost(e.input_tokens, e.output_tokens)
                    for e in subset
                )
                if savings <= 0:
                    continue
                alerts.append(
                    make_alert(
                        self.name,
                        Severity.INFO,
                        f"Downshift candidate: {model} to {name}",
                        f"{app} sends short outputs (avg {avg_out:.0f} tokens) to {model}. Serving the same "
                        f"tokens on {name} would cost about ${savings:,.2f} less in this window.",
                        key=f"downshift-{model}",
                        app=app,
                        evidence={
                            "from": model,
                            "to": name,
                            "estimated_savings_usd": round(savings, 2),
                        },
                        recommendation="Run the app's evaluation suite against the cheaper model before switching; "
                        "the estimate ignores any quality difference.",
                    )
                )
        return alerts
