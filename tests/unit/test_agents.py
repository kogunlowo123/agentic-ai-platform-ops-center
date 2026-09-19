"""Unit tests for the specialist agents and the supervisor."""

from __future__ import annotations

import random
from datetime import date, datetime, timedelta

import pytest

from opscenter.agents import (
    AnalysisContext,
    CostAgent,
    DriftAgent,
    GovernanceAgent,
    ObservabilityAgent,
    QualityAgent,
    SecurityAgent,
    Supervisor,
    compute_health,
    make_alert,
)
from opscenter.config import AppConfig, Thresholds
from opscenter.evals import CaseResult, EvalRun
from opscenter.models import AgentResult, Alert, AlertRecord, Severity, StoredEvent
from tests.conftest import NOW, Env, make_ctx, make_event, many

CFG = {"a": AppConfig(slo_availability=0.99, slo_p95_ms=5000)}


def _titles(result: AgentResult) -> dict[str, Severity]:
    return {a.title: a.severity for a in result.alerts}


def _events(count: int, **kw: object) -> list[StoredEvent]:
    return many(count, lambda i: make_event(NOW - timedelta(minutes=i + 1), **kw))  # type: ignore[arg-type]


class TestObservability:
    def test_error_budget_burn_levels(self, env: Env) -> None:
        ok = _events(92, latency_ms=500.0)
        bad = _events(8, status="error", error_type="x", latency_ms=500.0)
        result = ObservabilityAgent().analyze(make_ctx(env, ok + bad, apps=CFG))
        assert _titles(result)["Error budget burning at 8.0x"] is Severity.HIGH
        worse = _events(80, latency_ms=500.0) + _events(20, status="timeout", latency_ms=500.0)
        assert (
            Severity.CRITICAL
            in _titles(ObservabilityAgent().analyze(make_ctx(env, worse, apps=CFG))).values()
        )

    def test_latency_slo(self, env: Env) -> None:
        medium = ObservabilityAgent().analyze(
            make_ctx(env, _events(50, latency_ms=6000.0), apps=CFG)
        )
        high = ObservabilityAgent().analyze(make_ctx(env, _events(50, latency_ms=9000.0), apps=CFG))
        assert _titles(medium)["p95 latency above SLO"] is Severity.MEDIUM
        assert _titles(high)["p95 latency above SLO"] is Severity.HIGH

    def test_error_spike_against_baseline(self, env: Env) -> None:
        base = _events(99, latency_ms=500.0) + _events(1, status="error", latency_ms=500.0)
        cur = _events(94, latency_ms=500.0) + _events(6, status="error", latency_ms=500.0)
        result = ObservabilityAgent().analyze(
            make_ctx(env, cur, base, apps={"a": AppConfig(slo_availability=0.9)})
        )
        assert "Error rate spike versus baseline" in _titles(result)

    def test_small_samples_and_metrics(self, env: Env) -> None:
        result = ObservabilityAgent().analyze(make_ctx(env, _events(5, status="error"), apps=CFG))
        assert result.alerts == []
        assert (
            result.metrics["apps"]["app"]["requests"] == 5
            and result.metrics["models"][0]["model"] == "small-model"
        )

    def test_healthy_traffic_is_quiet(self, env: Env) -> None:
        assert (
            ObservabilityAgent()
            .analyze(make_ctx(env, _events(100, latency_ms=400.0), apps=CFG))
            .alerts
            == []
        )


class TestCost:
    def test_unpriced_models(self, env: Env) -> None:
        result = CostAgent().analyze(make_ctx(env, _events(5, model="mystery", cost_usd=None)))
        assert _titles(result)["Usage without pricing"] is Severity.MEDIUM

    def test_budgets(self, env: Env) -> None:
        events = _events(10, cost_usd=1.0)
        cfg = {"app": AppConfig(daily_budget_usd=5.0, monthly_budget_usd=100.0)}
        titles = _titles(CostAgent().analyze(make_ctx(env, events, apps=cfg)))
        assert titles["Daily budget exceeded"] is Severity.HIGH
        assert titles["Projected monthly spend over budget"] is Severity.HIGH
        assert "Daily budget exceeded" not in _titles(
            CostAgent().analyze(
                make_ctx(env, events, apps={"app": AppConfig(daily_budget_usd=50.0)})
            )
        )
        short = CostAgent().analyze(make_ctx(env, events, apps=cfg, window_days=0.25))
        assert not [a for a in short.alerts if "budget" in a.title.lower()]

    def test_spend_spike_versus_baseline(self, env: Env) -> None:
        base = _events(6, cost_usd=1.0)
        cur = _events(3, cost_usd=1.0)
        result = CostAgent().analyze(make_ctx(env, cur, base))
        assert "Cost spike: 3.0x baseline" in _titles(result)
        steady = CostAgent().analyze(
            make_ctx(env, _events(2, cost_usd=1.0), _events(12, cost_usd=1.0))
        )
        assert not [a for a in steady.alerts if "Cost spike" in a.title]

    def test_cache_opportunity(self, env: Env) -> None:
        dup = many(
            40,
            lambda i: make_event(
                NOW - timedelta(minutes=i + 1), cost_usd=0.01, signals={"input_hash": f"h{i % 20}"}
            ),
        )
        result = CostAgent().analyze(make_ctx(env, dup))
        alert = next(a for a in result.alerts if a.title.startswith("Caching"))
        assert alert.severity is Severity.INFO and alert.evidence["duplicate_ratio"] == 0.5
        assert alert.evidence["repeat_cost_usd"] == pytest.approx(0.2)
        unique = many(
            40,
            lambda i: make_event(NOW - timedelta(minutes=i + 1), signals={"input_hash": f"u{i}"}),
        )
        assert not [
            a for a in CostAgent().analyze(make_ctx(env, unique)).alerts if "Caching" in a.title
        ]
        few = many(
            5, lambda i: make_event(NOW - timedelta(minutes=i + 1), signals={"input_hash": "same"})
        )
        assert not [
            a for a in CostAgent().analyze(make_ctx(env, few)).alerts if "Caching" in a.title
        ]

    def test_downshift_candidate(self, env: Env) -> None:
        big = many(
            50,
            lambda i: make_event(
                NOW - timedelta(minutes=i + 1),
                model="large-model",
                input_tokens=1000,
                output_tokens=50,
                cost_usd=0.00375,
            ),
        )
        alert = next(
            a
            for a in CostAgent().analyze(make_ctx(env, big)).alerts
            if a.title.startswith("Downshift")
        )
        assert alert.evidence["to"] == "small-model" and alert.evidence["estimated_savings_usd"] > 0
        long_out = many(
            50,
            lambda i: make_event(
                NOW - timedelta(minutes=i + 1),
                model="large-model",
                output_tokens=900,
                cost_usd=0.01,
            ),
        )
        assert not [
            a
            for a in CostAgent().analyze(make_ctx(env, long_out)).alerts
            if a.title.startswith("Downshift")
        ]
        errors = many(
            50,
            lambda i: make_event(
                NOW - timedelta(minutes=i + 1),
                model="large-model",
                output_tokens=50,
                status="error",
                cost_usd=0.01,
            ),
        )
        assert not [
            a
            for a in CostAgent().analyze(make_ctx(env, errors)).alerts
            if a.title.startswith("Downshift")
        ]

    def test_metrics_totals(self, env: Env) -> None:
        events = _events(4, cost_usd=0.25, prompt_id="p", prompt_version="1")
        metrics = CostAgent().analyze(make_ctx(env, events)).metrics
        assert metrics["total_usd"] == 1.0 and metrics["models"]["small-model"]["calls"] == 4
        assert metrics["prompts"] == {"p@1": 1.0}


class TestSecurity:
    def test_secrets_and_pii(self, env: Env) -> None:
        events = _events(199) + _events(1, signals={"secrets_out": 1, "pii_out": 1})
        titles = _titles(SecurityAgent().analyze(make_ctx(env, events)))
        assert titles["Credential-shaped data in model output"] is Severity.CRITICAL
        assert titles["PII in model output"] is Severity.MEDIUM
        more = _events(90) + _events(10, signals={"pii_out": 1})
        assert (
            _titles(SecurityAgent().analyze(make_ctx(env, more)))["PII in model output"]
            is Severity.HIGH
        )

    def test_injection_rates(self, env: Env) -> None:
        mild = _events(94) + _events(6, signals={"injection": ["jailbreak"]})
        severe = _events(75) + _events(25, signals={"injection": ["jailbreak"]})
        quiet = _events(99) + _events(1, signals={"injection": ["jailbreak"]})
        assert (
            _titles(SecurityAgent().analyze(make_ctx(env, mild)))[
                "Elevated prompt-injection attempts"
            ]
            is Severity.MEDIUM
        )
        assert (
            _titles(SecurityAgent().analyze(make_ctx(env, severe)))[
                "Elevated prompt-injection attempts"
            ]
            is Severity.HIGH
        )
        assert not SecurityAgent().analyze(make_ctx(env, quiet)).alerts

    def test_repeat_offenders(self, env: Env) -> None:
        events = _events(30) + _events(
            6, user_hash="u-bad", signals={"injection": ["ignore_instructions"]}
        )
        result = SecurityAgent().analyze(make_ctx(env, events))
        alert = next(a for a in result.alerts if a.title.startswith("Repeat"))
        assert alert.evidence["user_hashes"] == ["u-bad"] and alert.evidence["max_attempts"] == 6

    def test_metrics_and_blocked_counts(self, env: Env) -> None:
        result = SecurityAgent().analyze(make_ctx(env, _events(3, status="blocked")))
        assert result.metrics["apps"]["app"]["blocked"] == 3


class TestQuality:
    def test_grounding_mean_and_tail(self, env: Env) -> None:
        low = _events(30, signals={"grounding": 0.4})
        result = QualityAgent().analyze(
            make_ctx(env, low, apps={"app": AppConfig(min_grounding=0.7)})
        )
        assert _titles(result)["Answer grounding below target"] is Severity.HIGH
        tail = _events(25, signals={"grounding": 0.9}) + _events(5, signals={"grounding": 0.2})
        titles = _titles(
            QualityAgent().analyze(make_ctx(env, tail, apps={"app": AppConfig(min_grounding=0.7)}))
        )
        assert titles == {"Many poorly grounded answers": Severity.MEDIUM}
        assert (
            not QualityAgent()
            .analyze(make_ctx(env, _events(30, signals={"grounding": 0.95})))
            .alerts
        )
        assert (
            QualityAgent().analyze(make_ctx(env, _events(3, signals={"grounding": 0.1}))).alerts
            == []
        )

    def _run(self, rate: float, cases: dict[str, bool], hours: int) -> EvalRun:
        return EvalRun(
            run_id=f"r{hours}",
            suite="s",
            target="t",
            timestamp=NOW - timedelta(hours=hours),
            pass_rate=rate,
            passed=rate > 0.5,
            cases=[CaseResult(case_id=k, passed=v) for k, v in cases.items()],
        )

    def test_eval_regression_and_improvement(self, env: Env) -> None:
        env.evals.save(self._run(1.0, {"a": True, "b": True}, 5))
        env.evals.save(self._run(0.5, {"a": True, "b": False}, 1))
        result = QualityAgent().analyze(make_ctx(env, _events(3)))
        alert = next(a for a in result.alerts if a.title.startswith("Evaluation regression"))
        assert alert.severity is Severity.HIGH and alert.evidence["newly_failing"] == ["b"]
        assert result.metrics["evals"][0]["delta"] == -0.5

        fresh = Env(env.db, env.store, env.registry, env.alerts, env.evals)
        fresh.db.conn.execute("DELETE FROM eval_runs")
        fresh.evals.save(self._run(0.5, {"a": True, "b": False}, 5))
        fresh.evals.save(self._run(1.0, {"a": True, "b": True}, 1))
        assert not [
            a
            for a in QualityAgent().analyze(make_ctx(fresh, _events(3))).alerts
            if "regression" in a.title
        ]

    def test_stale_and_fresh_suites(self, env: Env) -> None:
        cfg = {"app": AppConfig(eval_suite="s")}
        stale = QualityAgent().analyze(make_ctx(env, _events(3), apps=cfg))
        assert _titles(stale) == {"Evaluation suite s is stale": Severity.LOW}
        env.evals.save(self._run(1.0, {"a": True}, 2))
        assert not [
            a
            for a in QualityAgent().analyze(make_ctx(env, _events(3), apps=cfg)).alerts
            if "stale" in a.title
        ]
        env.db.conn.execute("DELETE FROM eval_runs")
        env.evals.save(self._run(1.0, {"a": True}, 24 * 10))
        assert [
            a
            for a in QualityAgent().analyze(make_ctx(env, _events(3), apps=cfg)).alerts
            if "stale" in a.title
        ]


def _sample(seed: int, mu: float, sigma: float, n: int, **kw: object) -> list[StoredEvent]:
    rng = random.Random(seed)
    return many(
        n,
        lambda i: make_event(
            NOW - timedelta(minutes=i + 1), latency_ms=max(1.0, rng.gauss(mu, sigma)), **kw
        ),
    )  # type: ignore[arg-type]


class TestDrift:
    def test_detects_latency_shift(self, env: Env) -> None:
        result = DriftAgent().analyze(
            make_ctx(env, _sample(2, 150, 15, 200), _sample(1, 100, 10, 200))
        )
        alert = next(a for a in result.alerts if a.title == "Drift in latency_ms")
        assert alert.severity is Severity.HIGH and alert.evidence["psi"] > 0.25
        assert result.metrics["features"][0]["feature"] == "latency_ms"

    def test_stable_traffic_is_quiet(self, env: Env) -> None:
        result = DriftAgent().analyze(
            make_ctx(env, _sample(2, 100, 10, 300), _sample(1, 100, 10, 300))
        )
        assert not [a for a in result.alerts if a.title == "Drift in latency_ms"]

    def test_categorical_model_mix_shift(self, env: Env) -> None:
        base = _events(60, model="small-model")
        cur = _events(60, model="large-model")
        result = DriftAgent().analyze(make_ctx(env, cur, base))
        assert _titles(result)["Drift in model"] is Severity.HIGH

    def test_needs_enough_samples_in_both_windows(self, env: Env) -> None:
        result = DriftAgent().analyze(
            make_ctx(env, _sample(2, 500, 5, 10), _sample(1, 100, 5, 200))
        )
        assert result.alerts == [] and result.metrics["features"] == []

    def test_constant_metric_shift_is_caught(self, env: Env) -> None:
        base = _events(60, latency_ms=500.0, cost_usd=0.001)
        cur = _events(60, latency_ms=500.0, cost_usd=0.01)
        assert "Drift in cost_usd" in _titles(DriftAgent().analyze(make_ctx(env, cur, base)))


class TestGovernance:
    def _titles(self, env: Env, events: list[StoredEvent]) -> dict[str, Severity]:
        return _titles(GovernanceAgent().analyze(make_ctx(env, events)))

    def test_model_statuses(self, env: Env) -> None:
        env.registry.register_model("ok-model", actor="a", status="approved")
        env.registry.register_model("old-model", actor="a", status="deprecated")
        env.registry.register_model("bad-model", actor="a", status="blocked")
        env.registry.register_model("new-model", actor="a", status="proposed")
        events = [
            make_event(model=m, event_id=m)
            for m in ("ok-model", "old-model", "bad-model", "new-model", "ghost")
        ]
        titles = self._titles(env, events)
        assert "Production traffic on approved model ok-model" not in titles
        assert titles["Production traffic on deprecated model old-model"] is Severity.MEDIUM
        assert titles["Production traffic on blocked model bad-model"] is Severity.CRITICAL
        assert titles["Production traffic on proposed model new-model"] is Severity.HIGH
        assert titles["Production traffic on unregistered model ghost"] is Severity.HIGH

    def test_prompt_statuses(self, env: Env) -> None:
        env.registry.register_model("m", actor="a", status="approved")
        env.registry.register_prompt("ok", "1", content="x", author="a", status="approved")
        env.registry.register_prompt("wip", "1", content="x", author="a", status="draft")
        env.registry.register_prompt("rev", "1", content="x", author="a", status="in_review")
        env.registry.register_prompt("old", "1", content="x", author="a", status="deprecated")
        events = [
            make_event(model="m", prompt_id=p, prompt_version="1", event_id=p)
            for p in ("ok", "wip", "rev", "old", "ghost")
        ]
        titles = self._titles(env, events)
        assert not any("prompt ok@1" in t for t in titles)
        assert titles["Production uses draft prompt wip@1"] is Severity.HIGH
        assert titles["Production uses in_review prompt rev@1"] is Severity.HIGH
        assert titles["Production uses deprecated prompt old@1"] is Severity.MEDIUM
        assert titles["Production uses unregistered prompt ghost@1"] is Severity.MEDIUM

    def test_only_production_is_checked_and_metrics_are_accurate(self, env: Env) -> None:
        env.registry.register_prompt("wip", "1", content="x", author="a", status="draft")
        events = [
            make_event(
                model="ghost", environment="dev", prompt_id="wip", prompt_version="1", event_id="d"
            )
        ]
        result = GovernanceAgent().analyze(make_ctx(env, events))
        assert result.alerts == [] and result.metrics == {"models": [], "prompts": []}
        prod = GovernanceAgent().analyze(
            make_ctx(env, [make_event(model="ghost", prompt_id="wip", prompt_version="1")])
        )
        assert (
            prod.metrics["prompts"][0]["status"] == "draft"
            and prod.metrics["models"][0]["status"] == "unregistered"
        )

    def test_overdue_review(self, env: Env) -> None:
        env.registry.register_model(
            "m", actor="a", status="approved", owner="o", review_due=date(2026, 9, 1)
        )
        env.registry.register_model(
            "fine", actor="a", status="approved", review_due=date(2027, 1, 1)
        )
        assert self._titles(env, []) == {"Model review overdue: m": Severity.LOW}


class _Static:
    def __init__(self, name: str, *alerts: Alert) -> None:
        self.name = name
        self._alerts = list(alerts)

    def analyze(self, ctx: AnalysisContext) -> AgentResult:
        return AgentResult(name=self.name, alerts=list(self._alerts))


class _Boom:
    name = "boom"

    def analyze(self, ctx: AnalysisContext) -> AgentResult:
        raise RuntimeError("kaput sk-" + "b" * 30)


def _a(key: str, severity: Severity = Severity.HIGH, agent: str = "x", app: str = "a") -> Alert:
    return make_alert(agent, severity, f"T-{key}", "d", key=key, app=app)


class TestSupervisor:
    def test_merges_and_deduplicates_keeping_highest_severity(self, env: Env) -> None:
        low = make_alert("x", Severity.LOW, "same", "d", key="k", app="a")
        high = make_alert("x", Severity.HIGH, "same", "d", key="k", app="a")
        report = Supervisor([_Static("one", low), _Static("two", high)], env.alerts).run(
            make_ctx(env, _events(3))
        )
        assert [(a.severity, a.title) for a in report.alerts] == [(Severity.HIGH, "same")]

    def test_agent_failure_is_isolated_redacted_and_does_not_resolve(self, env: Env) -> None:
        keep = _a("keep", agent="stable")
        first = Supervisor([_Static("stable", keep)], env.alerts).run(make_ctx(env, _events(3)))
        assert first.alerts[0].status == "open"
        report = Supervisor([_Boom(), _Static("stable")], env.alerts).run(make_ctx(env, _events(3)))
        boom = next(r for r in report.results if r.name == "boom")
        assert boom.error is not None and "b" * 30 not in boom.error
        assert any(a.title == "Analysis agent failed: boom" for a in report.alerts)
        assert (
            next(a for a in env.alerts.list() if a.title == "T-keep").status == "resolved"
        )  # stable ran and found nothing

        env.alerts.sync([_a("other", agent="drift")], NOW, {"drift"})
        Supervisor([_Boom()], env.alerts).run(make_ctx(env, _events(3)))
        assert next(a for a in env.alerts.list() if a.title == "T-other").status == "open"

    def test_health_scores(self) -> None:
        def rec(sev: Severity, app: str, status: str = "open") -> AlertRecord:
            return AlertRecord(
                fingerprint=f"{sev}{app}{status}",
                agent="x",
                severity=sev,
                title="t",
                detail="d",
                app=app,
                status=status,
                first_seen=NOW,
                last_seen=NOW,
            )  # type: ignore[arg-type]

        health, overall = compute_health(
            {"a": 10, "b": 10},
            [
                rec(Severity.HIGH, "a"),
                rec(Severity.CRITICAL, "a", "acked"),
                rec(Severity.LOW, "b", "resolved"),
            ],
        )
        scores = {h.app: h.score for h in health}
        assert scores == {"a": 78, "b": 100} and health[0].open_alerts["high"] == 1
        assert overall == 89
        _, with_platform = compute_health({"a": 10}, [rec(Severity.HIGH, "")])
        assert with_platform == 78
        assert compute_health({}, [])[1] == 100

    def test_summary_and_delivery_of_new_high_alerts_only(self, env: Env) -> None:
        sent: list[list[AlertRecord]] = []

        class Sink:
            def send(self, alerts: list[AlertRecord]) -> None:
                sent.append(alerts)

        agents = [_Static("s", _a("h", Severity.HIGH, "s"), _a("m", Severity.MEDIUM, "s"))]
        supervisor = Supervisor(agents, env.alerts, [Sink()])
        report = supervisor.run(make_ctx(env, _events(5)))
        assert "(1 high, 1 medium)" in report.summary
        assert "Weakest application: app (" in report.summary
        assert [a.severity for a in sent[0]] == [Severity.HIGH]
        supervisor.run(make_ctx(env, _events(5)))
        assert len(sent) == 1

    def test_report_metadata(self, env: Env) -> None:
        ctx = make_ctx(env, _events(4), _events(2))
        report = Supervisor([_Static("s")], env.alerts).run(ctx)
        assert (report.events_analyzed, report.baseline_events) == (4, 2)
        assert report.window_end == NOW and report.window_start == NOW - timedelta(days=1)
        assert report.overall_health == 100 and report.health[0].app == "app"
        assert isinstance(NOW, datetime)


def test_thresholds_defaults_are_sane() -> None:
    t = Thresholds()
    assert t.psi_significant > t.psi_moderate and t.burn_critical > t.burn_high
