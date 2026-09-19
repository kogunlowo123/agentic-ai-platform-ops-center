"""Unit tests for the router, simulator, service helpers, reporting and container."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from opscenter.container import build_llm_client, build_service
from opscenter.errors import (
    ConfigurationError,
    OpscenterError,
    ProviderError,
    ReportError,
    RoutingError,
)
from opscenter.models import LLMEvent
from opscenter.reporting import FORMATS, render, write_reports
from opscenter.router import ModelRouter, RouteCandidate
from opscenter.service import parse_duration
from opscenter.simulate import simulate
from tests.conftest import CONFIGS, NOW, FakeLLM, make_settings

END = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)


class Scripted:
    """Client that yields queued outcomes (strings return, exceptions raise)."""

    def __init__(self, *outcomes: str | Exception) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def _cand(name: str, client: Scripted, **kw: object) -> RouteCandidate:
    return RouteCandidate(name=name, client=client, **kw)  # type: ignore[arg-type]


class TestRouter:
    def test_falls_back_and_emits_telemetry(self) -> None:
        events: list[LLMEvent] = []
        primary, backup = Scripted(ProviderError("boom sk-" + "a" * 30)), Scripted("answer text")
        router = ModelRouter(
            [_cand("p", primary), _cand("b", backup)], on_event=events.append, now=lambda: NOW
        )
        result = router.complete("sys", "user question")
        assert result.text == "answer text" and result.model == "b"
        assert [a.outcome for a in result.attempts] == ["error", "ok"]
        assert "a" * 30 not in (result.attempts[0].error or "")
        assert [(e.model, e.status) for e in events] == [("p", "error"), ("b", "ok")]
        assert events[1].output_tokens == len("answer text") // 4 and events[0].timestamp == NOW

    def test_all_fail_raises_with_summary(self) -> None:
        router = ModelRouter(
            [_cand("a", Scripted(ProviderError("x"))), _cand("b", Scripted(ProviderError("y")))]
        )
        with pytest.raises(RoutingError, match="a: error; b: error"):
            router.complete("s", "u")

    def test_circuit_breaker_opens_then_half_opens(self) -> None:
        clock = Clock()
        flaky = Scripted(ProviderError("x"), ProviderError("x"), "back")
        stable = Scripted("ok")
        router = ModelRouter(
            [_cand("flaky", flaky), _cand("stable", stable)],
            failure_threshold=2,
            cooldown_seconds=30,
            clock=clock,
        )
        router.complete("s", "u")
        router.complete("s", "u")
        assert router.state()["flaky"]["breaker"] == "open"
        calls_before = flaky.calls
        third = router.complete("s", "u")
        assert flaky.calls == calls_before and third.attempts[0].outcome == "skipped_open"

        clock.t = 31
        recovered = router.complete("s", "u")
        assert recovered.model == "flaky" and router.state()["flaky"]["breaker"] == "closed"

    def test_failed_trial_reopens_and_only_one_trial_runs(self) -> None:
        clock = Clock()
        bad = Scripted(ProviderError("x"))
        router = ModelRouter(
            [_cand("bad", bad), _cand("good", Scripted("ok"))],
            failure_threshold=1,
            cooldown_seconds=10,
            clock=clock,
        )
        router.complete("s", "u")
        clock.t = 11
        assert router._allow("bad") is True
        assert router._allow("bad") is False
        router._record_failure("bad")
        clock.t = 15
        assert router._allow("bad") is False
        clock.t = 22
        assert router._allow("bad") is True

    def test_strategies(self) -> None:
        cheap = _cand("cheap", Scripted("c"), input_per_mtok=1, output_per_mtok=1, quality=10)
        pricey = _cand("pricey", Scripted("p"), input_per_mtok=10, output_per_mtok=10, quality=90)
        assert ModelRouter([pricey, cheap], strategy="cost").complete("s", "u").model == "cheap"
        assert ModelRouter([cheap, pricey], strategy="quality").complete("s", "u").model == "pricey"
        assert ModelRouter([pricey, cheap], strategy="ordered").complete("s", "u").model == "pricey"
        fast = ModelRouter([pricey, cheap], strategy="latency")
        fast._latency = {"pricey": 900.0, "cheap": 100.0}
        assert fast.complete("s", "u").model == "cheap"

    def test_tier_filter_and_empty_pool(self) -> None:
        router = ModelRouter(
            [_cand("a", Scripted("a"), tier="fast"), _cand("b", Scripted("b"), tier="smart")]
        )
        assert router.complete("s", "u", tier="smart").model == "b"
        with pytest.raises(RoutingError, match="no candidates"):
            router.complete("s", "u", tier="missing")
        with pytest.raises(ValueError):
            ModelRouter([])

    def test_state_and_unexpected_errors_propagate(self) -> None:
        router = ModelRouter([_cand("a", Scripted("x"))])
        router.complete("s", "u")
        state = router.state()["a"]
        assert state["breaker"] == "closed" and state["avg_latency_ms"] is not None
        with pytest.raises(KeyError):
            ModelRouter([_cand("a", Scripted(KeyError("bug")))]).complete("s", "u")


class TestSimulator:
    def test_deterministic_and_seeded(self) -> None:
        a = simulate(end=END, days=2, per_day=20, seed=3)
        b = simulate(end=END, days=2, per_day=20, seed=3)
        c = simulate(end=END, days=2, per_day=20, seed=4)
        assert [e.model_dump_json() for e in a] == [e.model_dump_json() for e in b]
        assert [e.model_dump_json() for e in a] != [e.model_dump_json() for e in c]

    def test_incident_structure(self) -> None:
        events = simulate(end=END, days=3, per_day=150, seed=7)
        last_day = [e for e in events if e.timestamp >= END - timedelta(days=1)]
        earlier = [e for e in events if e.timestamp < END - timedelta(days=1)]
        assert any(e.user_id and e.user_id.startswith("attacker") for e in last_day)
        assert not any(e.user_id and e.user_id.startswith("attacker") for e in earlier)
        assert any("jane.doe@example.com" in (e.output_text or "") for e in last_day)
        assert any(e.model == "experimental-model" for e in last_day) and not any(
            e.model == "experimental-model" for e in earlier
        )
        assert any(e.event_id.startswith("leak-") for e in events)
        assert all(e.timestamp <= END for e in events) and events == sorted(
            events, key=lambda e: e.timestamp
        )

    def test_no_incident_is_clean(self) -> None:
        events = simulate(end=END, days=3, per_day=100, incident=False)
        assert not any(
            e.model == "experimental-model" or (e.user_id or "").startswith("attacker")
            for e in events
        )
        assert not any("@example.com" in (e.output_text or "") for e in events)


class TestDuration:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("90m", timedelta(minutes=90)),
            ("24h", timedelta(hours=24)),
            ("7d", timedelta(days=7)),
            ("2w", timedelta(weeks=2)),
        ],
    )
    def test_valid(self, text: str, expected: timedelta) -> None:
        assert parse_duration(text) == expected

    @pytest.mark.parametrize("text", ["", "0h", "5", "h", "1.5d", "-1d", "3x"])
    def test_invalid(self, text: str) -> None:
        with pytest.raises(OpscenterError, match="invalid duration"):
            parse_duration(text)


class TestServiceAndContainer:
    def test_report_window_semantics(self, tmp_path: Path) -> None:
        service = build_service(make_settings(tmp_path), clock=lambda: NOW)
        events = [
            LLMEvent(event_id="in", timestamp=NOW - timedelta(hours=2), app="a", model="m"),
            LLMEvent(event_id="edge", timestamp=NOW, app="a", model="m"),
            LLMEvent(event_id="base", timestamp=NOW - timedelta(days=3), app="a", model="m"),
            LLMEvent(event_id="old", timestamp=NOW - timedelta(days=30), app="a", model="m"),
        ]
        service.ingest_events(events)
        report = service.report(window=timedelta(hours=24), baseline=timedelta(days=6))
        assert (report.events_analyzed, report.baseline_events) == (2, 1)
        assert report.window_end == NOW and report.generated_at == NOW

    def test_store_event_hook_used_by_router(self, tmp_path: Path) -> None:
        service = build_service(make_settings(tmp_path), clock=lambda: NOW)
        router = ModelRouter(
            [_cand("m", Scripted("hello there"))], on_event=service.store_event, now=lambda: NOW
        )
        router.complete("s", "u")
        assert service.store.count() == 1

    def test_llm_client_configuration(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        for provider, fragment in (
            ("none", "OPSCENTER_LLM_PROVIDER"),
            ("openai", "OPENAI"),
            ("anthropic", "ANTHROPIC"),
        ):
            with pytest.raises(ConfigurationError, match=fragment):
                build_llm_client(make_settings(tmp_path, llm_provider=provider))

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/chat/completions"):
                return httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
            return httpx.Response(200, json={"content": [{"type": "text", "text": "yo"}]})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        openai = build_llm_client(
            make_settings(
                tmp_path, llm_provider="openai", openai_api_key="sk-test-000000000000000000"
            ),
            client,
        )
        anthropic = build_llm_client(
            make_settings(
                tmp_path, llm_provider="anthropic", anthropic_api_key="ak-test-000000000000000000"
            ),
            client,
        )
        assert openai.complete("s", "u") == "hi" and anthropic.complete("s", "u") == "yo"

    def test_webhook_sink_is_wired_when_configured(self, tmp_path: Path) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, json={})

        settings = make_settings(tmp_path, webhook_url="https://hooks.example/secret-token")
        service = build_service(
            settings,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
            clock=lambda: NOW,
        )
        service.ingest_events(
            [LLMEvent(timestamp=NOW - timedelta(hours=1), app="a", model="ghost")]
        )
        service.report(window=timedelta(hours=24), baseline=timedelta(days=6))
        assert seen == ["https://hooks.example/secret-token"]
        assert "secret-token" not in repr(settings)

    def test_settings_validation(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="retry_max_wait"):
            make_settings(tmp_path, retry_min_wait=5.0, retry_max_wait=1.0)
        with pytest.raises(ValueError, match="psi_significant"):
            make_settings(tmp_path, thresholds={"psi_moderate": 0.3, "psi_significant": 0.2})


class TestReporting:
    def _report(self, tmp_path: Path):  # type: ignore[no-untyped-def]
        settings = make_settings(
            tmp_path,
            pricing_file=CONFIGS / "pricing.example.json",
            apps_file=CONFIGS / "apps.example.yaml",
        )
        service = build_service(settings, clock=lambda: END)
        service.ingest_events(simulate(end=END, days=3, per_day=120, seed=7))
        return service.report(window=timedelta(hours=24), baseline=timedelta(days=2))

    def test_markdown_sections_json_round_trip_and_files(self, tmp_path: Path) -> None:
        report = self._report(tmp_path)
        md = render(report, "md")
        for heading in (
            "## Summary",
            "## Application health",
            "## Alerts",
            "## Observability",
            "## Cost",
            "## Drift",
            "## Governance",
            "## Quality",
            "## Notice",
        ):
            assert heading in md
        assert type(report).model_validate_json(render(report, "json")) == report
        paths = write_reports(report, tmp_path / "out", list(FORMATS))
        assert sorted(p.name for p in paths) == ["ops-report.json", "ops-report.md"]

    def test_markdown_escapes_hostile_text(self, tmp_path: Path) -> None:
        report = self._report(tmp_path)
        hacked = report.model_copy(update={"summary": "<script>alert(1)</script> | pipe"})
        md = render(hacked, "md")
        assert "<script>" not in md and "\\| pipe" in md

    def test_errors(self, tmp_path: Path) -> None:
        report = self._report(tmp_path)
        with pytest.raises(ReportError, match="unknown format"):
            render(report, "pdf")
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(ReportError, match="cannot write"):
            write_reports(report, blocker / "sub", ["md"])

    def test_agent_errors_section(self, tmp_path: Path) -> None:
        report = self._report(tmp_path)
        broken = report.model_copy(
            update={
                "results": [
                    *report.results,
                    type(report.results[0])(name="x", error="Boom: failed"),
                ]
            }
        )
        assert "## Agent errors" in render(broken, "md") and "x: Boom: failed" in render(
            broken, "md"
        )

    def test_empty_platform_renders(self, tmp_path: Path) -> None:
        service = build_service(make_settings(tmp_path), clock=lambda: NOW)
        md = render(service.report(window=timedelta(hours=1), baseline=timedelta(days=1)), "md")
        assert "No active alerts." in md and "Platform health 100/100" in md
        assert json.loads(FakeLLM('{"a": 1}').complete("", "")) == {"a": 1}
