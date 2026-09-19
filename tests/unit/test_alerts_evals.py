"""Unit tests for alert lifecycle, sinks and evaluation suites."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import httpx
import pydantic
import pytest
from pydantic import SecretStr

from opscenter.alerts import FileSink, WebhookSink, deliver, fingerprint
from opscenter.errors import EvalError, ProviderError, RegistryError
from opscenter.evals import (
    Assertion,
    CaseResult,
    EvalRun,
    EvalSuite,
    check_assertion,
    compare_runs,
    load_suite,
    run_suite,
)
from opscenter.models import Alert, AlertRecord, Severity
from tests.conftest import CONFIGS, NOW, Env, FakeLLM, json_client


def _alert(
    fp: str = "f1",
    *,
    agent: str = "cost",
    severity: Severity = Severity.HIGH,
    app: str = "a",
    title: str = "T",
) -> Alert:
    return Alert(fingerprint=fp, agent=agent, severity=severity, title=title, detail="d", app=app)


class TestAlertLifecycle:
    def test_fingerprint_is_stable_and_distinct(self) -> None:
        assert fingerprint("a", "b", "c") == fingerprint("a", "b", "c")
        assert fingerprint("a", "b", "c") != fingerprint("a", "b", "d")

    def test_new_repeat_resolve_reopen(self, env: Env) -> None:
        records, newly = env.alerts.sync([_alert()], NOW, {"cost"})
        assert (
            [r.status for r in records] == ["open"]
            and len(newly) == 1
            and records[0].occurrences == 1
        )

        later = NOW + timedelta(hours=1)
        records, newly = env.alerts.sync([_alert()], later, {"cost"})
        assert records[0].occurrences == 2 and newly == [] and records[0].first_seen == NOW
        assert records[0].last_seen == later

        env.alerts.sync([], later, {"cost"})
        assert [r.status for r in env.alerts.list()] == ["resolved"]

        records, newly = env.alerts.sync([_alert()], later, {"cost"})
        assert records[0].status == "open" and len(newly) == 1

    def test_severity_and_title_updates_are_recorded(self, env: Env) -> None:
        env.alerts.sync([_alert(severity=Severity.MEDIUM, title="old")], NOW, {"cost"})
        (record,), _ = env.alerts.sync(
            [_alert(severity=Severity.CRITICAL, title="new")], NOW, {"cost"}
        )
        assert (record.severity, record.title) == (Severity.CRITICAL, "new")

    def test_alerts_from_agents_that_did_not_run_are_left_alone(self, env: Env) -> None:
        env.alerts.sync([_alert(agent="drift")], NOW, {"drift"})
        env.alerts.sync([], NOW, {"cost"})
        assert env.alerts.list()[0].status == "open"

    def test_ack_survives_repeats_and_is_audited(self, env: Env) -> None:
        (record,), _ = env.alerts.sync([_alert()], NOW, {"cost"})
        acked = env.alerts.acknowledge(record.fingerprint[:6], "alice")
        assert acked.status == "acked"
        (again,), newly = env.alerts.sync([_alert()], NOW, {"cost"})
        assert again.status == "acked" and newly == []
        assert env.registry.audit_log()[0].action == "alert.ack"
        env.alerts.sync([], NOW, {"cost"})
        assert env.alerts.list()[0].status == "resolved"

    def test_ack_errors(self, env: Env) -> None:
        with pytest.raises(RegistryError, match="no open alert"):
            env.alerts.acknowledge("zzz", "a")
        env.alerts.sync([_alert("aa1"), _alert("aa2")], NOW, {"cost"})
        with pytest.raises(RegistryError, match="2 open alerts match"):
            env.alerts.acknowledge("aa", "a")

    def test_listing_is_ordered_by_severity(self, env: Env) -> None:
        env.alerts.sync(
            [
                _alert("l", severity=Severity.LOW),
                _alert("c", severity=Severity.CRITICAL),
                _alert("m", severity=Severity.MEDIUM),
            ],
            NOW,
            {"cost"},
        )
        assert [r.severity for r in env.alerts.list()] == [
            Severity.CRITICAL,
            Severity.MEDIUM,
            Severity.LOW,
        ]
        assert len(env.alerts.list("open")) == 3 and env.alerts.list("resolved") == []


def _record(severity: Severity = Severity.HIGH, detail: str = "d") -> AlertRecord:
    return AlertRecord(
        fingerprint="fp",
        agent="x",
        severity=severity,
        title="T",
        detail=detail,
        app="a",
        first_seen=NOW,
        last_seen=NOW,
    )


class TestSinks:
    def test_file_sink_appends_redacted_json_lines(self, tmp_path: Path) -> None:
        sink = FileSink(tmp_path / "out" / "alerts.jsonl")
        secret = "sk-" + "k" * 30
        sink.send([_record(detail=f"leaked {secret}")])
        sink.send([_record()])
        lines = (tmp_path / "out" / "alerts.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2 and "k" * 30 not in lines[0]

    def test_webhook_posts_summary_without_evidence(self) -> None:
        seen: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert str(request.url) == "https://hooks.example/abc"
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={})

        WebhookSink(json_client(handler), SecretStr("https://hooks.example/abc")).send([_record()])
        (payload,) = seen
        (item,) = payload["alerts"]  # type: ignore[misc]
        assert item["severity"] == "high" and "evidence" not in item

    def test_deliver_filters_by_severity_and_isolates_failures(self) -> None:
        class Good:
            def __init__(self) -> None:
                self.got: list[AlertRecord] = []

            def send(self, alerts: list[AlertRecord]) -> None:
                self.got.extend(alerts)

        class Bad:
            def send(self, alerts: list[AlertRecord]) -> None:
                raise ProviderError("down sk-" + "x" * 30)

        good = Good()
        failures = deliver([Bad(), good], [_record(Severity.MEDIUM), _record(Severity.CRITICAL)])
        assert [a.severity for a in good.got] == [Severity.CRITICAL]
        assert len(failures) == 1 and failures[0].startswith("Bad:") and "x" * 30 not in failures[0]
        good2 = Good()
        assert deliver([good2], [_record(Severity.LOW)]) == [] and good2.got == []


class TestAssertions:
    @pytest.mark.parametrize(
        ("assertion", "output", "ok"),
        [
            ({"type": "contains", "value": "30"}, "within 30 days", True),
            ({"type": "contains", "value": "30"}, "soon", False),
            ({"type": "not_contains", "value": "sorry"}, "fine", True),
            ({"type": "not_contains", "value": "sorry"}, "so sorry", False),
            ({"type": "contains_any", "value": ["a", "b"]}, "xxbxx", True),
            ({"type": "contains_any", "value": ["a", "b"]}, "xxx", False),
            ({"type": "equals", "value": "yes"}, " yes\n", True),
            ({"type": "equals", "value": "yes"}, "no", False),
            ({"type": "regex", "value": r"\d{3}"}, "abc 123", True),
            ({"type": "regex", "value": r"\d{3}"}, "abc", False),
            ({"type": "max_chars", "value": 5}, "12345", True),
            ({"type": "max_chars", "value": 5}, "123456", False),
            ({"type": "min_chars", "value": 3}, "abc", True),
            ({"type": "min_chars", "value": 3}, "ab", False),
            ({"type": "json_valid"}, '{"a": 1}', True),
            ({"type": "json_valid"}, "{oops", False),
            ({"type": "json_has_keys", "value": ["a", "b"]}, '{"a":1,"b":2}', True),
            ({"type": "json_has_keys", "value": ["a", "b"]}, '{"a":1}', False),
            ({"type": "json_has_keys", "value": ["a"]}, "[1]", False),
            ({"type": "no_pii"}, "nothing here", True),
            ({"type": "no_pii"}, "mail a@b.co", False),
            ({"type": "no_secrets"}, "fine", True),
            ({"type": "no_secrets"}, "key sk-" + "z" * 30, False),
        ],
    )
    def test_check(self, assertion: dict[str, object], output: str, ok: bool) -> None:
        result = check_assertion(Assertion.model_validate(assertion), output)
        assert (result is None) is ok

    @pytest.mark.parametrize(
        "bad",
        [
            {"type": "contains"},
            {"type": "contains_any", "value": []},
            {"type": "max_chars", "value": "ten"},
            {"type": "regex", "value": "("},
            {"type": "made_up", "value": "x"},
        ],
    )
    def test_invalid_assertions(self, bad: dict[str, object]) -> None:
        with pytest.raises(pydantic.ValidationError):
            Assertion.model_validate(bad)


def _suite(**kw: object) -> EvalSuite:
    data: dict[str, object] = {
        "name": "s",
        "pass_threshold": 0.5,
        "cases": [
            {"id": "c1", "input": "q1", "assertions": [{"type": "contains", "value": "ok"}]},
            {
                "id": "c2",
                "input": "q2",
                "assertions": [{"type": "no_pii"}, {"type": "max_chars", "value": 20}],
            },
        ],
    }
    data.update(kw)
    return EvalSuite.model_validate(data)


class TestRunSuite:
    def test_pass_fail_details_and_threshold(self) -> None:
        run = run_suite(
            _suite(),
            FakeLLM("ok", "mail a@b.co and a very long answer here"),
            target="t",
            clock=lambda: NOW,
        )
        assert run.pass_rate == 0.5 and run.passed and run.timestamp == NOW
        assert [c.passed for c in run.cases] == [True, False]
        assert len(run.cases[1].failures) == 2
        strict = run_suite(_suite(pass_threshold=0.9), FakeLLM("ok", "bad a@b.co"), target="t")
        assert not strict.passed

    def test_provider_errors_fail_the_case_not_the_run(self) -> None:
        class Flaky:
            def __init__(self) -> None:
                self.n = 0

            def complete(self, system: str, user: str) -> str:
                self.n += 1
                if self.n == 1:
                    raise ProviderError("down sk-" + "e" * 30)
                return "ok"

        run = run_suite(_suite(), Flaky(), target="t")
        assert run.cases[0].error is not None and "e" * 30 not in run.cases[0].error
        assert run.cases[1].passed

    def test_previews_are_redacted_and_truncated(self) -> None:
        secret = "sk-" + "p" * 30
        suite = _suite(
            cases=[{"id": "c", "input": "q", "assertions": [{"type": "min_chars", "value": 1}]}]
        )
        run = run_suite(suite, FakeLLM(f"key {secret} " + "x" * 500), target="t")
        assert (
            "p" * 30 not in run.cases[0].output_preview and len(run.cases[0].output_preview) <= 220
        )

    def test_suite_validation(self) -> None:
        with pytest.raises(pydantic.ValidationError, match="unique"):
            _suite(cases=[{"id": "x", "input": "a", "assertions": [{"type": "no_pii"}]}] * 2)
        with pytest.raises(pydantic.ValidationError):
            _suite(cases=[])
        with pytest.raises(pydantic.ValidationError):
            _suite(surprise=1)

    def test_bundled_suite_loads_and_errors(self, tmp_path: Path) -> None:
        suite = load_suite(CONFIGS / "evals" / "support-regression.yaml")
        assert suite.name == "support-regression" and len(suite.cases) == 3
        bad = tmp_path / "bad.yaml"
        bad.write_text("name: x\ncases: []\n", encoding="utf-8")
        with pytest.raises(EvalError, match="cannot load"):
            load_suite(bad)
        with pytest.raises(EvalError):
            load_suite(tmp_path / "missing.yaml")


def _run(rate: float, passed: dict[str, bool], target: str = "t", hours: int = 0) -> EvalRun:
    return EvalRun(
        run_id=f"r{hours}{rate}",
        suite="s",
        target=target,
        timestamp=NOW + timedelta(hours=hours),
        pass_rate=rate,
        passed=rate >= 0.5,
        cases=[CaseResult(case_id=k, passed=v) for k, v in passed.items()],
    )


class TestRegressionAndRepo:
    def test_compare_runs(self) -> None:
        diff = compare_runs(
            _run(1.0, {"a": True, "b": True, "c": False}),
            _run(0.67, {"a": True, "b": False, "c": True}),
        )
        assert (
            diff.newly_failing == ["b"]
            and diff.newly_passing == ["c"]
            and diff.pass_rate_delta == -0.33
        )

    def test_repo_history_suites_and_latest(self, env: Env) -> None:
        assert env.evals.latest_time("s") is None and env.evals.history("s") == []
        env.evals.save(_run(0.8, {"a": True}, hours=0))
        env.evals.save(_run(0.9, {"a": True}, hours=2))
        env.evals.save(_run(0.7, {"a": True}, target="other", hours=1))
        assert [r.pass_rate for r in env.evals.history("s")] == [0.9, 0.7, 0.8]
        assert [r.pass_rate for r in env.evals.history("s", "t")] == [0.9, 0.8]
        assert env.evals.suites() == [("s", "other"), ("s", "t")]
        assert env.evals.latest_time("s") == NOW + timedelta(hours=2)
