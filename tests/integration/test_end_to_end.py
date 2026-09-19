"""End-to-end tests: simulated incident, alert lifecycle, privacy audit and CLI workflows."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from opscenter.cli import main
from opscenter.container import build_service
from opscenter.registry import ImportedModel, ImportedPrompt, import_entries
from opscenter.service import OpsService
from opscenter.simulate import simulate
from tests.conftest import CONFIGS, FakeLLM, make_settings

pytestmark = pytest.mark.integration

END = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)
END_ISO = "2026-09-19T12:00:00Z"
QUIET_ISO = "2026-09-18T12:00:00Z"


def _bootstrap(
    tmp_path: Path, *, incident: bool = True, per_day: int = 400, **settings: object
) -> OpsService:
    service = build_service(
        make_settings(
            tmp_path,
            pricing_file=CONFIGS / "pricing.example.json",
            apps_file=CONFIGS / "apps.example.yaml",
            **settings,
        ),
        clock=lambda: END,
    )
    service.ingest_events(simulate(end=END, days=7, seed=7, per_day=per_day, incident=incident))
    models = [
        ImportedModel(name=n, status="approved", owner="ml")
        for n in ("small-model", "large-model", "reasoning-model")
    ]
    prompts = [
        ImportedPrompt(prompt_id="support-answer", version="3", status="approved", content="a"),
        ImportedPrompt(prompt_id="code-review", version="1", status="in_review", content="b"),
    ]
    import_entries(service.registry, models, prompts)
    return service


def _titles(report, agent: str) -> list[str]:  # type: ignore[no-untyped-def]
    return [a.title for a in report.alerts if a.agent == agent]


@pytest.fixture(scope="module")
def report(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    service = _bootstrap(tmp_path_factory.mktemp("incident"))
    try:
        return service.report(window=timedelta(hours=24), baseline=timedelta(days=6))
    finally:
        service.close()


class TestIncidentDetection:
    def test_every_agent_reports_the_planted_problems(self, report) -> None:  # type: ignore[no-untyped-def]
        obs = " | ".join(_titles(report, "observability"))
        assert (
            "Error budget burning" in obs
            and "p95 latency above SLO" in obs
            and "Error rate spike" in obs
        )
        cost = " | ".join(_titles(report, "cost"))
        assert (
            "Cost spike" in cost
            and "Daily budget exceeded" in cost
            and "Usage without pricing" in cost
        )
        assert "Caching opportunity" in cost
        sec = _titles(report, "security")
        assert "Credential-shaped data in model output" in sec and "PII in model output" in sec
        assert (
            "Elevated prompt-injection attempts" in sec
            and "Repeat injection attempts from the same users" in sec
        )
        quality = _titles(report, "quality")
        assert (
            "Answer grounding below target" in quality
            and "Evaluation suite support-regression is stale" in quality
        )
        drift = _titles(report, "drift")
        assert {
            "Drift in latency_ms",
            "Drift in input_tokens",
            "Drift in model",
            "Drift in grounding",
        } <= set(drift)
        gov = _titles(report, "governance")
        assert "Production traffic on unregistered model experimental-model" in gov
        assert "Production uses in_review prompt code-review@1" in gov

    def test_health_ranks_the_affected_app_lowest(self, report) -> None:  # type: ignore[no-untyped-def]
        scores = {h.app: h.score for h in report.health}
        assert scores["support-bot"] < scores["code-assistant"] < 100
        assert report.overall_health < 50
        assert "Weakest application: support-bot" in report.summary
        assert sum(1 for a in report.alerts if a.severity.value == "critical") >= 1
        assert not any(r.error for r in report.results)

    def test_evidence_is_specific_and_actionable(self, report) -> None:  # type: ignore[no-untyped-def]
        model_drift = next(a for a in report.alerts if a.title == "Drift in model")
        assert (
            model_drift.evidence["current_share"]["large-model"]
            > model_drift.evidence["baseline_share"]["large-model"]
        )
        assert all(a.recommendation for a in report.alerts if a.severity.rank >= 3)
        spike = next(a for a in report.alerts if a.title.startswith("Cost spike"))
        assert spike.evidence["daily_usd"] > 1.5 * spike.evidence["baseline_daily_usd"]

    def test_the_quiet_period_before_the_incident_is_clean(self, tmp_path: Path) -> None:
        service = _bootstrap(tmp_path)
        report = service.report(
            window=timedelta(hours=24), baseline=timedelta(days=5), now=END - timedelta(days=1)
        )
        noisy = [
            a
            for a in report.alerts
            if a.agent in {"observability", "security", "drift"} or a.severity.value == "critical"
        ]
        assert noisy == []

    def test_without_an_incident_nothing_serious_fires(self, tmp_path: Path) -> None:
        service = _bootstrap(tmp_path, incident=False)
        report = service.report(window=timedelta(hours=24), baseline=timedelta(days=6))
        assert [
            a.title for a in report.alerts if a.agent in {"observability", "security", "drift"}
        ] == []


class TestAlertLifecycle:
    def test_ack_keeps_alerts_out_of_the_gate_and_recovery_resolves_them(
        self, tmp_path: Path
    ) -> None:
        service = _bootstrap(tmp_path)
        first = service.report(window=timedelta(hours=24), baseline=timedelta(days=6))
        urgent = [a for a in first.open_alerts() if a.severity.rank >= 3]
        assert urgent
        for alert in urgent:
            service.alerts.acknowledge(alert.fingerprint, "oncall")
        second = service.report(window=timedelta(hours=24), baseline=timedelta(days=6))
        assert not [a for a in second.open_alerts() if a.severity.rank >= 3]
        assert all(
            a.status == "acked"
            for a in second.alerts
            if a.fingerprint in {u.fingerprint for u in urgent}
        )
        assert all(
            a.occurrences == 2
            for a in second.alerts
            if a.fingerprint in {u.fingerprint for u in urgent}
        )

        recovered = service.report(
            window=timedelta(hours=24), baseline=timedelta(days=5), now=END - timedelta(days=1)
        )
        resolved = {a.fingerprint for a in service.alerts.list("resolved")}
        assert {
            u.fingerprint for u in urgent if u.agent in {"observability", "security", "drift"}
        } <= resolved
        assert recovered.overall_health > second.overall_health

    def test_new_alerts_are_delivered_once(self, tmp_path: Path) -> None:
        sent: list[list[str]] = []

        class Sink:
            def send(self, alerts) -> None:  # type: ignore[no-untyped-def]
                sent.append([a.title for a in alerts])

        service = build_service(
            make_settings(
                tmp_path,
                pricing_file=CONFIGS / "pricing.example.json",
                apps_file=CONFIGS / "apps.example.yaml",
            ),
            clock=lambda: END,
            sinks=[Sink()],
        )
        service.ingest_events(simulate(end=END, days=7, per_day=150))
        service.report(window=timedelta(hours=24), baseline=timedelta(days=6))
        service.report(window=timedelta(hours=24), baseline=timedelta(days=6))
        assert len(sent) == 1 and "Credential-shaped data in model output" in sent[0]


class TestPrivacy:
    def test_database_contains_no_raw_text_user_ids_or_secrets(self, tmp_path: Path) -> None:
        service = _bootstrap(tmp_path, per_day=120)
        service.db.conn.commit()
        with closing(sqlite3.connect(tmp_path / "ops.db")) as raw:
            dump = "\n".join(raw.iterdump())
        for forbidden in (
            "jane.doe@example.com",
            "sk-" + "s" * 24,
            "Ignore all previous instructions",
            "When do backups run?",
            "Acme Cloud backups",
            "attacker-0",
            "user-1",
            "Consider adding a regression test",
        ):
            assert forbidden not in dump, forbidden
        assert re.search(r'"pii_out":\s*[1-9]', dump) and "secrets_out" in dump

    def test_user_hashes_depend_on_the_salt(self, tmp_path: Path) -> None:
        def hashes(salt: str, sub: str) -> set[str]:
            path = tmp_path / sub
            path.mkdir()
            service = _bootstrap(path, per_day=20, hash_salt=salt)
            rows = service.db.conn.execute("SELECT DISTINCT user_hash FROM events").fetchall()
            return {r[0] for r in rows if r[0]}

        a, b = hashes("salt-one", "one"), hashes("salt-two", "two")
        assert a and b and a.isdisjoint(b)


class TestCLI:
    @pytest.fixture(autouse=True)
    def _env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPSCENTER_DB_PATH", str(tmp_path / "cli.db"))
        monkeypatch.setenv("OPSCENTER_PRICING_FILE", str(CONFIGS / "pricing.example.json"))
        monkeypatch.setenv("OPSCENTER_APPS_FILE", str(CONFIGS / "apps.example.yaml"))
        monkeypatch.setenv("OPSCENTER_HASH_SALT", "cli-salt")
        monkeypatch.setenv("OPSCENTER_LOG_LEVEL", "CRITICAL")
        for var in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.chdir(tmp_path)

    def _load(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        data = tmp_path / "sim.jsonl"
        assert main(["simulate", "--out", str(data), "--end", END_ISO, "--per-day", "150"]) == 0
        assert main(["ingest", str(data)]) == 0
        assert main(["registry", "import", str(CONFIGS / "registry.example.yaml")]) == 0
        capsys.readouterr()

    def test_full_workflow_and_gating(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._load(tmp_path, capsys)
        out = tmp_path / "rep"
        assert main(["report", "--now", END_ISO, "--out", str(out), "--fail-on", "critical"]) == 1
        text = capsys.readouterr().out
        assert (
            "open alerts" in text
            and (out / "ops-report.md").exists()
            and (out / "ops-report.json").exists()
        )
        payload = json.loads((out / "ops-report.json").read_text(encoding="utf-8"))
        assert payload["overall_health"] < 60 and payload["events_analyzed"] > 200

        assert main(["alerts", "list", "--status", "open"]) == 0
        listing = capsys.readouterr().out.splitlines()
        criticals = [line.split()[0] for line in listing if " critical " in line]
        assert len(criticals) >= 2
        for fingerprint in criticals:
            assert main(["alerts", "ack", fingerprint, "--actor", "oncall"]) == 0
        assert "acknowledged" in capsys.readouterr().out
        assert main(["report", "--now", END_ISO, "--out", str(out), "--fail-on", "critical"]) == 0

    def test_quiet_window_passes_the_gate(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._load(tmp_path, capsys)
        assert (
            main(
                [
                    "report",
                    "--now",
                    QUIET_ISO,
                    "--out",
                    str(tmp_path / "q"),
                    "--fail-on",
                    "critical",
                ]
            )
            == 0
        )

    def test_eval_workflow_detects_regression(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import opscenter.cli as cli

        suite = str(CONFIGS / "evals" / "support-regression.yaml")
        good = FakeLLM(
            "Refunds are available within 30 days.",
            "Rotate the key in settings.",
            '{"plan": "free", "price": 0}',
        )
        monkeypatch.setattr(cli, "build_llm_client", lambda settings: good)
        assert main(["eval", "run", suite, "--target", "model-a"]) == 0
        assert "pass rate 100% (PASS)" in capsys.readouterr().out

        bad = FakeLLM("no idea", "key api_key = sk-" + "a" * 30, "oops")
        monkeypatch.setattr(cli, "build_llm_client", lambda settings: bad)
        assert main(["eval", "run", suite, "--target", "model-a"]) == 1
        failing = capsys.readouterr().out
        assert "pass rate 0% (FAIL)" in failing and "FAIL no-secrets" in failing

        assert main(["eval", "history", "support-regression"]) == 0
        assert capsys.readouterr().out.count("model-a") == 2
        assert (
            main(["report", "--now", END_ISO, "--out", str(tmp_path / "r"), "--fail-on", "high"])
            == 1
        )
        assert "Evaluation regression in support-regression" in (
            tmp_path / "r" / "ops-report.md"
        ).read_text(encoding="utf-8")

    def test_registry_governance_workflow(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert (
            main(
                [
                    "registry",
                    "add-model",
                    "new-model",
                    "--actor",
                    "alice",
                    "--owner",
                    "alice",
                    "--review-due",
                    "2026-01-01",
                ]
            )
            == 0
        )
        assert main(["registry", "set-model", "new-model", "approved", "--actor", "alice"]) == 2
        assert "cannot be approved by its owner" in capsys.readouterr().err
        assert main(["registry", "set-model", "new-model", "approved", "--actor", "bob"]) == 0

        prompt = tmp_path / "p.txt"
        prompt.write_text("You are helpful.", encoding="utf-8")
        assert (
            main(
                [
                    "registry",
                    "add-prompt",
                    "helper",
                    "1",
                    "--file",
                    str(prompt),
                    "--author",
                    "alice",
                ]
            )
            == 0
        )
        assert main(["registry", "set-prompt", "helper", "1", "in_review", "--actor", "alice"]) == 0
        assert main(["registry", "set-prompt", "helper", "1", "approved", "--actor", "alice"]) == 2
        assert "author" in capsys.readouterr().err
        assert main(["registry", "set-prompt", "helper", "1", "approved", "--actor", "bob"]) == 0
        capsys.readouterr()

        assert main(["registry", "list"]) == 0
        listing = capsys.readouterr().out
        assert "new-model" in listing and "approved" in listing and "approved_by=bob" in listing
        assert main(["registry", "audit"]) == 0
        audit = capsys.readouterr().out
        assert "model.status" in audit and "prompt.status" in audit and "bob" in audit

    @pytest.mark.parametrize(
        ("argv", "fragment"),
        [
            (["ingest", "missing.jsonl"], "cannot read"),
            (["report", "--window", "soon"], "invalid duration"),
            (["report", "--now", "yesterday"], "invalid timestamp"),
            (["report", "--format", "pdf"], "unknown format"),
            (["eval", "run", "missing.yaml"], "cannot load suite"),
            (
                ["eval", "run", str(CONFIGS / "evals" / "support-regression.yaml")],
                "OPSCENTER_LLM_PROVIDER",
            ),
            (["registry", "set-model", "ghost", "approved", "--actor", "a"], "not registered"),
            (["registry", "import", "missing.yaml"], "cannot import"),
            (["alerts", "ack", "deadbeef", "--actor", "a"], "no open alert"),
        ],
    )
    def test_errors_exit_2(
        self, capsys: pytest.CaptureFixture[str], argv: list[str], fragment: str
    ) -> None:
        assert main(argv) == 2
        assert fragment in capsys.readouterr().err

    def test_corrupt_telemetry_is_reported_not_fatal(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "bad.jsonl"
        path.write_text(
            '{"timestamp": "2026-09-19T10:00:00Z", "app": "a", "model": "m"}\nnot json\n{"app": "x"}\n',
            encoding="utf-8",
        )
        assert main(["ingest", str(path)]) == 0
        result = json.loads(capsys.readouterr().out)
        assert (result["accepted"], result["rejected"]) == (1, 2) and result["errors"][
            0
        ] == "line 2: not valid JSON"

    def test_init_and_empty_database_report(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["init"]) == 0 and "database ready" in capsys.readouterr().out
        assert main(["report", "--out", str(tmp_path / "e"), "--fail-on", "low"]) == 0
        assert "Platform health 100/100" in capsys.readouterr().out
        assert main(["alerts", "list"]) == 0 and "no alerts" in capsys.readouterr().out
        assert main(["eval", "history", "nothing"]) == 0 and "no runs" in capsys.readouterr().out
