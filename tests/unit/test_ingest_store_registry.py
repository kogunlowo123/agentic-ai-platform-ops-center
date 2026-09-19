"""Unit tests for event validation, ingestion, the store and the registry."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from opscenter.config import load_apps
from opscenter.db import Database
from opscenter.errors import ConfigurationError, IngestError, RegistryError, StoreError
from opscenter.models import LLMEvent
from opscenter.pricing import PriceCatalog
from opscenter.registry import ImportedModel, ImportedPrompt, content_hash, import_entries
from opscenter.telemetry import ingest_file, ingest_lines, to_stored
from tests.conftest import CATALOG, CONFIGS, NOW, Env, make_event


def _line(**kw: object) -> str:
    data: dict[str, object] = {
        "timestamp": "2026-09-19T10:00:00Z",
        "app": "support-bot",
        "model": "small-model",
        "input_tokens": 1000,
        "output_tokens": 200,
        "latency_ms": 500,
    }
    data.update(kw)
    return json.dumps(data)


class TestLLMEvent:
    def test_naive_timestamps_become_utc(self) -> None:
        event = LLMEvent.model_validate(
            {"timestamp": "2026-01-01T00:00:00", "app": "a", "model": "m"}
        )
        assert event.timestamp.tzinfo is not None and event.timestamp.utcoffset() == timedelta(0)

    def test_offsets_are_normalised(self) -> None:
        event = LLMEvent.model_validate(
            {"timestamp": "2026-01-01T02:00:00+02:00", "app": "a", "model": "m"}
        )
        assert event.timestamp.hour == 0

    @pytest.mark.parametrize(
        "override",
        [
            {"app": "bad app!"},
            {"model": ""},
            {"input_tokens": -1},
            {"latency_ms": -5},
            {"status": "exploded"},
            {"tags": {f"k{i}": "v" for i in range(25)}},
            {"tags": {"k": "v" * 200}},
            {"context": ["x" * 25_000]},
            {"input_text": "x" * 60_000},
        ],
    )
    def test_rejects_invalid(self, override: dict[str, object]) -> None:
        base: dict[str, object] = {"timestamp": "2026-01-01T00:00:00Z", "app": "a", "model": "m"}
        base.update(override)
        with pytest.raises(ValidationError):
            LLMEvent.model_validate(base)

    def test_unknown_fields_are_ignored(self) -> None:
        event = LLMEvent.model_validate(
            {"timestamp": "2026-01-01T00:00:00Z", "app": "a", "model": "m", "vendor_x": 1}
        )
        assert event.app == "a"


class TestToStored:
    def _event(self, **kw: object) -> LLMEvent:
        base: dict[str, object] = {
            "timestamp": "2026-09-19T10:00:00Z",
            "app": "a",
            "model": "small-model",
            "input_tokens": 1_000_000,
            "output_tokens": 1_000_000,
            "user_id": "alice@example.com",
            "input_text": "my secret question",
            "output_text": "answer with a@b.co",
        }
        base.update(kw)
        return LLMEvent.model_validate(base)

    def test_text_and_user_id_are_not_retained(self) -> None:
        stored = to_stored(self._event(), salt="s", catalog=CATALOG)
        dumped = stored.model_dump_json()
        assert "alice@example.com" not in dumped and "my secret question" not in dumped
        assert "a@b.co" not in dumped
        assert stored.user_hash and stored.signals.pii_out == 1

    def test_cost_from_catalog_or_event(self) -> None:
        assert to_stored(self._event(), salt="s", catalog=CATALOG).cost_usd == pytest.approx(2.0)
        assert to_stored(self._event(cost_usd=9.5), salt="s", catalog=CATALOG).cost_usd == 9.5
        assert to_stored(self._event(model="mystery"), salt="s", catalog=CATALOG).cost_usd is None


class TestIngest:
    def test_mixed_input_is_counted_not_fatal(self, env: Env) -> None:
        lines = [
            _line(event_id="a"),
            "not json",
            _line(event_id="b", app="bad app"),
            "",
            _line(event_id="a"),
        ]
        report = ingest_lines(lines, env.store, salt="s", catalog=CATALOG)
        assert (report.lines, report.accepted, report.rejected, report.duplicates) == (4, 1, 2, 1)
        assert env.store.count() == 1
        assert report.errors[0] == "line 2: not valid JSON"
        assert report.errors[1].startswith("line 3: app:")

    def test_error_messages_never_echo_content(self, env: Env) -> None:
        secret = "sk-" + "q" * 30
        report = ingest_lines(
            [_line(app="bad app", input_text=secret)], env.store, salt="s", catalog=CATALOG
        )
        assert report.rejected == 1 and "q" * 30 not in " ".join(report.errors)

    def test_oversized_line_and_line_limit(self, env: Env) -> None:
        report = ingest_lines(
            [_line(input_text="x" * 5000)],
            env.store,
            salt="s",
            catalog=CATALOG,
            max_line_bytes=1000,
        )
        assert report.rejected == 1 and "exceeds 1000 bytes" in report.errors[0]
        with pytest.raises(IngestError, match="limit of 2 lines"):
            ingest_lines(
                [_line(event_id=str(i)) for i in range(5)],
                env.store,
                salt="s",
                catalog=CATALOG,
                max_lines=2,
            )

    def test_unpriced_counted_and_batches_flush(self, env: Env) -> None:
        lines = [
            _line(event_id=f"e{i}", model="mystery" if i % 2 else "small-model")
            for i in range(2500)
        ]
        report = ingest_lines(lines, env.store, salt="s", catalog=CATALOG)
        assert report.accepted == 2500 and report.unpriced == 1250 and env.store.count() == 2500

    def test_ingest_file(self, env: Env, tmp_path: Path) -> None:
        path = tmp_path / "t.jsonl"
        path.write_text(_line(event_id="x") + "\n" + _line(event_id="y") + "\n", encoding="utf-8")
        assert ingest_file(path, env.store, salt="s", catalog=CATALOG).accepted == 2
        with pytest.raises(IngestError, match="cannot read"):
            ingest_file(tmp_path / "missing.jsonl", env.store, salt="s", catalog=CATALOG)

    def test_invalid_utf8_is_replaced_not_fatal(self, env: Env, tmp_path: Path) -> None:
        path = tmp_path / "t.jsonl"
        path.write_bytes(_line(event_id="x").encode() + b"\n\xff\xfe garbage\n")
        report = ingest_file(path, env.store, salt="s", catalog=CATALOG)
        assert report.accepted == 1 and report.rejected == 1


class TestStore:
    def test_window_queries_and_filters(self, env: Env) -> None:
        events = [
            make_event(
                NOW - timedelta(hours=h),
                app="a" if h % 2 else "b",
                event_id=f"e{h}",
                environment="prod" if h < 3 else "dev",
            )
            for h in range(1, 6)
        ]
        assert env.store.insert(events) == 5
        assert env.store.insert(events) == 0
        assert len(env.store.query(NOW - timedelta(hours=10), NOW)) == 5
        assert [
            e.event_id for e in env.store.query(NOW - timedelta(hours=3), NOW - timedelta(hours=1))
        ] == ["e3", "e2"]
        assert {e.app for e in env.store.query(NOW - timedelta(hours=10), NOW, app="a")} == {"a"}
        assert {
            e.environment
            for e in env.store.query(NOW - timedelta(hours=10), NOW, environment="dev")
        } == {"dev"}
        assert env.store.time_range() == (NOW - timedelta(hours=5), NOW - timedelta(hours=1))

    def test_round_trip_preserves_fields(self, env: Env) -> None:
        original = make_event(
            event_id="rt",
            signals={"pii_out": 2, "injection": ["jailbreak"], "grounding": 0.4},
            tags={"k": "v"},
            user_hash="u1",
            cost_usd=None,
        )
        env.store.insert([original])
        (loaded,) = env.store.query(NOW - timedelta(days=1), NOW)
        assert loaded == original

    def test_empty_store(self, env: Env) -> None:
        assert env.store.count() == 0 and env.store.time_range() is None

    def test_sql_injection_in_filters_is_inert(self, env: Env) -> None:
        env.store.insert([make_event(event_id="x")])
        hostile = "x'; DROP TABLE events; --"
        assert env.store.query(NOW - timedelta(days=1), NOW, app=hostile) == []
        assert env.store.count() == 1

    def test_transaction_rolls_back(self) -> None:
        db = Database(":memory:")
        with pytest.raises(RuntimeError), db.transaction() as conn:
            conn.execute("INSERT INTO models VALUES ('m','p','proposed','o',NULL,'')")
            raise RuntimeError("boom")
        assert db.conn.execute("SELECT COUNT(*) FROM models").fetchone()[0] == 0

    def test_open_failure(self, tmp_path: Path) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(StoreError, match="cannot open"):
            Database(blocker / "sub" / "db.sqlite")


class TestRegistry:
    def test_model_lifecycle_and_separation_of_duties(self, env: Env) -> None:
        env.registry.register_model("gpt-x", actor="alice", owner="alice", provider="p")
        assert env.registry.get_model("gpt-x").status == "proposed"  # type: ignore[union-attr]
        with pytest.raises(RegistryError, match="owner"):
            env.registry.set_model_status("gpt-x", "approved", actor="alice")
        env.registry.set_model_status("gpt-x", "approved", actor="bob")
        env.registry.set_model_status("gpt-x", "deprecated", actor="bob")
        with pytest.raises(RegistryError, match="cannot move"):
            env.registry.set_model_status("gpt-x", "approved", actor="bob")
        env.registry.set_model_status("gpt-x", "blocked", actor="bob")
        assert [m.status for m in env.registry.models()] == ["blocked"]

    def test_model_errors(self, env: Env) -> None:
        with pytest.raises(RegistryError, match="invalid model name"):
            env.registry.register_model("bad name", actor="a")
        env.registry.register_model("m1", actor="a")
        with pytest.raises(RegistryError, match="already registered"):
            env.registry.register_model("m1", actor="a")
        with pytest.raises(RegistryError, match="not registered"):
            env.registry.set_model_status("nope", "approved", actor="a")

    def test_prompt_lifecycle(self, env: Env) -> None:
        env.registry.register_prompt("greet", "1", content="Hello {name}", author="alice")
        with pytest.raises(RegistryError, match="cannot move"):
            env.registry.transition_prompt("greet", "1", "approved", actor="bob")
        env.registry.transition_prompt("greet", "1", "in_review", actor="alice")
        with pytest.raises(RegistryError, match="author"):
            env.registry.transition_prompt("greet", "1", "approved", actor="alice")
        approved = env.registry.transition_prompt("greet", "1", "approved", actor="bob")
        assert approved.approved_by == "bob"
        env.registry.transition_prompt("greet", "1", "deprecated", actor="bob")
        assert env.registry.get_prompt("greet", "1").approved_by == "bob"  # type: ignore[union-attr]

    def test_prompt_errors_and_hash_pinning(self, env: Env) -> None:
        with pytest.raises(RegistryError, match="invalid prompt"):
            env.registry.register_prompt("ok", "bad version!", content="x", author="a")
        env.registry.register_prompt("p", "1", content="text", author="a")
        with pytest.raises(RegistryError, match="already exists"):
            env.registry.register_prompt("p", "1", content="other", author="a")
        with pytest.raises(RegistryError, match="does not exist"):
            env.registry.transition_prompt("p", "9", "in_review", actor="a")
        assert env.registry.verify_prompt("p", "1", "text") is True
        assert env.registry.verify_prompt("p", "1", "tampered") is False
        assert env.registry.verify_prompt("p", "2", "text") is False
        assert content_hash("text") == env.registry.get_prompt("p", "1").content_hash  # type: ignore[union-attr]

    def test_prompt_content_is_not_stored(self, env: Env) -> None:
        env.registry.register_prompt("p", "1", content="TOP SECRET PROMPT TEXT", author="a")
        rows = env.db.conn.execute("SELECT * FROM prompt_versions").fetchall()
        assert "TOP SECRET" not in str([tuple(r) for r in rows])

    def test_audit_log_records_every_change(self, env: Env) -> None:
        env.registry.register_model("m", actor="alice", owner="alice")
        env.registry.set_model_status("m", "approved", actor="bob")
        env.registry.register_prompt("p", "1", content="x", author="alice")
        log = env.registry.audit_log()
        assert [e.action for e in log] == ["prompt.register", "model.status", "model.register"]
        assert log[1].actor == "bob" and log[1].detail == "proposed -> approved"

    def test_import_is_idempotent_and_audited(self, env: Env) -> None:
        models = [ImportedModel(name="m1", status="approved", owner="x")]
        prompts = [ImportedPrompt(prompt_id="p", version="1", status="approved", content="c")]
        assert import_entries(env.registry, models, prompts) == (1, 1)
        assert import_entries(env.registry, models, prompts) == (0, 0)
        assert env.registry.get_model("m1").status == "approved"  # type: ignore[union-attr]
        assert {e.actor for e in env.registry.audit_log()} == {"import"}

    def test_review_due_round_trips(self, env: Env) -> None:
        env.registry.register_model("m", actor="a", review_due=date(2026, 1, 1))
        assert env.registry.get_model("m").review_due == date(2026, 1, 1)  # type: ignore[union-attr]


class TestConfigFiles:
    def test_bundled_examples_load(self) -> None:
        catalog = PriceCatalog.load(CONFIGS / "pricing.example.json")
        assert catalog.models() == ["large-model", "reasoning-model", "small-model"]
        apps = load_apps(CONFIGS / "apps.example.yaml")
        assert apps["support-bot"].slo_availability == 0.995 and apps["support-bot"].eval_suite

    def test_loader_errors(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text(
            '{"models": {"m": {"input_per_mtok": -1, "output_per_mtok": 1}}}', encoding="utf-8"
        )
        with pytest.raises(ConfigurationError, match="pricing"):
            PriceCatalog.load(bad)
        with pytest.raises(ConfigurationError):
            PriceCatalog.load(tmp_path / "missing.json")
        apps = tmp_path / "apps.yaml"
        apps.write_text("apps:\n  'bad name!': {}\n", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="invalid application name"):
            load_apps(apps)
        apps.write_text("apps:\n  ok: {unknown_field: 1}\n", encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_apps(apps)
        assert load_apps(None) == {}
        assert PriceCatalog.load(None).models() == []

    def test_price_math(self) -> None:
        price = CATALOG.get("large-model")
        assert price is not None and price.cost(1_000_000, 1_000_000) == 18.0
        assert price.blended() == pytest.approx(0.7 * 3 + 0.3 * 15)
        assert "small-model" in CATALOG and CATALOG.cost("mystery", 1, 1) is None


def test_now_fixture_is_utc() -> None:
    assert NOW.tzinfo == timezone.utc and isinstance(NOW, datetime)
