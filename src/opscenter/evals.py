"""Evaluation suites: deterministic assertions over model outputs, stored runs and regression checks."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from opscenter.db import Database
from opscenter.errors import EvalError, ProviderError
from opscenter.models import NAME_PATTERN
from opscenter.providers.llm import LLMClient
from opscenter.security import count_pii, redact, redact_secrets
from opscenter.store import from_epoch, to_epoch

AssertionType = Literal[
    "contains",
    "not_contains",
    "contains_any",
    "equals",
    "regex",
    "max_chars",
    "min_chars",
    "json_valid",
    "json_has_keys",
    "no_pii",
    "no_secrets",
]
_NEEDS_VALUE = {"contains", "not_contains", "equals", "regex", "max_chars", "min_chars"}
_NEEDS_LIST = {"contains_any", "json_has_keys"}
_MAX_OUTPUT = 20_000


class Assertion(BaseModel):
    """One check on a model output."""

    model_config = ConfigDict(extra="forbid")

    type: AssertionType
    value: str | int | list[str] | None = None

    @model_validator(mode="after")
    def _check_value(self) -> Assertion:
        if self.type in _NEEDS_VALUE and self.value in (None, "", []):
            raise ValueError(f"assertion '{self.type}' needs a value")
        if self.type in _NEEDS_LIST and not (isinstance(self.value, list) and self.value):
            raise ValueError(f"assertion '{self.type}' needs a non-empty list")
        if self.type in {"max_chars", "min_chars"} and not isinstance(self.value, int):
            raise ValueError(f"assertion '{self.type}' needs an integer")
        if self.type == "regex":
            try:
                re.compile(str(self.value))
            except re.error as exc:
                raise ValueError(f"invalid regex: {exc}") from exc
        return self


class EvalCase(BaseModel):
    """A prompt and the assertions its output must satisfy."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=NAME_PATTERN)
    input: str = Field(min_length=1, max_length=20_000)
    system: str = Field(default="", max_length=20_000)
    assertions: list[Assertion] = Field(min_length=1)


class EvalSuite(BaseModel):
    """A named collection of cases."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=NAME_PATTERN)
    description: str = ""
    pass_threshold: float = Field(default=0.9, ge=0, le=1)
    cases: list[EvalCase] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _unique_ids(self) -> EvalSuite:
        ids = [c.id for c in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("case ids must be unique")
        return self


def load_suite(path: Path) -> EvalSuite:
    """Load and validate a YAML or JSON suite."""
    try:
        return EvalSuite.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise EvalError(f"cannot load suite {path}: {redact(str(exc))[:400]}") from exc


def check_assertion(assertion: Assertion, output: str) -> str | None:
    """Return a failure message, or ``None`` when ``output`` satisfies ``assertion``."""
    kind, value = assertion.type, assertion.value
    if kind == "contains":
        return None if str(value) in output else f"missing {str(value)!r}"
    if kind == "not_contains":
        return None if str(value) not in output else f"contains forbidden {str(value)!r}"
    if kind == "contains_any":
        assert isinstance(value, list)
        return None if any(v in output for v in value) else f"none of {value!r} present"
    if kind == "equals":
        return None if output.strip() == str(value).strip() else "output differs from expected"
    if kind == "regex":
        return None if re.search(str(value), output) else f"does not match /{value}/"
    if kind == "max_chars":
        assert isinstance(value, int)
        return None if len(output) <= value else f"{len(output)} chars exceeds {value}"
    if kind == "min_chars":
        assert isinstance(value, int)
        return None if len(output) >= value else f"{len(output)} chars is below {value}"
    if kind == "json_valid":
        return None if _load_json(output) is not None else "output is not valid JSON"
    if kind == "json_has_keys":
        parsed = _load_json(output)
        assert isinstance(value, list)
        if not isinstance(parsed, dict):
            return "output is not a JSON object"
        missing = [k for k in value if k not in parsed]
        return None if not missing else f"missing keys {missing}"
    if kind == "no_pii":
        return None if count_pii(output) == 0 else "output contains PII"
    if kind == "no_secrets":
        return None if redact_secrets(output)[1] == 0 else "output contains a credential"
    return f"unknown assertion {kind}"


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


class CaseResult(BaseModel):
    """Outcome of one case."""

    case_id: str
    passed: bool
    failures: list[str] = Field(default_factory=list)
    error: str | None = None
    latency_ms: float = 0.0
    output_preview: str = ""


class EvalRun(BaseModel):
    """Outcome of running a suite against one target."""

    run_id: str
    suite: str
    target: str
    timestamp: datetime
    pass_rate: float
    passed: bool
    cases: list[CaseResult]


def run_suite(
    suite: EvalSuite,
    client: LLMClient,
    *,
    target: str,
    clock: Callable[[], datetime] | None = None,
) -> EvalRun:
    """Run every case against ``client``.

    A provider failure fails that case with the error recorded and does not stop the run. Output
    previews are redacted and truncated before storage.
    """
    now = clock or (lambda: datetime.now(timezone.utc))
    results: list[CaseResult] = []
    for case in suite.cases:
        start = time.perf_counter()
        try:
            output = client.complete(case.system, case.input)[:_MAX_OUTPUT]
        except ProviderError as exc:
            results.append(
                CaseResult(
                    case_id=case.id,
                    passed=False,
                    error=redact(str(exc))[:200],
                    failures=["provider error"],
                )
            )
            continue
        failures = [m for a in case.assertions if (m := check_assertion(a, output))]
        results.append(
            CaseResult(
                case_id=case.id,
                passed=not failures,
                failures=failures,
                latency_ms=round((time.perf_counter() - start) * 1000.0, 2),
                output_preview=redact(output[:200]),
            )
        )
    rate = sum(r.passed for r in results) / len(results)
    return EvalRun(
        run_id=uuid4().hex,
        suite=suite.name,
        target=target,
        timestamp=now(),
        pass_rate=round(rate, 4),
        passed=rate >= suite.pass_threshold,
        cases=results,
    )


class Regression(BaseModel):
    """Difference between two runs of the same suite and target."""

    pass_rate_delta: float
    newly_failing: list[str]
    newly_passing: list[str]


def compare_runs(previous: EvalRun, current: EvalRun) -> Regression:
    """Compare two runs case by case."""
    before = {c.case_id: c.passed for c in previous.cases}
    after = {c.case_id: c.passed for c in current.cases}
    return Regression(
        pass_rate_delta=round(current.pass_rate - previous.pass_rate, 4),
        newly_failing=sorted(i for i in after if before.get(i) is True and not after[i]),
        newly_passing=sorted(i for i in after if before.get(i) is False and after[i]),
    )


class EvalRepo:
    """Persistence for evaluation runs."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, run: EvalRun) -> None:
        """Store ``run``."""
        with self._db.transaction() as conn:
            conn.execute(
                "INSERT INTO eval_runs VALUES (?,?,?,?,?,?)",
                (
                    run.run_id,
                    run.suite,
                    run.target,
                    to_epoch(run.timestamp),
                    run.pass_rate,
                    run.model_dump_json(),
                ),
            )

    def history(self, suite: str, target: str | None = None, limit: int = 20) -> list[EvalRun]:
        """Runs of ``suite`` (optionally for one target), newest first."""
        sql = "SELECT payload FROM eval_runs WHERE suite = ?"
        params: list[object] = [suite]
        if target:
            sql += " AND target = ?"
            params.append(target)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = self._db.conn.execute(sql, params).fetchall()
        return [EvalRun.model_validate_json(r["payload"]) for r in rows]

    def suites(self) -> list[tuple[str, str]]:
        """Distinct ``(suite, target)`` pairs that have runs."""
        rows = self._db.conn.execute(
            "SELECT DISTINCT suite, target FROM eval_runs ORDER BY suite, target"
        ).fetchall()
        return [(r["suite"], r["target"]) for r in rows]

    def latest_time(self, suite: str) -> datetime | None:
        """Timestamp of the most recent run of ``suite`` on any target."""
        row = self._db.conn.execute(
            "SELECT MAX(ts) FROM eval_runs WHERE suite = ?", (suite,)
        ).fetchone()
        return from_epoch(row[0]) if row and row[0] is not None else None
