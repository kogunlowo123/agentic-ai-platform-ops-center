"""Domain models: telemetry events, derived signals, alerts and reports."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,79}$"


class Severity(str, Enum):
    """Alert severity, ordered from most to least serious."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher is more severe."""
        return _RANK[self]

    @property
    def penalty(self) -> int:
        """Points that one open alert of this severity deducts from an app's health score."""
        return _PENALTY[self]


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_PENALTY = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 6,
    Severity.HIGH: 15,
    Severity.CRITICAL: 30,
}

EventStatus = Literal["ok", "error", "timeout", "blocked"]


class LLMEvent(BaseModel):
    """One LLM call as reported by an application (untrusted input).

    Raw text fields are used only to derive signals at ingestion. They are stored only when text
    storage is explicitly enabled, and ``user_id`` is never stored, only a salted hash of it.
    """

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(default_factory=lambda: uuid4().hex, min_length=1, max_length=100)
    timestamp: datetime
    app: str = Field(pattern=NAME_PATTERN)
    environment: str = Field(default="prod", pattern=NAME_PATTERN)
    model: str = Field(pattern=NAME_PATTERN)
    provider: str = Field(default="", max_length=80)
    prompt_id: str | None = Field(default=None, pattern=NAME_PATTERN)
    prompt_version: str | None = Field(default=None, max_length=40)
    input_tokens: int = Field(default=0, ge=0, le=10_000_000)
    output_tokens: int = Field(default=0, ge=0, le=10_000_000)
    latency_ms: float = Field(default=0.0, ge=0, le=3_600_000)
    status: EventStatus = "ok"
    error_type: str | None = Field(default=None, max_length=100)
    user_id: str | None = Field(default=None, max_length=200)
    input_text: str | None = Field(default=None, max_length=50_000)
    output_text: str | None = Field(default=None, max_length=50_000)
    context: list[str] | None = Field(default=None, max_length=20)
    cost_usd: float | None = Field(default=None, ge=0)
    tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None
            else value.astimezone(timezone.utc)
        )

    @field_validator("context")
    @classmethod
    def _context_size(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and any(len(item) > 20_000 for item in value):
            raise ValueError("context passages are limited to 20000 characters")
        return value

    @field_validator("tags")
    @classmethod
    def _tag_limits(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 20 or any(len(k) > 50 or len(v) > 100 for k, v in value.items()):
            raise ValueError("at most 20 tags, keys up to 50 and values up to 100 characters")
        return value


class Signals(BaseModel):
    """Privacy-preserving features derived from an event's text at ingestion."""

    in_chars: int = 0
    out_chars: int = 0
    pii_in: int = 0
    pii_out: int = 0
    secrets_in: int = 0
    secrets_out: int = 0
    injection: list[str] = Field(default_factory=list)
    grounding: float | None = None
    input_hash: str | None = None


class StoredEvent(BaseModel):
    """An event as persisted: metrics and signals, no raw text."""

    event_id: str
    timestamp: datetime
    app: str
    environment: str
    model: str
    provider: str = ""
    prompt_id: str | None = None
    prompt_version: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    status: EventStatus = "ok"
    error_type: str | None = None
    user_hash: str | None = None
    cost_usd: float | None = None
    signals: Signals = Field(default_factory=Signals)
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def failed(self) -> bool:
        """True for errors and timeouts (blocked requests are a guardrail outcome, not a failure)."""
        return self.status in {"error", "timeout"}


class Alert(BaseModel):
    """A finding raised by an agent."""

    fingerprint: str
    agent: str
    severity: Severity
    title: str
    detail: str
    app: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str = ""


class AlertRecord(Alert):
    """An alert with its lifecycle state."""

    status: Literal["open", "acked", "resolved"] = "open"
    first_seen: datetime
    last_seen: datetime
    occurrences: int = 1


class AgentResult(BaseModel):
    """Output of one specialist agent."""

    name: str
    alerts: list[Alert] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class AppHealth(BaseModel):
    """Health score of one application."""

    app: str
    score: int
    open_alerts: dict[str, int]
    events: int


class IngestReport(BaseModel):
    """Summary of an ingestion run."""

    lines: int = 0
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    unpriced: int = 0
    errors: list[str] = Field(default_factory=list)


class OpsReport(BaseModel):
    """Everything the supervisor learned in one run."""

    schema_version: str = "1.0"
    tool_version: str
    generated_at: datetime
    window_start: datetime
    window_end: datetime
    baseline_start: datetime
    baseline_end: datetime
    events_analyzed: int
    baseline_events: int
    results: list[AgentResult]
    alerts: list[AlertRecord]
    health: list[AppHealth]
    overall_health: int
    summary: str

    def open_alerts(self) -> list[AlertRecord]:
        """Alerts that are open (not acknowledged, not resolved)."""
        return [a for a in self.alerts if a.status == "open"]
