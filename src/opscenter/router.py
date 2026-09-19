"""Multi-model router with strategy-based ordering, fallback and per-model circuit breakers."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel

from opscenter.errors import ProviderError, RoutingError
from opscenter.models import LLMEvent
from opscenter.providers.llm import LLMClient
from opscenter.security import redact

Strategy = Literal["ordered", "cost", "latency", "quality"]
_EWMA_ALPHA = 0.3
_INPUT_SHARE = 0.7


@dataclass
class RouteCandidate:
    """A model the router may use."""

    name: str
    client: LLMClient
    tier: str = "standard"
    quality: int = 50
    input_per_mtok: float = 0.0
    output_per_mtok: float = 0.0

    @property
    def blended_price(self) -> float:
        return _INPUT_SHARE * self.input_per_mtok + (1 - _INPUT_SHARE) * self.output_per_mtok


@dataclass
class _Breaker:
    failures: int = 0
    opened_at: float | None = None
    trial_in_flight: bool = False


class Attempt(BaseModel):
    """One try against one model."""

    model: str
    outcome: Literal["ok", "error", "skipped_open"]
    error: str | None = None
    latency_ms: float = 0.0


class RoutedResult(BaseModel):
    """A successful routed completion."""

    text: str
    model: str
    attempts: list[Attempt]
    latency_ms: float


@dataclass
class ModelRouter:
    """Routes requests across candidate models.

    Candidates are ordered by ``strategy`` (``ordered`` keeps the given order, ``cost`` prefers the
    cheapest blended price, ``latency`` the lowest observed average, ``quality`` the highest
    ``quality`` rank), optionally filtered by ``tier``. A failing model is skipped by its circuit
    breaker after ``failure_threshold`` consecutive errors and retried after ``cooldown_seconds``
    with a single trial request. Every real attempt is reported to ``on_event`` as telemetry.
    """

    candidates: list[RouteCandidate]
    strategy: Strategy = "ordered"
    failure_threshold: int = 3
    cooldown_seconds: float = 30.0
    app: str = "router"
    clock: Callable[[], float] = time.monotonic
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    on_event: Callable[[LLMEvent], None] | None = None
    _breakers: dict[str, _Breaker] = field(default_factory=dict, init=False)
    _latency: dict[str, float] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        if not self.candidates:
            raise ValueError("at least one candidate is required")
        self._breakers = {c.name: _Breaker() for c in self.candidates}

    # -- ordering and breaker ------------------------------------------------------------------

    def _ordered(self, tier: str | None) -> list[RouteCandidate]:
        pool = [c for c in self.candidates if tier is None or c.tier == tier]
        if self.strategy == "cost":
            return sorted(pool, key=lambda c: c.blended_price)
        if self.strategy == "latency":
            return sorted(pool, key=lambda c: self._latency.get(c.name, 0.0))
        if self.strategy == "quality":
            return sorted(pool, key=lambda c: -c.quality)
        return pool

    def _allow(self, name: str) -> bool:
        breaker = self._breakers[name]
        if breaker.opened_at is None:
            return True
        if self.clock() - breaker.opened_at < self.cooldown_seconds or breaker.trial_in_flight:
            return False
        breaker.trial_in_flight = True
        return True

    def _record_success(self, name: str, latency_ms: float) -> None:
        self._breakers[name] = _Breaker()
        previous = self._latency.get(name)
        self._latency[name] = (
            latency_ms
            if previous is None
            else _EWMA_ALPHA * latency_ms + (1 - _EWMA_ALPHA) * previous
        )

    def _record_failure(self, name: str) -> None:
        breaker = self._breakers[name]
        breaker.trial_in_flight = False
        breaker.failures += 1
        if breaker.opened_at is not None or breaker.failures >= self.failure_threshold:
            breaker.opened_at = self.clock()

    def state(self) -> dict[str, dict[str, object]]:
        """Breaker state and observed latency per model."""
        return {
            name: {
                "breaker": "open" if b.opened_at is not None else "closed",
                "consecutive_failures": b.failures,
                "avg_latency_ms": round(self._latency[name], 1) if name in self._latency else None,
            }
            for name, b in self._breakers.items()
        }

    # -- calls ---------------------------------------------------------------------------------

    def _emit(
        self,
        candidate: RouteCandidate,
        system: str,
        user: str,
        text: str,
        latency_ms: float,
        error: str | None,
    ) -> None:
        if self.on_event is None:
            return
        self.on_event(
            LLMEvent(
                timestamp=self.now(),
                app=self.app,
                model=candidate.name,
                input_tokens=max(1, (len(system) + len(user)) // 4),
                output_tokens=len(text) // 4,
                latency_ms=latency_ms,
                status="ok" if error is None else "error",
                error_type=error,
            )
        )

    def complete(self, system: str, user: str, *, tier: str | None = None) -> RoutedResult:
        """Return the first successful completion, trying candidates in strategy order.

        Token counts in emitted telemetry are estimated (four characters per token).

        Raises:
            RoutingError: If no candidate is available or every attempt failed.
        """
        attempts: list[Attempt] = []
        pool = self._ordered(tier)
        if not pool:
            raise RoutingError(f"no candidates for tier {tier!r}")
        for candidate in pool:
            if not self._allow(candidate.name):
                attempts.append(Attempt(model=candidate.name, outcome="skipped_open"))
                continue
            start = time.perf_counter()
            try:
                text = candidate.client.complete(system, user)
            except ProviderError as exc:
                elapsed = (time.perf_counter() - start) * 1000.0
                self._record_failure(candidate.name)
                attempts.append(
                    Attempt(
                        model=candidate.name,
                        outcome="error",
                        error=redact(str(exc))[:200],
                        latency_ms=round(elapsed, 2),
                    )
                )
                self._emit(candidate, system, user, "", elapsed, type(exc).__name__)
                continue
            elapsed = (time.perf_counter() - start) * 1000.0
            self._record_success(candidate.name, elapsed)
            attempts.append(
                Attempt(model=candidate.name, outcome="ok", latency_ms=round(elapsed, 2))
            )
            self._emit(candidate, system, user, text, elapsed, None)
            return RoutedResult(
                text=text, model=candidate.name, attempts=attempts, latency_ms=round(elapsed, 2)
            )
        summary = "; ".join(f"{a.model}: {a.outcome}" for a in attempts)
        raise RoutingError(f"no model could serve the request ({summary})")
