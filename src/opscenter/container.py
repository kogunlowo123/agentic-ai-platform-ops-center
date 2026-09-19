"""Composition root: builds an :class:`OpsService` from :class:`Settings`."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

import httpx

from opscenter.agents import (
    CostAgent,
    DriftAgent,
    GovernanceAgent,
    ObservabilityAgent,
    QualityAgent,
    SecurityAgent,
    Supervisor,
)
from opscenter.alerts import AlertManager, AlertSink, WebhookSink
from opscenter.config import Settings, load_apps
from opscenter.db import Database
from opscenter.errors import ConfigurationError
from opscenter.evals import EvalRepo
from opscenter.pricing import PriceCatalog
from opscenter.providers import AnthropicChatClient, JsonClient, LLMClient, OpenAIChatClient
from opscenter.registry import Registry
from opscenter.service import OpsService
from opscenter.store import EventStore


def _json_client(settings: Settings, http_client: httpx.Client | None) -> JsonClient:
    return JsonClient(
        http_client or httpx.Client(timeout=settings.http_timeout_seconds),
        attempts=settings.retry_attempts,
        min_wait=settings.retry_min_wait,
        max_wait=settings.retry_max_wait,
    )


def build_llm_client(settings: Settings, http_client: httpx.Client | None = None) -> LLMClient:
    """Chat client for evaluations, from the configured provider.

    Raises:
        ConfigurationError: If no provider is configured or its API key is missing.
    """
    if settings.llm_provider == "none":
        raise ConfigurationError(
            "set OPSCENTER_LLM_PROVIDER to openai or anthropic to run evaluations"
        )
    client = _json_client(settings, http_client)
    if settings.llm_provider == "openai":
        if settings.openai_api_key is None:
            raise ConfigurationError(
                "OPSCENTER_OPENAI_API_KEY must be set when llm_provider=openai"
            )
        return OpenAIChatClient(
            client,
            api_key=settings.openai_api_key,
            model=settings.openai_chat_model,
            base_url=settings.openai_base_url,
        )
    if settings.anthropic_api_key is None:
        raise ConfigurationError(
            "OPSCENTER_ANTHROPIC_API_KEY must be set when llm_provider=anthropic"
        )
    return AnthropicChatClient(
        client,
        api_key=settings.anthropic_api_key,
        model=settings.anthropic_model,
        max_tokens=settings.anthropic_max_tokens,
        base_url=settings.anthropic_base_url,
    )


def build_service(
    settings: Settings,
    *,
    http_client: httpx.Client | None = None,
    clock: Callable[[], datetime] | None = None,
    sinks: list[AlertSink] | None = None,
) -> OpsService:
    """Assemble the dependency graph and open the database.

    Args:
        settings: Validated configuration.
        http_client: Optional client, mainly for tests using a mock transport.
        clock: Clock override for deterministic runs.
        sinks: Alert sinks. When omitted, a webhook sink is added if a webhook URL is configured.
    """
    db = Database(settings.db_path)
    catalog = PriceCatalog.load(settings.pricing_file)
    delivery: list[AlertSink] = list(sinks or [])
    if sinks is None and settings.webhook_url is not None:
        delivery.append(WebhookSink(_json_client(settings, http_client), settings.webhook_url))
    alert_manager = AlertManager(db, clock)
    supervisor = Supervisor(
        [
            ObservabilityAgent(),
            CostAgent(),
            SecurityAgent(),
            QualityAgent(),
            DriftAgent(),
            GovernanceAgent(),
        ],
        alert_manager,
        delivery,
    )
    return OpsService(
        settings,
        db,
        EventStore(db),
        Registry(db, clock),
        alert_manager,
        EvalRepo(db),
        catalog,
        load_apps(settings.apps_file),
        supervisor,
        clock,
    )
