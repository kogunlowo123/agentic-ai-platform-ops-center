"""Typed configuration: environment settings, per-application SLOs and analysis thresholds."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from opscenter.errors import ConfigurationError
from opscenter.models import NAME_PATTERN


class AppConfig(BaseModel):
    """Service-level objectives and budgets for one application."""

    model_config = ConfigDict(extra="forbid")

    owner: str = ""
    slo_availability: float = Field(default=0.99, gt=0, lt=1)
    slo_p95_ms: float = Field(default=5000.0, gt=0)
    daily_budget_usd: float | None = Field(default=None, gt=0)
    monthly_budget_usd: float | None = Field(default=None, gt=0)
    min_grounding: float = Field(default=0.7, ge=0, le=1)
    eval_suite: str | None = None


class Thresholds(BaseModel):
    """Numeric thresholds the agents use. Every default is a starting point to tune."""

    model_config = ConfigDict(extra="forbid")

    min_samples: int = Field(default=20, ge=1)
    drift_min_samples: int = Field(default=30, ge=2)
    burn_high: float = Field(default=2.0, gt=0)
    burn_critical: float = Field(default=10.0, gt=0)
    error_spike_ratio: float = Field(default=3.0, gt=1)
    cost_spike_ratio: float = Field(default=1.5, gt=1)
    cost_spike_min_usd: float = Field(default=1.0, ge=0)
    psi_moderate: float = Field(default=0.1, gt=0)
    psi_significant: float = Field(default=0.25, gt=0)
    injection_rate_medium: float = Field(default=0.05, ge=0, le=1)
    injection_rate_high: float = Field(default=0.2, ge=0, le=1)
    duplicate_ratio: float = Field(default=0.15, ge=0, le=1)
    eval_drop: float = Field(default=0.05, gt=0, le=1)
    eval_max_age_days: int = Field(default=7, ge=1)
    repeat_offender: int = Field(default=5, ge=2)


class Settings(BaseSettings):
    """Runtime settings from ``OPSCENTER_*`` environment variables and ``.env``."""

    model_config = SettingsConfigDict(
        env_prefix="OPSCENTER_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    db_path: Path = Path(".opscenter/opscenter.db")
    pricing_file: Path | None = None
    apps_file: Path | None = None
    hash_salt: SecretStr = SecretStr("")
    max_line_bytes: int = Field(default=200_000, ge=1000)
    max_lines: int = Field(default=2_000_000, ge=1)
    thresholds: Thresholds = Field(default_factory=Thresholds)

    # Models used by evaluations
    llm_provider: Literal["none", "openai", "anthropic"] = "none"
    openai_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("OPSCENTER_OPENAI_API_KEY", "OPENAI_API_KEY")
    )
    openai_base_url: str = "https://api.openai.com/v1"
    openai_chat_model: str = "gpt-4o-mini"
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("OPSCENTER_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_model: str = "claude-sonnet-5"
    anthropic_max_tokens: int = Field(default=1024, gt=0)

    # Alert delivery
    webhook_url: SecretStr | None = None

    # Networking
    http_timeout_seconds: float = Field(default=30.0, gt=0)
    retry_attempts: int = Field(default=3, ge=1)
    retry_min_wait: float = Field(default=0.5, ge=0)
    retry_max_wait: float = Field(default=8.0, ge=0)

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "WARNING"
    log_json: bool = True

    @model_validator(mode="after")
    def _check_consistency(self) -> Settings:
        if self.retry_max_wait < self.retry_min_wait:
            raise ValueError("retry_max_wait must be >= retry_min_wait")
        if self.thresholds.psi_significant <= self.thresholds.psi_moderate:
            raise ValueError("psi_significant must exceed psi_moderate")
        return self


def load_apps(path: Path | None) -> dict[str, AppConfig]:
    """Load per-application configuration from YAML (``apps:`` mapping). ``None`` yields no apps."""
    if path is None:
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw = data.get("apps", {})
        if not isinstance(raw, dict):
            raise ValueError("'apps' must be a mapping")
        for name in raw:
            if not isinstance(name, str) or not re.match(NAME_PATTERN, name):
                raise ValueError(f"invalid application name: {name!r}")
        return {name: AppConfig.model_validate(cfg or {}) for name, cfg in raw.items()}
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"cannot load apps file {path}: {exc}") from exc
