"""Model price catalog used to attribute cost to token usage.

Prices change and differ by contract, so the catalog is data you maintain. The bundled example file
contains illustrative numbers for fictional model names, not real vendor prices.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from opscenter.errors import ConfigurationError


class ModelPrice(BaseModel):
    """Price per million tokens in USD."""

    input_per_mtok: float = Field(ge=0)
    output_per_mtok: float = Field(ge=0)

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        """Cost in USD of one call."""
        return (
            input_tokens * self.input_per_mtok + output_tokens * self.output_per_mtok
        ) / 1_000_000

    def blended(self, input_share: float = 0.7) -> float:
        """A single comparable price per million tokens assuming ``input_share`` input tokens."""
        return input_share * self.input_per_mtok + (1 - input_share) * self.output_per_mtok


class PriceCatalog:
    """Lookup of :class:`ModelPrice` by model name."""

    def __init__(self, prices: dict[str, ModelPrice] | None = None) -> None:
        self._prices = dict(prices or {})

    def __contains__(self, model: str) -> bool:
        return model in self._prices

    def get(self, model: str) -> ModelPrice | None:
        """Price for ``model`` or ``None`` when it is not in the catalog."""
        return self._prices.get(model)

    def cost(self, model: str, input_tokens: int, output_tokens: int) -> float | None:
        """Cost of a call, or ``None`` for an unpriced model."""
        price = self._prices.get(model)
        return price.cost(input_tokens, output_tokens) if price else None

    def models(self) -> list[str]:
        """Names of the priced models."""
        return sorted(self._prices)

    @classmethod
    def load(cls, path: Path | None) -> PriceCatalog:
        """Load a JSON catalog ``{"models": {name: {input_per_mtok, output_per_mtok}}}``."""
        if path is None:
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            models = data["models"]
            return cls({name: ModelPrice.model_validate(price) for name, price in models.items()})
        except (OSError, ValueError, KeyError, TypeError, ValidationError) as exc:
            raise ConfigurationError(f"cannot load pricing file {path}: {exc}") from exc
