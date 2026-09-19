"""Chat-completion clients for OpenAI-compatible and Anthropic endpoints."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import SecretStr

from opscenter.errors import ProviderError
from opscenter.providers.http import JsonClient


@runtime_checkable
class LLMClient(Protocol):
    """Minimal text-in, text-out chat interface."""

    def complete(self, system: str, user: str) -> str:
        """Return the model's reply to ``user`` under the ``system`` instruction."""


class OpenAIChatClient:
    """Client for the OpenAI ``/chat/completions`` endpoint."""

    def __init__(
        self,
        client: JsonClient,
        *,
        api_key: SecretStr,
        model: str,
        base_url: str = "https://api.openai.com/v1",
    ) -> None:
        self._client = client
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")

    def complete(self, system: str, user: str) -> str:
        body = self._client.request(
            "POST",
            f"{self._base_url}/chat/completions",
            json={
                "model": self._model,
                "temperature": 0,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            headers={"Authorization": f"Bearer {self._api_key.get_secret_value()}"},
        )
        try:
            return str(body["choices"][0]["message"]["content"]).strip()
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError("unexpected chat completion response shape") from exc


class AnthropicChatClient:
    """Client for the Anthropic ``/v1/messages`` endpoint."""

    def __init__(
        self,
        client: JsonClient,
        *,
        api_key: SecretStr,
        model: str,
        max_tokens: int = 1024,
        base_url: str = "https://api.anthropic.com",
    ) -> None:
        self._client = client
        self._api_key = api_key
        self._model = model
        self._max_tokens = max_tokens
        self._base_url = base_url.rstrip("/")

    def complete(self, system: str, user: str) -> str:
        body = self._client.request(
            "POST",
            f"{self._base_url}/v1/messages",
            json={
                "model": self._model,
                "max_tokens": self._max_tokens,
                "temperature": 0,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            headers={
                "x-api-key": self._api_key.get_secret_value(),
                "anthropic-version": "2023-06-01",
            },
        )
        try:
            blocks = [b["text"] for b in body["content"] if b.get("type") == "text"]
        except (KeyError, TypeError) as exc:
            raise ProviderError("unexpected messages response shape") from exc
        if not blocks:
            raise ProviderError("model returned no text content")
        return "".join(blocks).strip()
