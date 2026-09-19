"""Shared HTTP helper that maps upstream failures onto opscenter error types."""

from __future__ import annotations

from typing import Any

import httpx

from opscenter.errors import ProviderError, TransientProviderError
from opscenter.retry import call_with_retry
from opscenter.security import redact

_TRANSIENT_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504})


class JsonClient:
    """Thin wrapper over :class:`httpx.Client` with retry and error mapping."""

    def __init__(
        self,
        client: httpx.Client,
        *,
        attempts: int,
        min_wait: float,
        max_wait: float,
    ) -> None:
        self._client = client
        self._attempts = attempts
        self._min_wait = min_wait
        self._max_wait = max_wait

    def request(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        """Send a JSON request and return the decoded JSON body.

        Raises:
            TransientProviderError: After retries are exhausted on 429/5xx or transport errors.
            ProviderError: On any other non-2xx response or malformed body.
        """

        def send() -> Any:
            try:
                response = self._client.request(method, url, json=json, headers=headers)
            except httpx.TransportError as exc:
                raise TransientProviderError(f"transport error calling {url}: {exc}") from exc
            if response.status_code in _TRANSIENT_STATUS:
                raise TransientProviderError(f"{url} returned {response.status_code}")
            if response.status_code >= 400:
                raise ProviderError(
                    f"{url} returned {response.status_code}: {redact(response.text[:300])}"
                )
            try:
                return response.json()
            except ValueError as exc:
                raise ProviderError(f"{url} returned a non-JSON body") from exc

        return call_with_retry(
            send, attempts=self._attempts, min_wait=self._min_wait, max_wait=self._max_wait
        )
