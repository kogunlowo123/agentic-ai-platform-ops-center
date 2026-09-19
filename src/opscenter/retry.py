"""Retry policy for calls to external services."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from tenacity import (
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from opscenter.errors import TransientProviderError

T = TypeVar("T")


def call_with_retry(
    func: Callable[[], T],
    *,
    attempts: int,
    min_wait: float,
    max_wait: float,
) -> T:
    """Invoke ``func`` and retry on :class:`TransientProviderError`.

    Uses exponential backoff bounded by ``min_wait`` and ``max_wait`` seconds.
    Non-transient errors propagate immediately; after the final attempt the last
    transient error is re-raised unchanged.
    """
    retrying = Retrying(
        stop=stop_after_attempt(attempts),
        wait=wait_exponential(multiplier=min_wait or 0.0, min=min_wait, max=max_wait),
        retry=retry_if_exception_type(TransientProviderError),
        reraise=True,
    )
    return retrying(func)
