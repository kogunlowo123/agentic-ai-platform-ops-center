"""Exception hierarchy for the opscenter package."""

from __future__ import annotations


class OpscenterError(Exception):
    """Base class for all errors raised deliberately by opscenter."""


class ConfigurationError(OpscenterError):
    """Raised when settings or configuration files are missing, inconsistent or invalid."""


class IngestError(OpscenterError):
    """Raised when telemetry cannot be read."""


class StoreError(OpscenterError):
    """Raised when the database cannot be read or written."""


class RegistryError(OpscenterError):
    """Raised for invalid registry operations, such as an illegal status transition."""


class EvalError(OpscenterError):
    """Raised when an evaluation suite is invalid or cannot run."""


class RoutingError(OpscenterError):
    """Raised when no model in a routing policy could serve a request."""


class ReportError(OpscenterError):
    """Raised when a report cannot be rendered or written."""


class ProviderError(OpscenterError):
    """Raised when an upstream provider returns a non-retryable failure."""


class TransientProviderError(ProviderError):
    """Raised for retryable upstream failures such as rate limits or 5xx responses."""
