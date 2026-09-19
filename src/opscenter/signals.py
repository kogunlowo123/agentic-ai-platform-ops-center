"""Derives privacy-preserving signals from an event's text."""

from __future__ import annotations

import re

from opscenter.models import LLMEvent, Signals
from opscenter.security import count_pii, redact_secrets, salted_hash, scan_injection

_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "but",
        "by",
        "for",
        "from",
        "has",
        "have",
        "he",
        "her",
        "his",
        "i",
        "in",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "our",
        "she",
        "that",
        "the",
        "their",
        "them",
        "they",
        "this",
        "to",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "who",
        "will",
        "with",
        "you",
        "your",
    ]
)
_WORD = re.compile(r"[a-z0-9]+")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")
_CLAIM_SUPPORT = 0.6


def _content_tokens(text: str) -> set[str]:
    tokens = (t for t in _WORD.findall(text.lower()) if t not in _STOPWORDS)
    return {t[:-1] if len(t) > 3 and t.endswith("s") else t for t in tokens}


def grounding_score(output: str, context: list[str]) -> float | None:
    """Fraction of output sentences whose content words are mostly present in the context.

    A lexical proxy for hallucination risk: it catches invented facts, not subtle misreadings.
    Returns ``None`` when the output has no substantive sentences.
    """
    supporting = set().union(*(_content_tokens(passage) for passage in context))
    claims = [s for s in _SENTENCE.split(output.strip()) if _content_tokens(s)]
    if not claims:
        return None
    supported = sum(
        1
        for claim in claims
        if len(_content_tokens(claim) & supporting) / len(_content_tokens(claim)) >= _CLAIM_SUPPORT
    )
    return round(supported / len(claims), 4)


def normalize_input(text: str) -> str:
    """Canonical form of a user input for duplicate detection."""
    return " ".join(text.lower().split())


def derive_signals(event: LLMEvent, *, salt: str) -> Signals:
    """Compute the signals stored in place of the event's raw text."""
    inp, out = event.input_text or "", event.output_text or ""
    grounding = grounding_score(out, event.context) if event.context and out else None
    return Signals(
        in_chars=len(inp),
        out_chars=len(out),
        pii_in=count_pii(inp),
        pii_out=count_pii(out),
        secrets_in=redact_secrets(inp)[1],
        secrets_out=redact_secrets(out)[1],
        injection=scan_injection(inp),
        grounding=grounding,
        input_hash=salted_hash(normalize_input(inp), salt) if inp.strip() else None,
    )
