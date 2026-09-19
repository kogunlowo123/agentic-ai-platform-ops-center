"""Secret and PII detection, injection screening and salted hashing.

Telemetry carries prompts and responses, which routinely contain personal data and credentials. The
functions here detect those at ingestion so only counts and hashes need to be kept.
"""

from __future__ import annotations

import hashlib
import hmac
import re

REDACTION = "[REDACTED]"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END "
        r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?"
        r"(?!\[REDACTED\])[^\s'\",;]{6,}"
    ),
)

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]\d{3}[\s.\-]\d{4}(?!\d)"
)
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")

_INJECTION: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any)\b"
        r"[^.\n]{0,40}\b(instructions?|rules?|prompts?|guidelines?)\b",
        re.IGNORECASE,
    ),
    "role_reassignment": re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    "prompt_exfiltration": re.compile(
        r"\b(reveal|print|show|repeat|leak|output)\b[^.\n]{0,40}\b(system\s+prompt|hidden\s+prompt|"
        r"api\s+key|secrets?|credentials?)\b",
        re.IGNORECASE,
    ),
    "role_tags": re.compile(r"<\s*/?\s*(system|assistant|developer)\s*>", re.IGNORECASE),
    "jailbreak": re.compile(r"\b(jailbreak|do\s+anything\s+now|developer\s+mode)\b", re.IGNORECASE),
}


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace credential-shaped substrings and return the text with the substitution count."""
    total = 0
    for pattern in _SECRET_PATTERNS:
        text, count = pattern.subn(_secret_replacement, text)
        total += count
    return text, total


def _secret_replacement(match: re.Match[str]) -> str:
    key = re.match(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]", match.group(0))
    return f"{key.group(0)} {REDACTION}" if key else REDACTION


def redact(text: str) -> str:
    """Return ``text`` with credential-shaped substrings replaced."""
    return redact_secrets(text)[0]


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _card_matches(text: str) -> list[re.Match[str]]:
    found = []
    for match in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            found.append(match)
    return found


def count_pii(text: str | None) -> int:
    """Count emails, phone numbers, SSN-shaped values and Luhn-valid card numbers in ``text``."""
    if not text:
        return 0
    return (
        len(_EMAIL.findall(text))
        + len(_PHONE.findall(text))
        + len(_SSN.findall(text))
        + len(_card_matches(text))
    )


def redact_pii(text: str) -> str:
    """Replace the PII counted by :func:`count_pii` with typed placeholders."""
    for match in reversed(_card_matches(text)):
        text = text[: match.start()] + "[CARD]" + text[match.end() :]
    text = _SSN.sub("[SSN]", text)
    text = _EMAIL.sub("[EMAIL]", text)
    return _PHONE.sub("[PHONE]", text)


def scan_injection(text: str | None) -> list[str]:
    """Names of the injection heuristics that match ``text``."""
    if not text:
        return []
    return [name for name, pattern in _INJECTION.items() if pattern.search(text)]


def salted_hash(value: str, salt: str) -> str:
    """Keyed hash (HMAC-SHA256, truncated) used for user ids and duplicate-input detection.

    Hashing hides values but does not make low-entropy inputs unguessable. Set a secret salt.
    """
    return hmac.new(salt.encode(), value.encode(), hashlib.sha256).hexdigest()[:16]
