"""Central redactor.

Every user-facing string — stdout, step summaries, notifications, and exception
messages — passes through here so that no secret, identifier, domain, credential,
cookie, or response fragment can escape. Two complementary layers:

1. Exact-value masking of known secrets supplied at construction (all values from
   the loaded config: ids, names, usernames, passwords, hosts).
2. Pattern masking of secret-*shaped* text (UUIDs, emails, http(s) URLs, and long
   opaque tokens/cookies) to catch leaks we were never handed explicitly.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

MASK = "[REDACTED]"

# Ordered longest-first at runtime; patterns are deliberately conservative so that
# ordinary prose ("gateway not running") is untouched.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    # UUID
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
               r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    # email
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    # http(s) URL (host + path)
    re.compile(r"\bhttps?://[^\s\"'<>]+"),
    # Set-Cookie / cookie pair: name=value where value is a long opaque token
    re.compile(r"\b[\w.-]+=[A-Za-z0-9+/_=-]{16,}"),
    # bearer / api-key style long tokens
    re.compile(r"\b(?:Bearer\s+)?[A-Za-z0-9_-]*(?:sk|pk|tok|key)_[A-Za-z0-9_-]{12,}",
               re.IGNORECASE),
    # generic long opaque token (32+ base64-ish chars) not caught above
    re.compile(r"\b[A-Za-z0-9+/_-]{32,}\b"),
)


class Redactor:
    """Immutable-ish scrubber built once per run from the active config's secrets."""

    def __init__(self, secrets: Iterable[str] | None = None) -> None:
        # Drop empties/whitespace; longest first so overlapping secrets mask fully.
        cleaned = {s for s in (secrets or ()) if s and s.strip()}
        self._secrets: tuple[str, ...] = tuple(sorted(cleaned, key=len, reverse=True))

    def redact(self, value: Any) -> str:
        text = value if isinstance(value, str) else str(value)
        for secret in self._secrets:
            if secret in text:
                text = text.replace(secret, MASK)
        for pattern in _PATTERNS:
            text = pattern.sub(MASK, text)
        return text

    def redact_exc(self, exc: BaseException) -> str:
        return self.redact(f"{type(exc).__name__}: {exc}")

    def redact_mapping(self, mapping: Mapping[str, Any]) -> dict[str, str]:
        return {key: self.redact(val) for key, val in mapping.items()}
