"""Shared HTTP configuration used by the Railway and Hermes clients.

Centralises bounded timeouts and the safe-read retry policy so every outbound call
is time-bounded and so retries can be applied to idempotent reads only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

import httpx


class Deadline(Protocol):
    """A live remaining-time provider.

    Clients consult ``remaining()`` immediately before every HTTP attempt, retry
    backoff, and poll sleep — never a stale snapshot — so an absolute budget is
    honoured across internal loops. :class:`Budget` is the concrete implementation.
    """

    def remaining(self) -> float: ...


@dataclass(frozen=True)
class Timeouts:
    """Bounded connect/read/write/pool timeouts (seconds)."""

    connect: float = 5.0
    read: float = 10.0
    write: float = 5.0
    pool: float = 5.0

    def as_httpx(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.connect, read=self.read, write=self.write, pool=self.pool
        )


@dataclass(frozen=True)
class RetryPolicy:
    """Retry policy for **safe reads only**. Mutations must never use this."""

    max_retries: int = 2
    backoff_base: float = 0.2
    retry_statuses: frozenset[int] = field(
        default_factory=lambda: frozenset({429, 500, 502, 503, 504})
    )

    def backoff_for(self, attempt: int) -> float:
        """Exponential backoff for the given zero-based attempt index."""
        return float(self.backoff_base * (2**attempt))


class Budget:
    """An absolute time budget for one target's recovery.

    Created once (``now + total``) and consulted before every operation so that no
    sleep, poll, request, or mutation may run past the deadline. ``remaining`` is the
    live seconds left (may go negative); ``timeout`` clamps a per-request timeout to
    what is left; ``clip`` bounds a sleep interval.
    """

    def __init__(self, monotonic: Callable[[], float], total: float) -> None:
        self._monotonic = monotonic
        self._end = monotonic() + total

    def remaining(self) -> float:
        return self._end - self._monotonic()

    def expired(self) -> bool:
        return self.remaining() <= 0

    def clip(self, interval: float) -> float:
        """A sleep interval bounded by both its own value and the remaining budget."""
        return max(0.0, min(interval, self.remaining()))

    def timeout(self) -> float:
        """Non-negative seconds left, for use as a per-request timeout."""
        return max(0.0, self.remaining())
