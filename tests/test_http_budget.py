"""Finding 2: the absolute time Budget primitive."""

from __future__ import annotations

from watchdog.http import Budget


def _clock(values):
    it = iter(values)
    return lambda: next(it)


def test_remaining_and_expired():
    # created at t=0 with total 10; then observed at t=3 and t=12.
    b = Budget(_clock([0.0, 3.0, 12.0]), 10.0)
    assert b.remaining() == 7.0
    assert b.expired() is True  # 10 - 12 < 0


def test_clip_bounds_sleep_to_remaining():
    b = Budget(_clock([0.0, 0.0, 0.0]), 5.0)
    assert b.clip(30.0) == 5.0   # clipped to remaining
    b2 = Budget(_clock([0.0, 0.0]), 5.0)
    assert b2.clip(2.0) == 2.0   # smaller interval preserved


def test_clip_never_negative():
    b = Budget(_clock([0.0, 100.0]), 5.0)  # already overrun
    assert b.clip(10.0) == 0.0


def test_timeout_is_non_negative_remaining():
    b = Budget(_clock([0.0, 2.0]), 5.0)
    assert b.timeout() == 3.0
    b2 = Budget(_clock([0.0, 100.0]), 5.0)
    assert b2.timeout() == 0.0
