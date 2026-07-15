"""Phase 2 Cycle 1 (RED first): status vocabulary + bounded timeouts."""

from __future__ import annotations

from watchdog.http import RetryPolicy, Timeouts
from watchdog.railway import DeploymentStatus


def test_parse_known_status():
    assert DeploymentStatus.parse("SUCCESS") is DeploymentStatus.SUCCESS
    assert DeploymentStatus.parse("CRASHED") is DeploymentStatus.CRASHED


def test_parse_is_case_insensitive():
    assert DeploymentStatus.parse("building") is DeploymentStatus.BUILDING


def test_parse_unknown_never_crashes():
    assert DeploymentStatus.parse("WAT") is DeploymentStatus.UNKNOWN
    assert DeploymentStatus.parse(None) is DeploymentStatus.UNKNOWN
    assert DeploymentStatus.parse("") is DeploymentStatus.UNKNOWN


def test_timeouts_are_bounded_and_positive():
    t = Timeouts()
    assert 0 < t.connect <= 30
    assert 0 < t.read <= 60
    hx = t.as_httpx()
    assert hx.connect == t.connect
    assert hx.read == t.read


def test_retry_policy_backoff_grows():
    p = RetryPolicy(max_retries=3, backoff_base=0.1)
    assert p.backoff_for(0) == 0.1
    assert p.backoff_for(1) == 0.2
    assert p.backoff_for(2) == 0.4
    assert 429 in p.retry_statuses and 500 in p.retry_statuses
