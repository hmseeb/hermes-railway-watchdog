"""Finding (async wall clock): the absolute deadline is a total wall-clock cap.

The httpx scalar timeout only bounds each network phase. These tests use a custom
*async* transport that awaits beyond the remaining budget and prove the sync client
methods raise the typed timeout at the absolute deadline, that no further request or
mutation is started afterwards, that the login cookie still reaches restart, and that
Railway mutations remain at-most-once. The deadline uses real monotonic time so the
asyncio wall (which uses the event-loop clock) is consistent with remaining().
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from watchdog.errors import HermesTimeoutError, RailwayTimeoutError
from watchdog.hermes import HermesClient
from watchdog.http import RetryPolicy
from watchdog.railway import RailwayClient

PROJECT, ENV, SERVICE = "proj-1", "env-2", "svc-3"
HEALTH_URL = "https://gw.hermes.test/health"

# Small, generous margins keep these deterministic without being slow.
SHORT = 0.05   # remaining budget (seconds)
LONG = 5.0     # how long a stalled handler would await


class RealDeadline:
    """remaining() = end - real_monotonic(); consistent with the asyncio wall clock."""

    def __init__(self, total: float) -> None:
        self._end = time.monotonic() + total

    def remaining(self) -> float:
        return self._end - time.monotonic()


def _si_ok():
    return {
        "data": {
            "service": {"id": SERVICE, "projectId": PROJECT},
            "environment": {"id": ENV, "projectId": PROJECT},
            "serviceInstance": {"serviceId": SERVICE, "environmentId": ENV,
                                "activeDeployments": [], "latestDeployment": None},
        }
    }


# --- Railway: total wall cap cancels a stalled request ------------------------

def test_railway_total_wall_timeout_cancels_stalled_request():
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await asyncio.sleep(LONG)  # stalls well past the remaining budget
        return httpx.Response(200, json=_si_ok())

    client = RailwayClient(
        "tok", transport=httpx.MockTransport(handler),
        retry=RetryPolicy(max_retries=2, backoff_base=0.0), sleep=lambda _s: None,
    )
    started = time.monotonic()
    with pytest.raises(RailwayTimeoutError):
        client.get_service_status(PROJECT, ENV, SERVICE, deadline=RealDeadline(SHORT))
    # Returned at the absolute deadline, not after LONG seconds.
    assert time.monotonic() - started < LONG / 2


def test_railway_refuses_new_attempt_after_expiry():
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await asyncio.sleep(LONG)
        return httpx.Response(500)

    client = RailwayClient(
        "tok", transport=httpx.MockTransport(handler),
        retry=RetryPolicy(max_retries=3, backoff_base=0.0), sleep=lambda _s: None,
    )
    with pytest.raises(RailwayTimeoutError):
        client.get_service_status(PROJECT, ENV, SERVICE, deadline=RealDeadline(SHORT))
    # First attempt was cancelled at the wall; the budget is now spent so no retry ran.
    assert calls["n"] == 1


def test_railway_mutation_is_at_most_once_under_wall_timeout():
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        await asyncio.sleep(LONG)
        return httpx.Response(200, json={"data": {"deploymentRestart": True}})

    client = RailwayClient(
        "tok", transport=httpx.MockTransport(handler),
        retry=RetryPolicy(max_retries=3, backoff_base=0.0), sleep=lambda _s: None,
    )
    with pytest.raises(RailwayTimeoutError):
        client.restart_current_deployment("dep-1", deadline=RealDeadline(SHORT))
    assert calls["n"] == 1  # mutation attempted exactly once, never retried


def test_railway_completes_when_within_budget():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_si_ok())

    client = RailwayClient(
        "tok", transport=httpx.MockTransport(handler), sleep=lambda _s: None,
    )
    status = client.get_service_status(PROJECT, ENV, SERVICE, deadline=RealDeadline(LONG))
    assert status.has_active_deployment is False


# --- Hermes: cookie persists; wall cap stops polling --------------------------

def _hermes_router(*, login_delay=0.0, restart_delay=0.0, health_delay=0.0,
                   gateway="running", record=None):
    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/login":
            await asyncio.sleep(login_delay)
            return httpx.Response(
                302, headers={"set-cookie": "hermes_auth=SECRET", "location": "/"}
            )
        if path == "/setup/api/gateway/restart":
            await asyncio.sleep(restart_delay)
            if record is not None:
                record["restart_cookie"] = request.headers.get("cookie", "")
            return httpx.Response(200, json={"ok": True})
        if path == "/health":
            await asyncio.sleep(health_delay)
            return httpx.Response(200, json={"status": "ok", "gateway": gateway})
        return httpx.Response(404)

    return handler


def test_hermes_restart_cookie_reaches_restart_within_budget():
    record: dict = {}
    client = HermesClient(
        HEALTH_URL, transport=httpx.MockTransport(_hermes_router(record=record)),
        poll_attempts=3, poll_interval=0.0,
    )
    assert client.restart_gateway("u", "p", deadline=RealDeadline(LONG)) is True
    assert "hermes_auth=" in record["restart_cookie"]  # cookie persisted login -> restart


def test_hermes_health_poll_stops_at_wall_deadline():
    # Gateway never reports running; each poll stalls, so the wall must stop it.
    client = HermesClient(
        HEALTH_URL,
        transport=httpx.MockTransport(_hermes_router(gateway="stopped", health_delay=LONG)),
        poll_attempts=50, poll_interval=0.0,
    )
    started = time.monotonic()
    with pytest.raises(HermesTimeoutError):
        client.restart_gateway("u", "p", deadline=RealDeadline(SHORT))
    assert time.monotonic() - started < LONG / 2  # stopped at the deadline, not per poll


def test_hermes_budget_exhausted_refuses_request():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok", "gateway": "running"})

    client = HermesClient(HEALTH_URL, transport=httpx.MockTransport(handler))
    with pytest.raises(HermesTimeoutError):
        client.check_health(deadline=RealDeadline(-1.0))  # already expired
