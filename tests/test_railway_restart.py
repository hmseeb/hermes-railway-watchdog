"""Phase 2 Cycle 3 (RED first): restart_current_deployment (mutation, never retried)."""

from __future__ import annotations

import json

import httpx
import pytest

from watchdog.errors import RailwayGraphQLError, RailwayHTTPError, RailwayTimeoutError
from watchdog.http import RetryPolicy
from watchdog.railway import RailwayClient

TOKEN = "rlwy-secret-token-DO-NOT-LEAK"
DEPLOY_ID = "dep-current-999"


def _client(handler) -> RailwayClient:
    calls = {"n": 0}

    def counting(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return handler(request, calls["n"])

    c = RailwayClient(
        token=TOKEN,
        transport=httpx.MockTransport(counting),
        retry=RetryPolicy(max_retries=3, backoff_base=0.0),
        sleep=lambda _s: None,
    )
    c._calls = calls  # type: ignore[attr-defined]
    return c


def test_restart_success_returns_true_and_targets_exact_id():
    seen = {}

    def handler(req, n):
        seen["payload"] = json.loads(req.content)
        return httpx.Response(200, json={"data": {"deploymentRestart": True}})

    with _client(handler) as c:
        assert c.restart_current_deployment(DEPLOY_ID) is True
    assert seen["payload"]["variables"]["id"] == DEPLOY_ID
    assert "deploymentRestart" in seen["payload"]["query"]


def test_restart_is_not_retried_on_500():
    with _client(lambda req, n: httpx.Response(500, text="err")) as c:
        with pytest.raises(RailwayHTTPError):
            c.restart_current_deployment(DEPLOY_ID)
        # Mutations must be attempted exactly once — no retry.
        assert c._calls["n"] == 1  # type: ignore[attr-defined]


def test_restart_graphql_error_raises():
    body = {"errors": [{"message": "not allowed"}]}
    with _client(lambda req, n: httpx.Response(200, json=body)) as c:
        with pytest.raises(RailwayGraphQLError):
            c.restart_current_deployment(DEPLOY_ID)
        assert c._calls["n"] == 1  # type: ignore[attr-defined]


def test_restart_transport_error_not_retried():
    def handler(req, n):
        raise httpx.ConnectError("refused")

    with _client(handler) as c:
        with pytest.raises((RailwayHTTPError, RailwayTimeoutError)):
            c.restart_current_deployment(DEPLOY_ID)
        # Mutations must never be retried, even on a transport failure.
        assert c._calls["n"] == 1  # type: ignore[attr-defined]


def test_restart_false_result_is_returned():
    body = {"data": {"deploymentRestart": False}}
    with _client(lambda req, n: httpx.Response(200, json=body)) as c:
        assert c.restart_current_deployment(DEPLOY_ID) is False
