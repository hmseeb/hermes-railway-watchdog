"""Hermes native-dashboard client — authenticated status + gateway restart."""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from watchdog.errors import (
    HermesAuthError,
    HermesHTTPError,
    HermesProtocolError,
    HermesTimeoutError,
)
from watchdog.hermes import HealthResult, HermesClient
from watchdog.http import Budget

BASE = "https://gw.hermes.test"
HEALTH_URL = f"{BASE}/api/status"
LOGIN = "/auth/password-login"
RESTART = "/api/gateway/restart"
STATUS = "/api/status"
USER = "admin-user"
# Minimal non-secret value: exercises the login/redaction paths without resembling
# a real credential (avoids secret-scanning false alarms).
PASSWORD = "p"
# The native dashboard sets one or more hermes_session* cookies on a 200 login.
COOKIE = "hermes_session=SECRETCOOKIEVALUE1234567890abcdef; Path=/; HttpOnly"


def _login_ok(req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True}, headers={"set-cookie": COOKIE})


def _status(running: bool, authed: bool = True) -> httpx.Response:
    if not authed:
        return httpx.Response(401, json={"error": "unauthorized"})
    return httpx.Response(200, json={
        "gateway_running": running,
        "gateway_state": "running" if running else "stopped",
        "gateway_platforms": {},
        "version": "test",
    })


def _client(handler, **kw) -> HermesClient:
    return HermesClient(
        health_url=HEALTH_URL,
        username=USER,
        password=PASSWORD,
        transport=httpx.MockTransport(handler),
        sleep=lambda _s: None,
        poll_attempts=kw.pop("poll_attempts", 3),
        poll_interval=0.0,
        **kw,
    )


def _router(login_response, restart_response, status_sequence, *, require_cookie=True):
    """Route by path; /api/status returns successive bodies from status_sequence."""
    state: dict[str, Any] = {"status_calls": 0, "login_calls": 0, "restart_calls": 0, "paths": []}

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        state["paths"].append(path)
        authed = "hermes_session=" in req.headers.get("cookie", "")
        if path == LOGIN:
            state["login_calls"] += 1
            return login_response(req)
        if path == RESTART:
            state["restart_calls"] += 1
            if require_cookie and not authed:
                return httpx.Response(401)
            return restart_response(req)
        if path == STATUS:
            if require_cookie and not authed:
                return httpx.Response(401)
            i = min(state["status_calls"], len(status_sequence) - 1)
            state["status_calls"] += 1
            return status_sequence[i]
        return httpx.Response(404)

    return handler, state


# --- health -------------------------------------------------------------------


def test_health_logs_in_then_reads_status():
    seen: dict[str, str] = {}

    def login(req):
        seen["ct"] = req.headers.get("content-type", "")
        seen["body"] = req.content.decode()
        return _login_ok(req)

    handler, state = _router(login, _login_ok, [_status(True)])
    with _client(handler) as c:
        r = c.check_health()
    assert isinstance(r, HealthResult)
    assert r.status_ok is True and r.gateway_running is True and r.healthy is True
    assert state["paths"] == [LOGIN, STATUS]
    assert "application/json" in seen["ct"]
    assert json.loads(seen["body"]) == {
        "provider": "basic", "username": USER, "password": PASSWORD,
    }


def test_health_session_reused_across_calls():
    handler, state = _router(_login_ok, _login_ok, [_status(True)])
    with _client(handler) as c:
        c.check_health()
        c.check_health()
    assert state["login_calls"] == 1
    assert state["status_calls"] == 2


def test_health_relogins_once_on_401():
    calls = {"status": 0}

    def handler(req):
        if req.url.path == LOGIN:
            return _login_ok(req)
        calls["status"] += 1
        return _status(True, authed=calls["status"] != 2)  # second read: expired

    with _client(handler) as c:
        c.check_health()
        assert c.check_health().healthy is True
    assert calls["status"] == 3


def test_health_persistent_401_raises_auth():
    handler, _ = _router(_login_ok, _login_ok, [_status(True)], require_cookie=False)

    def h(req):
        return httpx.Response(401) if req.url.path == STATUS else handler(req)

    with _client(h) as c, pytest.raises(HermesAuthError):
        c.check_health()


def test_health_gateway_not_running():
    handler, _ = _router(_login_ok, _login_ok, [_status(False)])
    with _client(handler) as c:
        r = c.check_health()
    assert r.status_ok is True
    assert r.gateway_running is False
    assert r.healthy is False


def test_health_gateway_running_must_be_bool_true():
    handler, _ = _router(
        _login_ok, _login_ok, [httpx.Response(200, json={"gateway_running": "yes"})]
    )
    with _client(handler) as c:
        assert c.check_health().gateway_running is False


def test_health_non_200_raises_http():
    handler, _ = _router(_login_ok, _login_ok, [httpx.Response(503, text="down")])
    with _client(handler) as c, pytest.raises(HermesHTTPError):
        c.check_health()


def test_health_timeout_raises():
    def handler(req):
        raise httpx.ReadTimeout("t", request=req)

    with _client(handler) as c, pytest.raises(HermesTimeoutError):
        c.check_health()


def test_health_malformed_json_raises_protocol():
    handler, _ = _router(_login_ok, _login_ok, [httpx.Response(200, text="not json")])
    with _client(handler) as c, pytest.raises(HermesProtocolError):
        c.check_health()


def test_health_non_object_json_raises_protocol():
    handler, _ = _router(_login_ok, _login_ok, [httpx.Response(200, json=[1, 2, 3])])
    with _client(handler) as c, pytest.raises(HermesProtocolError):
        c.check_health()


# --- login --------------------------------------------------------------------


@pytest.mark.parametrize("status", [401, 403, 500])
def test_login_non_200_raises_auth_and_never_restarts(status):
    handler, state = _router(
        lambda req: httpx.Response(status, text="denied"), _login_ok, [_status(True)]
    )
    with _client(handler) as c, pytest.raises(HermesAuthError):
        c.restart_gateway(USER, PASSWORD)
    assert state["restart_calls"] == 0


def test_login_ok_false_raises_auth():
    handler, state = _router(
        lambda req: httpx.Response(200, json={"ok": False}, headers={"set-cookie": COOKIE}),
        _login_ok, [_status(True)],
    )
    with _client(handler) as c, pytest.raises(HermesAuthError):
        c.restart_gateway(USER, PASSWORD)
    assert state["restart_calls"] == 0


def test_login_without_session_cookie_raises_auth():
    handler, state = _router(
        lambda req: httpx.Response(200, json={"ok": True}), _login_ok, [_status(True)]
    )
    with _client(handler) as c, pytest.raises(HermesAuthError):
        c.restart_gateway(USER, PASSWORD)
    assert state["restart_calls"] == 0


def test_login_non_json_raises_auth():
    handler, _ = _router(
        lambda req: httpx.Response(200, text="<html>", headers={"set-cookie": COOKIE}),
        _login_ok, [_status(True)],
    )
    with _client(handler) as c, pytest.raises(HermesAuthError):
        c.check_health()


def test_login_rejects_cross_origin_redirect():
    handler, state = _router(
        lambda req: httpx.Response(302, headers={"location": "https://evil.other.test/x"}),
        _login_ok, [_status(True)],
    )
    with _client(handler) as c, pytest.raises(HermesProtocolError):
        c.restart_gateway(USER, PASSWORD)
    assert state["restart_calls"] == 0


# --- restart ------------------------------------------------------------------


def test_restart_happy_path_login_cookie_then_polls():
    seen: dict[str, str] = {}

    def restart(req):
        seen["cookie"] = req.headers.get("cookie") or ""
        return httpx.Response(200, json={"ok": True})

    handler, state = _router(_login_ok, restart, [_status(False), _status(True)])
    with _client(handler) as c:
        assert c.restart_gateway(USER, PASSWORD) is True
    assert "hermes_session=" in seen["cookie"]
    assert state["paths"] == [LOGIN, RESTART, STATUS, STATUS]


def test_restart_reuses_session_from_health():
    handler, state = _router(_login_ok, _login_ok, [_status(False), _status(True)])
    with _client(handler) as c:
        assert c.check_health().healthy is False
        assert c.restart_gateway(USER, PASSWORD) is True
    assert state["login_calls"] == 1


def test_restart_relogins_once_on_401():
    handler, state = _router(_login_ok, _login_ok, [_status(True)])
    first = {"seen": False}

    def h(req):
        if req.url.path == RESTART and not first["seen"]:
            first["seen"] = True
            return httpx.Response(401)  # session expired between health and restart
        return handler(req)

    with _client(h) as c:
        c.check_health()
        assert c.restart_gateway(USER, PASSWORD) is True
    assert state["login_calls"] == 2
    assert state["restart_calls"] == 1  # the first 401 was intercepted before routing


def test_restart_endpoint_http_error_raises():
    handler, _ = _router(_login_ok, lambda req: httpx.Response(500, text="boom"), [_status(True)])
    with _client(handler) as c, pytest.raises(HermesHTTPError):
        c.restart_gateway(USER, PASSWORD)


@pytest.mark.parametrize("body", [{"ok": False}, {"error": "busy"}])
def test_restart_body_reporting_failure_is_failure(body):
    handler, _ = _router(_login_ok, lambda req: httpx.Response(200, json=body), [_status(True)])
    with _client(handler) as c, pytest.raises(HermesHTTPError):
        c.restart_gateway(USER, PASSWORD)


@pytest.mark.parametrize(
    "response",
    [httpx.Response(200, json={"ok": True}), httpx.Response(202, json={"status": "queued"}),
     httpx.Response(204)],
)
def test_restart_any_2xx_without_failure_is_success(response):
    handler, _ = _router(_login_ok, lambda req: response, [_status(True)])
    with _client(handler) as c:
        assert c.restart_gateway(USER, PASSWORD) is True


def test_restart_poll_never_running_times_out():
    handler, state = _router(
        _login_ok, lambda req: httpx.Response(200, json={"ok": True}), [_status(False)]
    )
    with _client(handler, poll_attempts=2) as c, pytest.raises(HermesTimeoutError):
        c.restart_gateway(USER, PASSWORD)
    assert state["status_calls"] == 2


def test_secrets_never_leak_in_exceptions():
    # The server echoes a distinctive detail in the failed-login body; the typed
    # exception must not carry that response body, the cookie, or the base URL.
    body_marker = "server-echoed-detail-marker"
    handler, _ = _router(
        lambda req: httpx.Response(403, text=f"denied {body_marker}"), _login_ok, [_status(True)]
    )
    with _client(handler) as c, pytest.raises(HermesAuthError) as ei:
        c.restart_gateway(USER, PASSWORD)
    assert body_marker not in str(ei.value)
    assert "SECRETCOOKIEVALUE" not in str(ei.value)
    assert BASE not in str(ei.value)


def test_expired_budget_prevents_status_after_login():
    clock = [0.0]
    deadline = Budget(lambda: clock[0], 1.0)
    paths = []

    def handler(req):
        paths.append(req.url.path)
        clock[0] = 2.0
        return _login_ok(req)

    with _client(handler) as client, pytest.raises(HermesTimeoutError):
        client.check_health(deadline=deadline)
    assert paths == [LOGIN]
