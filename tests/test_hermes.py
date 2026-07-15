"""Phase 3 (RED first): Hermes gateway client — health + authenticated restart."""

from __future__ import annotations

import httpx
import pytest

from watchdog.errors import (
    HermesAuthError,
    HermesHTTPError,
    HermesProtocolError,
    HermesTimeoutError,
)
from watchdog.hermes import HealthResult, HermesClient

BASE = "https://gw.hermes.test"
HEALTH_URL = f"{BASE}/health"
USER = "admin-user"
# Minimal non-secret form value: exercises the login form/redaction paths without
# resembling a real credential (avoids secret-scanning false alarms).
PASSWORD = "p"
# The deployed template sets this cookie on a successful 302 login.
COOKIE = "hermes_auth=SECRETCOOKIEVALUE1234567890abcdef; Path=/; HttpOnly"


def _login_ok(req: httpx.Request) -> httpx.Response:
    return httpx.Response(302, headers={"set-cookie": COOKIE, "location": "/"})


def _client(handler, **kw) -> HermesClient:
    return HermesClient(
        health_url=HEALTH_URL,
        transport=httpx.MockTransport(handler),
        sleep=lambda _s: None,
        poll_attempts=kw.pop("poll_attempts", 3),
        poll_interval=0.0,
        **kw,
    )


# --- health -------------------------------------------------------------------

def _health(status: str, gateway: str) -> httpx.Response:
    return httpx.Response(200, json={"status": status, "gateway": gateway})


def test_health_healthy():
    with _client(lambda req: _health("ok", "running")) as c:
        r = c.check_health()
    assert isinstance(r, HealthResult)
    assert r.status_ok is True
    assert r.gateway_running is True
    assert r.healthy is True


def test_health_gateway_not_running():
    with _client(lambda req: _health("ok", "stopped")) as c:
        r = c.check_health()
    assert r.status_ok is True
    assert r.gateway_running is False
    assert r.healthy is False


def test_health_status_not_ok():
    with _client(lambda req: _health("degraded", "running")) as c:
        r = c.check_health()
    assert r.status_ok is False
    assert r.healthy is False


def test_health_non_200_raises_http():
    with _client(lambda req: httpx.Response(503, text="down")) as c:
        with pytest.raises(HermesHTTPError):
            c.check_health()


def test_health_timeout_raises():
    def handler(req):
        raise httpx.ReadTimeout("t", request=req)

    with _client(handler) as c:
        with pytest.raises(HermesTimeoutError):
            c.check_health()


def test_health_malformed_json_raises_protocol():
    with _client(lambda req: httpx.Response(200, text="not json")) as c:
        with pytest.raises(HermesProtocolError):
            c.check_health()


def test_health_non_object_json_raises_protocol():
    with _client(lambda req: httpx.Response(200, json=[1, 2, 3])) as c:
        with pytest.raises(HermesProtocolError):
            c.check_health()


# --- restart ------------------------------------------------------------------

def _restart_router(login_response, restart_response, health_sequence):
    """Route by path; /health returns successive bodies from health_sequence."""
    state = {"health_calls": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/login":
            return login_response(req)
        if path == "/setup/api/gateway/restart":
            return restart_response(req)
        if path == "/health":
            i = min(state["health_calls"], len(health_sequence) - 1)
            state["health_calls"] += 1
            return health_sequence[i]
        return httpx.Response(404)

    return handler, state


def test_restart_happy_path_form_login_cookie_then_polls():
    seen: dict[str, str] = {}

    def login(req):
        seen["login_ct"] = req.headers.get("content-type", "")
        seen["login_body"] = req.content.decode()
        return _login_ok(req)

    def restart(req):
        seen["restart_cookie"] = req.headers.get("cookie") or ""
        return httpx.Response(200, json={"ok": True})

    handler, _ = _restart_router(
        login, restart, [_health("ok", "stopped"), _health("ok", "running")]
    )
    with _client(handler) as c:
        assert c.restart_gateway(USER, PASSWORD) is True
    # Login is form-encoded with username, password, returnTo=/.
    assert "application/x-www-form-urlencoded" in seen["login_ct"]
    assert "username=" in seen["login_body"]
    assert "password=" in seen["login_body"]
    assert "returnTo=%2F" in seen["login_body"] or "returnTo=/" in seen["login_body"]
    # The hermes_auth cookie is retained and replayed on the restart call.
    assert "hermes_auth=" in seen.get("restart_cookie", "")


def test_restart_login_non_302_raises_auth():
    handler, _ = _restart_router(
        lambda req: httpx.Response(200, headers={"set-cookie": COOKIE}),  # 200, not 302
        lambda req: httpx.Response(200),
        [_health("ok", "running")],
    )
    with _client(handler) as c:
        with pytest.raises(HermesAuthError):
            c.restart_gateway(USER, PASSWORD)


def test_restart_login_error_redirect_raises_and_does_not_restart():
    restart_called = {"n": 0}

    def login(req):
        # Same-origin redirect back to /login?error=1 — a failed login.
        return httpx.Response(302, headers={"location": "/login?error=1"})

    def restart(req):
        restart_called["n"] += 1
        return httpx.Response(200)

    handler, _ = _restart_router(login, restart, [_health("ok", "running")])
    with _client(handler) as c:
        with pytest.raises(HermesAuthError):
            c.restart_gateway(USER, PASSWORD)
    assert restart_called["n"] == 0


def test_restart_login_302_without_auth_cookie_raises():
    restart_called = {"n": 0}

    def login(req):
        return httpx.Response(302, headers={"location": "/"})  # no Set-Cookie

    def restart(req):
        restart_called["n"] += 1
        return httpx.Response(200)

    handler, _ = _restart_router(login, restart, [_health("ok", "running")])
    with _client(handler) as c:
        with pytest.raises(HermesAuthError):
            c.restart_gateway(USER, PASSWORD)
    assert restart_called["n"] == 0  # no auth cookie → never restart


def test_restart_rejects_cross_origin_redirect_on_login():
    def login(req):
        return httpx.Response(302, headers={"location": "https://evil.other.test/steal"})

    restart_called = {"n": 0}

    def restart(req):
        restart_called["n"] += 1
        return httpx.Response(200)

    handler, _ = _restart_router(login, restart, [_health("ok", "running")])
    with _client(handler) as c:
        with pytest.raises(HermesProtocolError):
            c.restart_gateway(USER, PASSWORD)
    assert restart_called["n"] == 0  # must not proceed to restart


def test_restart_endpoint_http_error_raises():
    handler, _ = _restart_router(
        _login_ok,
        lambda req: httpx.Response(500, text="boom"),
        [_health("ok", "running")],
    )
    with _client(handler) as c:
        with pytest.raises(HermesHTTPError):
            c.restart_gateway(USER, PASSWORD)


def test_restart_body_without_ok_true_is_failure():
    # A 200 response that does not contain exactly {ok: true} must not be treated as
    # a successful mutation.
    handler, _ = _restart_router(
        _login_ok,
        lambda req: httpx.Response(200, json={"status": "queued"}),
        [_health("ok", "running")],
    )
    with _client(handler) as c:
        with pytest.raises(HermesHTTPError):
            c.restart_gateway(USER, PASSWORD)


def test_restart_body_ok_false_is_failure():
    handler, _ = _restart_router(
        _login_ok,
        lambda req: httpx.Response(200, json={"ok": False}),
        [_health("ok", "running")],
    )
    with _client(handler) as c:
        with pytest.raises(HermesHTTPError):
            c.restart_gateway(USER, PASSWORD)


def test_restart_poll_never_running_times_out():
    handler, _ = _restart_router(
        _login_ok,
        lambda req: httpx.Response(200, json={"ok": True}),
        [_health("ok", "stopped")],
    )
    with _client(handler, poll_attempts=2) as c:
        with pytest.raises(HermesTimeoutError):
            c.restart_gateway(USER, PASSWORD)


def test_secrets_never_leak_in_exceptions():
    # The server echoes a distinctive detail in the failed-login body; the typed
    # exception must not carry that response body, the cookie, or the base URL.
    body_marker = "server-echoed-detail-marker"
    handler, _ = _restart_router(
        lambda req: httpx.Response(403, text=f"denied {body_marker}"),
        lambda req: httpx.Response(200),
        [_health("ok", "running")],
    )
    with _client(handler) as c:
        with pytest.raises(HermesAuthError) as ei:
            c.restart_gateway(USER, PASSWORD)
    assert body_marker not in str(ei.value)
    assert "SECRETCOOKIEVALUE" not in str(ei.value)
    assert BASE not in str(ei.value)
