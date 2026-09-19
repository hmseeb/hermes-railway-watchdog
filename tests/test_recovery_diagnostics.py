"""Recovery failures must retain a safe, actionable reason through both outputs."""
from __future__ import annotations

import httpx
import pytest

from tests.test_orchestrator import RUNNING, FakeRailway, _cfg, _one, _orch
from watchdog.cli import render_summary
from watchdog.errors import FailureReason
from watchdog.hermes import HermesClient
from watchdog.notify import build_email
from watchdog.redaction import Redactor


@pytest.mark.parametrize("stage,reason", [
    ("login", FailureReason.AUTH),
    ("restart", FailureReason.HTTP),
    ("poll", FailureReason.TIMEOUT),
])
def test_real_http_recovery_failure_has_safe_reason_in_summary_and_alert(stage, reason):
    cfg = _cfg()
    paths = []
    secret = "private-response-body-do-not-publish"
    restarted = False

    def handler(request):
        nonlocal restarted
        paths.append(request.url.path)
        if request.url.path == "/health":
            return httpx.Response(200, json={"gateway_running": False})
        if request.url.path == "/auth/password-login":
            if stage == "login" and restarted:  # session expired at restart; re-login denied
                return httpx.Response(401, text=secret)
            return httpx.Response(200, json={"ok": True}, headers={
                "set-cookie": "hermes_session=fake; Path=/; HttpOnly",
            })
        if request.url.path == "/api/gateway/restart":
            restarted = True
            if stage == "login":
                return httpx.Response(401, text=secret)
            if stage == "restart":
                return httpx.Response(500, text=secret)
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    client = HermesClient(
        cfg.targets[0].health_url, transport=httpx.MockTransport(handler),
        poll_attempts=1, poll_interval=0,
    )
    result = _orch(cfg, FakeRailway(RUNNING), {"svc-a": client}).run(_one(cfg))
    outcome = result.outcomes[0]
    assert result.exit_code == 1
    assert outcome.failure_reason is reason
    assert restarted is True
    assert paths.count("/api/gateway/restart") == 1
    # The orchestration fixture uses one-letter ids; don't mask letters in prose.
    redactor = Redactor([cfg.targets[0].health_url])
    summary = render_summary(result, redactor, dry_run=False)
    subject, html, text = build_email(outcome, "failure", redactor)
    for output in (summary, html, text):
        assert reason.value in output
        assert secret not in output
    assert "Recovery failed" in subject
