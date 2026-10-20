"""Self-hosted mode (no Railway): config, classification, host-down, webui, dedupe.

FAKE identifiers only.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime

import httpx
import pytest

from tests.test_notify import _client as _am_client
from tests.test_notify import _inbox
from watchdog import cli
from watchdog.cli import render_summary
from watchdog.config import WatchdogConfig, load_config
from watchdog.errors import HermesAuthError, HermesHTTPError, TargetValidationError
from watchdog.hermes import HealthResult, HermesClient, PlatformState, check_webui
from watchdog.notify import AgentMailIncidentStore, Notifier
from watchdog.orchestrator import Orchestrator, RunResult
from watchdog.redaction import Redactor
from watchdog.state import Classification

ENV = "WATCHDOG_TARGETS_JSON"
SECRET_MSG = "token sk_live_abcdefghijklmnop1234 rejected by https://api.chat.example.test/x"

_SELFHOSTED: dict = {
    "mode": "selfhosted",
    "targets": [
        {
            "alias": f"svc-{c}",
            "service_name": f"agent-{c}",
            "health_url": f"https://{c}-dashboard.example.test/api/status",
            "webui_url": f"https://{c}.example.test",
            "admin_username": f"admin-{c}",
            "admin_password": f"pw-{c}-secret",
        }
        for c in "abcdefg"
    ],
}


def _load(monkeypatch, data) -> WatchdogConfig:
    monkeypatch.setenv(ENV, json.dumps(data))
    return load_config()


@pytest.fixture
def raw():
    return copy.deepcopy(_SELFHOSTED)


@pytest.fixture
def cfg(monkeypatch, raw) -> WatchdogConfig:
    raw["targets"][0]["ignore_platforms"] = ["WhatsApp"]
    return _load(monkeypatch, raw)


# --- config -------------------------------------------------------------------

def test_selfhosted_config_needs_no_railway_ids(cfg):
    assert cfg.selfhosted and len(cfg.targets) == 7
    assert cfg.project_id == cfg.environment_id == cfg.excluded_service_id == ""
    t = cfg.targets[0]
    assert t.service_id == "" and t.webui_url == "https://a.example.test"
    assert t.ignore_platforms == frozenset({"whatsapp"})
    assert cfg.select_target("svc-a") is t  # empty excluded id never matches
    secrets = cfg.all_secret_values()
    assert "a.example.test" in secrets and "https://a.example.test" in secrets
    assert "" not in secrets and "agent-a" not in secrets


def test_selfhosted_ignores_railway_ids_if_present(monkeypatch, raw):
    raw["project_id"] = "p"
    for t in raw["targets"]:
        t["service_id"] = "same-id"  # duplicates would fail in railway mode
    cfg = _load(monkeypatch, raw)
    assert cfg.project_id == "" and all(t.service_id == "" for t in cfg.targets)


def test_webui_url_optional(monkeypatch, raw):
    del raw["targets"][1]["webui_url"]
    assert _load(monkeypatch, raw).targets[1].webui_url is None


@pytest.mark.parametrize("mutate", [
    lambda t: t.update(webui_url="http://plain.example.test"),
    lambda t: t.update(webui_url=" "),
    lambda t: t.update(ignore_platforms="whatsapp"),
    lambda t: t.update(ignore_platforms=[""]),
    lambda t: t.update(alias="Bad"),
    lambda t: t.pop("admin_password"),
])
def test_selfhosted_target_validation(monkeypatch, raw, mutate):
    mutate(raw["targets"][0])
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, raw)


def test_selfhosted_still_requires_seven_targets(monkeypatch, raw):
    raw["targets"].pop()
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, raw)


def test_unknown_mode_rejected(monkeypatch, raw):
    raw["mode"] = "k8s"
    with pytest.raises(Exception, match="mode"):
        _load(monkeypatch, raw)


def test_default_runtime_needs_no_railway_token(monkeypatch, cfg):
    monkeypatch.delenv("RAILWAY_API_TOKEN", raising=False)
    monkeypatch.delenv("AGENTMAIL_API_KEY", raising=False)
    rt = cli._default_runtime(cfg, Redactor(), False)
    assert rt.orchestrator._railway is None
    assert rt.closeables == (rt.notifier,)


# --- hermes client: platforms + webui -----------------------------------------

def test_hermes_parses_gateway_platforms():
    def handler(req):
        if req.url.path == "/auth/password-login":
            return httpx.Response(200, json={"ok": True},
                                  headers={"set-cookie": "hermes_session=abc; Path=/"})
        return httpx.Response(200, json={
            "gateway_running": True, "gateway_state": "running", "version": "t",
            "gateway_platforms": {
                "telegram": {"state": "fatal", "error_code": "bad_token",
                             "error_message": "nope"},
                "discord": {"state": "connected"},
                "weird": "not-a-dict",
            },
        })

    c = HermesClient("https://a-dashboard.example.test/api/status", username="u",
                     password="p", transport=httpx.MockTransport(handler))
    result = c.check_health()
    assert result.platforms == (
        PlatformState("discord", "connected"),
        PlatformState("telegram", "fatal", "bad_token", "nope"),
        PlatformState("weird", "unknown"),
    )


@pytest.mark.parametrize("code", [200, 302, 404, 502])
def test_check_webui_returns_code_without_following_redirects(code):
    seen = []

    def handler(req):
        seen.append(req.url.path)
        return httpx.Response(code, headers={"location": "https://a.example.test/login"})

    assert check_webui("https://a.example.test/", transport=httpx.MockTransport(handler)) == code
    assert seen == ["/"]  # the 302 was not followed


def test_check_webui_transport_error_is_generic():
    def handler(req):
        raise httpx.ConnectError("boom https://a.example.test")

    with pytest.raises(HermesHTTPError) as exc:
        check_webui("https://a.example.test/", transport=httpx.MockTransport(handler))
    assert "example.test" not in str(exc.value)


# --- orchestrator classification ----------------------------------------------

class FakeHermes:
    def __init__(self, *, error=None, running=True, platforms=(), restart_fixes=True):
        self.error, self.running, self.platforms = error, running, platforms
        self.restart_fixes = restart_fixes
        self.restart_calls = 0

    def check_health(self, *, deadline=None):
        if self.error is not None:
            raise self.error
        return HealthResult(True, self.running, tuple(self.platforms))

    def restart_gateway(self, u, p, *, deadline=None):
        self.restart_calls += 1
        if self.restart_fixes:
            self.running = True
        return True


def _orch(cfg, hermes_map, webui=None, *, dry_run=False):
    webui = webui or {}

    def webui_check(url, deadline):
        code = webui.get(url, 200)
        if isinstance(code, Exception):
            raise code
        return code

    return Orchestrator(
        config=cfg, railway=None, hermes_factory=lambda t: hermes_map[t.alias],
        redactor=Redactor(cfg.all_secret_values()), now=lambda: datetime.now(UTC),
        monotonic=lambda: 0.0, sleep=lambda _s: None, dry_run=dry_run,
        health_retries=1, wait_interval=0.0, webui_check=webui_check,
    )


def _run_one(cfg, hermes, webui=None, *, dry_run=False):
    out = _orch(cfg, {"svc-a": hermes}, webui, dry_run=dry_run).run([cfg.targets[0]])
    return out.outcomes[0]


def test_healthy(cfg):
    o = _run_one(cfg, FakeHermes(platforms=[PlatformState("telegram", "connected")]))
    assert o.classification is Classification.HEALTHY and o.recovered and o.action == "none"


@pytest.mark.parametrize("error", [HermesHTTPError("x"), HermesAuthError("x")])
def test_host_unreachable_no_action(cfg, error):
    h = FakeHermes(error=error)
    o = _run_one(cfg, h)
    assert o.classification is Classification.HOST_UNREACHABLE
    assert not o.recovered and o.action == "none" and h.restart_calls == 0
    assert o.failure_reason is not None


def test_gateway_down_restarts_once(cfg):
    h = FakeHermes(running=False)
    o = _run_one(cfg, h)
    assert h.restart_calls == 1
    assert o.action == "gateway_restart" and o.recovered
    assert o.classification is Classification.HEALTHY


def test_gateway_restart_ineffective_is_unrecovered_and_not_retried(cfg):
    h = FakeHermes(running=False, restart_fixes=False)
    o = _run_one(cfg, h)
    assert h.restart_calls == 1 and not o.recovered and o.action == "gateway_restart"


def test_gateway_down_dry_run_does_not_mutate(cfg):
    h = FakeHermes(running=False)
    o = _run_one(cfg, h, dry_run=True)
    assert h.restart_calls == 0 and o.classification is Classification.GATEWAY_ONLY_FAILURE


def test_platform_degraded_names_platform_and_redacts_error(cfg):
    h = FakeHermes(platforms=[
        PlatformState("telegram", "fatal", "invalid_token", SECRET_MSG),
        PlatformState("discord", "connected"),
    ])
    o = _run_one(cfg, h)
    assert o.classification is Classification.PLATFORM_DEGRADED
    assert not o.recovered and o.action == "none" and h.restart_calls == 0
    assert "telegram=fatal" in o.detail and "invalid_token" in o.detail
    assert "sk_live" not in o.detail and "api.chat.example.test" not in o.detail
    summary = render_summary(RunResult((o,)), Redactor(cfg.all_secret_values()), dry_run=False)
    assert "telegram=fatal" in summary and "platform\\_degraded" not in summary
    assert "platform_degraded" in summary and "sk_live" not in summary


def test_ignored_platform_does_not_alert(cfg):
    # svc-a ignores whatsapp (case-insensitively); other targets do not.
    states = [PlatformState("WhatsApp", "disconnected")]
    assert _run_one(cfg, FakeHermes(platforms=states)).classification is Classification.HEALTHY
    other = _orch(cfg, {"svc-b": FakeHermes(platforms=states)}).run([cfg.targets[1]])
    assert other.outcomes[0].classification is Classification.PLATFORM_DEGRADED


@pytest.mark.parametrize("code,ok", [(200, True), (302, True), (301, False), (404, False),
                                     (502, False), (HermesHTTPError("x"), False)])
def test_webui_codes(cfg, code, ok):
    o = _run_one(cfg, FakeHermes(), {"https://a.example.test": code})
    assert o.recovered is ok
    if not ok:
        assert o.classification is Classification.WEBUI_DOWN and o.action == "none"
        expected = "unreachable" if isinstance(code, Exception) else f"HTTP {code}"
        assert o.detail == f"webui: {expected}"


def test_all_unreachable_summary_says_host_down(cfg):
    hermes = {t.alias: FakeHermes(error=HermesHTTPError("x")) for t in cfg.targets}
    result = _orch(cfg, hermes).run()
    assert result.host_down and result.exit_code == 1
    summary = render_summary(result, Redactor(cfg.all_secret_values()), dry_run=False)
    assert "HOST DOWN" in summary and "Mac mini" in summary
    assert "agent-a" not in summary  # one host line, not seven failures


def test_partial_unreachable_is_not_host_down(cfg):
    hermes = {t.alias: FakeHermes(error=HermesHTTPError("x")) for t in cfg.targets}
    hermes["svc-g"] = FakeHermes()
    result = _orch(cfg, hermes).run()
    assert not result.host_down
    assert "HOST DOWN" not in render_summary(result, Redactor(), dry_run=False)


# --- notification dedupe ------------------------------------------------------

def _alerts(state):
    return [m["subject"] for m in state["sent"] if m["subject"].startswith("[watchdog]")]


def _sh_notifier(handler):
    client = _am_client(handler)
    return Notifier(client=client, recipient="ops@example.test",
                    store=AgentMailIncidentStore(client), redactor=Redactor(),
                    selfhosted=True)


def _result(cfg, hermes_map, webui=None):
    return _orch(cfg, hermes_map, webui).run([cfg.targets[0]])


def test_dedupe_alert_once_realert_on_change_and_resolve_once(cfg):
    handler, state = _inbox()
    n = _sh_notifier(handler)
    degraded = {"svc-a": FakeHermes(platforms=[PlatformState("telegram", "fatal", None, "m1")])}

    n.process(_result(cfg, degraded))
    assert len(_alerts(state)) == 1 and "Recovery failed" in _alerts(state)[0]

    # Same condition (even with a different error message) on later runs: silent.
    degraded["svc-a"].platforms = [PlatformState("telegram", "fatal", None, "m2")]
    for _ in range(3):
        assert n.process(_result(cfg, degraded)).suppressed == ["svc-a"]
    assert len(_alerts(state)) == 1

    # Condition changes (web UI now down instead): one new alert.
    n.process(_result(cfg, {"svc-a": FakeHermes()}, {"https://a.example.test": 502}))
    assert len(_alerts(state)) == 2 and "webui_down" in _alerts(state)[1]
    n.process(_result(cfg, {"svc-a": FakeHermes()}, {"https://a.example.test": 503}))
    assert len(_alerts(state)) == 2

    # Recovers on its own: exactly one "Resolved" email, then silence.
    for _ in range(2):
        n.process(_result(cfg, {"svc-a": FakeHermes()}))
    assert len(_alerts(state)) == 3 and "Resolved" in _alerts(state)[2]


def test_host_down_single_alert_then_single_resolved(cfg):
    handler, state = _inbox()
    n = _sh_notifier(handler)
    down = {t.alias: FakeHermes(error=HermesHTTPError("x")) for t in cfg.targets}

    for _ in range(3):
        n.process(_orch(cfg, down).run())
    alerts = _alerts(state)
    assert len(alerts) == 1 and "self-hosted host" in alerts[0]
    assert "Mac mini" in state["sent"][0]["text"]

    up = {t.alias: FakeHermes() for t in cfg.targets}
    for _ in range(2):
        n.process(_orch(cfg, up).run())
    alerts = _alerts(state)
    assert len(alerts) == 2 and "Resolved" in alerts[1]
