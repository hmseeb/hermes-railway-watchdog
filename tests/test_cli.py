"""Phase 6 (RED first): CLI wiring — orchestration, summary, exit codes, redaction."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from watchdog.cli import Runtime, build_parser, main
from watchdog.config import WatchdogConfig
from watchdog.notify import Notifier
from watchdog.orchestrator import Orchestrator
from watchdog.railway import DeploymentStatus, ServiceStatus
from watchdog.redaction import Redactor

ENV = "WATCHDOG_TARGETS_JSON"
NOW = datetime(2026, 7, 15, 12, 0, 0, tzinfo=UTC)


def _running():
    return ServiceStatus(
        service_id="svc", has_active_deployment=True, active_deployment_id="dep-1",
        restartable_deployment_id="dep-1",
        latest_status=DeploymentStatus.SUCCESS, latest_created_at=NOW, latest_updated_at=NOW,
        stopped=False, instance_running=True, raw_instance_state="RUNNING",
    )


class FakeRailway:
    def __init__(self, status):
        self._status = status
        self.restart_calls = []

    def get_service_status(self, p, e, s, *, deadline=None):
        return self._status

    def restart_current_deployment(self, dep_id, *, deadline=None):
        self.restart_calls.append(dep_id)
        return True


class FakeHermes:
    def __init__(self, gateway_running=True):
        from watchdog.hermes import HealthResult
        self._r = HealthResult(status_ok=True, gateway_running=gateway_running)
        self.closed = False

    def check_health(self, *, deadline=None):
        return self._r

    def restart_gateway(self, u, p, *, deadline=None):
        return True

    def close(self):
        self.closed = True


def _runtime_factory(railway, hermes_map, *, notifier=None):
    def factory(config: WatchdogConfig, redactor: Redactor, dry_run: bool) -> Runtime:
        orch = Orchestrator(
            config=config, railway=railway,
            hermes_factory=lambda t: hermes_map[t.alias],
            redactor=redactor, now=lambda: NOW, monotonic=lambda: 0.0,
            sleep=lambda _s: None, dry_run=dry_run,
            transition_threshold=timedelta(minutes=15),
        )
        nf = notifier or Notifier(client=None, recipient=None, store=None, redactor=redactor)
        return Runtime(orchestrator=orch, notifier=nf)

    return factory


# --- arg parsing --------------------------------------------------------------

def test_parser_defaults():
    args = build_parser().parse_args([])
    assert args.dry_run is False and args.service is None


def test_parser_flags():
    args = build_parser().parse_args(["--dry-run", "--service", "svc-a"])
    assert args.dry_run is True and args.service == "svc-a"


# --- dry-run ------------------------------------------------------------------

def test_dry_run_healthy_all_exit_zero(monkeypatch, capsys, valid_config_json, valid_config_dict):
    monkeypatch.setenv(ENV, valid_config_json)
    hermes_map = {t["alias"]: FakeHermes() for t in valid_config_dict["targets"]}
    factory = _runtime_factory(FakeRailway(_running()), hermes_map)
    code = main(["--dry-run"], runtime_factory=factory)
    out = capsys.readouterr().out
    assert code == 0
    assert "svc-a" in out and "healthy" in out


def test_output_never_leaks_secrets(monkeypatch, capsys, valid_config_json, valid_config_dict):
    monkeypatch.setenv(ENV, valid_config_json)
    hermes_map = {t["alias"]: FakeHermes() for t in valid_config_dict["targets"]}
    factory = _runtime_factory(FakeRailway(_running()), hermes_map)
    code = main(["--dry-run"], runtime_factory=factory)
    out = capsys.readouterr().out
    assert code == 0
    for t in valid_config_dict["targets"]:
        assert t["service_name"] not in out
        assert t["admin_password"] not in out
        assert t["health_url"] not in out
    assert "example.test" not in out


def test_dry_run_unhealthy_exits_nonzero(monkeypatch, capsys, valid_config_json, valid_config_dict):
    monkeypatch.setenv(ENV, valid_config_json)
    # One gateway-down target → classified failure → dry-run reports FAIL.
    hermes_map = {t["alias"]: FakeHermes() for t in valid_config_dict["targets"]}
    hermes_map["svc-a"] = FakeHermes(gateway_running=False)
    factory = _runtime_factory(FakeRailway(_running()), hermes_map)
    code = main(["--dry-run"], runtime_factory=factory)
    out = capsys.readouterr().out
    assert code == 1
    assert "FAIL" in out


def test_writes_github_step_summary(tmp_path, monkeypatch, valid_config_json, valid_config_dict):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv(ENV, valid_config_json)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    hermes_map = {t["alias"]: FakeHermes() for t in valid_config_dict["targets"]}
    main(["--dry-run"], runtime_factory=_runtime_factory(FakeRailway(_running()), hermes_map))
    assert "svc-a" in summary.read_text()


# --- selection & errors -------------------------------------------------------

def test_single_service_selection(monkeypatch, capsys, valid_config_json, valid_config_dict):
    monkeypatch.setenv(ENV, valid_config_json)
    hermes_map = {t["alias"]: FakeHermes() for t in valid_config_dict["targets"]}
    code = main(["--dry-run", "--service", "svc-c"],
                runtime_factory=_runtime_factory(FakeRailway(_running()), hermes_map))
    out = capsys.readouterr().out
    assert code == 0
    assert "svc-c" in out
    assert "svc-a" not in out


def test_unknown_service_exits_two(monkeypatch, capsys, valid_config_json):
    monkeypatch.setenv(ENV, valid_config_json)
    code = main(["--dry-run", "--service", "svc-nope"],
                runtime_factory=_runtime_factory(FakeRailway(_running()), {}))
    combined = capsys.readouterr()
    assert code == 2
    assert "svc-nope" in (combined.out + combined.err)


def test_missing_env_exits_two(monkeypatch, capsys):
    monkeypatch.delenv(ENV, raising=False)
    code = main(["--dry-run"])
    assert code == 2
    assert capsys.readouterr().err.strip() != ""


def test_invalid_config_does_not_leak(monkeypatch, capsys):
    leak = "https://secret-host.example.test/health"
    monkeypatch.setenv(ENV, '{"project_id": "' + leak + '"}')
    code = main(["--dry-run"])
    combined = capsys.readouterr()
    assert code == 2
    assert "secret-host.example.test" not in (combined.out + combined.err)


# --- live path + notifications ------------------------------------------------

def test_live_run_invokes_notifier_and_degraded_sets_nonzero(
    monkeypatch, capsys, valid_config_json, valid_config_dict
):
    monkeypatch.setenv(ENV, valid_config_json)
    hermes_map = {t["alias"]: FakeHermes() for t in valid_config_dict["targets"]}
    # All healthy → recovered; notifier degraded (no creds) must flag a soft failure.
    degraded_notifier = Notifier(client=None, recipient=None, store=None,
                                 redactor=Redactor())
    # Force a failure so there is something notable to degrade on.
    hermes_map["svc-a"] = FakeHermes(gateway_running=False)

    class StuckHermes(FakeHermes):
        def restart_gateway(self, u, p, *, deadline=None):
            return True  # ineffective: gateway stays down

        def check_health(self, *, deadline=None):
            from watchdog.hermes import HealthResult
            return HealthResult(status_ok=True, gateway_running=False)

    hermes_map["svc-a"] = StuckHermes(gateway_running=False)
    factory = _runtime_factory(FakeRailway(_running()), hermes_map, notifier=degraded_notifier)
    code = main([], runtime_factory=factory)
    assert code == 1  # unrecovered + degraded


class _Closer:
    def __init__(self):
        self.closes = 0

    def close(self):
        self.closes += 1


def test_repeated_main_closes_all_clients(monkeypatch, valid_config_json, valid_config_dict):
    monkeypatch.setenv(ENV, valid_config_json)
    rw_closer, am_closer = _Closer(), _Closer()
    hermes_map = {t["alias"]: FakeHermes() for t in valid_config_dict["targets"]}

    def factory(config, redactor, dry_run):
        orch = Orchestrator(
            config=config, railway=FakeRailway(_running()),
            hermes_factory=lambda t: hermes_map[t.alias], redactor=redactor,
            now=lambda: NOW, monotonic=lambda: 0.0, sleep=lambda _s: None, dry_run=dry_run,
        )
        nf = Notifier(client=None, recipient=None, store=None, redactor=redactor)
        return Runtime(orchestrator=orch, notifier=nf, closeables=(rw_closer, am_closer))

    main(["--dry-run"], runtime_factory=factory)
    main(["--dry-run"], runtime_factory=factory)
    # No leak: each run closes the Railway + AgentMail clients deterministically.
    assert rw_closer.closes == 2
    assert am_closer.closes == 2
    assert all(h.closed for h in hermes_map.values())


def test_runtime_close_runs_even_on_orchestrator_error(monkeypatch, valid_config_json):
    monkeypatch.setenv(ENV, valid_config_json)
    closer = _Closer()

    class BoomOrch:
        def run(self, targets=None):
            raise RuntimeError("unexpected")

    def factory(config, redactor, dry_run):
        return Runtime(
            orchestrator=BoomOrch(),  # type: ignore[arg-type]
            notifier=Notifier(client=None, recipient=None, store=None, redactor=redactor),
            closeables=(closer,),
        )

    try:
        main(["--dry-run"], runtime_factory=factory)
    except RuntimeError:
        pass
    assert closer.closes == 1  # cleanup still ran


def test_notification_error_is_sanitized_not_raised(
    monkeypatch, capsys, valid_config_json, valid_config_dict
):
    from watchdog.errors import NotificationError

    class RaisingNotifier:
        def process(self, result):
            raise NotificationError("smtp secret https://real-host.example.test failed")

    monkeypatch.setenv(ENV, valid_config_json)
    hermes_map = {t["alias"]: FakeHermes() for t in valid_config_dict["targets"]}
    factory = _runtime_factory(FakeRailway(_running()), hermes_map, notifier=RaisingNotifier())
    code = main([], runtime_factory=factory)  # must not raise
    err = capsys.readouterr().err
    assert code == 1
    assert "real-host.example.test" not in err
    assert "Traceback" not in err
