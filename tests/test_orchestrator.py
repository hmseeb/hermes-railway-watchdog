"""Phase 4 Cycle 2 (RED first): recovery orchestration.

State-based fakes model reality: a mutation (deployment restart / gateway restart)
changes the world so a later probe observes recovery. This lets the orchestrator's
call pattern vary without brittle per-call sequencing, while we still assert each
mutation happens at most once.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from watchdog.config import load_config
from watchdog.errors import HermesHTTPError, RailwayError
from watchdog.hermes import HealthResult
from watchdog.orchestrator import Orchestrator
from watchdog.railway import DeploymentStatus, ServiceStatus
from watchdog.redaction import Redactor
from watchdog.state import Classification

NOW = datetime(2026, 7, 15, 12, 0, 0, tzinfo=UTC)


def _status(*, instance_running=True, stopped=False, status=DeploymentStatus.SUCCESS,
            has_active=True, dep_id="dep-1", restartable="dep-1") -> ServiceStatus:
    return ServiceStatus(
        service_id="svc",
        has_active_deployment=has_active,
        active_deployment_id=dep_id if has_active else None,
        restartable_deployment_id=restartable,
        latest_status=status,
        latest_created_at=NOW,
        latest_updated_at=NOW,
        stopped=stopped,
        instance_running=instance_running,
        raw_instance_state="RUNNING" if instance_running else "STOPPED",
    )


RUNNING = _status()
CONTAINER_DOWN = _status(instance_running=False)


class FakeRailway:
    def __init__(self, status, *, restart_effective=True, recovered_status=None, raises=None,
                 restart_result=True):
        self._status = status
        self._effective = restart_effective
        self._recovered = recovered_status or RUNNING
        self._raises = raises
        self._restart_result = restart_result
        self.restart_calls: list[str] = []
        self.remaining_seen: list = []

    def get_service_status(self, project_id, environment_id, service_id, *, deadline=None):
        self.remaining_seen.append(deadline.remaining() if deadline is not None else None)
        if self._raises is not None:
            raise self._raises
        return self._status

    def restart_current_deployment(self, deployment_id, *, deadline=None):
        self.restart_calls.append(deployment_id)
        if self._effective:
            self._status = self._recovered
        return self._restart_result


class FakeHermes:
    def __init__(self, *, status_ok=True, gateway_running=True, railway=None,
                 restart_effective=True, restart_result=True, close_raises=False):
        self._status_ok = status_ok
        self._gateway = gateway_running
        self._railway = railway
        self._restart_effective = restart_effective
        self._restart_result = restart_result
        self._close_raises = close_raises
        self.restart_calls = 0
        self.closed = False

    def _reachable(self) -> bool:
        if self._railway is None:
            return True
        return self._railway._status.instance_running

    def check_health(self, *, deadline=None):
        if not self._reachable():
            raise HermesHTTPError("unreachable")
        return HealthResult(status_ok=self._status_ok, gateway_running=self._gateway)

    def restart_gateway(self, username, password, *, deadline=None):
        self.restart_calls += 1
        if self._restart_effective:
            self._gateway = True
        return self._restart_result

    def close(self):
        self.closed = True
        if self._close_raises:
            raise RuntimeError("close boom")


def _cfg():
    valid = {
        "project_id": "p", "environment_id": "e", "excluded_service_id": "x",
        "targets": [
            {"alias": f"svc-{c}", "service_name": f"n-{c}", "service_id": f"id-{c}",
             "health_url": f"https://h-{c}.test/health", "admin_username": f"u-{c}",
             "admin_password": f"pw-{c}"} for c in "abcdefg"
        ],
    }
    import os
    os.environ["WATCHDOG_TARGETS_JSON"] = json.dumps(valid)
    return load_config()


def _orch(cfg, railway, hermes_map, *, dry_run=False, per_target_deadline=60.0,
          wait_attempts=5, monotonic=None):
    clock = monotonic or (lambda: 0.0)
    return Orchestrator(
        config=cfg,
        railway=railway,
        hermes_factory=lambda t: hermes_map[t.alias],
        redactor=Redactor(cfg.all_secret_values()),
        now=lambda: NOW,
        monotonic=clock,
        sleep=lambda _s: None,
        dry_run=dry_run,
        transition_threshold=timedelta(minutes=15),
        per_target_deadline=per_target_deadline,
        health_retries=1,
        wait_attempts=wait_attempts,
        wait_interval=0.0,
        concurrency=3,
    )


def _one(cfg):
    return [cfg.targets[0]]


# --- healthy ------------------------------------------------------------------

def test_outcome_carries_real_service_name_and_internal_alias():
    # The outcome must expose the operator-chosen public service_name for rendering,
    # while retaining the opaque alias for internal dedup/selection.
    cfg = _cfg()
    rw = FakeRailway(RUNNING)
    hm = FakeHermes()
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.alias == "svc-a"
    assert o.service_name == "n-a"


def test_healthy_target_is_never_mutated():
    cfg = _cfg()
    rw = FakeRailway(RUNNING)
    hm = FakeHermes()
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.classification is Classification.HEALTHY
    assert o.action == "none"
    assert o.recovered is True
    assert rw.restart_calls == [] and hm.restart_calls == 0
    assert hm.closed is True
    assert res.exit_code == 0


# --- gateway only -------------------------------------------------------------

def test_gateway_only_failure_restarts_only_gateway():
    cfg = _cfg()
    rw = FakeRailway(RUNNING)
    hm = FakeHermes(gateway_running=False)  # railway up, gateway down
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.classification is Classification.GATEWAY_ONLY_FAILURE
    assert o.action == "gateway_restart"
    assert o.recovered is True
    assert rw.restart_calls == []          # container never touched
    assert hm.restart_calls == 1           # at most once
    assert res.exit_code == 0


def test_gateway_only_fresh_recheck_avoids_mutation_on_race():
    cfg = _cfg()
    rw = FakeRailway(RUNNING)
    # Health flips to running between the initial classify and the recheck.
    hm = FakeHermes(gateway_running=False)

    calls = {"n": 0}
    real_check = hm.check_health

    def flip(*, deadline=None):
        calls["n"] += 1
        if calls["n"] >= 2:
            hm._gateway = True
        return real_check()

    hm.check_health = flip  # type: ignore[method-assign]
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is True
    assert o.action == "none"              # race avoided; no restart
    assert hm.restart_calls == 0


def test_gateway_restart_ineffective_stays_unrecovered_once():
    cfg = _cfg()
    rw = FakeRailway(RUNNING)
    hm = FakeHermes(gateway_running=False, restart_effective=False)
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is False
    assert hm.restart_calls == 1           # not retried
    assert res.exit_code == 1


# --- container ----------------------------------------------------------------

def test_container_failure_restarts_deployment_then_gateway():
    cfg = _cfg()
    rw = FakeRailway(CONTAINER_DOWN, recovered_status=RUNNING)
    hm = FakeHermes(gateway_running=False, railway=rw)  # reachable only once up
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.classification is Classification.CONTAINER_FAILURE
    assert o.action == "container_restart"
    assert o.recovered is True
    assert rw.restart_calls == ["dep-1"]   # exact current deployment, once
    assert hm.restart_calls == 1           # gateway restarted after container up
    assert res.exit_code == 0


def test_container_restart_ineffective_no_gateway_restart():
    cfg = _cfg()
    rw = FakeRailway(CONTAINER_DOWN, restart_effective=False)
    hm = FakeHermes(gateway_running=False, railway=rw)
    res = _orch(cfg, rw, {"svc-a": hm}, wait_attempts=2).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is False
    assert rw.restart_calls == ["dep-1"]   # attempted once
    assert hm.restart_calls == 0           # never reached gateway restart
    assert res.exit_code == 1


def test_container_failure_without_any_deployment_id_is_unrecovered():
    cfg = _cfg()
    rw = FakeRailway(_status(has_active=False, instance_running=False, restartable=None))
    hm = FakeHermes(railway=rw)
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is False
    assert rw.restart_calls == []          # nothing safe to restart


def test_no_active_completed_restarts_latest_deployment():
    cfg = _cfg()
    down = _status(has_active=False, instance_running=False,
                   status=DeploymentStatus.COMPLETED, restartable="dep-latest")
    rw = FakeRailway(down, recovered_status=RUNNING)
    hm = FakeHermes(gateway_running=False, railway=rw)
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.classification is Classification.CONTAINER_FAILURE
    assert o.action == "container_restart"
    assert o.recovered is True
    assert rw.restart_calls == ["dep-latest"]   # restarts the latest image, not skipped
    assert hm.restart_calls == 1


def test_per_target_deadline_aborts_wait():
    cfg = _cfg()
    ticks = {"t": 0.0}

    def clock():
        ticks["t"] += 5.0
        return ticks["t"]

    rw = FakeRailway(CONTAINER_DOWN, restart_effective=False)
    hm = FakeHermes(gateway_running=False, railway=rw)
    res = _orch(cfg, rw, {"svc-a": hm}, per_target_deadline=1.0, monotonic=clock).run(_one(cfg))
    assert res.outcomes[0].recovered is False


# --- transitional -------------------------------------------------------------

def test_transitional_is_deferred_not_a_failure():
    cfg = _cfg()
    rw = FakeRailway(_status(status=DeploymentStatus.BUILDING, instance_running=False))
    hm = FakeHermes(railway=rw)
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.classification is Classification.TRANSITIONAL
    assert o.action == "none"
    assert o.deferred is True
    assert rw.restart_calls == [] and hm.restart_calls == 0
    assert res.exit_code == 0               # deferred is not unrecovered


# --- dry-run ------------------------------------------------------------------

def test_dry_run_never_mutates_but_flags_unhealthy():
    cfg = _cfg()
    rw = FakeRailway(CONTAINER_DOWN)
    hm = FakeHermes(gateway_running=False, railway=rw)
    res = _orch(cfg, rw, {"svc-a": hm}, dry_run=True).run(_one(cfg))
    o = res.outcomes[0]
    assert o.classification is Classification.CONTAINER_FAILURE
    assert o.action == "none"
    assert o.recovered is False
    assert rw.restart_calls == [] and hm.restart_calls == 0
    assert res.exit_code == 1


# --- concurrency & isolation --------------------------------------------------

def test_concurrency_isolation_across_targets():
    cfg = _cfg()
    rw = FakeRailway(RUNNING)  # railway healthy for all
    hermes_map = {
        "svc-a": FakeHermes(),                       # healthy
        "svc-b": FakeHermes(gateway_running=False),  # gateway only -> recovers
        "svc-c": FakeHermes(gateway_running=False, restart_effective=False),  # stuck
    }
    targets = list(cfg.targets[:3])
    res = _orch(cfg, rw, hermes_map).run(targets)
    by_alias = {o.alias: o for o in res.outcomes}
    assert by_alias["svc-a"].recovered is True and hermes_map["svc-a"].restart_calls == 0
    assert by_alias["svc-b"].recovered is True and hermes_map["svc-b"].restart_calls == 1
    assert by_alias["svc-c"].recovered is False
    assert res.exit_code == 1               # one still failing
    assert all(h.closed for h in hermes_map.values())


# --- error handling / redaction ----------------------------------------------

def test_railway_error_is_captured_and_redacted():
    cfg = _cfg()
    leak = "https://secret-host.example.test/x"
    rw = FakeRailway(RUNNING, raises=RailwayError(f"boom {leak}"))
    hm = FakeHermes()
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is False
    assert o.error is not None
    assert leak not in o.error
    assert "secret-host.example.test" not in o.error


# --- finding 1: container-path race recheck before gateway restart ------------

def test_container_recheck_healthy_skips_gateway_restart():
    cfg = _cfg()
    # After the container comes back up it is already fully healthy (gateway running).
    rw = FakeRailway(CONTAINER_DOWN, recovered_status=RUNNING)
    hm = FakeHermes(gateway_running=True, railway=rw)  # gateway up once reachable
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.action == "container_restart"
    assert o.recovered is True
    assert rw.restart_calls == ["dep-1"]
    assert hm.restart_calls == 0  # fresh recheck was healthy → no gateway mutation


# --- finding 6: false mutation results are failures ---------------------------

def test_false_deployment_restart_result_is_failure_even_if_state_healthy():
    cfg = _cfg()
    # restart_result=False but restart_effective=True: state becomes healthy anyway.
    rw = FakeRailway(CONTAINER_DOWN, recovered_status=RUNNING,
                     restart_effective=True, restart_result=False)
    hm = FakeHermes(gateway_running=True, railway=rw)
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is False  # no false success
    assert rw.restart_calls == ["dep-1"]
    assert hm.restart_calls == 0  # never proceeded after failed mutation
    assert res.exit_code == 1


def test_false_gateway_restart_result_is_failure_even_if_gateway_running():
    cfg = _cfg()
    rw = FakeRailway(RUNNING)
    hm = FakeHermes(gateway_running=False, restart_effective=True, restart_result=False)
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is False
    assert hm.restart_calls == 1  # attempted once, reported failure


# --- finding 2: absolute budget ------------------------------------------------

def test_budget_expiry_before_gateway_restart_skips_mutation():
    cfg = _cfg()
    ticks = {"t": 0.0}

    def clock():
        ticks["t"] += 1.0
        return ticks["t"]

    rw = FakeRailway(RUNNING)
    hm = FakeHermes(gateway_running=False)  # would be a gateway-only failure
    # Tiny budget: expires during the fresh recheck, before any gateway restart.
    res = _orch(cfg, rw, {"svc-a": hm}, per_target_deadline=0.5, monotonic=clock).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is False
    assert hm.restart_calls == 0  # no mutation started after deadline


def test_budget_expiry_during_container_poll_blocks_gateway_mutation():
    cfg = _cfg()
    ticks = {"t": 0.0}

    def clock():
        ticks["t"] += 2.0
        return ticks["t"]

    # Restart succeeds but container never comes up within the budget.
    rw = FakeRailway(CONTAINER_DOWN, restart_effective=False)
    hm = FakeHermes(gateway_running=False, railway=rw)
    res = _orch(cfg, rw, {"svc-a": hm}, per_target_deadline=3.0, monotonic=clock,
                wait_attempts=10).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is False
    assert hm.restart_calls == 0  # polling budget exhausted → gateway never mutated


def test_calls_receive_live_deadline_from_budget():
    cfg = _cfg()
    rw = FakeRailway(RUNNING)
    hm = FakeHermes()
    _orch(cfg, rw, {"svc-a": hm}, per_target_deadline=60.0).run(_one(cfg))
    assert rw.remaining_seen  # a live deadline was passed
    assert all(t is not None and 0 < t <= 60.0 for t in rw.remaining_seen)


# --- finding 5: per-worker isolation of unexpected failures -------------------

def test_unexpected_exception_is_isolated_and_sanitized():
    cfg = _cfg()
    leak = "https://secret.example.test/boom"
    rw_bad = FakeRailway(RUNNING, raises=ValueError(leak))  # not a WatchdogError
    good_hm = FakeHermes()
    # Run two targets; the failing one must not abort the other.
    targets = list(cfg.targets[:2])

    def factory(t):
        return good_hm

    from watchdog.orchestrator import Orchestrator
    orch = Orchestrator(
        config=cfg, railway=rw_bad, hermes_factory=factory,
        redactor=Redactor(cfg.all_secret_values()), now=lambda: NOW,
        monotonic=lambda: 0.0, sleep=lambda _s: None, transition_threshold=timedelta(minutes=15),
    )
    res = orch.run(targets)
    assert len(res.outcomes) == 2
    for o in res.outcomes:
        assert o.recovered is False
        assert o.error is not None
        assert "secret.example.test" not in o.error


def test_hermes_factory_failure_is_isolated():
    cfg = _cfg()

    def factory(t):
        raise RuntimeError("factory boom secret.example.test")

    from watchdog.orchestrator import Orchestrator
    orch = Orchestrator(
        config=cfg, railway=FakeRailway(RUNNING), hermes_factory=factory,
        redactor=Redactor(cfg.all_secret_values()), now=lambda: NOW,
        monotonic=lambda: 0.0, sleep=lambda _s: None,
    )
    res = orch.run(list(cfg.targets[:2]))
    assert len(res.outcomes) == 2
    assert all(o.recovered is False and o.error is not None for o in res.outcomes)
    assert all("secret.example.test" not in (o.error or "") for o in res.outcomes)


def test_close_failure_does_not_override_result_or_abort():
    cfg = _cfg()
    rw = FakeRailway(RUNNING)
    hm = FakeHermes(close_raises=True)  # healthy but close() throws
    res = _orch(cfg, rw, {"svc-a": hm}).run(_one(cfg))
    o = res.outcomes[0]
    assert o.recovered is True  # close failure must not flip a good result
    assert o.classification is Classification.HEALTHY
