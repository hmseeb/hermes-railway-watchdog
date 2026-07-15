"""Phase 4 Cycle 1 (RED first): health classification state machine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from watchdog.hermes import HealthResult
from watchdog.railway import DeploymentStatus, ServiceStatus
from watchdog.state import Classification, HealthProbe, classify

NOW = datetime(2026, 7, 15, 12, 0, 0, tzinfo=UTC)


def _status(**kw) -> ServiceStatus:
    base = dict(
        service_id="svc-1",
        has_active_deployment=True,
        active_deployment_id="dep-1",
        restartable_deployment_id="dep-1",
        latest_status=DeploymentStatus.SUCCESS,
        latest_created_at=NOW,
        latest_updated_at=NOW,
        stopped=False,
        instance_running=True,
        raw_instance_state="RUNNING",
    )
    base.update(kw)
    return ServiceStatus(**base)  # type: ignore[arg-type]


def _no_active(status, *, updated=NOW) -> ServiceStatus:
    """A service with no active deployment but a latest deployment (fail closed)."""
    return _status(
        has_active_deployment=False,
        active_deployment_id=None,
        restartable_deployment_id="dep-latest",
        latest_status=status,
        latest_updated_at=updated,
        latest_created_at=updated,
        stopped=False,
        instance_running=False,
        raw_instance_state=None,
    )


def _probe(reachable=True, status_ok=True, gateway_running=True) -> HealthProbe:
    result = (
        HealthResult(status_ok=status_ok, gateway_running=gateway_running)
        if reachable
        else None
    )
    return HealthProbe(reachable=reachable, result=result)


def _classify(status, probe, now=NOW):
    return classify(status, probe, now=now, transition_threshold=timedelta(minutes=15))


def test_healthy():
    assert _classify(_status(), _probe()) is Classification.HEALTHY


def test_gateway_only_failure_when_running_but_gateway_down():
    assert (
        _classify(_status(), _probe(gateway_running=False))
        is Classification.GATEWAY_ONLY_FAILURE
    )


def test_reachable_but_status_not_ok_is_gateway_only():
    assert (
        _classify(_status(), _probe(status_ok=False)) is Classification.GATEWAY_ONLY_FAILURE
    )


@pytest.mark.parametrize(
    "st",
    [
        DeploymentStatus.INITIALIZING,
        DeploymentStatus.QUEUED,
        DeploymentStatus.BUILDING,
        DeploymentStatus.DEPLOYING,
        DeploymentStatus.WAITING,
        DeploymentStatus.NEEDS_APPROVAL,
    ],
)
def test_recent_transition_is_transitional(st):
    s = _status(latest_status=st, instance_running=False, latest_updated_at=NOW)
    assert _classify(s, _probe(reachable=False)) is Classification.TRANSITIONAL


def test_stale_transition_is_container_failure():
    old = NOW - timedelta(minutes=30)
    s = _status(latest_status=DeploymentStatus.BUILDING, latest_updated_at=old,
                latest_created_at=old, instance_running=False)
    assert _classify(s, _probe(reachable=False)) is Classification.CONTAINER_FAILURE


def test_transition_without_timestamp_is_container_failure():
    s = _status(latest_status=DeploymentStatus.DEPLOYING, latest_updated_at=None,
                latest_created_at=None, instance_running=False)
    assert _classify(s, _probe(reachable=False)) is Classification.CONTAINER_FAILURE


def test_no_active_deployment_is_container_failure():
    s = _status(has_active_deployment=False, active_deployment_id=None)
    assert _classify(s, _probe()) is Classification.CONTAINER_FAILURE


@pytest.mark.parametrize(
    "st",
    [
        DeploymentStatus.COMPLETED,
        DeploymentStatus.FAILED,
        DeploymentStatus.CRASHED,
        DeploymentStatus.REMOVED,
        DeploymentStatus.SLEEPING,
        DeploymentStatus.SKIPPED,
    ],
)
def test_terminal_inactive_statuses_are_container_failure(st):
    assert _classify(_status(latest_status=st), _probe()) is Classification.CONTAINER_FAILURE


def test_stopped_deployment_is_container_failure():
    assert _classify(_status(stopped=True), _probe()) is Classification.CONTAINER_FAILURE


def test_no_running_instance_is_container_failure():
    s = _status(instance_running=False, raw_instance_state="STOPPED")
    assert _classify(s, _probe()) is Classification.CONTAINER_FAILURE


def test_unreachable_health_while_running_is_container_failure():
    assert _classify(_status(), _probe(reachable=False)) is Classification.CONTAINER_FAILURE


# --- no-active latest-deployment behavior (new serviceInstance semantics) ------


@pytest.mark.parametrize(
    "st",
    [
        DeploymentStatus.COMPLETED,
        DeploymentStatus.FAILED,
        DeploymentStatus.CRASHED,
        DeploymentStatus.REMOVED,
        DeploymentStatus.SLEEPING,
        DeploymentStatus.SKIPPED,
    ],
)
def test_no_active_terminal_latest_is_container_failure(st):
    assert _classify(_no_active(st), _probe(reachable=False)) is Classification.CONTAINER_FAILURE


def test_no_active_recent_transition_is_transitional():
    s = _no_active(DeploymentStatus.DEPLOYING, updated=NOW)
    assert _classify(s, _probe(reachable=False)) is Classification.TRANSITIONAL


def test_no_active_stale_transition_is_container_failure():
    old = NOW - timedelta(minutes=30)
    s = _no_active(DeploymentStatus.DEPLOYING, updated=old)
    assert _classify(s, _probe(reachable=False)) is Classification.CONTAINER_FAILURE
