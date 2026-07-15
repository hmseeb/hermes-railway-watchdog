"""Health classification state machine.

A pure function that maps a Railway :class:`ServiceStatus` and a Hermes health probe
to one of four broad classifications. "Broad" is deliberate: the classification is the
only failure detail allowed to reach public output.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from .hermes import HealthResult
from .railway import DeploymentStatus, ServiceStatus

DEFAULT_TRANSITION_THRESHOLD = timedelta(minutes=15)

_TRANSITIONAL_STATUSES = frozenset(
    {
        DeploymentStatus.INITIALIZING,
        DeploymentStatus.QUEUED,
        DeploymentStatus.BUILDING,
        DeploymentStatus.DEPLOYING,
        DeploymentStatus.WAITING,
        DeploymentStatus.NEEDS_APPROVAL,
    }
)
_TERMINAL_INACTIVE_STATUSES = frozenset(
    {
        DeploymentStatus.COMPLETED,
        DeploymentStatus.FAILED,
        DeploymentStatus.CRASHED,
        DeploymentStatus.REMOVED,
        DeploymentStatus.SLEEPING,
        DeploymentStatus.SKIPPED,
    }
)


class Classification(str, Enum):
    HEALTHY = "healthy"
    GATEWAY_ONLY_FAILURE = "gateway_only_failure"
    TRANSITIONAL = "transitional"
    CONTAINER_FAILURE = "container_failure"


@dataclass(frozen=True)
class HealthProbe:
    """Outcome of probing ``/health`` (after any bounded retries)."""

    reachable: bool
    result: HealthResult | None


def classify(
    status: ServiceStatus,
    health: HealthProbe,
    *,
    now: datetime,
    transition_threshold: timedelta = DEFAULT_TRANSITION_THRESHOLD,
) -> Classification:
    st = status.latest_status

    # 1. A deployment mid-transition: defer if recent, else it is a stuck deploy.
    if st in _TRANSITIONAL_STATUSES:
        timestamp = status.latest_updated_at or status.latest_created_at
        if timestamp is not None and (now - timestamp) <= transition_threshold:
            return Classification.TRANSITIONAL
        return Classification.CONTAINER_FAILURE

    # 2. Definitive container-level failures.
    if not status.has_active_deployment:
        return Classification.CONTAINER_FAILURE
    if st in _TERMINAL_INACTIVE_STATUSES:
        return Classification.CONTAINER_FAILURE
    if status.stopped:
        return Classification.CONTAINER_FAILURE
    if not status.instance_running:
        return Classification.CONTAINER_FAILURE

    # 3. Railway reports the container running — the gateway health decides.
    if not health.reachable or health.result is None:
        return Classification.CONTAINER_FAILURE
    if health.result.healthy:
        return Classification.HEALTHY
    return Classification.GATEWAY_ONLY_FAILURE
