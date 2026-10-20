"""Health classification state machine.

A pure function that maps a Railway :class:`ServiceStatus` and a Hermes health probe
to one of four broad classifications. "Broad" is deliberate: the classification is the
only failure detail allowed to reach public output.
"""

from __future__ import annotations

from collections.abc import Collection
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
    # Self-hosted mode only.
    HOST_UNREACHABLE = "host_unreachable"
    PLATFORM_DEGRADED = "platform_degraded"
    WEBUI_DOWN = "webui_down"


WEBUI_OK_STATUSES = frozenset({200, 302})  # 302 = the web UI's login redirect
_MAX_ERROR_CHARS = 160


@dataclass(frozen=True)
class Verdict:
    """Self-hosted classification. ``detail`` is display text (may hold raw platform
    error messages: redact before output); ``condition`` is a stable dedupe signature
    that deliberately excludes error text and HTTP codes so flapping messages do not
    re-alert."""

    classification: Classification
    detail: str | None = None
    condition: str | None = None


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


def classify_selfhosted(health: HealthProbe, *, ignore_platforms: Collection[str] = ()) -> Verdict:
    """Dashboard-only classification (no Railway): host, gateway, then platforms."""
    if not health.reachable or health.result is None or not health.result.status_ok:
        return Verdict(Classification.HOST_UNREACHABLE, condition="host_unreachable")
    if not health.result.gateway_running:
        return Verdict(Classification.GATEWAY_ONLY_FAILURE, condition="gateway_only_failure")
    bad = [
        p for p in health.result.platforms
        if p.state != "connected" and p.name.lower() not in ignore_platforms
    ]
    if not bad:
        return Verdict(Classification.HEALTHY)
    parts = []
    for p in bad:
        part = f"{p.name}={p.state}"
        extra = ": ".join(x for x in (p.error_code, p.error_message) if x)
        if extra:
            part += f" ({extra[:_MAX_ERROR_CHARS]})"
        parts.append(part)
    names = ",".join(sorted(p.name for p in bad))
    return Verdict(
        Classification.PLATFORM_DEGRADED,
        detail="platforms: " + "; ".join(parts),
        condition=f"platform_degraded:{names}",
    )


def classify_webui(status_code: int | None) -> Verdict:
    """``None`` means the request errored (timeout / connection failure)."""
    if status_code in WEBUI_OK_STATUSES:
        return Verdict(Classification.HEALTHY)
    shown = "unreachable" if status_code is None else f"HTTP {status_code}"
    return Verdict(Classification.WEBUI_DOWN, detail=f"webui: {shown}", condition="webui_down")
