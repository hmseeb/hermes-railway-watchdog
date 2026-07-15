"""Railway GraphQL client.

Talks to Railway's official GraphQL API over HTTPS using ``RAILWAY_API_TOKEN`` in an
``Authorization: Bearer`` header. It reads service/deployment status and restarts the
*current* deployment via ``deploymentRestart`` — no rebuild, no shell, no SSH.

Safety properties:
- Every request is time-bounded (:class:`~watchdog.http.Timeouts`).
- Only idempotent **reads** are retried; the restart mutation is attempted once.
- No secret ever reaches an exception message or is logged here. The token lives in a
  header; GraphQL error bodies are summarised generically, never embedded.

The GraphQL field selection targets the documented Railway schema. Because this cannot
be exercised against the live API in CI, parsing is intentionally defensive: unknown
statuses degrade to ``UNKNOWN`` and missing fields degrade to safe defaults.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import TracebackType
from typing import Any

import httpx

from .errors import (
    RailwayAuthError,
    RailwayGraphQLError,
    RailwayHTTPError,
    RailwayTimeoutError,
)
from .http import Deadline, RetryPolicy, Timeouts

DEFAULT_ENDPOINT = "https://backboard.railway.com/graphql/v2"
_RUNNING_INSTANCE_STATES = frozenset({"RUNNING", "HEALTHY"})


class DeploymentStatus(str, Enum):
    INITIALIZING = "INITIALIZING"
    QUEUED = "QUEUED"
    BUILDING = "BUILDING"
    DEPLOYING = "DEPLOYING"
    WAITING = "WAITING"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"
    SUCCESS = "SUCCESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CRASHED = "CRASHED"
    REMOVED = "REMOVED"
    REMOVING = "REMOVING"
    SLEEPING = "SLEEPING"
    SKIPPED = "SKIPPED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, raw: Any) -> DeploymentStatus:
        if not isinstance(raw, str):
            return cls.UNKNOWN
        try:
            return cls(raw.strip().upper())
        except ValueError:
            return cls.UNKNOWN


@dataclass(frozen=True)
class ServiceStatus:
    """A public-safe snapshot of one service's current deployment.

    ``active_deployment_id`` is the currently-serving deployment (if any).
    ``restartable_deployment_id`` is the id to call ``deploymentRestart`` on — the
    latest deployment's id, preserved even when there is no active deployment so a
    COMPLETED/stopped service can still be restarted onto its latest image.
    """

    service_id: str
    has_active_deployment: bool
    active_deployment_id: str | None
    restartable_deployment_id: str | None
    latest_status: DeploymentStatus
    latest_created_at: datetime | None
    latest_updated_at: datetime | None
    stopped: bool
    instance_running: bool
    raw_instance_state: str | None


_STATUS_QUERY = """
query ServiceStatus($projectId: String!, $environmentId: String!, $serviceId: String!) {
  service(id: $serviceId) { id projectId }
  environment(id: $environmentId, projectId: $projectId) { id projectId }
  serviceInstance(environmentId: $environmentId, serviceId: $serviceId) {
    serviceId
    environmentId
    activeDeployments {
      id
      status
      createdAt
      updatedAt
      deploymentStopped
      instances { status }
    }
    latestDeployment {
      id
      status
      createdAt
      updatedAt
      deploymentStopped
      instances { status }
    }
  }
}
""".strip()


def _expect_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RailwayGraphQLError("railway response has an unexpected shape")
    return value


def _expect_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RailwayGraphQLError("railway response has an unexpected shape")
    return value

_RESTART_MUTATION = """
mutation RestartDeployment($id: String!) {
  deploymentRestart(id: $id)
}
""".strip()


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class RailwayClient:
    def __init__(
        self,
        token: str,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        transport: httpx.AsyncBaseTransport | None = None,
        timeouts: Timeouts | None = None,
        retry: RetryPolicy | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._token = token
        self._transport = transport
        self._retry = retry or RetryPolicy()
        self._timeouts = timeouts or Timeouts()
        self._sleep = sleep or time.sleep

    def __enter__(self) -> RailwayClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        # No persistent client: a fresh AsyncClient is created and closed per attempt,
        # so there is nothing to release here. Kept for interface compatibility.
        return

    # -- transport ------------------------------------------------------------

    def _clip_backoff(self, attempt: int, deadline: Deadline | None) -> float:
        delay = self._retry.backoff_for(attempt)
        if deadline is not None:
            delay = max(0.0, min(delay, deadline.remaining()))
        return delay

    async def _async_post(self, payload: dict[str, Any], wall: float | None) -> httpx.Response:
        # Configured phase timeouts are the inner limits; the absolute remaining budget
        # is the outer wall enforced by cancellable async I/O.
        async with httpx.AsyncClient(
            transport=self._transport,
            timeout=self._timeouts.as_httpx(),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
        ) as client:
            request = client.post(self._endpoint, json=payload)
            if wall is None:
                return await request
            return await asyncio.wait_for(request, timeout=max(0.0, wall))

    def _execute(self, payload: dict[str, Any], deadline: Deadline | None) -> httpx.Response:
        wall = deadline.remaining() if deadline is not None else None
        return asyncio.run(self._async_post(payload, wall))

    def _post(
        self, payload: dict[str, Any], *, retryable: bool, deadline: Deadline | None = None
    ) -> dict[str, Any]:
        attempts = self._retry.max_retries + 1 if retryable else 1
        for attempt in range(attempts):
            is_last = attempt == attempts - 1
            if deadline is not None and deadline.remaining() <= 0:
                raise RailwayTimeoutError("railway budget exhausted")
            try:
                # TimeoutError is asyncio's total wall timeout; httpx.TimeoutException
                # is a per-phase timeout. Both map to the typed timeout error.
                response = self._execute(payload, deadline)
            except (httpx.TimeoutException, TimeoutError):
                if is_last:
                    raise RailwayTimeoutError("railway request timed out") from None
                self._sleep(self._clip_backoff(attempt, deadline))
                continue
            except httpx.TransportError:
                # Non-timeout transport failure (e.g. connection refused). Retried for
                # safe reads only; mutations (attempts == 1) fail immediately.
                if is_last:
                    raise RailwayHTTPError("railway transport error") from None
                self._sleep(self._clip_backoff(attempt, deadline))
                continue

            status = response.status_code
            if status in (401, 403):
                raise RailwayAuthError(f"railway auth rejected (HTTP {status})")
            if status >= 400:
                if retryable and status in self._retry.retry_statuses and not is_last:
                    self._sleep(self._clip_backoff(attempt, deadline))
                    continue
                raise RailwayHTTPError(f"railway returned HTTP {status}")

            data = self._decode(response)
            return data
        # Unreachable: the loop always returns or raises.
        raise RailwayHTTPError("railway request failed")  # pragma: no cover

    def _decode(self, response: httpx.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError:
            raise RailwayGraphQLError("railway returned a non-JSON body") from None
        if not isinstance(body, dict):
            raise RailwayGraphQLError("railway returned an unexpected body")
        if body.get("errors"):
            # Never embed the raw error text — it may carry ids/names.
            raise RailwayGraphQLError("railway GraphQL query returned errors")
        data = body.get("data")
        if not isinstance(data, dict):
            raise RailwayGraphQLError("railway response missing data")
        return data

    # -- reads ----------------------------------------------------------------

    def get_service_status(
        self,
        project_id: str,
        environment_id: str,
        service_id: str,
        *,
        deadline: Deadline | None = None,
    ) -> ServiceStatus:
        payload = {
            "query": _STATUS_QUERY,
            "variables": {
                "projectId": project_id,
                "environmentId": environment_id,
                "serviceId": service_id,
            },
        }
        data = self._post(payload, retryable=True, deadline=deadline)
        return self._parse_status(data, project_id, environment_id, service_id)

    @staticmethod
    def _parse_status(
        data: dict[str, Any], project_id: str, environment_id: str, service_id: str
    ) -> ServiceStatus:
        # Relational ownership enforcement: the service and environment must both
        # belong to the requested project, and every returned id must match what was
        # requested — otherwise a generic error (no ids leaked).
        service = _expect_dict(data.get("service"))
        environment = _expect_dict(data.get("environment"))
        instance = _expect_dict(data.get("serviceInstance"))
        if (
            service.get("id") != service_id
            or service.get("projectId") != project_id
            or environment.get("id") != environment_id
            or environment.get("projectId") != project_id
            or instance.get("serviceId") != service_id
            or instance.get("environmentId") != environment_id
        ):
            raise RailwayGraphQLError("railway response identity mismatch")

        active_deployments = _expect_list(instance.get("activeDeployments"))
        raw_latest = instance.get("latestDeployment")
        latest = _expect_dict(raw_latest) if raw_latest is not None else None
        active_dep = _expect_dict(active_deployments[0]) if active_deployments else None

        has_active = bool(active_deployments)
        latest_status = (
            DeploymentStatus.parse(latest.get("status")) if latest else DeploymentStatus.UNKNOWN
        )
        latest_created = _parse_dt(latest.get("createdAt")) if latest else None
        latest_updated = _parse_dt(latest.get("updatedAt")) if latest else None

        # Preserve the latest deployment id so a no-active service can still restart.
        restartable_id = (latest.get("id") if latest else None) or (
            active_dep.get("id") if active_dep else None
        )
        active_deployment_id = active_dep.get("id") if active_dep else None

        # stopped / instance_running come from the ACTIVE deployment when present;
        # otherwise fail closed (never infer RUNNING from a SUCCESS status).
        stopped = False
        instance_running = False
        raw_state: str | None = None
        if active_dep is not None:
            stopped = bool(active_dep.get("deploymentStopped", False))
            instances = _expect_list(active_dep.get("instances"))
            if instances:
                first = _expect_dict(instances[0])
                raw_state = first.get("status")
                instance_running = any(
                    isinstance(inst, dict)
                    and str(inst.get("status", "")).upper() in _RUNNING_INSTANCE_STATES
                    for inst in instances
                )
        return ServiceStatus(
            service_id=service_id,
            has_active_deployment=has_active,
            active_deployment_id=active_deployment_id,
            restartable_deployment_id=restartable_id,
            latest_status=latest_status,
            latest_created_at=latest_created,
            latest_updated_at=latest_updated,
            stopped=stopped,
            instance_running=instance_running,
            raw_instance_state=raw_state,
        )

    # -- mutation (never retried) ---------------------------------------------

    def restart_current_deployment(
        self, deployment_id: str, *, deadline: Deadline | None = None
    ) -> bool:
        payload = {"query": _RESTART_MUTATION, "variables": {"id": deployment_id}}
        data = self._post(payload, retryable=False, deadline=deadline)
        # Only an explicit ``true`` counts as a successful mutation.
        return data.get("deploymentRestart") is True
