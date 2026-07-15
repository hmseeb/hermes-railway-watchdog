"""Railway read path against the live serviceInstance schema + errors/retries."""

from __future__ import annotations

import json

import httpx
import pytest

from watchdog.errors import (
    RailwayAuthError,
    RailwayGraphQLError,
    RailwayHTTPError,
    RailwayTimeoutError,
)
from watchdog.http import RetryPolicy
from watchdog.railway import DEFAULT_ENDPOINT, DeploymentStatus, RailwayClient

TOKEN = "rlwy-secret-token-DO-NOT-LEAK-1234567890"
PROJECT = "proj-1111"
ENV = "env-2222"
SERVICE = "svc-3333"


def test_default_endpoint_is_railway_com():
    assert DEFAULT_ENDPOINT == "https://backboard.railway.com/graphql/v2"


def _client(handler, **kw) -> RailwayClient:
    calls = {"n": 0}

    def counting(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return handler(request, calls["n"])

    client = RailwayClient(
        token=TOKEN,
        transport=httpx.MockTransport(counting),
        retry=kw.pop("retry", RetryPolicy(max_retries=2, backoff_base=0.0)),
        sleep=lambda _s: None,
        **kw,
    )
    client._calls = calls  # type: ignore[attr-defined]
    return client


def _si(active_deployments, latest_deployment, *, project=PROJECT, service=SERVICE, env=ENV,
        svc_project=None, env_project=None):
    # Ownership is proven relationally: Service.projectId and Environment.projectId
    # must both equal the requested project.
    body = {
        "data": {
            "service": {"id": service, "projectId": svc_project or project},
            "environment": {"id": env, "projectId": env_project or project},
            "serviceInstance": {
                "serviceId": service,
                "environmentId": env,
                "activeDeployments": active_deployments,
                "latestDeployment": latest_deployment,
            },
        }
    }
    return httpx.Response(200, json=body)


ACTIVE_DEP = {
    "id": "dep-current",
    "status": "SUCCESS",
    "createdAt": "2026-07-15T10:00:00Z",
    "updatedAt": "2026-07-15T10:05:00Z",
    "deploymentStopped": False,
    "instances": [{"status": "RUNNING"}],
}


def test_active_running_deployment_parsed():
    with _client(lambda req, n: _si([ACTIVE_DEP], ACTIVE_DEP)) as c:
        s = c.get_service_status(PROJECT, ENV, SERVICE)
    assert s.has_active_deployment is True
    assert s.active_deployment_id == "dep-current"
    assert s.restartable_deployment_id == "dep-current"
    assert s.latest_status is DeploymentStatus.SUCCESS
    assert s.stopped is False
    assert s.instance_running is True
    assert s.latest_created_at is not None
    assert s.latest_updated_at is not None


def test_no_active_completed_keeps_restartable_latest_id():
    latest = {
        "id": "dep-latest",
        "status": "COMPLETED",
        "createdAt": "2026-07-15T09:00:00Z",
        "updatedAt": "2026-07-15T09:10:00Z",
    }
    with _client(lambda req, n: _si([], latest)) as c:
        s = c.get_service_status(PROJECT, ENV, SERVICE)
    assert s.has_active_deployment is False
    assert s.active_deployment_id is None
    # Preserved so a COMPLETED/no-active service can still be restarted.
    assert s.restartable_deployment_id == "dep-latest"
    assert s.latest_status is DeploymentStatus.COMPLETED
    # Fail closed: no active deployment → not running, not inferred from SUCCESS.
    assert s.instance_running is False
    assert s.stopped is False


def test_stopped_and_non_running_instance_flags_from_active():
    dep = {**ACTIVE_DEP, "deploymentStopped": True, "instances": [{"status": "STOPPED"}]}
    with _client(lambda req, n: _si([dep], dep)) as c:
        s = c.get_service_status(PROJECT, ENV, SERVICE)
    assert s.stopped is True
    assert s.instance_running is False
    assert s.raw_instance_state == "STOPPED"


def test_active_success_without_instances_is_not_running():
    # Never infer RUNNING from SUCCESS when instances are absent.
    dep = {"id": "dep-x", "status": "SUCCESS", "deploymentStopped": False}
    with _client(lambda req, n: _si([dep], dep)) as c:
        s = c.get_service_status(PROJECT, ENV, SERVICE)
    assert s.latest_status is DeploymentStatus.SUCCESS
    assert s.instance_running is False


def test_crashed_active_status_parsed():
    dep = {**ACTIVE_DEP, "status": "CRASHED", "instances": [{"status": "STOPPED"}]}
    with _client(lambda req, n: _si([dep], dep)) as c:
        s = c.get_service_status(PROJECT, ENV, SERVICE)
    assert s.latest_status is DeploymentStatus.CRASHED
    assert s.instance_running is False


def test_empty_service_instance_is_no_active():
    with _client(lambda req, n: _si([], None)) as c:
        s = c.get_service_status(PROJECT, ENV, SERVICE)
    assert s.has_active_deployment is False
    assert s.active_deployment_id is None
    assert s.restartable_deployment_id is None
    assert s.instance_running is False


def test_graphql_errors_raise_and_do_not_leak_body():
    secret = "internal-service-name-leak"
    body = {"errors": [{"message": f"boom {secret}"}]}
    with _client(lambda req, n: httpx.Response(200, json=body)) as c:
        with pytest.raises(RailwayGraphQLError) as ei:
            c.get_service_status(PROJECT, ENV, SERVICE)
    assert secret not in str(ei.value)


def test_http_401_is_auth_error_not_retried():
    with _client(lambda req, n: httpx.Response(401, json={})) as c:
        with pytest.raises(RailwayAuthError):
            c.get_service_status(PROJECT, ENV, SERVICE)
        assert c._calls["n"] == 1  # type: ignore[attr-defined]


def test_http_500_retried_then_http_error():
    with _client(lambda req, n: httpx.Response(500, text="err")) as c:
        with pytest.raises(RailwayHTTPError):
            c.get_service_status(PROJECT, ENV, SERVICE)
        assert c._calls["n"] == 3  # type: ignore[attr-defined]


def test_transient_500_then_success_recovers():
    def handler(req, n):
        return httpx.Response(500) if n == 1 else _si([ACTIVE_DEP], ACTIVE_DEP)

    with _client(handler) as c:
        s = c.get_service_status(PROJECT, ENV, SERVICE)
    assert s.latest_status is DeploymentStatus.SUCCESS
    assert c._calls["n"] == 2  # type: ignore[attr-defined]


def test_timeout_retried_then_timeout_error():
    def handler(req, n):
        raise httpx.ReadTimeout("read timed out", request=req)

    with _client(handler) as c:
        with pytest.raises(RailwayTimeoutError):
            c.get_service_status(PROJECT, ENV, SERVICE)
        assert c._calls["n"] == 3  # type: ignore[attr-defined]


def test_token_never_appears_in_exceptions():
    def handler(req, n):
        assert TOKEN in req.headers.get("authorization", "")
        raise httpx.ConnectTimeout("nope", request=req)

    with _client(handler) as c:
        with pytest.raises(RailwayTimeoutError) as ei:
            c.get_service_status(PROJECT, ENV, SERVICE)
    assert TOKEN not in str(ei.value)
    assert TOKEN not in repr(ei.value)


def test_request_uses_project_scoped_query_with_all_vars():
    seen = {}

    def handler(req, n):
        seen["method"] = req.method
        seen["payload"] = json.loads(req.content)
        return _si([ACTIVE_DEP], ACTIVE_DEP)

    with _client(handler) as c:
        c.get_service_status(PROJECT, ENV, SERVICE)
    assert seen["method"] == "POST"
    query = seen["payload"]["query"]
    assert "serviceInstance" in query
    assert "service(id: $serviceId)" in query
    assert "environment(id: $environmentId, projectId: $projectId)" in query
    variables = seen["payload"]["variables"]
    assert variables["serviceId"] == SERVICE
    assert variables["environmentId"] == ENV
    assert variables["projectId"] == PROJECT


# --- relational project-ownership enforcement (finding B) ---------------------


def test_project_id_mismatch_raises_generic_and_does_not_leak():
    with _client(lambda req, n: _si([ACTIVE_DEP], ACTIVE_DEP, project="wrong-proj-secret")) as c:
        with pytest.raises(RailwayGraphQLError) as ei:
            c.get_service_status(PROJECT, ENV, SERVICE)
    assert "wrong-proj-secret" not in str(ei.value)


def test_service_id_mismatch_raises():
    with _client(lambda req, n: _si([ACTIVE_DEP], ACTIVE_DEP, service="wrong-svc")) as c:
        with pytest.raises(RailwayGraphQLError):
            c.get_service_status(PROJECT, ENV, SERVICE)


def test_environment_id_mismatch_raises():
    with _client(lambda req, n: _si([ACTIVE_DEP], ACTIVE_DEP, env="wrong-env")) as c:
        with pytest.raises(RailwayGraphQLError):
            c.get_service_status(PROJECT, ENV, SERVICE)


def test_service_project_ownership_mismatch_raises_without_leak():
    # All requested ids echo back correctly, but the service belongs to another project.
    resp = _si([ACTIVE_DEP], ACTIVE_DEP, svc_project="owned-by-other-secret")
    with _client(lambda req, n: resp) as c:
        with pytest.raises(RailwayGraphQLError) as ei:
            c.get_service_status(PROJECT, ENV, SERVICE)
    assert "owned-by-other-secret" not in str(ei.value)


def test_environment_project_ownership_mismatch_raises_without_leak():
    resp = _si([ACTIVE_DEP], ACTIVE_DEP, env_project="other-project-secret")
    with _client(lambda req, n: resp) as c:
        with pytest.raises(RailwayGraphQLError) as ei:
            c.get_service_status(PROJECT, ENV, SERVICE)
    assert "other-project-secret" not in str(ei.value)


# --- malformed shapes must raise typed error, not AttributeError (finding 5) --


def _wrap_si(si) -> dict:
    return {
        "data": {
            "service": {"id": SERVICE, "projectId": PROJECT},
            "environment": {"id": ENV, "projectId": PROJECT},
            "serviceInstance": si,
        }
    }


def _valid_si(**overrides) -> dict:
    si = {"serviceId": SERVICE, "environmentId": ENV,
          "activeDeployments": [], "latestDeployment": None}
    si.update(overrides)
    return si


@pytest.mark.parametrize(
    "body",
    [
        _wrap_si([]),                                                # serviceInstance not a dict
        _wrap_si(_valid_si(activeDeployments={"bad": 1})),          # active not a list
        _wrap_si(_valid_si(activeDeployments=["not-a-dict"])),      # active item not a dict
        _wrap_si(_valid_si(activeDeployments=[{"id": "d", "status": "SUCCESS",
                                               "instances": "oops"}])),  # instances not a list
        {"data": {"service": "nope"}},                              # service not a dict
        {"data": {"service": {"id": SERVICE, "projectId": PROJECT},
                  "environment": "nope"}},                          # environment not a dict
    ],
)
def test_malformed_shapes_raise_graphql_error(body):
    with _client(lambda req, n: httpx.Response(200, json=body)) as c:
        with pytest.raises(RailwayGraphQLError):
            c.get_service_status(PROJECT, ENV, SERVICE)


# --- non-timeout transport failures (finding 10) ------------------------------


def test_connect_error_retried_then_typed_error_for_reads():
    def handler(req, n):
        raise httpx.ConnectError("connection refused")

    with _client(handler) as c:
        with pytest.raises((RailwayHTTPError, RailwayTimeoutError)):
            c.get_service_status(PROJECT, ENV, SERVICE)
        assert c._calls["n"] == 3  # type: ignore[attr-defined]  # reads are retried


def test_transient_connect_error_then_success_recovers():
    def handler(req, n):
        if n == 1:
            raise httpx.ConnectError("refused")
        return _si([ACTIVE_DEP], ACTIVE_DEP)

    with _client(handler) as c:
        s = c.get_service_status(PROJECT, ENV, SERVICE)
    assert s.latest_status is DeploymentStatus.SUCCESS
    assert c._calls["n"] == 2  # type: ignore[attr-defined]
