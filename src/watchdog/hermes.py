"""Hermes gateway client.

Per-target client that checks the public ``/health`` endpoint and, when authorised,
restarts the gateway by logging in, replaying the in-memory session cookie to the
restart endpoint, and polling ``/health`` until the gateway reports running.

Secret hygiene: this module never logs. Cookies, credentials, URLs, response bodies,
ids, and names are never placed into exception messages — errors carry only generic
descriptions and, at most, an HTTP status code.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from .errors import (
    HermesAuthError,
    HermesHTTPError,
    HermesProtocolError,
    HermesTimeoutError,
)
from .http import Deadline, Timeouts

_LOGIN_PATH = "/login"
_RESTART_PATH = "/setup/api/gateway/restart"
_AUTH_COOKIE = "hermes_auth"


@dataclass(frozen=True)
class HealthResult:
    status_ok: bool
    gateway_running: bool

    @property
    def healthy(self) -> bool:
        return self.status_ok and self.gateway_running


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    return (parts.scheme, parts.hostname or "", parts.port)


class HermesClient:
    def __init__(
        self,
        health_url: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeouts: Timeouts | None = None,
        sleep: Callable[[float], None] | None = None,
        poll_attempts: int = 10,
        poll_interval: float = 3.0,
    ) -> None:
        parts = urlsplit(health_url)
        self._health_url = health_url
        self._base = f"{parts.scheme}://{parts.netloc}"
        self._origin = _origin(health_url)
        self._poll_attempts = poll_attempts
        self._poll_interval = poll_interval
        self._sleep = sleep or time.sleep  # retained for interface compatibility
        self._timeouts = timeouts or Timeouts()
        self._transport = transport

    def __enter__(self) -> HermesClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        # Async clients are created and closed per operation; nothing persists here.
        return

    def _new_client(self) -> httpx.AsyncClient:
        # follow_redirects=False so cross-origin redirects can be rejected explicitly.
        return httpx.AsyncClient(
            transport=self._transport,
            timeout=self._timeouts.as_httpx(),  # configured phase limits (inner)
            follow_redirects=False,
        )

    # -- helpers --------------------------------------------------------------

    async def _async_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        deadline: Deadline | None = None,
        **kw: Any,
    ) -> httpx.Response:
        wall: float | None = None
        if deadline is not None:
            # Recompute now: refuse if the budget is spent, else use the remaining time
            # as an absolute wall enforced by cancellable async I/O.
            remaining = deadline.remaining()
            if remaining <= 0:
                raise HermesTimeoutError("hermes budget exhausted")
            wall = remaining
        request = client.request(method, url, **kw)
        try:
            if wall is None:
                response = await request
            else:
                response = await asyncio.wait_for(request, timeout=max(0.0, wall))
        except (httpx.TimeoutException, TimeoutError):
            raise HermesTimeoutError("hermes request timed out") from None
        except httpx.HTTPError:
            raise HermesHTTPError("hermes request failed") from None
        self._reject_unsafe_redirect(response)
        return response

    def _reject_unsafe_redirect(self, response: httpx.Response) -> None:
        if not response.is_redirect:
            return
        location = response.headers.get("location", "")
        target = urljoin(self._base + "/", location)
        if _origin(target) != self._origin:
            raise HermesProtocolError("hermes returned a redirect to an untrusted origin")

    def _parse_health(self, response: httpx.Response) -> HealthResult:
        if response.status_code != 200:
            raise HermesHTTPError(f"hermes health returned HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError:
            raise HermesProtocolError("hermes health returned invalid JSON") from None
        if not isinstance(body, dict):
            raise HermesProtocolError("hermes health returned a non-object body")
        return HealthResult(
            status_ok=body.get("status") == "ok",
            gateway_running=body.get("gateway") == "running",
        )

    # -- health ---------------------------------------------------------------

    def check_health(self, *, deadline: Deadline | None = None) -> HealthResult:
        return asyncio.run(self._async_check_health(deadline))

    async def _async_check_health(self, deadline: Deadline | None) -> HealthResult:
        # Standalone health uses a bounded short-lived async client.
        async with self._new_client() as client:
            response = await self._async_request(client, "GET", self._health_url, deadline=deadline)
        return self._parse_health(response)

    # -- restart --------------------------------------------------------------

    def restart_gateway(
        self, username: str, password: str, *, deadline: Deadline | None = None
    ) -> bool:
        return asyncio.run(self._async_restart_gateway(username, password, deadline))

    async def _async_restart_gateway(
        self, username: str, password: str, deadline: Deadline | None
    ) -> bool:
        # One async client spans login, restart, and polling so the hermes_auth cookie
        # set at login is replayed to the restart and health calls.
        async with self._new_client() as client:
            await self._async_login(client, username, password, deadline)
            await self._async_post_restart(client, deadline)
            return await self._async_poll(client, deadline)

    async def _async_login(
        self, client: httpx.AsyncClient, username: str, password: str, deadline: Deadline | None
    ) -> None:
        response = await self._async_request(
            client, "POST", self._base + _LOGIN_PATH, deadline=deadline,
            data={"username": username, "password": password, "returnTo": "/"},
        )
        if response.status_code != 302:
            raise HermesAuthError(f"hermes login unexpected status (HTTP {response.status_code})")
        if "error=1" in response.headers.get("location", ""):
            raise HermesAuthError("hermes login was rejected")
        if client.cookies.get(_AUTH_COOKIE) is None:
            raise HermesAuthError("hermes login did not establish an auth session")

    async def _async_post_restart(
        self, client: httpx.AsyncClient, deadline: Deadline | None
    ) -> None:
        response = await self._async_request(
            client, "POST", self._base + _RESTART_PATH, deadline=deadline
        )
        if response.status_code >= 400:
            raise HermesHTTPError(f"hermes restart returned HTTP {response.status_code}")
        # The restart is only confirmed by an exact {"ok": true} body.
        try:
            body = response.json()
        except ValueError:
            raise HermesHTTPError("hermes restart returned a non-JSON body") from None
        if not (isinstance(body, dict) and body.get("ok") is True):
            raise HermesHTTPError("hermes restart did not confirm success")

    async def _async_poll(self, client: httpx.AsyncClient, deadline: Deadline | None) -> bool:
        for attempt in range(self._poll_attempts):
            if deadline is not None and deadline.remaining() <= 0:
                break  # refuse to start a poll once the budget is spent
            try:
                response = await self._async_request(
                    client, "GET", self._health_url, deadline=deadline
                )
                if self._parse_health(response).gateway_running:
                    return True
            except (HermesHTTPError, HermesTimeoutError, HermesProtocolError):
                pass  # transient during restart; keep polling within the bound
            if attempt < self._poll_attempts - 1:
                await asyncio.sleep(self._clip_sleep(self._poll_interval, deadline))
        raise HermesTimeoutError("hermes gateway did not report running in time")

    @staticmethod
    def _clip_sleep(interval: float, deadline: Deadline | None) -> float:
        if deadline is None:
            return interval
        return max(0.0, min(interval, deadline.remaining()))
