"""Hermes gateway client.

Per-target client for the native Hermes dashboard. Health is the authenticated
``/api/status`` endpoint (the configured ``health_url``); the client logs in lazily
via ``/auth/password-login`` once per instance, keeps the ``hermes_session*`` cookies
in memory, re-logs in once on a 401, and restarts the gateway via
``/api/gateway/restart`` then polls ``/api/status`` until the gateway reports running.

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

_LOGIN_PATH = "/auth/password-login"
_RESTART_PATH = "/api/gateway/restart"
_SESSION_COOKIE_PREFIX = "hermes_session"


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
        username: str = "",
        password: str = "",
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
        self._username = username
        self._password = password
        self._cookies = httpx.Cookies()  # session cookies, reused across operations

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
        # Async clients are created and closed per operation; only cookies persist.
        self._cookies.clear()

    def _new_client(self) -> httpx.AsyncClient:
        # follow_redirects=False so cross-origin redirects can be rejected explicitly.
        return httpx.AsyncClient(
            transport=self._transport,
            cookies=self._cookies,
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
        if response.status_code == 401:
            raise HermesAuthError("hermes health requires authentication")
        if response.status_code != 200:
            raise HermesHTTPError(f"hermes health returned HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError:
            raise HermesProtocolError("hermes health returned invalid JSON") from None
        if not isinstance(body, dict):
            raise HermesProtocolError("hermes health returned a non-object body")
        return HealthResult(status_ok=True, gateway_running=body.get("gateway_running") is True)

    # -- health ---------------------------------------------------------------

    def check_health(self, *, deadline: Deadline | None = None) -> HealthResult:
        return asyncio.run(self._async_check_health(deadline))

    async def _async_check_health(self, deadline: Deadline | None) -> HealthResult:
        # Standalone health uses a bounded short-lived async client.
        async with self._new_client() as client:
            try:
                return await self._async_status(
                    client, self._username, self._password, deadline
                )
            finally:
                self._cookies = client.cookies

    # -- restart --------------------------------------------------------------

    def restart_gateway(
        self, username: str, password: str, *, deadline: Deadline | None = None
    ) -> bool:
        return asyncio.run(self._async_restart_gateway(username, password, deadline))

    async def _async_restart_gateway(
        self, username: str, password: str, deadline: Deadline | None
    ) -> bool:
        # One async client spans login, restart, and polling so the session cookies
        # set at login are replayed to the restart and status calls.
        async with self._new_client() as client:
            try:
                await self._async_ensure_login(client, username, password, deadline)
                await self._async_post_restart(client, username, password, deadline)
                return await self._async_poll(client, username, password, deadline)
            finally:
                self._cookies = client.cookies

    @staticmethod
    def _has_session(client: httpx.AsyncClient) -> bool:
        return any(c.name.startswith(_SESSION_COOKIE_PREFIX) for c in client.cookies.jar)

    async def _async_ensure_login(
        self, client: httpx.AsyncClient, username: str, password: str, deadline: Deadline | None
    ) -> None:
        if not self._has_session(client):
            await self._async_login(client, username, password, deadline)

    async def _async_login(
        self, client: httpx.AsyncClient, username: str, password: str, deadline: Deadline | None
    ) -> None:
        client.cookies.clear()
        response = await self._async_request(
            client, "POST", self._base + _LOGIN_PATH, deadline=deadline,
            json={"provider": "basic", "username": username, "password": password},
        )
        if response.status_code != 200:
            raise HermesAuthError(f"hermes login unexpected status (HTTP {response.status_code})")
        try:
            body = response.json()
        except ValueError:
            raise HermesAuthError("hermes login returned a non-JSON body") from None
        if not (isinstance(body, dict) and body.get("ok") is True):
            raise HermesAuthError("hermes login was rejected")
        if not self._has_session(client):
            raise HermesAuthError("hermes login did not establish an auth session")

    async def _async_status(
        self, client: httpx.AsyncClient, username: str, password: str, deadline: Deadline | None
    ) -> HealthResult:
        await self._async_ensure_login(client, username, password, deadline)
        response = await self._async_request(client, "GET", self._health_url, deadline=deadline)
        if response.status_code == 401:  # session expired/revoked: re-login once
            await self._async_login(client, username, password, deadline)
            response = await self._async_request(
                client, "GET", self._health_url, deadline=deadline
            )
        return self._parse_health(response)

    async def _async_post_restart(
        self, client: httpx.AsyncClient, username: str, password: str, deadline: Deadline | None
    ) -> None:
        response = await self._async_request(
            client, "POST", self._base + _RESTART_PATH, deadline=deadline
        )
        if response.status_code == 401:  # session expired/revoked: re-login once
            await self._async_login(client, username, password, deadline)
            response = await self._async_request(
                client, "POST", self._base + _RESTART_PATH, deadline=deadline
            )
        if response.status_code >= 400:
            raise HermesHTTPError(f"hermes restart returned HTTP {response.status_code}")
        # Any 2xx is success unless a JSON body explicitly reports failure.
        try:
            body = response.json()
        except ValueError:
            return
        if isinstance(body, dict) and (body.get("ok") is False or "error" in body):
            raise HermesHTTPError("hermes restart reported failure")

    async def _async_poll(
        self, client: httpx.AsyncClient, username: str, password: str, deadline: Deadline | None
    ) -> bool:
        for attempt in range(self._poll_attempts):
            if deadline is not None and deadline.remaining() <= 0:
                break  # refuse to start a poll once the budget is spent
            try:
                if (await self._async_status(client, username, password, deadline)).healthy:
                    return True
            except (HermesHTTPError, HermesTimeoutError, HermesProtocolError, HermesAuthError):
                pass  # transient during restart; keep polling within the bound
            if attempt < self._poll_attempts - 1:
                await asyncio.sleep(self._clip_sleep(self._poll_interval, deadline))
        raise HermesTimeoutError("hermes gateway did not report running in time")

    @staticmethod
    def _clip_sleep(interval: float, deadline: Deadline | None) -> float:
        if deadline is None:
            return interval
        return max(0.0, min(interval, deadline.remaining()))
