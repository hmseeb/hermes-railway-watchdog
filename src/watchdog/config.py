"""Configuration loading and validation.

The *only* source of target configuration is the `WATCHDOG_TARGETS_JSON` environment
variable — never a checked-in file. It must decode to an object with three non-empty
opaque ids and exactly seven fully-specified targets, none of which may equal the
excluded service. Every validation failure raises a typed, public-safe error.

With ``"mode": "selfhosted"`` there is no Railway: the Railway ids (top-level and
per-target ``service_id``) are not required and are ignored; targets may add an https
``webui_url`` and an ``ignore_platforms`` list.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .errors import (
    ConfigError,
    ExcludedServiceError,
    TargetValidationError,
    UnknownServiceError,
)

ENV_VAR = "WATCHDOG_TARGETS_JSON"
EXPECTED_TARGET_COUNT = 7
MODE_RAILWAY = "railway"
MODE_SELFHOSTED = "selfhosted"

# Aliases must be strictly opaque (never a real service name) and safe to render:
# lowercase ``svc-`` followed by 1-12 alphanumerics. This blocks markup, uppercase,
# and name-like values from ever entering output.
ALIAS_PATTERN = re.compile(r"^svc-[a-z0-9]{1,12}$")

_TARGET_FIELDS = (
    "alias",
    "service_name",
    "service_id",
    "health_url",
    "admin_username",
    "admin_password",
)


@dataclass(frozen=True)
class Target:
    """One watched service.

    ``service_name`` is the operator-chosen, intentionally-public identity used in all
    user-facing output; it is deliberately *not* a secret. Every remaining
    secret-bearing field (ids, url, credentials) is kept out of ``repr`` and masked by
    the redactor.
    """

    alias: str
    service_name: str
    service_id: str = field(repr=False)
    health_url: str = field(repr=False)
    admin_username: str = field(repr=False)
    admin_password: str = field(repr=False)
    # Self-hosted mode only: optional web UI URL (secret) and platforms whose
    # non-connected state is expected (platform names are public).
    webui_url: str | None = field(default=None, repr=False)
    ignore_platforms: frozenset[str] = frozenset()

    def secret_values(self) -> tuple[str, ...]:
        """Values the redactor must mask for this target.

        ``service_name`` is intentionally excluded: it is public by operator choice.
        """
        return (
            self.service_id,
            self.health_url,
            self.admin_username,
            self.admin_password,
            _host_of(self.health_url),
            self.webui_url or "",
            _host_of(self.webui_url or ""),
        )


@dataclass(frozen=True)
class WatchdogConfig:
    project_id: str
    environment_id: str
    excluded_service_id: str
    targets: tuple[Target, ...]
    mode: str = MODE_RAILWAY

    @property
    def selfhosted(self) -> bool:
        return self.mode == MODE_SELFHOSTED

    def select_target(self, alias: str) -> Target:
        for target in self.targets:
            if target.alias == alias:
                if self.excluded_service_id and target.service_id == self.excluded_service_id:
                    raise ExcludedServiceError(f"alias {alias!r} maps to the excluded service")
                return target
        raise UnknownServiceError(f"unknown service alias {alias!r}")

    def all_secret_values(self) -> tuple[str, ...]:
        values: list[str] = [self.project_id, self.environment_id, self.excluded_service_id]
        for target in self.targets:
            values.extend(target.secret_values())
        return tuple(v for v in values if v)


def _host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def _require_nonblank_str(value: Any, label: str, exc: type[ConfigError]) -> str:
    if not isinstance(value, str) or not value.strip():
        raise exc(f"{label} is missing or blank")
    return value


def _validate_https_url(url: str, label: str = "health_url") -> None:
    try:
        parsed = urlparse(url)
    except ValueError as err:  # pragma: no cover - urlparse rarely raises
        raise TargetValidationError(f"{label} is malformed") from err
    if parsed.scheme != "https" or not parsed.hostname:
        raise TargetValidationError(f"{label} must be a valid https URL with a host")


def _build_target(raw: Any, *, selfhosted: bool = False) -> Target:
    if not isinstance(raw, dict):
        raise TargetValidationError("each target must be an object")
    values: dict[str, str] = {}
    for name in _TARGET_FIELDS:
        if selfhosted and name == "service_id":
            values[name] = ""  # no Railway in self-hosted mode; ignore if present
            continue
        values[name] = _require_nonblank_str(raw.get(name), f"target.{name}", TargetValidationError)
    if not ALIAS_PATTERN.match(values["alias"]):
        raise TargetValidationError("target alias must match the opaque svc- pattern")
    _validate_https_url(values["health_url"])
    webui_url = raw.get("webui_url") if selfhosted else None  # Railway mode ignores both
    ignore = raw.get("ignore_platforms", []) if selfhosted else []
    if webui_url is not None:
        webui_url = _require_nonblank_str(webui_url, "target.webui_url", TargetValidationError)
        _validate_https_url(webui_url, "webui_url")
    if not isinstance(ignore, list) or not all(
        isinstance(p, str) and p.strip() for p in ignore
    ):
        raise TargetValidationError("target.ignore_platforms must be a list of names")
    return Target(
        alias=values["alias"],
        service_name=values["service_name"],
        service_id=values["service_id"],
        health_url=values["health_url"],
        admin_username=values["admin_username"],
        admin_password=values["admin_password"],
        webui_url=webui_url,
        ignore_platforms=frozenset(p.strip().lower() for p in ignore),
    )


def load_config() -> WatchdogConfig:
    raw = os.environ.get(ENV_VAR)
    if raw is None or not raw.strip():
        raise ConfigError(f"{ENV_VAR} is not set")
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError as err:
        raise ConfigError(f"{ENV_VAR} is not valid JSON") from err
    if not isinstance(data, dict):
        raise ConfigError(f"{ENV_VAR} must be a JSON object")

    mode = data.get("mode", MODE_RAILWAY)
    if mode not in (MODE_RAILWAY, MODE_SELFHOSTED):
        raise ConfigError("mode must be 'railway' or 'selfhosted'")
    if mode == MODE_SELFHOSTED:
        return _load_selfhosted(data)

    project_id = _require_nonblank_str(data.get("project_id"), "project_id", ConfigError)
    environment_id = _require_nonblank_str(
        data.get("environment_id"), "environment_id", ConfigError
    )
    excluded_service_id = _require_nonblank_str(
        data.get("excluded_service_id"), "excluded_service_id", ConfigError
    )

    targets = _build_targets(data)
    service_ids = [t.service_id for t in targets]
    if len(set(service_ids)) != len(service_ids):
        raise TargetValidationError("duplicate target service_id")
    if any(t.service_id == excluded_service_id for t in targets):
        raise TargetValidationError("a target equals the excluded service")

    return WatchdogConfig(
        project_id=project_id,
        environment_id=environment_id,
        excluded_service_id=excluded_service_id,
        targets=targets,
    )


def _build_targets(data: dict[str, Any], *, selfhosted: bool = False) -> tuple[Target, ...]:
    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list):
        raise ConfigError("targets must be a list")
    if len(raw_targets) != EXPECTED_TARGET_COUNT:
        raise TargetValidationError(
            f"expected exactly {EXPECTED_TARGET_COUNT} targets, got {len(raw_targets)}"
        )
    targets = tuple(_build_target(item, selfhosted=selfhosted) for item in raw_targets)
    aliases = [t.alias for t in targets]
    if len(set(aliases)) != len(aliases):
        raise TargetValidationError("duplicate target alias")
    return targets


def _load_selfhosted(data: dict[str, Any]) -> WatchdogConfig:
    """Self-hosted (no Railway) mode: Railway ids are not required and are ignored."""
    return WatchdogConfig(
        project_id="",
        environment_id="",
        excluded_service_id="",
        targets=_build_targets(data, selfhosted=True),
        mode=MODE_SELFHOSTED,
    )
