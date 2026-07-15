"""Configuration loading and validation.

The *only* source of target configuration is the `WATCHDOG_TARGETS_JSON` environment
variable — never a checked-in file. It must decode to an object with three non-empty
opaque ids and exactly seven fully-specified targets, none of which may equal the
excluded service. Every validation failure raises a typed, public-safe error.
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
        )


@dataclass(frozen=True)
class WatchdogConfig:
    project_id: str
    environment_id: str
    excluded_service_id: str
    targets: tuple[Target, ...]

    def select_target(self, alias: str) -> Target:
        for target in self.targets:
            if target.alias == alias:
                if target.service_id == self.excluded_service_id:
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


def _validate_https_url(url: str) -> None:
    try:
        parsed = urlparse(url)
    except ValueError as err:  # pragma: no cover - urlparse rarely raises
        raise TargetValidationError("health_url is malformed") from err
    if parsed.scheme != "https" or not parsed.hostname:
        raise TargetValidationError("health_url must be a valid https URL with a host")


def _build_target(raw: Any) -> Target:
    if not isinstance(raw, dict):
        raise TargetValidationError("each target must be an object")
    values: dict[str, str] = {}
    for name in _TARGET_FIELDS:
        values[name] = _require_nonblank_str(raw.get(name), f"target.{name}", TargetValidationError)
    if not ALIAS_PATTERN.match(values["alias"]):
        raise TargetValidationError("target alias must match the opaque svc- pattern")
    _validate_https_url(values["health_url"])
    return Target(**values)


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

    project_id = _require_nonblank_str(data.get("project_id"), "project_id", ConfigError)
    environment_id = _require_nonblank_str(
        data.get("environment_id"), "environment_id", ConfigError
    )
    excluded_service_id = _require_nonblank_str(
        data.get("excluded_service_id"), "excluded_service_id", ConfigError
    )

    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list):
        raise ConfigError("targets must be a list")
    if len(raw_targets) != EXPECTED_TARGET_COUNT:
        raise TargetValidationError(
            f"expected exactly {EXPECTED_TARGET_COUNT} targets, got {len(raw_targets)}"
        )

    targets = tuple(_build_target(item) for item in raw_targets)

    aliases = [t.alias for t in targets]
    if len(set(aliases)) != len(aliases):
        raise TargetValidationError("duplicate target alias")
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
