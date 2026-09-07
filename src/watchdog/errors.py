"""Typed exception hierarchy.

Error *messages* must stay public-safe: raise with opaque aliases or generic
descriptions only, and always route through the redactor before display. Nothing
here should carry a raw secret, id, name, URL, or response body.
"""

from __future__ import annotations

from enum import StrEnum


class WatchdogError(Exception):
    """Base class for all watchdog errors."""


class ConfigError(WatchdogError):
    """The WATCHDOG_TARGETS_JSON source is missing, blank, or not a JSON object."""


class TargetValidationError(ConfigError):
    """A target list failed structural or semantic validation."""


class UnknownServiceError(WatchdogError):
    """A `--service` alias was requested that does not exist in the config."""


class ExcludedServiceError(WatchdogError):
    """An operation targeted the explicitly excluded service."""


# --- Railway client -----------------------------------------------------------


class RailwayError(WatchdogError):
    """Base class for Railway GraphQL client failures."""


class RailwayAuthError(RailwayError):
    """Authentication/authorization was rejected (e.g. HTTP 401/403)."""


class RailwayTimeoutError(RailwayError):
    """A Railway request exceeded its bounded connect/read timeout."""


class RailwayHTTPError(RailwayError):
    """Railway returned a non-success HTTP status after any allowed retries."""


class RailwayGraphQLError(RailwayError):
    """Railway returned a GraphQL ``errors`` array."""


# --- Hermes client ------------------------------------------------------------


class HermesError(WatchdogError):
    """Base class for Hermes gateway client failures."""


class HermesTimeoutError(HermesError):
    """A Hermes request exceeded its bounded connect/read timeout."""


class HermesHTTPError(HermesError):
    """Hermes returned a non-success HTTP status."""


class HermesAuthError(HermesError):
    """Login to the Hermes gateway failed."""


class HermesProtocolError(HermesError):
    """Hermes response violated the expected contract (bad JSON, unsafe redirect)."""


# --- Notifications ------------------------------------------------------------


class NotificationError(WatchdogError):
    """A notification could not be delivered."""


class FailureReason(StrEnum):
    AUTH = "gateway_authentication_failed"
    TIMEOUT = "gateway_timeout"
    PROTOCOL = "gateway_protocol_error"
    HTTP = "gateway_http_error"
    RAILWAY = "railway_request_failed"
    INTERNAL = "unexpected_error"


def failure_reason(error: Exception) -> FailureReason:
    """Only fixed codes may leave the process; never exception text or payloads."""
    for kind, reason in (
        (HermesAuthError, FailureReason.AUTH),
        (HermesTimeoutError, FailureReason.TIMEOUT),
        (HermesProtocolError, FailureReason.PROTOCOL),
        (HermesHTTPError, FailureReason.HTTP),
        (RailwayError, FailureReason.RAILWAY),
    ):
        if isinstance(error, kind):
            return reason
    return FailureReason.INTERNAL
