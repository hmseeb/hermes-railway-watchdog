"""Cycle 1 (RED first): the central redactor must let no secret-like text escape."""

from __future__ import annotations

import pytest

from watchdog.redaction import Redactor

UUID = "3a7c1e2b-9f4d-4a6b-8c1d-2e3f4a5b6c7d"
EMAIL = "nixbot@agentmail.to"
URL = "https://svc-a.internal.example.test/setup/api/gateway/restart"
COOKIE = "session=abcDEF123456ghijKLMN7890opqrSTUV; Path=/; HttpOnly"
# Neutral bearer sentinel: exercises the bearer/long-token redaction rule without
# matching any real provider credential pattern (avoids secret-scanning false alarms).
BEARER = "Bearer redaction_test_sentinel_0123456789abcdef"


@pytest.fixture
def redactor() -> Redactor:
    return Redactor(secrets=["p@ss-w0rd-a-secret", "admin-a", "internal-name-a"])


def test_masks_exact_supplied_secrets(redactor: Redactor) -> None:
    out = redactor.redact("login admin-a with p@ss-w0rd-a-secret to internal-name-a")
    assert "p@ss-w0rd-a-secret" not in out
    assert "admin-a" not in out
    assert "internal-name-a" not in out
    assert "[REDACTED]" in out


def test_masks_uuid(redactor: Redactor) -> None:
    out = redactor.redact(f"service {UUID} failed")
    assert UUID not in out


def test_masks_email(redactor: Redactor) -> None:
    assert EMAIL not in redactor.redact(f"contact {EMAIL}")


def test_masks_https_url(redactor: Redactor) -> None:
    out = redactor.redact(f"posting to {URL}")
    assert "internal.example.test" not in out
    assert "/setup/api/gateway/restart" not in out


def test_masks_cookie_and_bearer(redactor: Redactor) -> None:
    out = redactor.redact(f"{COOKIE} :: {BEARER}")
    assert "abcDEF123456ghijKLMN7890opqrSTUV" not in out
    assert "redaction_test_sentinel_0123456789abcdef" not in out


def test_leaves_innocuous_text(redactor: Redactor) -> None:
    assert redactor.redact("gateway not running") == "gateway not running"


def test_is_idempotent(redactor: Redactor) -> None:
    once = redactor.redact(f"{UUID} {EMAIL}")
    assert redactor.redact(once) == once


def test_coerces_non_str(redactor: Redactor) -> None:
    assert redactor.redact(1234) == "1234"
    assert isinstance(redactor.redact(None), str)


def test_redact_mapping_scrubs_values(redactor: Redactor) -> None:
    scrubbed = redactor.redact_mapping({"pw": "p@ss-w0rd-a-secret", "n": 5, "id": UUID})
    assert scrubbed["pw"] != "p@ss-w0rd-a-secret"
    assert UUID not in scrubbed["id"]


def test_redact_exc_scrubs_message(redactor: Redactor) -> None:
    err = ValueError(f"boom {UUID} {EMAIL}")
    msg = redactor.redact_exc(err)
    assert UUID not in msg and EMAIL not in msg


def test_empty_secret_is_ignored() -> None:
    # Guard against a blank secret nuking every character boundary.
    r = Redactor(secrets=["", "realname"])
    assert r.redact("hello world") == "hello world"
    assert "realname" not in r.redact("x realname y")
