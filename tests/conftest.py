"""Shared fixtures. FAKE identifiers only — never real production data."""

from __future__ import annotations

import copy
import json

import pytest

# A syntactically valid config using entirely fabricated values.
_VALID: dict = {
    "project_id": "11111111-1111-4111-8111-111111111111",
    "environment_id": "22222222-2222-4222-8222-222222222222",
    "excluded_service_id": "99999999-9999-4999-8999-999999999999",
    "targets": [
        {
            "alias": f"svc-{letter}",
            "service_name": f"internal-name-{letter}",
            "service_id": f"3333333{i}-3333-4333-8333-33333333333{i}",
            "health_url": f"https://svc-{letter}.example.test/health",
            "admin_username": f"admin-{letter}",
            "admin_password": f"p@ss-w0rd-{letter}-secret",
        }
        for i, letter in enumerate("abcdefg")
    ],
}


@pytest.fixture
def valid_config_dict() -> dict:
    """A deep copy so tests may mutate freely."""
    return copy.deepcopy(_VALID)


@pytest.fixture
def valid_config_json(valid_config_dict: dict) -> str:
    return json.dumps(valid_config_dict)
