"""Cycle 2 (RED first): WATCHDOG_TARGETS_JSON parsing + full validation matrix."""

from __future__ import annotations

import json

import pytest

from watchdog.config import Target, WatchdogConfig, load_config
from watchdog.errors import (
    ConfigError,
    ExcludedServiceError,
    TargetValidationError,
    UnknownServiceError,
)

ENV = "WATCHDOG_TARGETS_JSON"


def _load(monkeypatch: pytest.MonkeyPatch, data: dict | str) -> WatchdogConfig:
    raw = data if isinstance(data, str) else json.dumps(data)
    monkeypatch.setenv(ENV, raw)
    return load_config()


# --- happy path ---------------------------------------------------------------

def test_valid_config_loads_seven_targets(monkeypatch, valid_config_dict):
    cfg = _load(monkeypatch, valid_config_dict)
    assert isinstance(cfg, WatchdogConfig)
    assert len(cfg.targets) == 7
    assert all(isinstance(t, Target) for t in cfg.targets)
    assert cfg.project_id and cfg.environment_id and cfg.excluded_service_id


def test_aliases_are_opaque_and_selectable(monkeypatch, valid_config_dict):
    cfg = _load(monkeypatch, valid_config_dict)
    target = cfg.select_target("svc-a")
    assert target.alias == "svc-a"


# --- source / decode errors ---------------------------------------------------

def test_missing_env_var_raises_config_error(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_blank_env_var_raises_config_error(monkeypatch):
    monkeypatch.setenv(ENV, "   ")
    with pytest.raises(ConfigError):
        load_config()


def test_invalid_json_raises_config_error(monkeypatch):
    monkeypatch.setenv(ENV, "{not json")
    with pytest.raises(ConfigError):
        load_config()


def test_non_object_json_raises_config_error(monkeypatch):
    monkeypatch.setenv(ENV, "[1, 2, 3]")
    with pytest.raises(ConfigError):
        load_config()


# --- top-level field errors ---------------------------------------------------

@pytest.mark.parametrize("field", ["project_id", "environment_id", "excluded_service_id"])
def test_missing_top_level_id_raises(monkeypatch, valid_config_dict, field):
    valid_config_dict.pop(field)
    with pytest.raises(ConfigError):
        _load(monkeypatch, valid_config_dict)


@pytest.mark.parametrize("field", ["project_id", "environment_id", "excluded_service_id"])
def test_blank_top_level_id_raises(monkeypatch, valid_config_dict, field):
    valid_config_dict[field] = "   "
    with pytest.raises(ConfigError):
        _load(monkeypatch, valid_config_dict)


# --- target count -------------------------------------------------------------

@pytest.mark.parametrize("count", [0, 6, 8, 14])
def test_wrong_target_count_rejected(monkeypatch, valid_config_dict, count):
    base = valid_config_dict["targets"]
    # Rebuild to `count` targets with unique alias/service_id.
    valid_config_dict["targets"] = [
        {**base[0], "alias": f"svc-x{i}", "service_id": f"id-{i}"} for i in range(count)
    ]
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, valid_config_dict)


def test_targets_missing_key_rejected(monkeypatch, valid_config_dict):
    del valid_config_dict["targets"]
    with pytest.raises((ConfigError, TargetValidationError)):
        _load(monkeypatch, valid_config_dict)


# --- per-target field errors --------------------------------------------------

@pytest.mark.parametrize(
    "field",
    ["alias", "service_name", "service_id", "health_url", "admin_username", "admin_password"],
)
def test_missing_target_field_rejected(monkeypatch, valid_config_dict, field):
    valid_config_dict["targets"][0].pop(field)
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, valid_config_dict)


@pytest.mark.parametrize(
    "field",
    ["alias", "service_name", "service_id", "health_url", "admin_username", "admin_password"],
)
def test_blank_target_field_rejected(monkeypatch, valid_config_dict, field):
    valid_config_dict["targets"][0][field] = "  "
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, valid_config_dict)


# --- URL validation -----------------------------------------------------------

@pytest.mark.parametrize(
    "bad_url",
    [
        "http://svc-a.example.test/health",   # not https
        "ftp://svc-a.example.test/health",    # wrong scheme
        "https:///health",                    # no host
        "not-a-url",                          # no scheme/host
        "svc-a.example.test/health",          # scheme-less
    ],
)
def test_malformed_or_non_https_url_rejected(monkeypatch, valid_config_dict, bad_url):
    valid_config_dict["targets"][0]["health_url"] = bad_url
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, valid_config_dict)


# --- uniqueness ---------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_alias",
    [
        "svc-<script>",          # markup
        "production-api",        # name-like, not the opaque svc- pattern
        "svc-A",                 # uppercase not allowed
        "svc-",                  # empty suffix
        "svc-toolongalias1234",  # exceeds 12-char suffix
        "svc_a",                 # wrong separator
        "internal-name-a",       # real-name shaped
    ],
)
def test_non_opaque_alias_rejected(monkeypatch, valid_config_dict, bad_alias):
    valid_config_dict["targets"][0]["alias"] = bad_alias
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, valid_config_dict)


@pytest.mark.parametrize("good_alias", ["svc-a", "svc-a1", "svc-abc123def456"])
def test_opaque_alias_accepted(monkeypatch, valid_config_dict, good_alias):
    valid_config_dict["targets"][0]["alias"] = good_alias
    cfg = _load(monkeypatch, valid_config_dict)
    assert cfg.targets[0].alias == good_alias


def test_duplicate_alias_rejected(monkeypatch, valid_config_dict):
    valid_config_dict["targets"][1]["alias"] = valid_config_dict["targets"][0]["alias"]
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, valid_config_dict)


def test_duplicate_service_id_rejected(monkeypatch, valid_config_dict):
    valid_config_dict["targets"][1]["service_id"] = valid_config_dict["targets"][0]["service_id"]
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, valid_config_dict)


# --- exclusion enforcement ----------------------------------------------------

def test_target_equal_to_excluded_service_rejected(monkeypatch, valid_config_dict):
    valid_config_dict["targets"][3]["service_id"] = valid_config_dict["excluded_service_id"]
    with pytest.raises(TargetValidationError):
        _load(monkeypatch, valid_config_dict)


# --- selection ----------------------------------------------------------------

def test_select_unknown_alias_raises(monkeypatch, valid_config_dict):
    cfg = _load(monkeypatch, valid_config_dict)
    with pytest.raises(UnknownServiceError):
        cfg.select_target("does-not-exist")


def test_select_excluded_target_raises(monkeypatch, valid_config_dict):
    # Force one target's id onto the excluded id *after* validation to prove the
    # selection guard is independent of load-time validation.
    cfg = _load(monkeypatch, valid_config_dict)
    poisoned = [
        Target(
            alias=t.alias,
            service_name=t.service_name,
            service_id=(cfg.excluded_service_id if i == 0 else t.service_id),
            health_url=t.health_url,
            admin_username=t.admin_username,
            admin_password=t.admin_password,
        )
        for i, t in enumerate(cfg.targets)
    ]
    cfg2 = WatchdogConfig(
        project_id=cfg.project_id,
        environment_id=cfg.environment_id,
        excluded_service_id=cfg.excluded_service_id,
        targets=tuple(poisoned),
    )
    with pytest.raises(ExcludedServiceError):
        cfg2.select_target(poisoned[0].alias)


def test_target_repr_hides_secrets(monkeypatch, valid_config_dict):
    cfg = _load(monkeypatch, valid_config_dict)
    text = repr(cfg.targets[0])
    assert "p@ss-w0rd-a-secret" not in text
    assert "admin-a" not in text
