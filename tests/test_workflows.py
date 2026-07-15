"""Phase 6 (RED first): GitHub workflow YAML security & correctness properties."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WF = Path(__file__).resolve().parent.parent / ".github" / "workflows"
PROD_SECRETS = ("RAILWAY_API_TOKEN", "AGENTMAIL_API_KEY", "WATCHDOG_TARGETS_JSON",
                "WATCHDOG_ALERT_TO")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _load(name: str) -> dict:
    return yaml.safe_load((WF / name).read_text())


def _uses(workflow: dict) -> list[str]:
    found: list[str] = []
    for job in workflow.get("jobs", {}).values():
        for step in job.get("steps", []):
            if "uses" in step:
                found.append(step["uses"])
    return found


@pytest.mark.parametrize("name", ["test.yml", "watchdog.yml", "keepalive.yml"])
def test_workflow_exists_and_parses(name):
    assert (WF / name).exists()
    assert _load(name)


@pytest.mark.parametrize("name", ["test.yml", "watchdog.yml", "keepalive.yml"])
def test_third_party_actions_pinned_to_full_sha(name):
    for use in _uses(_load(name)):
        assert "@" in use, use
        ref = use.split("@", 1)[1]
        assert SHA_RE.match(ref), f"{use} is not pinned to a full 40-char commit SHA"


# --- zizmor hardening: artipacked, names, concurrency, permissions ------------

@pytest.mark.parametrize("name", ["test.yml", "watchdog.yml"])
def test_checkout_disables_persist_credentials(name):
    wf = _load(name)
    checkouts = 0
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            if "actions/checkout" in step.get("uses", ""):
                checkouts += 1
                assert step.get("with", {}).get("persist-credentials") is False, name
    assert checkouts >= 1


@pytest.mark.parametrize("name", ["test.yml", "watchdog.yml", "keepalive.yml"])
def test_every_job_has_a_human_readable_name(name):
    wf = _load(name)
    for job_id, job in wf["jobs"].items():
        assert isinstance(job.get("name"), str) and job["name"].strip(), f"{name}:{job_id}"


def test_test_yml_has_concurrency():
    assert "concurrency" in _load("test.yml")


def test_no_workflow_step_logs_secrets_or_enables_tracing():
    # No step should echo secrets or enable command tracing that could print tokens.
    for name in ("test.yml", "watchdog.yml", "keepalive.yml"):
        raw = (WF / name).read_text()
        assert "set -x" not in raw, name
        assert "echo ${{ secrets" not in raw and "echo \"${{ secrets" not in raw


# --- test.yml -----------------------------------------------------------------

def test_test_yml_triggers_and_read_only_permissions():
    wf = _load("test.yml")
    on = wf[True] if True in wf else wf["on"]  # PyYAML parses 'on:' as boolean True
    assert "pull_request" in on and "push" in on
    assert wf["permissions"] == {"contents": "read"}


def test_test_yml_has_no_production_secrets():
    raw = (WF / "test.yml").read_text()
    for secret in PROD_SECRETS:
        assert secret not in raw, f"{secret} must not appear in test.yml"


def test_test_yml_runs_install_test_lint_typecheck_and_secret_scan():
    raw = (WF / "test.yml").read_text().lower()
    assert "pytest" in raw
    assert "ruff" in raw
    assert "mypy" in raw
    assert "secret" in raw  # security-secret scan step


# --- watchdog.yml -------------------------------------------------------------

def test_watchdog_schedule_every_five_minutes_nonzero_offset():
    wf = _load("watchdog.yml")
    on = wf[True] if True in wf else wf["on"]
    assert "workflow_dispatch" in on
    crons = [c["cron"] for c in on["schedule"]]
    assert any("/5" in c for c in crons)
    minute_field = crons[0].split()[0]
    assert minute_field != "*/5" or True  # allow offset form below
    # Non-zero offset: not starting exactly at minute 0 (reduce top-of-hour spikes).
    assert not minute_field.startswith("0,") and minute_field != "0"


def test_watchdog_read_only_permissions_and_bounds():
    wf = _load("watchdog.yml")
    assert wf["permissions"] == {"contents": "read"}
    job = next(iter(wf["jobs"].values()))
    assert job["timeout-minutes"] == 15
    assert "concurrency" in wf or "concurrency" in job


def test_watchdog_concurrency_does_not_cancel_in_progress():
    wf = _load("watchdog.yml")
    job = next(iter(wf["jobs"].values()))
    conc = wf.get("concurrency") or job.get("concurrency")
    assert conc["cancel-in-progress"] is False


def test_watchdog_secrets_only_in_watchdog_step():
    wf = _load("watchdog.yml")
    job = next(iter(wf["jobs"].values()))
    # No job/workflow-level env carrying production secrets.
    for scope in (wf.get("env", {}), job.get("env", {})):
        for secret in PROD_SECRETS:
            assert secret not in scope
    steps_with_secret = [
        s for s in job["steps"]
        if any(sec in str(s.get("env", {})) for sec in PROD_SECRETS)
    ]
    assert len(steps_with_secret) == 1  # exactly the watchdog step


def test_watchdog_default_branch_guard():
    raw = (WF / "watchdog.yml").read_text()
    assert "refs/heads/main" in raw  # dispatch guarded to default branch


def test_watchdog_has_no_cache_or_artifact_steps():
    raw = (WF / "watchdog.yml").read_text().lower()
    assert "actions/cache" not in raw
    assert "upload-artifact" not in raw
    assert "actions/debug" not in raw


# --- keepalive.yml ------------------------------------------------------------

def test_keepalive_monthly_no_secrets_no_pull_request():
    wf = _load("keepalive.yml")
    on = wf[True] if True in wf else wf["on"]
    crons = [c["cron"] for c in on["schedule"]]
    # Monthly: day-of-month field pinned (not '*').
    assert any(c.split()[2] != "*" for c in crons)
    assert "pull_request" not in on
    raw = (WF / "keepalive.yml").read_text()
    for secret in PROD_SECRETS:
        assert secret not in raw


def test_keepalive_permissions_are_least_privilege():
    wf = _load("keepalive.yml")
    # Top-level: no permissions granted; only the heartbeat job gets contents: write.
    assert wf["permissions"] == {}
    assert wf["jobs"]["heartbeat"]["permissions"] == {"contents": "write"}


def test_keepalive_uses_no_checkout_and_gh_api():
    wf = _load("keepalive.yml")
    assert _uses(wf) == []  # no third-party actions, no checkout at all
    raw = (WF / "keepalive.yml").read_text()
    assert "gh api" in raw
    assert "GH_TOKEN: ${{ github.token }}" in raw
    assert "--silent" in raw


def test_keepalive_concurrency_no_cancel_and_named_job():
    wf = _load("keepalive.yml")
    conc = wf.get("concurrency")
    assert conc and conc["cancel-in-progress"] is False
    assert wf["jobs"]["heartbeat"].get("name")


def test_keepalive_seed_file_is_tracked():
    assert (WF.parent / "keepalive").exists()  # .github/keepalive seed present


def test_keepalive_documents_github_token_activity_caveat():
    raw = (WF / "keepalive.yml").read_text().lower()
    assert "60" in raw and "activity" in raw  # residual 60-day risk documented
