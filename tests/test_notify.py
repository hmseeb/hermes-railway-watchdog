"""Phase 5 (RED first): AgentMail notifications, dedup, and degrade-on-no-creds."""

from __future__ import annotations

import json

import httpx

from watchdog.notify import (
    AGENTMAIL_BASE,
    AGENTMAIL_INBOX,
    AgentMailClient,
    AgentMailIncidentStore,
    Notifier,
    build_email,
    incident_key,
)
from watchdog.orchestrator import RunResult, TargetOutcome
from watchdog.redaction import Redactor
from watchdog.state import Classification

REDACTOR = Redactor(secrets=["internal-name-a", "https://real-host.example.test/health"])


def _outcome(alias="svc-a", *, cls, action="none", recovered, deferred=False, error=None):
    return TargetOutcome(
        alias=alias,
        classification=cls,
        action=action,
        recovered=recovered,
        deferred=deferred,
        elapsed_seconds=1.23,
        error=error,
    )


# --- in-memory AgentMail inbox ------------------------------------------------

def _inbox():
    # messages stored oldest-first; the list API returns them newest-first, supports a
    # subject substring filter, a limit, and a next_page_token — mirroring AgentMail.
    state: dict[str, list] = {"messages": [], "sent": []}

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers.get("authorization", "").startswith("Bearer ")
        if req.method == "POST" and req.url.path.endswith("/messages/send"):
            body = json.loads(req.content)
            state["sent"].append(body)
            state["messages"].append({"subject": body["subject"]})
            return httpx.Response(200, json={"id": "m1"})
        if req.method == "GET" and req.url.path.endswith("/messages"):
            subject = req.url.params.get("subject")
            limit = int(req.url.params.get("limit", "100"))
            msgs = list(reversed(state["messages"]))  # newest-first
            if subject:
                msgs = [m for m in msgs if subject in m["subject"]]
            page = msgs[:limit]
            resp: dict = {"count": len(page), "limit": limit, "messages": page}
            if len(msgs) > limit:
                resp["next_page_token"] = "more"
            return httpx.Response(200, json=resp)
        return httpx.Response(404)

    return handler, state


def _seed_unrelated(state, n):
    for i in range(n):
        state["messages"].append({"subject": f"unrelated message {i}"})


def _client(handler) -> AgentMailClient:
    return AgentMailClient(
        api_key="am-secret-key",
        transport=httpx.MockTransport(handler),
    )


# --- email content ------------------------------------------------------------

def test_build_email_is_public_safe():
    o = _outcome(cls=Classification.CONTAINER_FAILURE, action="container_restart",
                 recovered=False, error="boom https://real-host.example.test/health leaked")
    subject, html, text = build_email(o, "incident", REDACTOR)
    for blob in (subject, html, text):
        assert "real-host.example.test" not in blob
        assert "internal-name-a" not in blob
    # Allowed public content is present.
    assert "svc-a" in subject
    assert "container_failure" in html
    assert "container_restart" in text


def test_build_email_has_html_and_text_fallback():
    o = _outcome(cls=Classification.GATEWAY_ONLY_FAILURE, action="gateway_restart",
                 recovered=True)
    _, html, text = build_email(o, "recovery", REDACTOR)
    assert "<html" in html.lower() or "<div" in html.lower()
    assert "background" in html.lower()  # dark theme styling present
    assert "<" not in text  # plain-text fallback


# --- AgentMail client + store -------------------------------------------------

def test_client_send_uses_agentmail_endpoint_with_recipient_array():
    handler, state = _inbox()
    with _client(handler) as c:
        c.send_message("to@x.test", "subj", "<b>h</b>", "t")
    assert state["sent"][0]["subject"] == "subj"
    # Per AgentMail API docs, recipients must be an array.
    assert state["sent"][0]["to"] == ["to@x.test"]
    assert AGENTMAIL_BASE.startswith("https://api.agentmail.to/v0")
    assert AGENTMAIL_INBOX == "nixbot@agentmail.to"


def test_incident_store_active_mark_clear_cycle():
    handler, _ = _inbox()
    with _client(handler) as c:
        store = AgentMailIncidentStore(c)
        key = "abc123"
        assert store.is_active(key) is False
        store.mark_active(key)
        assert store.is_active(key) is True
        store.clear(key)
        assert store.is_active(key) is False


def test_incident_state_survives_hundreds_of_unrelated_messages():
    # Finding 4: unrelated message volume must not evict dedup state, because we query
    # by the opaque key. The newest exact marker decides.
    handler, state = _inbox()
    with _client(handler) as c:
        store = AgentMailIncidentStore(c)
        key = "deadbeefcafef00d"
        _seed_unrelated(state, 250)
        store.mark_active(key)
        _seed_unrelated(state, 250)
        assert store.is_active(key) is True   # not evicted by 500 unrelated messages
        store.clear(key)
        _seed_unrelated(state, 250)
        assert store.is_active(key) is False  # newest exact marker is RESOLVED


def test_incident_lookup_uses_subject_filtered_query():
    # The list request must carry the key as a subject filter, not scan a default page.
    seen = {}

    def handler(req):
        if req.method == "GET":
            seen["subject"] = req.url.params.get("subject")
            return httpx.Response(200, json={"messages": [], "count": 0, "limit": 1})
        return httpx.Response(200, json={"id": "m1"})

    with _client(handler) as c:
        AgentMailIncidentStore(c).is_active("mykey123")
    assert seen["subject"] == "mykey123"


# --- notifier triggers + dedup ------------------------------------------------

def _notifier(handler, *, recipient="alert@x.test", with_store=True):
    client = _client(handler)
    store = AgentMailIncidentStore(client) if with_store else None
    return Notifier(client=client, recipient=recipient, store=store, redactor=REDACTOR)


def test_healthy_and_deferred_are_silent():
    handler, state = _inbox()
    n = _notifier(handler)
    result = RunResult((
        _outcome("svc-a", cls=Classification.HEALTHY, recovered=True),
        _outcome("svc-b", cls=Classification.TRANSITIONAL, recovered=False, deferred=True),
    ))
    report = n.process(result)
    assert state["sent"] == []
    assert report.recoveries == [] and report.incidents == []


def test_successful_recovery_sends_email():
    handler, state = _inbox()
    n = _notifier(handler)
    result = RunResult((
        _outcome("svc-a", cls=Classification.GATEWAY_ONLY_FAILURE,
                 action="gateway_restart", recovered=True),
    ))
    report = n.process(result)
    assert report.recoveries == ["svc-a"]
    # One recovery email + one RESOLVED marker.
    assert any(m["subject"].startswith("[watchdog]") for m in state["sent"])


def test_first_unrecoverable_alerts_then_dedups():
    handler, state = _inbox()
    n = _notifier(handler)
    failing = RunResult((
        _outcome("svc-a", cls=Classification.CONTAINER_FAILURE,
                 action="container_restart", recovered=False),
    ))
    first = n.process(failing)
    assert first.incidents == ["svc-a"]
    alerts_after_first = sum(1 for m in state["sent"] if m["subject"].startswith("[watchdog]"))

    second = n.process(failing)  # same incident still active
    assert second.incidents == []
    assert second.suppressed == ["svc-a"]
    alerts_after_second = sum(1 for m in state["sent"] if m["subject"].startswith("[watchdog]"))
    assert alerts_after_second == alerts_after_first  # no duplicate alert


def test_recovery_clears_incident_so_next_failure_alerts_again():
    handler, _ = _inbox()
    n = _notifier(handler)
    key = incident_key("svc-a")

    n.process(RunResult((_outcome("svc-a", cls=Classification.CONTAINER_FAILURE,
                                  action="container_restart", recovered=False),)))
    assert n._store.is_active(key) is True

    n.process(RunResult((_outcome("svc-a", cls=Classification.CONTAINER_FAILURE,
                                  action="container_restart", recovered=True),)))
    assert n._store.is_active(key) is False


def test_passive_recovery_clears_marker_silently():
    # Finding 3: a target that becomes healthy on its own (action=none) clears its
    # active incident marker without sending an email, so a later new outage alerts.
    handler, state = _inbox()
    n = _notifier(handler)
    key = incident_key("svc-a")

    # First: an unrecoverable failure opens an incident.
    n.process(RunResult((_outcome("svc-a", cls=Classification.CONTAINER_FAILURE,
                                  action="container_restart", recovered=False),)))
    assert n._store.is_active(key) is True
    alerts_before = sum(1 for m in state["sent"] if m["subject"].startswith("[watchdog]"))

    # Then: it becomes healthy naturally (no action taken).
    report = n.process(RunResult((_outcome("svc-a", cls=Classification.HEALTHY,
                                           action="none", recovered=True),)))
    assert report.cleared == ["svc-a"]
    assert report.recoveries == []  # no recovery email
    alerts_after = sum(1 for m in state["sent"] if m["subject"].startswith("[watchdog]"))
    assert alerts_after == alerts_before  # silent
    assert n._store.is_active(key) is False

    # A new failure alerts again (state was reset).
    report2 = n.process(RunResult((_outcome("svc-a", cls=Classification.CONTAINER_FAILURE,
                                            action="container_restart", recovered=False),)))
    assert report2.incidents == ["svc-a"]


def test_healthy_with_no_marker_stays_silent():
    handler, state = _inbox()
    n = _notifier(handler)
    report = n.process(RunResult((_outcome("svc-a", cls=Classification.HEALTHY,
                                           action="none", recovered=True),)))
    assert report.cleared == []
    assert state["sent"] == []


def test_build_email_escapes_html_injection():
    # Even if a markup-shaped alias reached rendering, it must be HTML-escaped.
    o = _outcome("svc-<script>alert(1)</script>", cls=Classification.CONTAINER_FAILURE,
                 action="container_restart", recovered=False)
    _, html, _ = build_email(o, "incident", Redactor())
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_absent_credentials_degrade_not_fail():
    n = Notifier(client=None, recipient=None, store=None, redactor=REDACTOR)
    result = RunResult((
        _outcome("svc-a", cls=Classification.CONTAINER_FAILURE, recovered=False),
    ))
    report = n.process(result)
    assert report.degraded is True
    assert report.incidents == []  # nothing sent, but recovery flow is not broken
