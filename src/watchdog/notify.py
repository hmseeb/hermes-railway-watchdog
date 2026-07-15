"""AgentMail notifications with durable, private incident deduplication.

Alerts are sent only for (a) a successful recovery and (b) the *first* time a target
becomes unrecoverable. Healthy and deferred targets are silent. Deduplication uses
opaque markers in a private AgentMail inbox — never public GitHub issues — so incident
details are never exposed. If notification credentials are absent, the notifier reports
a degraded state (to be surfaced as a sanitized workflow failure) rather than breaking
the recovery flow.

All email content is public-safe: only opaque aliases, broad classifications, action
names, elapsed time, and pass/fail — every field passes through the central redactor.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from html import escape as html_escape
from types import TracebackType
from typing import Any

import httpx

from .errors import NotificationError
from .http import Timeouts
from .orchestrator import RunResult, TargetOutcome
from .redaction import Redactor

AGENTMAIL_BASE = "https://api.agentmail.to/v0"
AGENTMAIL_INBOX = "nixbot@agentmail.to"
_INCIDENT_PREFIX = "WD-INCIDENT:"
_RESOLVED_PREFIX = "WD-RESOLVED:"
# Small filtered page: with a subject filter on the opaque key, the newest returned
# message is the newest marker, regardless of unrelated inbox volume.
_LOOKUP_LIMIT = 10


def incident_key(alias: str) -> str:
    """Stable, opaque key for a target's incident (no real identifiers)."""
    return hashlib.sha256(alias.encode("utf-8")).hexdigest()[:16]


# --- email rendering ----------------------------------------------------------


def build_email(outcome: TargetOutcome, kind: str, redactor: Redactor) -> tuple[str, str, str]:
    alias = redactor.redact(outcome.alias)
    classification = outcome.classification.value if outcome.classification else "unknown"
    action = outcome.action
    elapsed = f"{outcome.elapsed_seconds:.2f}s"
    verdict = "recovered" if kind == "recovery" else "unrecovered"
    headline = "Recovery succeeded" if kind == "recovery" else "Unrecoverable failure"
    accent = "#3fb950" if kind == "recovery" else "#f85149"

    subject = f"[watchdog] {headline} — {alias} ({classification})"

    rows = {
        "Service": alias,
        "Classification": classification,
        "Action": action,
        "Elapsed": elapsed,
        "Result": verdict,
    }
    # HTML-escape every rendered value so no value can inject markup.
    row_html = "".join(
        f'<tr><td style="padding:6px 14px;color:#8b949e">{html_escape(k)}</td>'
        f'<td style="padding:6px 14px;color:#e6edf3;font-weight:600">{html_escape(v)}</td></tr>'
        for k, v in rows.items()
    )
    headline_html = html_escape(headline)
    html = (
        '<html><body style="margin:0;background:#0d1117;'
        'font-family:-apple-system,Segoe UI,Roboto,sans-serif">'
        '<div style="max-width:520px;margin:24px auto;background:#161b22;'
        'border:1px solid #30363d;border-radius:12px;overflow:hidden">'
        f'<div style="padding:16px 20px;background:{accent};color:#0d1117;'
        f'font-size:16px;font-weight:700">{headline_html}</div>'
        f'<table style="width:100%;border-collapse:collapse;font-size:14px">{row_html}</table>'
        '<div style="padding:12px 20px;color:#6e7681;font-size:12px">'
        "Railway + Hermes watchdog — public-safe alert (opaque identifiers only).</div>"
        "</div></body></html>"
    )
    text = (
        f"{headline}\n"
        f"Service: {alias}\n"
        f"Classification: {classification}\n"
        f"Action: {action}\n"
        f"Elapsed: {elapsed}\n"
        f"Result: {verdict}\n"
    )
    # Defence in depth: redact the fully-rendered strings too.
    return redactor.redact(subject), redactor.redact(html), redactor.redact(text)


# --- AgentMail HTTP client ----------------------------------------------------


class AgentMailClient:
    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = AGENTMAIL_BASE,
        inbox: str = AGENTMAIL_INBOX,
        transport: httpx.BaseTransport | None = None,
        timeouts: Timeouts | None = None,
    ) -> None:
        self._inbox = inbox
        self._client = httpx.Client(
            base_url=base_url,
            transport=transport,
            timeout=(timeouts or Timeouts()).as_httpx(),
            headers={"Authorization": f"Bearer {api_key}"},
        )

    def __enter__(self) -> AgentMailClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def send_message(self, to: str, subject: str, html: str, text: str) -> None:
        try:
            response = self._client.post(
                f"/inboxes/{self._inbox}/messages/send",
                # AgentMail expects recipients as an array.
                json={"to": [to], "subject": subject, "html": html, "text": text},
            )
        except httpx.HTTPError:
            raise NotificationError("failed to send notification") from None
        if response.status_code >= 400:
            raise NotificationError(f"notification send returned HTTP {response.status_code}")

    def list_messages(self, *, subject_contains: str, limit: int) -> list[dict[str, Any]]:
        """Return messages whose subject contains the filter, newest-first.

        Filtering server-side by the opaque key means unrelated inbox volume can never
        evict dedup state — the query only ever sees this key's markers.
        """
        try:
            response = self._client.get(
                f"/inboxes/{self._inbox}/messages",
                params={"subject": subject_contains, "limit": limit},
            )
        except httpx.HTTPError:
            raise NotificationError("failed to list notifications") from None
        if response.status_code >= 400:
            raise NotificationError(f"notification list returned HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError:
            raise NotificationError("notification list returned invalid JSON") from None
        messages = body.get("messages", []) if isinstance(body, dict) else []
        return [m for m in messages if isinstance(m, dict)]


# --- durable dedup store ------------------------------------------------------


class AgentMailIncidentStore:
    """Marker store in the private inbox. An incident is active while more INCIDENT
    markers than RESOLVED markers exist for its opaque key."""

    def __init__(self, client: AgentMailClient) -> None:
        self._client = client

    def _marker_body(self, subject: str) -> None:
        self._client.send_message(AGENTMAIL_INBOX, subject, subject, subject)

    def is_active(self, key: str) -> bool:
        # Query by the opaque key; the newest exact marker for that key decides.
        messages = self._client.list_messages(subject_contains=key, limit=_LOOKUP_LIMIT)
        for message in messages:  # newest-first
            subject = message.get("subject", "")
            if subject == _INCIDENT_PREFIX + key:
                return True
            if subject == _RESOLVED_PREFIX + key:
                return False
        return False

    def mark_active(self, key: str) -> None:
        self._marker_body(_INCIDENT_PREFIX + key)

    def clear(self, key: str) -> None:
        if self.is_active(key):
            self._marker_body(_RESOLVED_PREFIX + key)


# --- notifier -----------------------------------------------------------------


@dataclass
class NotifyReport:
    recoveries: list[str] = field(default_factory=list)
    incidents: list[str] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)
    cleared: list[str] = field(default_factory=list)
    degraded: bool = False


class Notifier:
    def __init__(
        self,
        *,
        client: AgentMailClient | None,
        recipient: str | None,
        store: AgentMailIncidentStore | None,
        redactor: Redactor,
    ) -> None:
        self._client = client
        self._recipient = recipient
        self._store = store
        self._redactor = redactor

    @staticmethod
    def _is_recovery(o: TargetOutcome) -> bool:
        return o.recovered and o.action != "none"

    @staticmethod
    def _is_failure(o: TargetOutcome) -> bool:
        return not o.recovered and not o.deferred

    @staticmethod
    def _is_passive_healthy(o: TargetOutcome) -> bool:
        # Became healthy on its own — recovered with no action taken (not deferred).
        return o.recovered and o.action == "none" and not o.deferred

    def process(self, result: RunResult) -> NotifyReport:
        report = NotifyReport()
        notable = [o for o in result.outcomes if self._is_recovery(o) or self._is_failure(o)]
        if self._client is None or self._recipient is None:
            report.degraded = bool(notable)
            return report

        for o in result.outcomes:
            if self._is_recovery(o):
                self._send(o, "recovery")
                report.recoveries.append(o.alias)
                if self._store is not None:
                    self._store.clear(incident_key(o.alias))
            elif self._is_failure(o):
                key = incident_key(o.alias)
                if self._store is not None and self._store.is_active(key):
                    report.suppressed.append(o.alias)
                    continue
                self._send(o, "incident")
                report.incidents.append(o.alias)
                if self._store is not None:
                    self._store.mark_active(key)
            elif self._is_passive_healthy(o) and self._store is not None:
                # Silently clear a lingering incident marker so a later outage alerts.
                key = incident_key(o.alias)
                if self._store.is_active(key):
                    self._store.clear(key)
                    report.cleared.append(o.alias)
        return report

    def _send(self, outcome: TargetOutcome, kind: str) -> None:
        client, recipient = self._client, self._recipient
        if client is None or recipient is None:  # narrowed for the type checker
            return
        subject, html, text = build_email(outcome, kind, self._redactor)
        client.send_message(recipient, subject, html, text)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()


def build_notifier_from_env(
    redactor: Redactor,
    *,
    transport: httpx.BaseTransport | None = None,
    clock: Callable[[], float] = time.time,
) -> Notifier:
    """Construct a Notifier from environment credentials, degrading if absent."""
    api_key = os.environ.get("AGENTMAIL_API_KEY")
    recipient = os.environ.get("WATCHDOG_ALERT_TO")
    if not api_key or not recipient:
        return Notifier(client=None, recipient=None, store=None, redactor=redactor)
    client = AgentMailClient(api_key, transport=transport)
    store = AgentMailIncidentStore(client)
    return Notifier(client=client, recipient=recipient, store=store, redactor=redactor)
