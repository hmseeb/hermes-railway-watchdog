# Railway + Hermes Gateway Watchdog

A secret-safe watchdog that monitors Railway services and their Hermes gateways,
classifies health, and performs **bounded, at-most-once** recovery actions — while
guaranteeing that no production identifier, credential, domain, or payload ever
escapes into logs, summaries, notifications, or version control.

> ℹ️ **One deliberate exception:** the operator-chosen **service name** for each
> target *is* public by design. It is the user-facing identity in GitHub Actions
> logs/summaries and in private AgentMail alerts, so humans can tell which service an
> alert is about. This is an explicit product/privacy decision. **Everything else**
> — project/environment/service/deployment ids, domains and URLs, admin credentials,
> cookies, tokens, and raw payloads — remains redacted. See the threat model below.

> ⚠️ **Production data must never be committed.** All targets, ids, credentials, and
> URLs come from a single environment variable (`WATCHDOG_TARGETS_JSON`). There is no
> config file to check in. `.gitignore` blocks `.env*`, `*targets*.json`, and the local
> `.planning/` directory. If you are tempted to paste a real Railway payload into the
> repo for "just a test" — don't. Use fabricated values only.

## Architecture

```
WATCHDOG_TARGETS_JSON ─▶ config ─▶ ┌───────────────┐
                                    │  orchestrator │──▶ notify (AgentMail)
RAILWAY_API_TOKEN ─▶ railway ──────▶│ (concurrency 3│
                                    │  at-most-once)│
target creds ─▶ hermes ────────────▶└──────┬────────┘
                                           │ classify
                                     state machine
```

- **`config`** — parses/validates `WATCHDOG_TARGETS_JSON`: exactly seven targets, each
  with an opaque alias (internal — used for `--service` selection and uniqueness) plus
  the operator-chosen public `service_name`, the secret `service_id`, an HTTPS health
  URL, and admin credentials. Rejects duplicates, wrong counts, malformed/non-HTTPS
  URLs, missing values, and any target equal to the excluded service. Only
  `service_name` is treated as public; every other field is handed to the redactor.
- **`railway`** — official GraphQL API over HTTPS (`Authorization: Bearer`). Reads
  deployment status/instance state; restarts the *current* deployment via
  `deploymentRestart` (no rebuild, no shell, no SSH). Bounded timeouts; retries safe
  reads only.
- **`hermes`** — public `/health` check (requires `status=ok` + `gateway=running`);
  authenticated gateway restart via `/login` → session cookie → `/setup/api/gateway/restart`
  → poll. Redirects are not followed; cross-origin redirects are rejected.
- **`state`** — classifies each target as `healthy`, `gateway_only_failure`,
  `transitional`, or `container_failure` (15-minute transition threshold).
- **`orchestrator`** — per-target recovery with a fresh-state recheck before every
  mutation, at-most-once mutations, per-target time bound, concurrency cap 3, and a
  non-zero exit if any target remains unrecovered. Dry-run reads/classifies only.
- **`notify`** — AgentMail alerts for successful recovery and the first unrecoverable
  failure only; durable dedup via opaque markers in a private inbox.
- **`redaction`** — central redactor every output passes through.

## Threat model

> **Intentionally public by operator choice:** the `service_name` of each target. It is
> excluded from the redactor's secret set so it can appear in public GitHub Actions
> logs/summaries and private AgentMail alerts as the human-readable identity. This is a
> deliberate product/privacy trade-off. All other production detail
> (project/environment/service/deployment ids, domains/URLs, admin credentials,
> cookies, tokens, raw payloads) stays redacted. The internal opaque alias is never
> rendered — it is used only for `--service` selection, config uniqueness, and as the
> input to the hashed, opaque incident-dedup key.

| Threat | Mitigation |
|--------|------------|
| Secret leaks via logs/exceptions/summaries/notifications | Central `Redactor` (exact-value + pattern masking) on every emitted string; clients never log; typed errors carry generic text only. Tests assert real-like UUIDs/domains/creds/cookies never escape. The operator-chosen `service_name` is the **only** field excluded from the secret **set** (it is public by choice) — but its *content* is still redacted before rendering, so any secret it happens to embed is masked. In the Markdown summary the name is redacted **before** Markdown-escaping (`render_summary`), because escaping URL/email joiners first would defeat exact/pattern matching; the whole-summary redaction then runs again as defense in depth. |
| Production data committed to a public repo | Env-only config; `.gitignore` blocks secrets/planning; CI secret-scan step. |
| Operating on the wrong / excluded service | Hard validation + exclusion checks at load and at selection time; the Railway read proves ownership relationally (Service.projectId and Environment.projectId must both equal the configured project, and all returned ids must match the requested ones) before any restartable deployment id is accepted. |
| Markup/injection via rendered identities | The internal alias must match a strict opaque pattern (`^svc-[a-z0-9]{1,12}$`) and is never rendered. The public `service_name` is free operator text, so each output surface neutralizes it for **its own** format: the AgentMail email renders HTML and `html.escape`s every value (`src/watchdog/notify.py`); the GitHub step summary is Markdown, so the name is passed through a dedicated Markdown-inline sanitizer (`src/watchdog/markdown.py`) that collapses newlines/tabs/control whitespace to spaces, escapes/entity-encodes Markdown+HTML metacharacters, and backslash-escapes the URL/email joiners `.` `:` `/` `@` — so it cannot forge headings, verdicts, links, images, raw HTML, or extra rows, and GitHub cannot auto-link any bare `www.` domain, URL, or email in the name, while the readable characters stay intact. |
| Runs exceeding their time bound | Each target has an absolute recovery budget; every sleep, poll, request, and mutation is bounded by the remaining budget, and no operation starts after it expires. |
| Overlapping runs causing half-applied restarts | Workflow `concurrency` with `cancel-in-progress: false` + app-level fresh-state recheck immediately before each mutation. |
| Unsafe auth redirect (credential/cookie theft) | Redirects not followed; cross-origin redirects rejected before any further action. |
| Runaway recovery / infinite retry | Bounded timeouts, attempt caps, and a per-target recovery deadline; each mutation at most once per run. |
| Notification channel compromised as a data sink | Emails contain only the public `service_name`, broad classifications, action names, elapsed time, and pass/fail — no ids, URLs, credentials, or payloads. |
| Scheduled workflow silently disabled | Monthly keepalive — **with a documented, unguaranteed** 60-day residual risk (see below). |

## Required secrets (by key name only — never commit values)

| Key | Purpose |
|-----|---------|
| `WATCHDOG_TARGETS_JSON` | The seven targets + project/environment/excluded ids. |
| `RAILWAY_API_TOKEN` | Railway GraphQL API auth. |
| `AGENTMAIL_API_KEY` | AgentMail notification auth (optional; absence degrades gracefully). |
| `WATCHDOG_ALERT_TO` | Alert recipient address (optional; absence degrades gracefully). |

Set these as GitHub Actions repository secrets. They are injected **only** into the
watchdog step of `watchdog.yml`.

## Local development & exact test commands

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

pytest --cov=watchdog --cov-report=term-missing   # tests + coverage
ruff check .                                       # lint (incl. security rules)
mypy                                               # type check (strict on src)
```

Run locally against fabricated data:

```bash
export WATCHDOG_TARGETS_JSON='{...seven fake targets...}'
export RAILWAY_API_TOKEN='fake'
watchdog --dry-run                 # read + classify only, no mutation
watchdog --dry-run --service svc-a # select one target by its internal opaque alias
                                   # (output still shows that target's public name)
```

## Rollout gates

1. `pytest`, `ruff`, and `mypy` all green in CI (`test.yml`).
2. Repository secrets configured (keys above); values never in git.
3. `watchdog --dry-run` reviewed against production — classifications look correct, and
   output shows only the public service names + broad status (no ids, URLs, creds, or
   other production detail).
4. Workflow action SHAs are independently verified (checkout v4.2.2, setup-python
   v5.3.0); re-verify if you bump versions.
5. Enable the schedule only on the default branch after merge.
6. Contracts confirmed against the live/deployed services: Railway
   `serviceInstance` query + `deploymentRestart` mutation (endpoint
   `backboard.railway.com`), Hermes form-encoded `/login` → `hermes_auth` cookie →
   restart, and the AgentMail send/list endpoints. Smoke-test with `--dry-run` before
   enabling live mutations.

## CI/CD workflows

- **`test.yml`** — PR/push; read-only permissions; no production secrets; install,
  lint, typecheck, test, and a secret scan. Actions pinned to full commit SHAs.
- **`watchdog.yml`** — scheduled every 5 minutes (offset to minute 2 to avoid
  top-of-hour congestion) + manual dispatch; default-branch only; read-only
  permissions; `concurrency` (no cancel) + 15-minute timeout; production secrets
  injected only into the watchdog step; no caches/artifacts/debug.
- **`keepalive.yml`** — monthly heartbeat; no production secrets; minimal
  `contents: write`. **Residual risk:** GitHub may disable scheduled workflows after
  60 days of inactivity, and it is not guaranteed that a `GITHUB_TOKEN` push re-arms
  that timer. Do not treat the heartbeat as a guarantee; verify against current GitHub
  behavior and, if needed, have a human commit occasionally.

---

Fake identifiers only, everywhere. This is a public repository.
