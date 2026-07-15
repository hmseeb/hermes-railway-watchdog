"""Command-line entry point.

Wires configuration, the Railway and Hermes clients, the recovery orchestrator, and
notifications into a single run. Production dependencies are built from the environment;
tests inject a :class:`Runtime` to stay fully network-free.

Only public-safe text is ever emitted: opaque aliases, broad classifications, action
names, elapsed time, and pass/fail — all passed through the central redactor.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from .config import Target, WatchdogConfig, load_config
from .errors import ConfigError, WatchdogError
from .hermes import HermesClient
from .notify import Notifier, build_notifier_from_env
from .orchestrator import Orchestrator, RunResult
from .railway import RailwayClient
from .redaction import Redactor

PROG = "watchdog"


@dataclass
class Runtime:
    orchestrator: Orchestrator
    notifier: Notifier
    closeables: Sequence[object] = ()

    def close(self) -> None:
        """Best-effort close of every owned client; never raises."""
        for resource in self.closeables:
            close = getattr(resource, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: S110 - cleanup must not mask the run result
                    pass


RuntimeFactory = Callable[[WatchdogConfig, Redactor, bool], Runtime]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Secret-safe Railway + Hermes gateway watchdog.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Read and classify only; never mutate any service.",
    )
    parser.add_argument(
        "--service",
        metavar="ALIAS",
        default=None,
        help="Restrict to a single opaque service alias.",
    )
    return parser


def _default_runtime(config: WatchdogConfig, redactor: Redactor, dry_run: bool) -> Runtime:
    token = os.environ.get("RAILWAY_API_TOKEN")
    if not token:
        raise ConfigError("RAILWAY_API_TOKEN is not set")
    railway = RailwayClient(token)
    orchestrator = Orchestrator(
        config=config,
        railway=railway,
        hermes_factory=lambda t: HermesClient(t.health_url),
        redactor=redactor,
        now=lambda: datetime.now(UTC),
        monotonic=time.monotonic,
        sleep=time.sleep,
        dry_run=dry_run,
    )
    notifier = build_notifier_from_env(redactor)
    # The Railway client and the notifier's AgentMail client must be closed after the
    # run; Hermes clients are closed per-target by the orchestrator.
    return Runtime(orchestrator=orchestrator, notifier=notifier, closeables=(railway, notifier))


def render_summary(result: RunResult, redactor: Redactor, *, dry_run: bool) -> str:
    mode = "dry-run" if dry_run else "live"
    lines = [f"# Watchdog run ({mode})", ""]
    for o in result.outcomes:
        verdict = "PASS" if (o.recovered or o.deferred) else "FAIL"
        cls = o.classification.value if o.classification else "unknown"
        lines.append(
            f"- {o.alias}: {cls} | action={o.action} | "
            f"elapsed={o.elapsed_seconds:.2f}s | {verdict}"
        )
    unrecovered = result.unrecovered()
    lines.append("")
    lines.append(f"Result: {'FAIL' if unrecovered else 'PASS'} "
                 f"({len(unrecovered)} unrecovered / {len(result.outcomes)} targets)")
    return redactor.redact("\n".join(lines))


def _emit(summary: str) -> None:
    print(summary)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        try:
            with open(step_summary, "a", encoding="utf-8") as handle:
                handle.write(summary + "\n")
        except OSError:
            pass  # never fail a run because the summary file is unavailable


def _select(config: WatchdogConfig, alias: str | None) -> list[Target]:
    if alias is None:
        return list(config.targets)
    return [config.select_target(alias)]


def main(
    argv: Sequence[str] | None = None, *, runtime_factory: RuntimeFactory | None = None
) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = load_config()
    except WatchdogError as err:
        print(Redactor().redact_exc(err), file=sys.stderr)
        return 2

    redactor = Redactor(secrets=config.all_secret_values())

    try:
        targets = _select(config, args.service)
        runtime = (runtime_factory or _default_runtime)(config, redactor, args.dry_run)
    except WatchdogError as err:
        print(redactor.redact_exc(err), file=sys.stderr)
        return 2

    try:
        result = runtime.orchestrator.run(targets)
        _emit(render_summary(result, redactor, dry_run=args.dry_run))

        exit_code = result.exit_code
        if not args.dry_run:
            try:
                report = runtime.notifier.process(result)
            except WatchdogError:
                # Never surface a public traceback with notification internals; degrade
                # to a sanitized failure without breaking the recovery that already ran.
                print("notification delivery failed", file=sys.stderr)
                return max(exit_code, 1)
            if report.degraded:
                print("notification degraded: alerts could not be delivered", file=sys.stderr)
                exit_code = max(exit_code, 1)
        return exit_code
    finally:
        runtime.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
