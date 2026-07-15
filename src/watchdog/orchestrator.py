"""Recovery orchestration.

For each selected target: probe Railway + Hermes, classify, and (unless dry-run) run
the bounded recovery appropriate to the classification. Guarantees:

- Healthy targets are never mutated.
- A fresh-state recheck runs immediately before any mutation (race avoidance).
- Each mutation (deployment restart, gateway restart) happens at most once per run.
- Per-target recovery time is bounded by a deadline and by attempt caps.
- Targets are processed concurrently with a hard cap (default 3), each isolated.
- The run exits non-zero if any target remains unrecovered.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from .config import Target, WatchdogConfig
from .errors import HermesError
from .hermes import HealthResult
from .http import Budget, Deadline
from .railway import DeploymentStatus, ServiceStatus
from .redaction import Redactor
from .state import Classification, HealthProbe, classify


class RailwayLike(Protocol):
    def get_service_status(
        self, project_id: str, environment_id: str, service_id: str,
        *, deadline: Deadline | None = None,
    ) -> ServiceStatus: ...

    def restart_current_deployment(
        self, deployment_id: str, *, deadline: Deadline | None = None
    ) -> bool: ...


class HermesLike(Protocol):
    def check_health(self, *, deadline: Deadline | None = None) -> HealthResult: ...

    def restart_gateway(
        self, username: str, password: str, *, deadline: Deadline | None = None
    ) -> bool: ...


@dataclass(frozen=True)
class TargetOutcome:
    alias: str
    classification: Classification | None
    action: str  # "none" | "gateway_restart" | "container_restart"
    recovered: bool
    deferred: bool
    elapsed_seconds: float
    error: str | None


@dataclass(frozen=True)
class RunResult:
    outcomes: tuple[TargetOutcome, ...]

    @property
    def exit_code(self) -> int:
        return 0 if all(o.recovered or o.deferred for o in self.outcomes) else 1

    def unrecovered(self) -> list[TargetOutcome]:
        return [o for o in self.outcomes if not o.recovered and not o.deferred]


@dataclass(frozen=True)
class _Recovery:
    recovered: bool
    action: str
    deferred: bool


class Orchestrator:
    def __init__(
        self,
        *,
        config: WatchdogConfig,
        railway: RailwayLike,
        hermes_factory: Callable[[Target], HermesLike],
        redactor: Redactor,
        now: Callable[[], datetime],
        monotonic: Callable[[], float],
        sleep: Callable[[float], None],
        dry_run: bool = False,
        transition_threshold: timedelta = timedelta(minutes=15),
        per_target_deadline: float | None = 600.0,
        health_retries: int = 2,
        wait_attempts: int = 20,
        wait_interval: float = 3.0,
        concurrency: int = 3,
    ) -> None:
        self._config = config
        self._railway = railway
        self._hermes_factory = hermes_factory
        self._redactor = redactor
        self._now = now
        self._monotonic = monotonic
        self._sleep = sleep
        self._dry_run = dry_run
        self._threshold = transition_threshold
        self._deadline = per_target_deadline
        self._health_retries = health_retries
        self._wait_attempts = wait_attempts
        self._wait_interval = wait_interval
        self._concurrency = concurrency

    # -- public ---------------------------------------------------------------

    def run(self, targets: Sequence[Target] | None = None) -> RunResult:
        selected = list(targets if targets is not None else self._config.targets)
        if not selected:
            return RunResult(())
        workers = max(1, min(self._concurrency, len(selected)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            outcomes = list(pool.map(self._recover_one, selected))
        return RunResult(tuple(outcomes))

    # -- per target -----------------------------------------------------------

    def _recover_one(self, target: Target) -> TargetOutcome:
        start = self._monotonic()
        budget = Budget(self._monotonic, self._deadline) if self._deadline is not None else None
        cls: Classification | None = None
        hermes: HermesLike | None = None
        try:
            hermes = self._hermes_factory(target)
            _, _, cls = self._probe(target, hermes, budget)
            if self._dry_run:
                return self._done(target, cls, "none",
                                  cls is Classification.HEALTHY,
                                  cls is Classification.TRANSITIONAL, start)
            if cls is Classification.HEALTHY:
                return self._done(target, cls, "none", True, False, start)
            if cls is Classification.TRANSITIONAL:
                return self._done(target, cls, "none", False, True, start)
            if cls is Classification.GATEWAY_ONLY_FAILURE:
                rec = self._recover_gateway_only(target, hermes, budget)
            else:
                rec = self._recover_container(target, hermes, budget)
            return self._done(target, cls, rec.action, rec.recovered, rec.deferred, start)
        except (SystemExit, KeyboardInterrupt):
            raise  # never swallow interpreter shutdown signals
        except Exception as err:
            # Any unexpected failure (parser, factory, transport, bug) is isolated to
            # this target and sanitized — other targets keep their outcomes.
            return self._done(target, cls, "none", False, False, start,
                              error=self._redactor.redact_exc(err))
        finally:
            if hermes is not None:
                self._safe_close(hermes)

    @staticmethod
    def _safe_close(hermes: HermesLike) -> None:
        close = getattr(hermes, "close", None)
        if not callable(close):
            return
        try:
            close()
        except Exception:  # noqa: S110 - a close failure must not override the result
            pass

    def _done(
        self,
        target: Target,
        cls: Classification | None,
        action: str,
        recovered: bool,
        deferred: bool,
        start: float,
        error: str | None = None,
    ) -> TargetOutcome:
        return TargetOutcome(
            alias=target.alias,
            classification=cls,
            action=action,
            recovered=recovered,
            deferred=deferred,
            elapsed_seconds=round(self._monotonic() - start, 3),
            error=error,
        )

    # -- recovery strategies --------------------------------------------------

    def _recover_gateway_only(
        self, target: Target, hermes: HermesLike, budget: Budget | None
    ) -> _Recovery:
        # Fresh-state recheck immediately before mutating.
        _, _, cls = self._probe(target, hermes, budget)
        if cls is Classification.HEALTHY:
            return _Recovery(True, "none", False)
        if cls is Classification.TRANSITIONAL:
            return _Recovery(False, "none", True)
        if cls is Classification.CONTAINER_FAILURE:
            return self._recover_container(target, hermes, budget)
        return self._do_gateway_restart(target, hermes, budget)

    def _recover_container(
        self, target: Target, hermes: HermesLike, budget: Budget | None
    ) -> _Recovery:
        # Fresh-state recheck immediately before mutating.
        status, _, cls = self._probe(target, hermes, budget)
        if cls is Classification.HEALTHY:
            return _Recovery(True, "none", False)
        if cls is Classification.TRANSITIONAL:
            return _Recovery(False, "none", True)
        if cls is Classification.GATEWAY_ONLY_FAILURE:
            return self._do_gateway_restart(target, hermes, budget)

        # Restart the latest deployment id (preserved even with no active deployment),
        # so COMPLETED/stopped services can be restarted onto their latest image.
        deployment_id = status.restartable_deployment_id
        if deployment_id is None or self._expired(budget):
            return _Recovery(False, "none", False)
        ok = self._railway.restart_current_deployment(
            deployment_id, deadline=budget
        )
        if not ok:  # a false result is a mutation failure, never a silent success
            return _Recovery(False, "container_restart", False)
        if not self._wait_container_up(target, hermes, budget) or self._expired(budget):
            return _Recovery(False, "container_restart", False)

        # Fresh full probe before the gateway mutation (race avoidance).
        _, _, cls2 = self._probe(target, hermes, budget)
        if cls2 is Classification.HEALTHY:
            return _Recovery(True, "container_restart", False)  # already healthy → skip gateway
        if cls2 is Classification.TRANSITIONAL:
            return _Recovery(False, "container_restart", True)
        if cls2 is Classification.CONTAINER_FAILURE:
            return _Recovery(False, "container_restart", False)  # regressed → no second mutation
        return self._do_gateway_restart(target, hermes, budget, action="container_restart")

    def _do_gateway_restart(
        self,
        target: Target,
        hermes: HermesLike,
        budget: Budget | None,
        *,
        action: str = "gateway_restart",
    ) -> _Recovery:
        if self._expired(budget):
            return _Recovery(False, "none" if action == "gateway_restart" else action, False)
        ok = hermes.restart_gateway(
            target.admin_username, target.admin_password, deadline=budget
        )
        if not ok:  # honor the boolean: a false restart is a failure
            return _Recovery(False, action, False)
        if self._expired(budget):  # returned after budget → fail without further work
            return _Recovery(False, action, False)
        _, _, verify = self._probe(target, hermes, budget)
        return _Recovery(verify is Classification.HEALTHY, action, False)

    def _wait_container_up(
        self, target: Target, hermes: HermesLike, budget: Budget | None
    ) -> bool:
        for attempt in range(self._wait_attempts):
            if self._expired(budget):
                return False
            status = self._railway.get_service_status(
                self._config.project_id, self._config.environment_id, target.service_id,
                deadline=budget,
            )
            health = self._health_probe(hermes, budget)
            if (
                status.instance_running
                and status.latest_status is DeploymentStatus.SUCCESS
                and not status.stopped
                and health.reachable
            ):
                return True
            if attempt < self._wait_attempts - 1:
                self._sleep_clipped(budget, self._wait_interval)
        return False

    # -- probing --------------------------------------------------------------

    def _probe(
        self, target: Target, hermes: HermesLike, budget: Budget | None
    ) -> tuple[ServiceStatus, HealthProbe, Classification]:
        status = self._railway.get_service_status(
            self._config.project_id, self._config.environment_id, target.service_id,
            deadline=budget,
        )
        health = self._health_probe(hermes, budget)
        cls = classify(status, health, now=self._now(), transition_threshold=self._threshold)
        return status, health, cls

    def _health_probe(self, hermes: HermesLike, budget: Budget | None) -> HealthProbe:
        for attempt in range(self._health_retries + 1):
            if self._expired(budget):
                break
            try:
                return HealthProbe(
                    reachable=True, result=hermes.check_health(deadline=budget)
                )
            except HermesError:
                if attempt < self._health_retries:
                    self._sleep_clipped(budget, self._wait_interval)
        return HealthProbe(reachable=False, result=None)

    # -- budget helpers -------------------------------------------------------

    @staticmethod
    def _expired(budget: Budget | None) -> bool:
        return budget is not None and budget.expired()

    def _sleep_clipped(self, budget: Budget | None, interval: float) -> None:
        duration = budget.clip(interval) if budget is not None else interval
        if duration > 0:
            self._sleep(duration)
