"""Ordered, fail-safe cleanup for resources owned by one ASF session.

The small execution core is shared by ``open`` exit cleanup, ``stop``, and
``reset``:
resources are removed in the dependency order defined by ``asf.ownership``,
every attempted action is recorded and failures are aggregated. Ordinary
session cleanup preserves persistent volumes; the narrow ``reset_volumes``
entry point is reserved for the explicit reset command.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .errors import InfrastructureError, ValidationError
from .ownership import Resource, ResourceKind, ResourceLedger, teardown_sequence
from .podman import (
    ContainerInspection,
    ObjectKind,
    ObjectNotFoundError,
    PodmanClient,
    PodmanError,
)
from .process import CommandResult
from .residue import SessionResidue
from .session_lock import AcquiredSessionLock, SessionLockManager
from .subnets import reservation_path

__all__ = [
    "NETWORK_ATTEMPTS",
    "NETWORK_RETRY_DELAY",
    "CleanupError",
    "CleanupExecutor",
    "CleanupFailedError",
    "CleanupOutcome",
    "CleanupReport",
    "CleanupResult",
]


NETWORK_ATTEMPTS = 3
NETWORK_RETRY_DELAY = 0.5
_NETWORK_IN_USE_MARKERS = (
    "is being used",
    "has active endpoints",
    "in use",
)


class CleanupError(InfrastructureError):
    """Base class for cleanup execution failures."""


class CleanupFailedError(CleanupError):
    """Cleanup did not complete after all available actions ran."""

    def __init__(self, report: "CleanupReport") -> None:
        if not isinstance(report, CleanupReport):
            raise TypeError("report must be a CleanupReport")
        self.report = report
        parts: list[str] = []
        if report.failures:
            count = len(report.failures)
            noun = "resource" if count == 1 else "resources"
            parts.append(f"{count} failed {noun}")
        if report.inconclusive:
            count = len(report.inconclusive)
            noun = "lookup" if count == 1 else "lookups"
            parts.append(f"{count} unchecked {noun}")
        super().__init__("cleanup incomplete: " + ", ".join(parts))


class CleanupOutcome(str, Enum):
    REMOVED = "removed"
    ABSENT = "absent"
    PRESERVED = "preserved"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CleanupResult:
    resource: Resource
    outcome: CleanupOutcome
    detail: str = field(default="", repr=False)
    returncode: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.resource, Resource):
            raise TypeError("resource must be a Resource")
        if not isinstance(self.outcome, CleanupOutcome):
            raise TypeError("outcome must be a CleanupOutcome")
        if not isinstance(self.detail, str):
            raise TypeError("detail must be text")
        if self.returncode is not None and (
            isinstance(self.returncode, bool)
            or not isinstance(self.returncode, int)
        ):
            raise TypeError("returncode must be an integer or None")

    @property
    def succeeded(self) -> bool:
        return self.outcome is not CleanupOutcome.FAILED

    def to_json_dict(self) -> dict:
        """Return one JSON-serialisable cleanup action record.

        ``detail`` carries the already-redacted evidence line produced by the
        executor; raw secret material never reaches a CleanupResult.
        """

        return {
            "kind": self.resource.kind.value,
            "name": self.resource.name,
            "runtime": self.resource.runtime,
            "outcome": self.outcome.value,
            "detail": self.detail,
            "returncode": self.returncode,
        }


@dataclass(frozen=True, slots=True)
class CleanupReport:
    results: tuple[CleanupResult, ...]
    inconclusive: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "results", tuple(self.results))
        object.__setattr__(self, "inconclusive", tuple(self.inconclusive))
        if not all(isinstance(result, CleanupResult) for result in self.results):
            raise TypeError("results must contain CleanupResult values")
        if not all(isinstance(reason, str) for reason in self.inconclusive):
            raise TypeError("inconclusive reasons must be text")

    @property
    def failures(self) -> tuple[CleanupResult, ...]:
        return tuple(
            result
            for result in self.results
            if result.outcome is CleanupOutcome.FAILED
        )

    @property
    def removed(self) -> tuple[CleanupResult, ...]:
        return tuple(
            result
            for result in self.results
            if result.outcome is CleanupOutcome.REMOVED
        )

    @property
    def absent(self) -> tuple[CleanupResult, ...]:
        return tuple(
            result
            for result in self.results
            if result.outcome is CleanupOutcome.ABSENT
        )

    @property
    def preserved(self) -> tuple[CleanupResult, ...]:
        return tuple(
            result
            for result in self.results
            if result.outcome is CleanupOutcome.PRESERVED
        )

    @property
    def succeeded(self) -> bool:
        return not self.failures and not self.inconclusive

    @property
    def complete(self) -> bool:
        """Whether all conclusive cleanup actions succeeded."""

        return self.succeeded

    @property
    def exit_code(self) -> int:
        return 0 if self.succeeded else 1

    def raise_for_failures(self) -> None:
        if not self.succeeded:
            raise CleanupFailedError(self)

    def to_json_dict(self) -> dict:
        """Return one JSON-serialisable aggregate cleanup record."""

        return {
            "succeeded": self.succeeded,
            "summary": self.summary(),
            "inconclusive": list(self.inconclusive),
            "results": [result.to_json_dict() for result in self.results],
        }

    def summary(self) -> str:
        """Return one compact, deterministic cleanup summary."""

        parts = [f"{len(self.removed)} removed"]
        if self.absent:
            parts.append(f"{len(self.absent)} absent")
        if self.preserved:
            parts.append(f"{len(self.preserved)} preserved")
        if self.failures:
            parts.append(f"{len(self.failures)} failed")
        if self.inconclusive:
            parts.append(f"{len(self.inconclusive)} not checked")
        return ", ".join(parts)


@dataclass(frozen=True, slots=True)
class CleanupExecutor:
    podman: PodmanClient
    lock_manager: SessionLockManager
    stop_timeout: float = 5.0
    network_attempts: int = NETWORK_ATTEMPTS
    network_retry_delay: float = NETWORK_RETRY_DELAY
    sleeper: Callable[[float], None] = field(default=time.sleep, repr=False)
    on_result: Callable[[CleanupResult], None] | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")
        if not isinstance(self.lock_manager, SessionLockManager):
            raise TypeError("lock_manager must be a SessionLockManager")
        if isinstance(self.stop_timeout, bool) or not isinstance(
            self.stop_timeout, (int, float)
        ):
            raise TypeError("stop_timeout must be a number")
        timeout = float(self.stop_timeout)
        if not math.isfinite(timeout) or timeout < 0:
            raise ValidationError("stop_timeout must be finite and non-negative")
        object.__setattr__(self, "stop_timeout", timeout)
        if (
            isinstance(self.network_attempts, bool)
            or not isinstance(self.network_attempts, int)
            or self.network_attempts <= 0
        ):
            raise ValidationError("network_attempts must be a positive integer")
        if isinstance(self.network_retry_delay, bool) or not isinstance(
            self.network_retry_delay,
            (int, float),
        ):
            raise TypeError("network_retry_delay must be a number")
        retry_delay = float(self.network_retry_delay)
        if not math.isfinite(retry_delay) or retry_delay < 0:
            raise ValidationError(
                "network_retry_delay must be finite and non-negative"
            )
        object.__setattr__(self, "network_retry_delay", retry_delay)
        if not callable(self.sleeper):
            raise TypeError("sleeper must be callable")
        if self.on_result is not None and not callable(self.on_result):
            raise TypeError("on_result must be callable or None")

    def cleanup(
        self,
        resources: ResourceLedger | SessionResidue | Sequence[Resource],
        *,
        ledger: ResourceLedger | None = None,
        acquired_lock: AcquiredSessionLock | None = None,
        allow_inconclusive: bool = False,
    ) -> CleanupReport:
        """Attempt every cleanup action and return one immutable report.

        Failures never short-circuit later actions. By default an inconclusive
        residue scan is rejected before mutation. Recovery callers may opt in to
        cleaning the ownership-validated subset; the resulting report remains
        unsuccessful until every lookup is conclusive.
        """

        if not isinstance(allow_inconclusive, bool):
            raise TypeError("allow_inconclusive must be a Boolean")

        active_ledger: ResourceLedger | None = None
        inconclusive: tuple[str, ...] = ()
        if isinstance(resources, ResourceLedger):
            if ledger is not None:
                raise TypeError("ledger must not be supplied twice")
            active_ledger = resources
            created = resources.created
        elif isinstance(resources, SessionResidue):
            inconclusive = tuple(resources.unreadable)
            if inconclusive and not allow_inconclusive:
                raise CleanupError(
                    "refusing cleanup from an inconclusive residue scan"
                )
            active_ledger = ledger
            if ledger is not None and (
                ledger.runtime
                and ledger.runtime != resources.runtime
            ):
                raise ValidationError(
                    "cleanup ledger runtime does not match residue runtime"
                )
            created = resources.resources() + (
                ledger.created if ledger is not None else ()
            )
        else:
            if ledger is not None:
                raise TypeError(
                    "ledger is supported only with SessionResidue input"
                )
            if isinstance(resources, (str, bytes)):
                raise TypeError("resources must be a ledger or resource sequence")
            created = tuple(resources)
            if not all(isinstance(resource, Resource) for resource in created):
                raise TypeError("resources must contain Resource values")

        created = _deduplicate_resources(created)
        ordered = teardown_sequence(created)
        results: list[CleanupResult] = []
        for resource in ordered:
            try:
                result = self._cleanup_one(resource, acquired_lock=acquired_lock)
            except Exception as exc:  # aggregate operational failures; not signals
                result = CleanupResult(
                    resource,
                    CleanupOutcome.FAILED,
                    detail=str(exc),
                )
            results.append(result)
            if active_ledger is not None and result.outcome in {
                CleanupOutcome.REMOVED,
                CleanupOutcome.ABSENT,
            }:
                _forget_matching(active_ledger, resource)
            if self.on_result is not None:
                self.on_result(result)

        # Volumes are part of the ownership inventory but never of teardown.
        for resource in created:
            if resource.kind is ResourceKind.VOLUME:
                result = CleanupResult(resource, CleanupOutcome.PRESERVED)
                results.append(result)
                if self.on_result is not None:
                    self.on_result(result)

        return CleanupReport(tuple(results), inconclusive=inconclusive)

    def reset_volumes(
        self,
        resources: Sequence[Resource],
    ) -> CleanupReport:
        """Remove one runtime's explicitly declared persistent volumes.

        Ordinary cleanup always preserves volumes. ``reset`` is the only
        lifecycle command that may remove them, so it uses this narrow method
        rather than weakening :meth:`cleanup` with a general delete-volumes
        switch. All resources must belong to one runtime and use that runtime's
        deterministic ASF volume prefix.
        """

        if isinstance(resources, (str, bytes)):
            raise TypeError("volume resources must be a sequence")
        volumes = _deduplicate_resources(tuple(resources))
        if not volumes:
            return CleanupReport(())
        if any(resource.kind is not ResourceKind.VOLUME for resource in volumes):
            raise CleanupError("reset_volumes accepts only volume resources")

        runtimes = {resource.runtime for resource in volumes}
        if len(runtimes) != 1 or "" in runtimes:
            raise CleanupError("reset volumes must belong to one runtime")
        runtime = next(iter(runtimes))
        prefix = f"{self.lock_manager.identity.session_key(runtime)}-"
        for resource in volumes:
            if not resource.name.startswith(prefix):
                raise CleanupError(
                    "refusing to remove volume outside runtime ownership: "
                    f"{resource.name}"
                )

        present: list[Resource] = []
        results: list[CleanupResult] = []
        for resource in volumes:
            if self.podman.exists(resource.name, ObjectKind.VOLUME):
                present.append(resource)
            else:
                results.append(
                    CleanupResult(resource, CleanupOutcome.ABSENT)
                )

        if not present:
            return CleanupReport(tuple(results))

        command = self.podman.observe(
            (
                str(self.podman.engine),
                "volume",
                "rm",
                *(resource.name for resource in present),
            ),
            timeout=self.podman.timeout,
        )
        if command.succeeded:
            results.extend(
                CleanupResult(resource, CleanupOutcome.REMOVED)
                for resource in present
            )
            return CleanupReport(tuple(results))

        detail = _command_detail(command)
        for resource in present:
            try:
                exists = self.podman.exists(resource.name, ObjectKind.VOLUME)
            except PodmanError as exc:
                results.append(
                    CleanupResult(
                        resource,
                        CleanupOutcome.FAILED,
                        detail=f"{detail}; verification failed: {exc}",
                        returncode=command.returncode,
                    )
                )
                continue
            results.append(
                CleanupResult(
                    resource,
                    CleanupOutcome.FAILED if exists else CleanupOutcome.REMOVED,
                    detail=detail if exists else "",
                    returncode=command.returncode if exists else None,
                )
            )
        return CleanupReport(tuple(results))

    def cleanup_or_raise(
        self,
        resources: ResourceLedger | SessionResidue | Sequence[Resource],
        *,
        ledger: ResourceLedger | None = None,
        acquired_lock: AcquiredSessionLock | None = None,
        allow_inconclusive: bool = False,
    ) -> CleanupReport:
        report = self.cleanup(
            resources,
            ledger=ledger,
            acquired_lock=acquired_lock,
            allow_inconclusive=allow_inconclusive,
        )
        report.raise_for_failures()
        return report

    def _cleanup_one(
        self,
        resource: Resource,
        *,
        acquired_lock: AcquiredSessionLock | None,
    ) -> CleanupResult:
        kind = resource.kind
        if kind in {
            ResourceKind.RUNTIME_CONTAINER,
            ResourceKind.BROKER_CONTAINER,
            ResourceKind.PROXY_CONTAINER,
        }:
            return self._remove_container(resource)
        if kind in {
            ResourceKind.NETWORK_OBSERVER_CONTAINER,
            ResourceKind.GATEWAY_INIT_CONTAINER,
            ResourceKind.GATEWAY_CONTAINER,
        }:
            return self._remove_routed_container(resource)
        if kind is ResourceKind.SECRET:
            return self._remove_secret(resource)
        if kind is ResourceKind.BROKER_STATE:
            return self._remove_file(resource, self._expected_broker_state(resource))
        if kind is ResourceKind.NETWORK:
            return self._remove_network(resource)
        if kind is ResourceKind.SUBNET_RESERVATION:
            return self._remove_file(resource, self._expected_reservation(resource))
        if kind is ResourceKind.SESSION_LOCK:
            return self._remove_lock(resource, acquired_lock)
        if kind is ResourceKind.VOLUME:
            return CleanupResult(resource, CleanupOutcome.PRESERVED)
        raise CleanupError(f"unsupported cleanup resource kind: {kind.value}")

    def _remove_container(self, resource: Resource) -> CleanupResult:
        if not self.podman.exists(resource.name, ObjectKind.CONTAINER):
            return CleanupResult(resource, CleanupOutcome.ABSENT)
        result = self.podman.observe(
            (
                str(self.podman.engine),
                "rm",
                "--force",
                "--time",
                _format_timeout(self.stop_timeout),
                "--ignore",
                resource.name,
            ),
            timeout=self.stop_timeout + self.podman.timeout,
        )
        return self._classify_podman_removal(
            resource,
            result,
            ObjectKind.CONTAINER,
        )

    def _remove_routed_container(self, resource: Resource) -> CleanupResult:
        if not self.podman.exists(resource.name, ObjectKind.CONTAINER):
            return CleanupResult(resource, CleanupOutcome.ABSENT)

        stop = self.podman.observe(
            (
                str(self.podman.engine),
                "stop",
                "--ignore",
                "--time",
                _format_timeout(self.stop_timeout),
                resource.name,
            ),
            timeout=self.stop_timeout + self.podman.timeout,
        )
        if not stop.succeeded:
            inspection = self._inspect_after_failed_stop(resource, stop)
            if inspection is None:
                return CleanupResult(resource, CleanupOutcome.REMOVED)
            if inspection.running:
                return CleanupResult(
                    resource,
                    CleanupOutcome.FAILED,
                    detail=_command_detail(stop),
                    returncode=stop.returncode,
                )

        remove = self.podman.observe(
            (str(self.podman.engine), "rm", "--ignore", resource.name),
            timeout=self.podman.timeout,
        )
        return self._classify_podman_removal(
            resource,
            remove,
            ObjectKind.CONTAINER,
        )

    def _inspect_after_failed_stop(
        self,
        resource: Resource,
        result: CommandResult,
    ) -> ContainerInspection | None:
        try:
            return self.podman.inspect_container(resource.name)
        except ObjectNotFoundError:
            return None
        except PodmanError as exc:
            raise CleanupError(
                f"could not verify container after failed stop "
                f"({_command_detail(result)}): {exc}"
            ) from exc

    def _remove_secret(self, resource: Resource) -> CleanupResult:
        prefix = self.lock_manager.identity.broker_secret_prefix(resource.runtime)
        if not resource.name.startswith(prefix):
            raise CleanupError(
                f"refusing to remove secret outside runtime ownership: "
                f"{resource.name}"
            )
        if not self.podman.exists(resource.name, ObjectKind.SECRET):
            return CleanupResult(resource, CleanupOutcome.ABSENT)
        result = self.podman.observe(
            (str(self.podman.engine), "secret", "rm", resource.name),
            timeout=self.podman.timeout,
        )
        return self._classify_podman_removal(
            resource,
            result,
            ObjectKind.SECRET,
        )

    def _remove_network(self, resource: Resource) -> CleanupResult:
        names = self.lock_manager.identity.network_names(resource.runtime)
        allowed = {
            value
            for value in (
                names.internal,
                names.egress,
                names.provider,
                names.scan,
                names.routed_egress,
            )
            if value
        }
        if resource.name not in allowed:
            raise CleanupError(
                f"refusing to remove network outside runtime ownership: "
                f"{resource.name}"
            )
        if not self.podman.exists(resource.name, ObjectKind.NETWORK):
            return CleanupResult(resource, CleanupOutcome.ABSENT)
        last_result: CleanupResult | None = None
        for attempt in range(1, self.network_attempts + 1):
            command = self.podman.observe(
                (
                    str(self.podman.engine),
                    "network",
                    "rm",
                    "-f",
                    resource.name,
                ),
                timeout=self.podman.timeout,
            )
            last_result = self._classify_podman_removal(
                resource,
                command,
                ObjectKind.NETWORK,
            )
            if last_result.outcome is not CleanupOutcome.FAILED:
                return last_result
            if (
                attempt == self.network_attempts
                or not _network_still_in_use(command.stderr)
            ):
                return last_result
            self.sleeper(self.network_retry_delay)

        assert last_result is not None  # validated positive attempt count
        return last_result

    def _classify_podman_removal(
        self,
        resource: Resource,
        result: CommandResult,
        kind: ObjectKind,
    ) -> CleanupResult:
        if result.succeeded:
            return CleanupResult(resource, CleanupOutcome.REMOVED)
        try:
            still_exists = self.podman.exists(resource.name, kind)
        except PodmanError as exc:
            raise CleanupError(
                f"could not verify failed {kind.value} removal "
                f"({_command_detail(result)}): {exc}"
            ) from exc
        if not still_exists:
            return CleanupResult(resource, CleanupOutcome.REMOVED)
        return CleanupResult(
            resource,
            CleanupOutcome.FAILED,
            detail=_command_detail(result),
            returncode=result.returncode,
        )

    def _remove_file(self, resource: Resource, expected: Path) -> CleanupResult:
        path = Path(resource.name)
        if path != expected:
            raise CleanupError(
                f"refusing to remove unexpected {resource.kind.value} path: {path}"
            )
        try:
            path.lstat()
        except FileNotFoundError:
            return CleanupResult(resource, CleanupOutcome.ABSENT)
        except OSError as exc:
            raise CleanupError(f"cannot inspect {path}: {exc}") from exc
        if path.is_dir() and not path.is_symlink():
            raise CleanupError(f"refusing to remove directory as file state: {path}")
        try:
            path.unlink()
        except FileNotFoundError:
            return CleanupResult(resource, CleanupOutcome.ABSENT)
        except OSError as exc:
            raise CleanupError(f"cannot remove {path}: {exc}") from exc
        return CleanupResult(resource, CleanupOutcome.REMOVED)

    def _remove_lock(
        self,
        resource: Resource,
        acquired_lock: AcquiredSessionLock | None,
    ) -> CleanupResult:
        expected = self.lock_manager.identity.session_lock(resource.runtime)
        if Path(resource.name) != expected:
            raise CleanupError(
                f"refusing to remove unexpected session-lock path: {resource.name}"
            )
        if acquired_lock is not None:
            if (
                acquired_lock.runtime != resource.runtime
                or acquired_lock.path != expected
            ):
                raise CleanupError("acquired session lock does not match resource")
            self.lock_manager.release(acquired_lock)
            return CleanupResult(resource, CleanupOutcome.REMOVED)

        removed = self.lock_manager.remove_stale(resource.runtime)
        return CleanupResult(
            resource,
            CleanupOutcome.REMOVED if removed else CleanupOutcome.ABSENT,
        )

    def _expected_broker_state(self, resource: Resource) -> Path:
        return self.lock_manager.identity.broker_state(resource.runtime)

    def _expected_reservation(self, resource: Resource) -> Path:
        return reservation_path(
            self.lock_manager.identity.subnet_reservation_session(resource.runtime)
        )


def _format_timeout(value: float) -> str:
    return str(int(value)) if value.is_integer() else str(value)


def _command_detail(result: CommandResult) -> str:
    detail = result.stderr.strip() or result.stdout.strip()
    if detail:
        return f"status {result.returncode}: {detail}"
    return f"status {result.returncode}: {result.command}"


def _network_still_in_use(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in _NETWORK_IN_USE_MARKERS)


def _deduplicate_resources(
    resources: Sequence[Resource],
) -> tuple[Resource, ...]:
    seen: set[tuple[ResourceKind, str]] = set()
    ordered: list[Resource] = []
    for resource in resources:
        key = (resource.kind, resource.name)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(resource)
    return tuple(ordered)


def _forget_matching(ledger: ResourceLedger, resource: Resource) -> None:
    for entry in ledger.created:
        if entry.kind is resource.kind and entry.name == resource.name:
            ledger.forget(entry)
            return
