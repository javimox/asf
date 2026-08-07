"""Stop orchestration and stale-session recovery.

This module coordinates existing discovery, ownership, cleanup, and lock
components. It deliberately contains no Podman parsing or filesystem-removal
logic of its own.

Normal output remains compatible with the former Bash command. Safety-related
failures are stricter: success is reported only after a conclusive post-cleanup
scan proves that no removable ASF-owned resource remains.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path

from .atomic import write_text_atomic
from .cleanup import CleanupError, CleanupExecutor, CleanupOutcome, CleanupReport
from .egress_evidence import EgressEvidenceError, finalize_egress_session
from .errors import InfrastructureError, UsageError, ValidationError
from .ownership import Resource, ResourceKind, teardown_sequence
from .paths import RepoPaths
from .podman import PodmanClient
from .residue import ResidueScanner, SessionResidue
from .session_lock import AcquiredSessionLock
from .session import (
    RuntimeSession,
    SessionDiscovery,
    SessionStatus,
    UnknownRuntimeError,
)

__all__ = [
    "StopCommandResult",
    "StopEmitter",
    "StopDisposition",
    "StopError",
    "StopEvent",
    "StopReport",
    "StopService",
    "StopStream",
    "StopUsageError",
    "emit_stop_completion",
    "run_stop_command",
    "stop_service_from_environment",
    "select_runtimes",
    "stop_runtime",
]

_BLUE = "\033[0;34m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[1;33m"
_RED = "\033[0;31m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_DEFAULT_VERIFY_ATTEMPTS = 20
_DEFAULT_VERIFY_DELAY = 0.5


class StopError(InfrastructureError):
    """A session could not be stopped or verified safely."""


class StopUsageError(UsageError):
    """The stop command invocation is invalid."""


class StopStream(str, Enum):
    STDOUT = "stdout"
    STDERR = "stderr"


@dataclass(frozen=True, slots=True)
class StopEvent:
    stream: StopStream
    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.stream, StopStream):
            raise TypeError("stop event stream must be a StopStream")
        if not isinstance(self.text, str):
            raise TypeError("stop event text must be text")


class StopDisposition(str, Enum):
    STOPPED = "stopped"
    ALREADY_STOPPED = "already-stopped"
    STALE_RECOVERED = "stale-recovered"
    PARTIALLY_CLEANED = "partially-cleaned"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"

    @property
    def succeeded(self) -> bool:
        return self in {
            StopDisposition.STOPPED,
            StopDisposition.ALREADY_STOPPED,
            StopDisposition.STALE_RECOVERED,
        }


@dataclass(frozen=True, slots=True)
class StopReport:
    runtime: str
    previous_status: SessionStatus
    before: SessionResidue
    cleanup: CleanupReport
    remaining: SessionResidue
    disposition: StopDisposition
    elapsed_seconds: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.runtime, str) or not self.runtime:
            raise ValidationError("stop report runtime must be non-empty text")
        if not isinstance(self.previous_status, SessionStatus):
            raise TypeError("previous_status must be a SessionStatus")
        if not isinstance(self.before, SessionResidue):
            raise TypeError("before must be a SessionResidue")
        if not isinstance(self.cleanup, CleanupReport):
            raise TypeError("cleanup must be a CleanupReport")
        if not isinstance(self.remaining, SessionResidue):
            raise TypeError("remaining must be a SessionResidue")
        if not isinstance(self.disposition, StopDisposition):
            raise TypeError("disposition must be a StopDisposition")
        if (
            isinstance(self.elapsed_seconds, bool)
            or not isinstance(self.elapsed_seconds, int)
            or self.elapsed_seconds < 0
        ):
            raise ValidationError("elapsed_seconds must be a non-negative integer")

    @property
    def succeeded(self) -> bool:
        return self.disposition.succeeded

    def to_json_dict(self) -> dict:
        """Return one JSON-serialisable session teardown record."""

        def residue(value: SessionResidue) -> dict:
            return {
                "resources": [
                    {
                        "kind": resource.kind.value,
                        "name": resource.name,
                    }
                    for resource in value.resources()
                ],
                "unreadable": list(value.unreadable),
            }

        return {
            "runtime": self.runtime,
            "previous_status": self.previous_status.value,
            "disposition": self.disposition.value,
            "succeeded": self.succeeded,
            "elapsed_seconds": self.elapsed_seconds,
            "before": residue(self.before),
            "cleanup": self.cleanup.to_json_dict(),
            "remaining": residue(self.remaining),
        }

    @property
    def was_running(self) -> bool:
        return self.previous_status is SessionStatus.RUNNING

    @property
    def had_residue(self) -> bool:
        return bool(self.before.resources())

    def summary(self) -> str:
        return f"{self.runtime}: {self.disposition.value} ({self.cleanup.summary()})"


@dataclass(frozen=True, slots=True)
class StopCommandResult:
    reports: tuple[StopReport, ...] = ()
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    events: tuple[StopEvent, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "reports", tuple(self.reports))
        object.__setattr__(self, "events", tuple(self.events))
        if not all(isinstance(report, StopReport) for report in self.reports):
            raise TypeError("reports must contain StopReport values")
        if not all(isinstance(event, StopEvent) for event in self.events):
            raise TypeError("events must contain StopEvent values")
        if (
            isinstance(self.returncode, bool)
            or not isinstance(self.returncode, int)
            or self.returncode < 0
        ):
            raise ValidationError("returncode must be a non-negative integer")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("stdout and stderr must be text")


@dataclass(slots=True)
class StopEmitter:
    sink: Callable[[StopEvent], None] | None = field(default=None, repr=False)
    events: list[StopEvent] = field(default_factory=list, repr=False)

    def emit(self, stream: StopStream, text: str) -> None:
        event = StopEvent(stream, text)
        self.events.append(event)
        if self.sink is not None:
            try:
                self.sink(event)
            except BrokenPipeError:
                # Output consumers must not be able to interrupt teardown.
                self.sink = None

    def out(self, text: str) -> None:
        self.emit(StopStream.STDOUT, text)

    def err(self, text: str) -> None:
        self.emit(StopStream.STDERR, text)

    @property
    def stdout(self) -> str:
        return "".join(
            event.text
            for event in self.events
            if event.stream is StopStream.STDOUT
        )

    @property
    def stderr(self) -> str:
        return "".join(
            event.text
            for event in self.events
            if event.stream is StopStream.STDERR
        )


# Groups reproduce the accepted Bash report order and labels. Reservation and
# lock cleanup remain silent, as in Bash.
_GROUPS: tuple[tuple[str, tuple[ResourceKind, ...], str, str], ...] = (
    (
        "runtime",
        (ResourceKind.RUNTIME_CONTAINER,),
        "Stopping and removing {runtime} container {dim}(grace: {grace}s){reset}",
        "Agent container removed",
    ),
    (
        "broker",
        (ResourceKind.BROKER_CONTAINER,),
        "Stopping and removing LiteLLM broker {dim}(grace: {grace}s){reset}",
        "LiteLLM broker removed",
    ),
    (
        "secret",
        (ResourceKind.SECRET,),
        "Removing temporary provider secret",
        "Temporary provider secret removed",
    ),
    (
        "broker-state",
        (ResourceKind.BROKER_STATE,),
        "Removing temporary broker state",
        "Temporary broker state removed",
    ),
    (
        "proxy",
        (ResourceKind.PROXY_CONTAINER,),
        "Stopping and removing egress proxy",
        "Egress proxy removed",
    ),
    (
        "gateway",
        (ResourceKind.GATEWAY_INIT_CONTAINER, ResourceKind.GATEWAY_CONTAINER),
        "Stopping and removing routed gateway",
        "Routed gateway removed",
    ),
    (
        "networks",
        (ResourceKind.NETWORK,),
        "Removing session networks",
        "Session networks removed",
    ),
    ("reservation", (ResourceKind.SUBNET_RESERVATION,), "", ""),
    ("lock", (ResourceKind.SESSION_LOCK,), "", ""),
)

_ANNOUNCE_ABSENT = {
    "runtime": "{runtime} container: already absent",
    "broker": "LiteLLM broker: already absent",
}
_STATUS_PREFIX = re.compile(r"^status \d+: ")


@dataclass(frozen=True, slots=True)
class StopService:
    discovery: SessionDiscovery
    scanner: ResidueScanner
    cleanup: CleanupExecutor
    verify_attempts: int = _DEFAULT_VERIFY_ATTEMPTS
    verify_delay: float = _DEFAULT_VERIFY_DELAY
    sleeper: Callable[[float], None] = field(default=time.sleep, repr=False)
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)
    # Optional: enables the persisted per-session cleanup record. Reports are
    # diagnostic evidence only and never change a cleanup verdict.
    paths: RepoPaths | None = None

    def __post_init__(self) -> None:
        if self.paths is not None and not isinstance(self.paths, RepoPaths):
            raise TypeError("paths must be a RepoPaths or None")
        if not isinstance(self.discovery, SessionDiscovery):
            raise TypeError("discovery must be a SessionDiscovery")
        if not isinstance(self.scanner, ResidueScanner):
            raise TypeError("scanner must be a ResidueScanner")
        if not isinstance(self.cleanup, CleanupExecutor):
            raise TypeError("cleanup must be a CleanupExecutor")
        if (
            isinstance(self.verify_attempts, bool)
            or not isinstance(self.verify_attempts, int)
            or self.verify_attempts <= 0
        ):
            raise ValidationError("verify_attempts must be a positive integer")
        if isinstance(self.verify_delay, bool) or not isinstance(
            self.verify_delay, (int, float)
        ):
            raise TypeError("verify_delay must be a number")
        delay = float(self.verify_delay)
        if not math.isfinite(delay) or delay < 0:
            raise ValidationError("verify_delay must be finite and non-negative")
        object.__setattr__(self, "verify_delay", delay)
        if not callable(self.sleeper) or not callable(self.clock):
            raise TypeError("sleeper and clock must be callable")

    @classmethod
    def from_paths(
        cls,
        paths: RepoPaths,
        *,
        podman: PodmanClient | None = None,
        stop_timeout: float = 2.0,
        verify_attempts: int = _DEFAULT_VERIFY_ATTEMPTS,
        verify_delay: float = _DEFAULT_VERIFY_DELAY,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> "StopService":
        client = PodmanClient() if podman is None else podman
        discovery = SessionDiscovery.from_paths(paths, podman=client)
        return cls(
            discovery,
            ResidueScanner(discovery),
            CleanupExecutor(
                client,
                discovery.lock_manager(),
                stop_timeout=stop_timeout,
            ),
            verify_attempts=verify_attempts,
            verify_delay=verify_delay,
            sleeper=sleeper,
            clock=clock,
            paths=paths,
        )

    def target_runtimes(self, requested: str | None = None) -> tuple[str, ...]:
        return select_runtimes(requested, self.discovery)

    def stop_runtime(
        self,
        runtime: str,
        *,
        emitter: StopEmitter | None = None,
        acquired_lock: AcquiredSessionLock | None = None,
    ) -> StopReport:
        """Stop one session and persist its cleanup record, best-effort."""

        report = self._stop_runtime(
            runtime,
            emitter=emitter,
            acquired_lock=acquired_lock,
        )
        if report.succeeded:
            self._finalize_egress_evidence(report.runtime, emitter)
        self._persist_stop_report(report, emitter)
        return report

    def _finalize_egress_evidence(
        self,
        runtime: str,
        emitter: StopEmitter | None,
    ) -> None:
        if self.paths is None:
            return
        try:
            evidence = finalize_egress_session(self.paths, runtime)
        except (OSError, ValidationError, EgressEvidenceError) as exc:
            if emitter is not None:
                emitter.err(
                    f"  {_YELLOW}⚠ Could not record egress evidence "
                    f"({exc}){_RESET}\n"
                )
            return
        if evidence is None or emitter is None:
            return
        denied = sum(evidence.denied_connects.values())
        noun = "CONNECT" if evidence.connect_attempts == 1 else "CONNECTs"
        emitter.out(
            f"  {_GREEN}✓{_RESET} Egress evidence recorded "
            f"{_DIM}({evidence.connect_attempts} agent {noun}; "
            f"{denied} denied){_RESET}\n"
        )
        if evidence.malformed_lines:
            emitter.err(
                f"  {_YELLOW}⚠ Ignored {evidence.malformed_lines} malformed "
                f"Caddy access-log line(s){_RESET}\n"
            )

    def _persist_stop_report(
        self,
        report: StopReport,
        emitter: StopEmitter | None,
    ) -> None:
        if self.paths is None:
            return
        try:
            destination = self.paths.session_artifact(
                report.runtime, "cleanup-report.json"
            )
            payload = (
                json.dumps(report.to_json_dict(), indent=2, sort_keys=True) + "\n"
            )
            write_text_atomic(destination, payload)
        except (OSError, ValidationError) as exc:
            if emitter is not None:
                emitter.err(
                    f"  {_YELLOW}⚠ Could not persist cleanup report "
                    f"({exc}){_RESET}\n"
                )

    def _stop_runtime(
        self,
        runtime: str,
        *,
        emitter: StopEmitter | None = None,
        acquired_lock: AcquiredSessionLock | None = None,
    ) -> StopReport:
        runtime = self.discovery.validate_runtime(runtime)
        if acquired_lock is not None:
            if not isinstance(acquired_lock, AcquiredSessionLock):
                raise TypeError("acquired_lock must be an AcquiredSessionLock or None")
            if acquired_lock.runtime != runtime:
                raise ValidationError("acquired session lock runtime does not match")
        started = self.clock()
        session = self.discovery.session(runtime)
        before = self.scanner.scan(runtime)
        if session.unreadable:
            before = replace(
                before,
                unreadable=tuple(dict.fromkeys(before.unreadable + session.unreadable)),
            )
        previous_status = _effective_status(session, before)

        if emitter is not None:
            emitter.out("\n")
            emitter.out(f"{_BLUE}Cleaning up ASF session...{_RESET}\n")

        if (
            previous_status is SessionStatus.STARTING
            and acquired_lock is None
        ):
            reason = "session lock is still being claimed by a live opener"
            cleanup = CleanupReport((), inconclusive=(reason,))
            return StopReport(
                runtime,
                previous_status,
                before,
                cleanup,
                before,
                StopDisposition.INCONCLUSIVE,
                _elapsed_seconds(started, self.clock()),
            )

        # An external stop must not steal a live opener's lock.  The open
        # lifecycle may provide the exact ownership token after Bash ``exec``s
        # into Python; only that path is allowed to remove the active lock.
        cleanup_input = before
        if before.active_lock and acquired_lock is None:
            cleanup_input = replace(before, lock=None)

        if (
            acquired_lock is None
            and before.inconclusive
            and (before.running or before.active_lock)
        ):
            cleanup = CleanupReport((), inconclusive=before.unreadable)
            return StopReport(
                runtime,
                previous_status,
                before,
                cleanup,
                before,
                StopDisposition.INCONCLUSIVE,
                _elapsed_seconds(started, self.clock()),
            )

        cleanup = self._cleanup_grouped(
            runtime,
            cleanup_input.resources(),
            inconclusive=before.unreadable if before.inconclusive else (),
            emitter=emitter,
            acquired_lock=acquired_lock,
        )
        remaining = self._verify_absent(runtime)
        disposition = _disposition(previous_status, before, cleanup, remaining)
        return StopReport(
            runtime,
            previous_status,
            before,
            cleanup,
            remaining,
            disposition,
            _elapsed_seconds(started, self.clock()),
        )

    def _cleanup_grouped(
        self,
        runtime: str,
        resources: Sequence[Resource],
        *,
        inconclusive: tuple[str, ...],
        emitter: StopEmitter | None,
        acquired_lock: AcquiredSessionLock | None = None,
    ) -> CleanupReport:
        ordered = teardown_sequence(tuple(resources))
        results = []
        grace = _format_timeout(self.cleanup.stop_timeout)

        for key, kinds, label, success in _GROUPS:
            group = tuple(resource for resource in ordered if resource.kind in kinds)
            if not group:
                absent = _ANNOUNCE_ABSENT.get(key)
                if absent is not None and emitter is not None:
                    emitter.out(
                        f"  {_DIM}{absent.format(runtime=runtime)}{_RESET}\n"
                    )
                continue

            rendered = label.format(
                runtime=runtime,
                grace=grace,
                dim=_DIM,
                reset=_RESET,
            )
            if rendered and emitter is not None:
                emitter.out(f"  {_BLUE}→{_RESET} {rendered}\n")

            group_started = self.clock()
            try:
                report = self.cleanup.cleanup(
                    group,
                    acquired_lock=(
                        acquired_lock
                        if any(
                            resource.kind is ResourceKind.SESSION_LOCK
                            for resource in group
                        )
                        else None
                    ),
                )
            except CleanupError as exc:
                report = CleanupReport((), inconclusive=(str(exc),))
            results.extend(report.results)
            elapsed = _elapsed_seconds(group_started, self.clock())

            if report.succeeded:
                if rendered and emitter is not None:
                    emitter.out(
                        f"  {_GREEN}✓{_RESET} {success} "
                        f"{_DIM}({elapsed}s){_RESET}\n"
                    )
                continue

            if rendered and emitter is not None:
                emitter.err(
                    f"  {_YELLOW}⚠ {rendered} failed; continuing cleanup.{_RESET}\n"
                )
                for failure in report.failures:
                    detail = _command_output(failure.detail)
                    for line in detail.splitlines() or ("cleanup failed",):
                        emitter.err(f"    {line}\n")

        return CleanupReport(tuple(results), inconclusive=inconclusive)

    def _verify_absent(self, runtime: str) -> SessionResidue:
        last: SessionResidue | None = None
        for attempt in range(self.verify_attempts):
            current = self.scanner.scan(runtime)
            last = current
            if current.empty:
                return current
            if attempt + 1 < self.verify_attempts:
                self.sleeper(self.verify_delay)
        assert last is not None
        return last


def select_runtimes(
    requested: str | None,
    discovery: SessionDiscovery,
) -> tuple[str, ...]:
    if requested:
        return (discovery.validate_runtime(requested),)
    running = discovery.running_runtimes()
    return running or discovery.known_runtimes()


def stop_runtime(
    runtime: str,
    *,
    service: StopService,
    event_sink: Callable[[StopEvent], None] | None = None,
) -> StopReport:
    """Thin public helper around the canonical :class:`StopService`."""

    emitter = StopEmitter(event_sink)
    emitter.out(f"{_BLUE}Stopping {runtime} session...{_RESET}\n")
    report = service.stop_runtime(runtime, emitter=emitter)
    emit_stop_completion(report, emitter)
    return report


def stop_service_from_environment(
    paths: RepoPaths,
    *,
    podman: PodmanClient | None = None,
) -> StopService:
    """Build the canonical stop service from validated lifecycle settings."""

    timeout_text = os.environ.get("ASF_SHUTDOWN_TIMEOUT", "2")
    if re.fullmatch(r"[0-9]+", timeout_text) is None:
        raise ValidationError(
            "ASF_SHUTDOWN_TIMEOUT must be a non-negative integer."
        )
    attempts_text = os.environ.get(
        "ASF_STOP_VERIFY_ATTEMPTS", str(_DEFAULT_VERIFY_ATTEMPTS)
    )
    delay_text = os.environ.get(
        "ASF_STOP_VERIFY_DELAY", str(_DEFAULT_VERIFY_DELAY)
    )
    if re.fullmatch(r"[1-9][0-9]*", attempts_text) is None:
        raise ValidationError(
            "ASF_STOP_VERIFY_ATTEMPTS must be a positive integer."
        )
    try:
        verify_delay = float(delay_text)
    except ValueError:
        verify_delay = math.nan
    if not math.isfinite(verify_delay) or verify_delay < 0:
        raise ValidationError(
            "ASF_STOP_VERIFY_DELAY must be a finite non-negative number."
        )
    return StopService.from_paths(
        paths,
        podman=podman,
        stop_timeout=float(timeout_text),
        verify_attempts=int(attempts_text),
        verify_delay=verify_delay,
    )


def run_stop_command(
    arguments: Sequence[str],
    paths: RepoPaths,
    *,
    podman: PodmanClient | None = None,
    require_available: bool = True,
    service: StopService | None = None,
    event_sink: Callable[[StopEvent], None] | None = None,
) -> StopCommandResult:
    """Run ``sandbox.sh stop`` and return one structured command result."""

    if isinstance(arguments, (str, bytes)):
        raise TypeError("stop arguments must be a sequence")
    argv = tuple(arguments)
    if not argv or argv[0] != "stop":
        raise StopUsageError("unsupported stop command")

    client = PodmanClient() if podman is None else podman
    if require_available:
        client.require_available()
    if service is None:
        try:
            active = stop_service_from_environment(paths, podman=client)
        except ValidationError as exc:
            return StopCommandResult(returncode=1, stderr=f"{exc}\n")
    else:
        active = service

    emitter = StopEmitter(event_sink)
    requested = argv[1] if len(argv) > 1 else ""
    try:
        runtimes = active.target_runtimes(requested or None)
    except UnknownRuntimeError as exc:
        emitter.out(_unknown_runtime_output(exc.runtime, exc.available))
        return StopCommandResult(
            returncode=1,
            stdout=emitter.stdout,
            stderr=emitter.stderr,
            events=tuple(emitter.events),
        )

    reports: list[StopReport] = []
    command_failed = False
    for runtime in runtimes:
        emitter.out(f"{_BLUE}Stopping {runtime} session...{_RESET}\n")
        try:
            report = active.stop_runtime(runtime, emitter=emitter)
        except (InfrastructureError, ValidationError) as exc:
            command_failed = True
            emitter.err(
                f"{_RED}ASF session cleanup failed for {runtime}.{_RESET}\n"
                f"  {exc}\n"
            )
            continue
        reports.append(report)
        emit_stop_completion(report, emitter)

    return StopCommandResult(
        reports=tuple(reports),
        returncode=(
            1
            if command_failed or not all(report.succeeded for report in reports)
            else 0
        ),
        stdout=emitter.stdout,
        stderr=emitter.stderr,
        events=tuple(emitter.events),
    )


def _effective_status(
    session: RuntimeSession,
    residue: SessionResidue,
) -> SessionStatus:
    if session.status in {SessionStatus.AMBIGUOUS, SessionStatus.UNREADABLE}:
        return session.status
    if residue.running:
        return SessionStatus.RUNNING
    if residue.active_lock:
        return SessionStatus.STARTING
    if residue.inconclusive:
        return SessionStatus.UNREADABLE
    if residue.resources():
        return SessionStatus.STALE
    return SessionStatus.ABSENT


def _disposition(
    previous: SessionStatus,
    before: SessionResidue,
    cleanup: CleanupReport,
    remaining: SessionResidue,
) -> StopDisposition:
    if cleanup.succeeded and remaining.empty:
        if previous is SessionStatus.ABSENT:
            return StopDisposition.ALREADY_STOPPED
        if previous is SessionStatus.RUNNING:
            return StopDisposition.STOPPED
        return StopDisposition.STALE_RECOVERED
    changed = bool(cleanup.removed or cleanup.absent)
    if changed:
        return StopDisposition.PARTIALLY_CLEANED
    if cleanup.inconclusive or remaining.inconclusive:
        return StopDisposition.INCONCLUSIVE
    if before.empty and remaining.empty:
        return StopDisposition.ALREADY_STOPPED
    return StopDisposition.FAILED


def emit_stop_completion(report: StopReport, emitter: StopEmitter) -> None:
    if report.succeeded:
        emitter.out(
            f"{_GREEN}✓ ASF session cleanup complete{_RESET} "
            f"{_DIM}({report.elapsed_seconds}s; persistent volumes preserved){_RESET}\n"
        )
        return

    emitter.err(
        f"{_RED}{report.runtime}: cleanup did not finish "
        f"({report.disposition.value}){_RESET}\n"
    )
    remaining = report.remaining.resources()
    if remaining:
        emitter.err(f"    {len(remaining)} resource(s) still present\n")
        for resource in remaining:
            emitter.err(f"    still present: {resource}\n")
    unchecked = tuple(
        dict.fromkeys(report.cleanup.inconclusive + report.remaining.unreadable)
    )
    if unchecked:
        emitter.err(f"    {len(unchecked)} unchecked lookup(s)\n")
        for reason in unchecked:
            emitter.err(f"    not checked: {reason}\n")
    if report.previous_status is SessionStatus.STARTING:
        emitter.err("    session is still starting\n")


def _command_output(detail: str) -> str:
    return _STATUS_PREFIX.sub("", detail).strip()


def _unknown_runtime_output(runtime: str, available: Sequence[str]) -> str:
    lines = [
        f"{_RED}Unknown agent: {runtime}{_RESET}",
        "  Available agents:",
    ]
    lines.extend(f"    {name}" for name in available)
    return "\n".join(lines) + "\n"


def _elapsed_seconds(started: float, ended: float) -> int:
    return int(max(0.0, ended - started))


def _format_timeout(value: float) -> str:
    return str(int(value)) if value.is_integer() else str(value)
