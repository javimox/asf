"""Persistent-state reset orchestration.

``reset`` reuses the accepted stop and cleanup services. It first tears down and
verifies the runtime session, then removes only the persistent volumes declared
by that runtime plus its shell-history volume. No Podman parsing or generic
cleanup path is duplicated here.
"""

from __future__ import annotations

from collections.abc import Sequence
import os
import re
from dataclasses import dataclass
from enum import Enum

from .cleanup import CleanupExecutor, CleanupReport
from .errors import InfrastructureError, UsageError, ValidationError
from .identity import ResourceIdentity
from .manifest import load_model
from .models import RuntimeManifest
from .ownership import Resource, ResourceKind
from .paths import RepoPaths
from .podman import ObjectKind, PodmanClient, PodmanError
from .session import UnknownRuntimeError
from .stop import StopReport, StopService

__all__ = [
    "ResetCommandResult",
    "ResetDisposition",
    "ResetError",
    "ResetReport",
    "ResetService",
    "ResetUsageError",
    "state_volume_names",
    "run_reset_command",
]

_GREEN = "\033[0;32m"
_YELLOW = "\033[1;33m"
_RED = "\033[0;31m"
_BLUE = "\033[0;34m"
_DIM = "\033[2m"
_RESET = "\033[0m"


class ResetError(InfrastructureError):
    """Persistent state could not be reset safely."""


class ResetUsageError(UsageError):
    """The reset command invocation is invalid."""


class ResetDisposition(str, Enum):
    """High-level outcome of one persistent-state reset."""

    CLEARED = "cleared"
    NOTHING_TO_CLEAR = "nothing-to-clear"
    SESSION_CLEANUP_FAILED = "session-cleanup-failed"
    VOLUME_CLEANUP_FAILED = "volume-cleanup-failed"

    @property
    def succeeded(self) -> bool:
        return self in {
            ResetDisposition.CLEARED,
            ResetDisposition.NOTHING_TO_CLEAR,
        }


def state_volume_names(
    identity: ResourceIdentity,
    runtime: str,
    manifest: RuntimeManifest,
) -> tuple[str, ...]:
    """Return exactly the persistent volumes owned by ``reset``.

    Manifest-declared state volumes retain manifest order and shell history is
    always last. Names come from deterministic resource identity, never from a
    broad Podman listing.
    """

    return tuple(
        identity.state_volume(runtime, entry.key)
        for entry in manifest.state_volumes
    ) + (identity.shell_history_volume(runtime),)


@dataclass(frozen=True, slots=True)
class ResetReport:
    runtime: str
    stop: StopReport
    volumes: tuple[Resource, ...]
    cleanup: CleanupReport
    remaining: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.runtime, str) or not self.runtime:
            raise ValidationError("reset report runtime must be non-empty text")
        if not isinstance(self.stop, StopReport):
            raise TypeError("stop must be a StopReport")
        object.__setattr__(self, "volumes", tuple(self.volumes))
        object.__setattr__(self, "remaining", tuple(self.remaining))
        if not all(
            isinstance(resource, Resource)
            and resource.kind is ResourceKind.VOLUME
            for resource in self.volumes
        ):
            raise TypeError("volumes must contain volume resources")
        if not isinstance(self.cleanup, CleanupReport):
            raise TypeError("cleanup must be a CleanupReport")
        if not all(isinstance(name, str) and name for name in self.remaining):
            raise TypeError("remaining volume names must be non-empty text")

    @property
    def removed(self) -> tuple[str, ...]:
        return tuple(result.resource.name for result in self.cleanup.removed)

    @property
    def absent(self) -> tuple[str, ...]:
        return tuple(result.resource.name for result in self.cleanup.absent)

    @property
    def disposition(self) -> ResetDisposition:
        if not self.stop.succeeded:
            return ResetDisposition.SESSION_CLEANUP_FAILED
        if not self.cleanup.succeeded or self.remaining:
            return ResetDisposition.VOLUME_CLEANUP_FAILED
        if self.removed:
            return ResetDisposition.CLEARED
        return ResetDisposition.NOTHING_TO_CLEAR

    @property
    def succeeded(self) -> bool:
        return self.disposition.succeeded


@dataclass(frozen=True, slots=True)
class ResetCommandResult:
    report: ResetReport | None = None
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""

    def __post_init__(self) -> None:
        if self.report is not None and not isinstance(self.report, ResetReport):
            raise TypeError("report must be a ResetReport or None")
        if (
            isinstance(self.returncode, bool)
            or not isinstance(self.returncode, int)
            or self.returncode < 0
        ):
            raise ValidationError("returncode must be a non-negative integer")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("stdout and stderr must be text")


@dataclass(frozen=True, slots=True)
class ResetService:
    paths: RepoPaths
    stop_service: StopService
    cleanup: CleanupExecutor

    def __post_init__(self) -> None:
        if not isinstance(self.paths, RepoPaths):
            raise TypeError("paths must be RepoPaths")
        if not isinstance(self.stop_service, StopService):
            raise TypeError("stop_service must be StopService")
        if not isinstance(self.cleanup, CleanupExecutor):
            raise TypeError("cleanup must be CleanupExecutor")
        if self.stop_service.cleanup is not self.cleanup:
            raise ValidationError(
                "reset must reuse the stop service cleanup executor"
            )

    @classmethod
    def from_paths(
        cls,
        paths: RepoPaths,
        *,
        podman: PodmanClient | None = None,
        stop_service: StopService | None = None,
        stop_timeout: float = 2.0,
    ) -> "ResetService":
        active_stop = (
            StopService.from_paths(
                paths,
                podman=podman,
                stop_timeout=stop_timeout,
            )
            if stop_service is None
            else stop_service
        )
        return cls(paths, active_stop, active_stop.cleanup)

    def reset(self, runtime: str) -> ResetReport:
        runtime = self.stop_service.discovery.validate_runtime(runtime)
        manifest = load_model(self.paths.identity.runtime_manifest(runtime))

        # Reset never races volume removal against an active or partially
        # cleaned session. The accepted stop service performs the complete
        # teardown and mandatory post-cleanup verification first.
        stop_report = self.stop_service.stop_runtime(runtime)
        volumes = tuple(
            Resource(ResourceKind.VOLUME, name, runtime=runtime)
            for name in state_volume_names(self.paths.identity, runtime, manifest)
        )

        if not stop_report.succeeded:
            return ResetReport(
                runtime,
                stop_report,
                volumes,
                CleanupReport(
                    (),
                    inconclusive=(
                        "session cleanup did not complete; persistent state "
                        "was not removed",
                    ),
                ),
            )

        cleanup = self.cleanup.reset_volumes(volumes)
        remaining = self._remaining_volumes(volumes)
        return ResetReport(runtime, stop_report, volumes, cleanup, remaining)

    def _remaining_volumes(
        self, volumes: Sequence[Resource]
    ) -> tuple[str, ...]:
        remaining: list[str] = []
        for resource in volumes:
            try:
                if self.cleanup.podman.exists(resource.name, ObjectKind.VOLUME):
                    remaining.append(resource.name)
            except PodmanError as exc:
                raise ResetError(
                    f"could not verify reset volume {resource.name}: {exc}"
                ) from exc
        return tuple(remaining)


def run_reset_command(
    arguments: Sequence[str],
    paths: RepoPaths,
    *,
    podman: PodmanClient | None = None,
    require_available: bool = True,
    service: ResetService | None = None,
) -> ResetCommandResult:
    """Run ``sandbox.sh reset <runtime>`` with Bash-compatible text output."""

    if isinstance(arguments, (str, bytes)):
        raise TypeError("reset arguments must be a sequence")
    argv = tuple(arguments)
    if not argv or argv[0] != "reset":
        raise ResetUsageError("unsupported reset command")

    runtime = argv[1] if len(argv) > 1 else ""
    client = PodmanClient() if podman is None else podman
    active = service
    if active is None:
        timeout_text = os.environ.get("ASF_SHUTDOWN_TIMEOUT", "2")
        if re.fullmatch(r"[0-9]+", timeout_text) is None:
            return ResetCommandResult(
                returncode=1,
                stderr="ASF_SHUTDOWN_TIMEOUT must be a non-negative integer.\n",
            )
        active = ResetService.from_paths(
            paths,
            podman=client,
            stop_timeout=float(timeout_text),
        )

    if not runtime:
        available = active.stop_service.discovery.known_runtimes()
        return ResetCommandResult(
            returncode=1,
            stdout=_missing_runtime_output(available),
        )

    try:
        active.stop_service.discovery.validate_runtime(runtime)
    except UnknownRuntimeError as exc:
        return ResetCommandResult(
            returncode=1,
            stdout=_unknown_runtime_output(exc.runtime, exc.available),
        )

    if require_available and service is None:
        client.require_available()

    report = active.reset(runtime)

    if not report.stop.succeeded:
        reasons: list[str] = []
        for failure in report.stop.cleanup.failures:
            detail = failure.detail or "cleanup failed"
            reasons.append(f"{failure.resource.name}: {detail}")
        reasons.extend(report.stop.cleanup.inconclusive)
        reasons.extend(report.stop.remaining.unreadable)
        unique = tuple(dict.fromkeys(reasons))
        detail = "".join(f"  {reason}\n" for reason in unique)
        return ResetCommandResult(
            report=report,
            returncode=1,
            stderr=(
                f"{_RED}Could not stop {runtime} safely; persistent state "
                f"was not cleared.{_RESET}\n{detail}"
            ),
        )

    if not report.cleanup.succeeded or report.remaining:
        lines = [f"{_RED}Could not clear all {runtime} state.{_RESET}"]
        for failure in report.cleanup.failures:
            detail = failure.detail or "volume removal failed"
            lines.append(f"  {failure.resource.name}: {detail}")
        for name in report.remaining:
            lines.append(f"  still present: {name}")
        return ResetCommandResult(
            report=report,
            returncode=1,
            stderr="\n".join(lines) + "\n",
        )

    removed = report.removed
    if removed:
        return ResetCommandResult(
            report=report,
            stdout=(
                f"{_GREEN}✓ Cleared all {runtime} state.{_RESET}\n"
                f"  {_DIM}{' '.join(removed)}{_RESET}\n"
                f"  Run {_BLUE}./sandbox.sh open {runtime}{_RESET} to start "
                "fresh (repopulates from the image).\n"
            ),
        )

    return ResetCommandResult(
        report=report,
        stdout=(
            f"{_YELLOW}No persistent volumes found for {runtime}.{_RESET}\n"
            "  Nothing to clear.\n"
        ),
    )


def _missing_runtime_output(available: Sequence[str]) -> str:
    lines = [
        f"{_RED}An agent name is required: ./sandbox.sh reset <agent>{_RESET}",
        "  Available agents:",
    ]
    lines.extend(f"    {name}" for name in available)
    return "\n".join(lines) + "\n"


def _unknown_runtime_output(runtime: str, available: Sequence[str]) -> str:
    lines = [
        f"{_RED}Unknown agent: {runtime}{_RESET}",
        "  Available agents:",
    ]
    lines.extend(f"    {name}" for name in available)
    return "\n".join(lines) + "\n"
