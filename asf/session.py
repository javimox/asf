"""Read-only ASF runtime and support-container session discovery.

A session is identified by ASF-owned labels, never by container-name patterns.
This module reports state only; lifecycle mutation belongs to the focused
runtime, stop, and cleanup services.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .errors import (
    AsfError,
    ConfigurationError,
    InfrastructureError,
    UsageError,
    ValidationError,
)
from .identity import NetworkNames, ResourceIdentity, validate_runtime_name
from .paths import RepoPaths
from .session_lock import (
    AcquiredSessionLock,
    SessionAlreadyRunningError,
    SessionLockAcquireError,
    SessionLockError,
    SessionLockManager,
    SessionLockOwnershipError,
    SessionLockSnapshot,
)
from .podman import (
    ContainerInspection,
    HealthStatus,
    ObjectNotFoundError,
    PodmanClient,
)

__all__ = [
    "AmbiguousSessionError",
    "InspectedSession",
    "MultipleRunningSessionsError",
    "NoRunningSessionError",
    "RuntimeCatalogError",
    "RuntimeSession",
    "SessionOwnership",
    "SessionStatus",
    "SessionContainer",
    "SessionDiscovery",
    "SessionDiscoveryError",
    "SessionError",
    "SessionInfrastructureError",
    "SessionLockSnapshot",
    "SessionLockManager",
    "SessionLockError",
    "SessionLockAcquireError",
    "SessionLockOwnershipError",
    "SessionAlreadyRunningError",
    "AcquiredSessionLock",
    "SessionMatch",
    "SessionRole",
    "UnknownRuntimeError",
]

_LABEL_SANDBOX = "asf.sandbox"
_LABEL_ROLE = "asf.role"
_LABEL_AGENT = "asf.agent"


class SessionDiscoveryError(AsfError):
    """Base class for session-discovery failures."""


class SessionError(SessionDiscoveryError, InfrastructureError):
    """Base class for session-discovery operational failures."""


class SessionInfrastructureError(SessionError):
    """Discovery could not safely determine ownership or state."""


class NoRunningSessionError(SessionError):
    """No ASF runtime session is running in this checkout."""

    def __init__(self, message: str | None = None) -> None:
        super().__init__(
            message
            or "no running session in this checkout; start one with "
            "./sandbox.sh open <agent>"
        )


class MultipleRunningSessionsError(SessionError):
    """More than one runtime is running and none was requested."""

    def __init__(self, runtimes: Sequence[str]) -> None:
        self.runtimes = tuple(runtimes)
        super().__init__(
            "several sessions are running; name the runtime: "
            + ", ".join(self.runtimes)
        )


class AmbiguousSessionError(SessionInfrastructureError):
    """One ASF ownership label matched more than one container."""

    def __init__(
        self,
        runtime: str,
        container_ids: Sequence[str],
        *,
        role: str = "runtime",
    ) -> None:
        self.runtime = runtime
        self.container_ids = tuple(container_ids)
        self.role = role
        super().__init__(
            f"runtime {runtime!r} matched multiple {role} containers: "
            + ", ".join(self.container_ids)
        )


class UnknownRuntimeError(
    SessionDiscoveryError, UsageError, ValidationError
):
    """The requested runtime has no manifest in this checkout."""

    def __init__(self, runtime: str, available: Sequence[str]) -> None:
        self.runtime = runtime
        self.requested = runtime
        self.available = tuple(available)
        suffix = ", ".join(self.available) if self.available else "none"
        super().__init__(f"unknown runtime {runtime!r}; available: {suffix}")


class RuntimeCatalogError(SessionDiscoveryError, ConfigurationError):
    """Runtime manifests cannot form a safe catalogue."""


class SessionRole(str, Enum):
    RUNTIME = "runtime"
    PROXY = "proxy"
    BROKER = "broker"
    ROUTED_GATEWAY = "routed-gateway"
    ROUTED_INIT = "routed-init"
    NETWORK_OBSERVER = "network-observer"

    @classmethod
    def parse(cls, value: str) -> "SessionRole | None":
        try:
            return cls(value)
        except ValueError:
            return None


_SUPPORT_ROLES = (
    SessionRole.BROKER,
    SessionRole.PROXY,
    SessionRole.ROUTED_GATEWAY,
    SessionRole.ROUTED_INIT,
    SessionRole.NETWORK_OBSERVER,
)


@dataclass(frozen=True, slots=True)
class SessionMatch:
    runtime: str
    container_id: str


@dataclass(frozen=True, slots=True)
class InspectedSession:
    runtime: str
    container: ContainerInspection


@dataclass(frozen=True, slots=True)
class SessionContainer:
    runtime: str
    role: SessionRole
    inspect: ContainerInspection

    @property
    def container_id(self) -> str:
        return self.inspect.container_id

    @property
    def name(self) -> str:
        return self.inspect.name

    @property
    def state(self):
        return self.inspect.state

    @property
    def health(self) -> HealthStatus:
        return self.inspect.health_status

    @property
    def is_running(self) -> bool:
        return self.inspect.is_running

    @property
    def is_healthy(self) -> bool:
        return self.is_running and self.health in (
            HealthStatus.HEALTHY,
            HealthStatus.NONE,
        )


class SessionStatus(str, Enum):
    ABSENT = "absent"
    STARTING = "starting"
    RUNNING = "running"
    STALE = "stale"
    AMBIGUOUS = "ambiguous"
    UNREADABLE = "unreadable"


@dataclass(frozen=True, slots=True)
class SessionOwnership:
    """Deterministic resources that belong to one runtime session."""

    runtime: str
    runtime_container: str
    session_label: str
    sandbox_label: str
    agent_label: str
    lock_path: Path
    broker_state_path: Path
    networks: NetworkNames
    subnet_reservation_session: str


@dataclass(frozen=True, slots=True)
class RuntimeSession:
    runtime: str
    containers: tuple[SessionContainer, ...] = ()
    lock: SessionLockSnapshot | None = None
    broker_state_present: bool = False
    unreadable: tuple[str, ...] = ()

    @property
    def runtime_containers(self) -> tuple[SessionContainer, ...]:
        return tuple(
            container
            for container in self.containers
            if container.role is SessionRole.RUNTIME
        )

    @property
    def support_containers(self) -> tuple[SessionContainer, ...]:
        return tuple(
            container
            for container in self.containers
            if container.role is not SessionRole.RUNTIME
        )

    @property
    def container(self) -> SessionContainer | None:
        running = tuple(
            container
            for container in self.runtime_containers
            if container.is_running
        )
        return running[0] if len(running) == 1 else None

    @property
    def is_running(self) -> bool:
        return any(container.is_running for container in self.runtime_containers)

    @property
    def is_ambiguous(self) -> bool:
        for role in SessionRole:
            matches = self.role_containers(role)
            if role is SessionRole.RUNTIME:
                matches = tuple(container for container in matches if container.is_running)
            if len(matches) > 1:
                return True
        return False

    @property
    def is_starting(self) -> bool:
        """A live opener owns the lock but has not exposed a runtime yet."""

        return (
            not self.is_running
            and self.lock is not None
            and not self.lock.is_stale
        )

    @property
    def leftovers(self) -> tuple[SessionContainer, ...]:
        return () if self.is_running else self.containers

    @property
    def is_stale(self) -> bool:
        if self.is_running or self.is_starting:
            return False
        stale_lock = self.lock is not None and self.lock.is_stale
        return bool(self.containers) or stale_lock or self.broker_state_present

    @property
    def status(self) -> SessionStatus:
        if self.is_ambiguous:
            return SessionStatus.AMBIGUOUS
        if self.unreadable:
            return SessionStatus.UNREADABLE
        if self.is_running:
            return SessionStatus.RUNNING
        if self.is_starting:
            return SessionStatus.STARTING
        if self.is_stale:
            return SessionStatus.STALE
        return SessionStatus.ABSENT

    def role_containers(
        self, role: SessionRole
    ) -> tuple[SessionContainer, ...]:
        return tuple(
            container for container in self.containers if container.role is role
        )

    def role(self, role: SessionRole) -> SessionContainer | None:
        matches = self.role_containers(role)
        if not matches:
            return None
        if len(matches) > 1:
            raise AmbiguousSessionError(
                self.runtime,
                tuple(container.container_id for container in matches),
                role=role.value,
            )
        return matches[0]


@dataclass(frozen=True, slots=True)
class SessionDiscovery:
    """Discover ASF containers for one physical checkout."""

    identity: ResourceIdentity
    runtimes: tuple[str, ...]
    podman: PodmanClient = field(default_factory=PodmanClient)

    def __post_init__(self) -> None:
        if isinstance(self.runtimes, (str, bytes)):
            raise TypeError("runtimes must be a sequence of names")
        normalised: list[str] = []
        seen: set[str] = set()
        for runtime in self.runtimes:
            try:
                name = validate_runtime_name(runtime)
            except (TypeError, AsfError) as exc:
                raise RuntimeCatalogError(
                    f"invalid runtime catalogue entry: {runtime!r}"
                ) from exc
            if name in seen:
                raise RuntimeCatalogError(
                    f"duplicate runtime catalogue entry: {name!r}"
                )
            seen.add(name)
            normalised.append(name)
        object.__setattr__(self, "runtimes", tuple(sorted(normalised)))

    @classmethod
    def from_paths(
        cls,
        paths: RepoPaths,
        *,
        podman: PodmanClient | None = None,
    ) -> "SessionDiscovery":
        return cls(
            identity=paths.identity,
            runtimes=_discover_runtimes(paths.agents_dir),
            podman=PodmanClient() if podman is None else podman,
        )

    @classmethod
    def for_checkout(
        cls,
        checkout: str | os.PathLike[str],
        podman: PodmanClient | None = None,
    ) -> "SessionDiscovery":
        return cls.from_paths(
            RepoPaths.for_root(checkout),
            podman=podman,
        )

    def lock_manager(self) -> SessionLockManager:
        return SessionLockManager(self.identity)

    def ownership(self, runtime: str) -> SessionOwnership:
        runtime = self.validate_runtime(runtime)
        return SessionOwnership(
            runtime=runtime,
            runtime_container=self.identity.container_name(runtime),
            session_label=self.identity.session_label(runtime),
            sandbox_label=f"asf.sandbox={self.identity.script_dir}",
            agent_label=f"asf.agent={runtime}",
            lock_path=self.identity.session_lock(runtime),
            broker_state_path=self.identity.broker_state(runtime),
            networks=self.identity.network_names(runtime),
            subnet_reservation_session=self.identity.subnet_reservation_session(runtime),
        )

    def known_runtimes(self) -> tuple[str, ...]:
        return self.runtimes

    def is_known_runtime(self, runtime: str) -> bool:
        try:
            return validate_runtime_name(runtime) in self.runtimes
        except (TypeError, AsfError):
            return False

    def validate_runtime(self, runtime: str) -> str:
        try:
            name = validate_runtime_name(runtime)
        except (TypeError, AsfError) as exc:
            raise UnknownRuntimeError(str(runtime), self.runtimes) from exc
        if name not in self.runtimes:
            raise UnknownRuntimeError(name, self.runtimes)
        return name

    def matches(
        self,
        runtime: str,
        *,
        include_stopped: bool = False,
    ) -> tuple[SessionMatch, ...]:
        runtime = self.validate_runtime(runtime)
        identifiers = self.podman.container_ids(
            labels=(self.identity.session_label(runtime),),
            include_stopped=include_stopped,
        )
        return tuple(
            SessionMatch(runtime, identifier) for identifier in identifiers
        )

    def runtime_container_ids(self, runtime: str) -> tuple[str, ...]:
        return tuple(match.container_id for match in self.matches(runtime))

    def unique_match(
        self,
        runtime: str,
        *,
        include_stopped: bool = False,
    ) -> SessionMatch | None:
        matches = self.matches(runtime, include_stopped=include_stopped)
        if not matches:
            return None
        if len(matches) > 1:
            raise AmbiguousSessionError(
                matches[0].runtime,
                tuple(match.container_id for match in matches),
            )
        return matches[0]

    def running_matches(self) -> tuple[SessionMatch, ...]:
        found: list[SessionMatch] = []
        for runtime in self.runtimes:
            match = self.unique_match(runtime)
            if match is not None:
                found.append(match)
        return tuple(found)

    def running_runtimes(self) -> tuple[str, ...]:
        return tuple(match.runtime for match in self.running_matches())

    def role_container_ids(
        self,
        runtime: str,
        role: SessionRole,
        *,
        include_stopped: bool = False,
    ) -> tuple[str, ...]:
        runtime = self.validate_runtime(runtime)
        if role is SessionRole.RUNTIME:
            return tuple(
                match.container_id
                for match in self.matches(
                    runtime, include_stopped=include_stopped
                )
            )
        labels = {
            _LABEL_SANDBOX: str(self.identity.script_dir),
            _LABEL_ROLE: role.value,
            _LABEL_AGENT: runtime,
        }
        return self.podman.container_ids(
            labels=labels,
            include_stopped=include_stopped,
        )

    def resolve_runtime(self, requested: str | None = None) -> str:
        if requested:
            return self.validate_runtime(requested)
        running = self.running_runtimes()
        if not running:
            raise NoRunningSessionError()
        if len(running) > 1:
            raise MultipleRunningSessionsError(running)
        return running[0]

    def extract_runtime_argument(
        self, arguments: Iterable[str]
    ) -> tuple[str, tuple[str, ...]]:
        runtime = ""
        rest: list[str] = []
        for argument in arguments:
            if not runtime and self.is_known_runtime(argument):
                runtime = argument
            else:
                rest.append(argument)
        return runtime, tuple(rest)

    def inspect(
        self,
        runtime: str,
        *,
        include_stopped: bool = False,
    ) -> InspectedSession | None:
        match = self.unique_match(runtime, include_stopped=include_stopped)
        if match is None:
            return None
        return InspectedSession(
            runtime=match.runtime,
            container=self.podman.inspect_container(match.container_id),
        )

    def session(self, runtime: str) -> RuntimeSession:
        runtime = self.validate_runtime(runtime)
        containers: list[SessionContainer] = []
        unreadable: list[str] = []
        seen: set[str] = set()

        for match in self.matches(runtime, include_stopped=True):
            inspection = self._inspect(match.container_id, unreadable)
            if inspection is not None and inspection.container_id not in seen:
                seen.add(inspection.container_id)
                containers.append(
                    SessionContainer(runtime, SessionRole.RUNTIME, inspection)
                )

        for role in _SUPPORT_ROLES:
            for container_id in self.role_container_ids(
                runtime,
                role,
                include_stopped=True,
            ):
                inspection = self._inspect(container_id, unreadable)
                if inspection is not None and inspection.container_id not in seen:
                    seen.add(inspection.container_id)
                    containers.append(SessionContainer(runtime, role, inspection))

        return RuntimeSession(
            runtime=runtime,
            containers=tuple(containers),
            lock=self.read_lock(runtime),
            broker_state_present=os.path.lexists(self.identity.broker_state(runtime)),
            unreadable=tuple(unreadable),
        )

    def sessions(self) -> tuple[RuntimeSession, ...]:
        return tuple(self.session(runtime) for runtime in self.runtimes)

    def stale_runtimes(self) -> tuple[str, ...]:
        return tuple(
            session.runtime for session in self.sessions() if session.is_stale
        )

    def read_lock(self, runtime: str) -> SessionLockSnapshot | None:
        runtime = self.validate_runtime(runtime)
        return self.lock_manager().inspect(runtime)

    def _inspect(
        self,
        container_id: str,
        unreadable: list[str],
    ) -> ContainerInspection | None:
        try:
            return self.podman.inspect_container(container_id)
        except ObjectNotFoundError:
            unreadable.append(container_id)
            return None


def _discover_runtimes(agents_dir: Path) -> tuple[str, ...]:
    if not agents_dir.is_dir():
        raise RuntimeCatalogError(f"missing agents directory: {agents_dir}")
    runtimes: list[str] = []
    for candidate in sorted(agents_dir.iterdir(), key=lambda path: path.name):
        if not candidate.is_dir() or not (candidate / "runtime.yml").is_file():
            continue
        try:
            runtimes.append(validate_runtime_name(candidate.name))
        except (TypeError, AsfError) as exc:
            raise RuntimeCatalogError(
                f"invalid runtime directory name: {candidate.name!r}"
            ) from exc
    return tuple(runtimes)


