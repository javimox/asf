"""Read-only discovery of resources left by one ASF runtime session."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .identity import ResourceIdentity
from .ownership import Resource, ResourceKind, teardown_sequence
from .podman import ObjectKind, PodmanClient, PodmanError
from .session import SessionDiscovery, SessionRole
from .session_lock import SessionLockError, SessionLockSnapshot
from .subnets import Reservation, read_reservation

__all__ = ["SessionResidue", "ResidueScanner"]

_ROLE_KINDS = {
    SessionRole.BROKER: ResourceKind.BROKER_CONTAINER,
    SessionRole.PROXY: ResourceKind.PROXY_CONTAINER,
    SessionRole.ROUTED_INIT: ResourceKind.GATEWAY_INIT_CONTAINER,
    SessionRole.NETWORK_OBSERVER: ResourceKind.NETWORK_OBSERVER_CONTAINER,
    SessionRole.ROUTED_GATEWAY: ResourceKind.GATEWAY_CONTAINER,
}


@dataclass(frozen=True, slots=True)
class SessionResidue:
    runtime: str
    containers: tuple[Resource, ...] = ()
    networks: tuple[Resource, ...] = ()
    secrets: tuple[Resource, ...] = ()
    lock: SessionLockSnapshot | None = None
    reservation: Reservation | None = None
    broker_state: Path | None = None
    running: bool = False
    unreadable: tuple[str, ...] = field(default=())

    @property
    def active_lock(self) -> bool:
        return self.lock is not None and (
            self.lock.owner_alive or self.lock.being_claimed
        )

    @property
    def inconclusive(self) -> bool:
        return bool(self.unreadable)

    @property
    def empty(self) -> bool:
        return not self.resources() and not self.unreadable

    @property
    def is_stale(self) -> bool:
        return (
            not self.running
            and not self.active_lock
            and not self.inconclusive
            and not self.empty
        )

    def resources(self) -> tuple[Resource, ...]:
        found = list(self.containers) + list(self.networks) + list(self.secrets)
        if self.broker_state is not None:
            found.append(
                Resource(
                    ResourceKind.BROKER_STATE,
                    str(self.broker_state),
                    runtime=self.runtime,
                )
            )
        if self.reservation is not None and self.reservation.exists:
            found.append(
                Resource(
                    ResourceKind.SUBNET_RESERVATION,
                    str(self.reservation.path),
                    runtime=self.runtime,
                    owner_pid=self.reservation.owner_pid,
                )
            )
        if self.lock is not None:
            found.append(
                Resource(
                    ResourceKind.SESSION_LOCK,
                    str(self.lock.path),
                    runtime=self.runtime,
                    owner_pid=self.lock.pid,
                )
            )
        return teardown_sequence(_deduplicate(found))

    def of_kind(self, kind: ResourceKind) -> tuple[Resource, ...]:
        return tuple(resource for resource in self.resources() if resource.kind is kind)

    def summary(self) -> str:
        counts: dict[str, int] = {}
        for resource in self.resources():
            counts[resource.kind.value] = counts.get(resource.kind.value, 0) + 1
        parts = [
            f"{count} {kind}" for kind, count in sorted(counts.items())
        ]
        if self.unreadable:
            parts.append(f"{len(self.unreadable)} unreadable lookup(s)")
        return ", ".join(parts) if parts else "nothing left"


@dataclass(frozen=True, slots=True)
class ResidueScanner:
    discovery: SessionDiscovery

    @property
    def identity(self) -> ResourceIdentity:
        return self.discovery.identity

    @property
    def podman(self) -> PodmanClient:
        return self.discovery.podman

    def scan(self, runtime: str) -> SessionResidue:
        runtime = self.discovery.validate_runtime(runtime)
        unreadable: list[str] = []

        containers = self._containers(runtime, unreadable)
        try:
            running = bool(self.discovery.runtime_container_ids(runtime))
        except PodmanError as exc:
            unreadable.append(f"running containers: {exc}")
            running = False

        return SessionResidue(
            runtime=runtime,
            containers=containers,
            networks=self._networks(runtime, unreadable),
            secrets=self._secrets(runtime, unreadable),
            lock=self._lock(runtime, unreadable),
            reservation=read_reservation(
                self.identity.subnet_reservation_session(runtime)
            ),
            broker_state=self._broker_state(runtime),
            running=running,
            unreadable=tuple(unreadable),
        )

    def scan_all(self) -> tuple[SessionResidue, ...]:
        return tuple(self.scan(runtime) for runtime in self.discovery.known_runtimes())

    def stale(self) -> tuple[SessionResidue, ...]:
        return tuple(residue for residue in self.scan_all() if residue.is_stale)

    def _containers(
        self, runtime: str, unreadable: list[str]
    ) -> tuple[Resource, ...]:
        found: list[Resource] = []
        try:
            found.extend(
                Resource(
                    ResourceKind.RUNTIME_CONTAINER,
                    match.container_id,
                    runtime=runtime,
                )
                for match in self.discovery.matches(runtime, include_stopped=True)
            )
        except PodmanError as exc:
            unreadable.append(f"runtime containers: {exc}")

        for role, kind in _ROLE_KINDS.items():
            try:
                identifiers = self.discovery.role_container_ids(
                    runtime, role, include_stopped=True
                )
            except PodmanError as exc:
                unreadable.append(f"{role.value} containers: {exc}")
                continue
            found.extend(
                Resource(kind, identifier, runtime=runtime)
                for identifier in identifiers
            )
        return _deduplicate(found)

    def _networks(
        self, runtime: str, unreadable: list[str]
    ) -> tuple[Resource, ...]:
        found: list[Resource] = []
        for name in _network_names(self.identity.network_names(runtime)):
            try:
                if self.podman.exists(name, ObjectKind.NETWORK):
                    found.append(Resource(ResourceKind.NETWORK, name, runtime=runtime))
            except PodmanError as exc:
                unreadable.append(f"network {name}: {exc}")
        return tuple(found)

    def _secrets(
        self, runtime: str, unreadable: list[str]
    ) -> tuple[Resource, ...]:
        prefix = self.identity.broker_secret_prefix(runtime)
        try:
            names = self.podman.secret_names()
        except PodmanError as exc:
            unreadable.append(f"secrets: {exc}")
            return ()
        return tuple(
            Resource(ResourceKind.SECRET, name, runtime=runtime)
            for name in names
            if name.startswith(prefix)
        )

    def _lock(
        self, runtime: str, unreadable: list[str]
    ) -> SessionLockSnapshot | None:
        try:
            return self.discovery.lock_manager().inspect(runtime)
        except SessionLockError as exc:
            unreadable.append(f"session lock: {exc}")
            return None

    def _broker_state(self, runtime: str) -> Path | None:
        path = self.identity.broker_state(runtime)
        return path if os.path.lexists(path) else None


def _network_names(names: object) -> tuple[str, ...]:
    return tuple(
        value
        for value in (
            getattr(names, attribute, "")
            for attribute in (
                "internal",
                "egress",
                "provider",
                "scan",
                "routed_egress",
            )
        )
        if value
    )


def _deduplicate(resources: list[Resource]) -> tuple[Resource, ...]:
    seen: set[Resource] = set()
    ordered: list[Resource] = []
    for resource in resources:
        if resource in seen:
            continue
        seen.add(resource)
        ordered.append(resource)
    return tuple(ordered)
