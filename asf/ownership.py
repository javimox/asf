"""Session resource ownership and deterministic teardown ordering.

This module records resources that actually came into existence during one ASF
session.  Cleanup can then remove only those resources, in dependency order,
instead of reconstructing mutable Bash state after an interrupted startup.

Persistent volumes are recordable for a complete inventory but are deliberately
never part of the teardown sequence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Iterator, Sequence

from .errors import ValidationError
from .identity import validate_runtime_name

__all__ = [
    "TEARDOWN_ORDER",
    "Resource",
    "ResourceKind",
    "ResourceLedger",
    "teardown_sequence",
]


class ResourceKind(str, Enum):
    RUNTIME_CONTAINER = "runtime-container"
    BROKER_CONTAINER = "broker-container"
    SECRET = "secret"
    BROKER_STATE = "broker-state"
    PROXY_CONTAINER = "proxy-container"
    GATEWAY_INIT_CONTAINER = "gateway-init-container"
    GATEWAY_CONTAINER = "gateway-container"
    NETWORK = "network"
    SUBNET_RESERVATION = "subnet-reservation"
    SESSION_LOCK = "session-lock"
    VOLUME = "volume"


# Canonical dependency-aware teardown order. Stable ordering within one kind
# keeps cleanup transcripts deterministic.
TEARDOWN_ORDER: tuple[ResourceKind, ...] = (
    ResourceKind.RUNTIME_CONTAINER,
    ResourceKind.BROKER_CONTAINER,
    ResourceKind.SECRET,
    ResourceKind.BROKER_STATE,
    ResourceKind.PROXY_CONTAINER,
    ResourceKind.GATEWAY_INIT_CONTAINER,
    ResourceKind.GATEWAY_CONTAINER,
    ResourceKind.NETWORK,
    ResourceKind.SUBNET_RESERVATION,
    ResourceKind.SESSION_LOCK,
)

_ORDER_INDEX = {kind: index for index, kind in enumerate(TEARDOWN_ORDER)}


@dataclass(frozen=True, slots=True)
class Resource:
    kind: ResourceKind
    name: str
    runtime: str = ""
    owner_pid: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ResourceKind):
            raise TypeError("kind must be a ResourceKind")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValidationError(f"{self.kind.value} resource needs a name")
        if "\x00" in self.name:
            raise ValidationError(f"{self.kind.value} resource contains a NUL byte")
        if self.runtime:
            validate_runtime_name(self.runtime)
        if self.owner_pid is not None and (
            isinstance(self.owner_pid, bool)
            or not isinstance(self.owner_pid, int)
            or self.owner_pid <= 0
        ):
            raise ValidationError("resource owner PID must be a positive integer")

    @property
    def removable(self) -> bool:
        return self.kind in _ORDER_INDEX

    def __str__(self) -> str:
        return f"{self.kind.value} {self.name}"


@dataclass(slots=True)
class ResourceLedger:
    runtime: str = ""
    _entries: list[Resource] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.runtime:
            self.runtime = validate_runtime_name(self.runtime)

    def record(
        self,
        kind: ResourceKind,
        name: str,
        *,
        owner_pid: int | None = None,
    ) -> Resource:
        resource = Resource(
            kind=kind,
            name=name,
            runtime=self.runtime,
            owner_pid=owner_pid,
        )
        if resource not in self._entries:
            self._entries.append(resource)
        return resource

    def forget(self, resource: Resource) -> None:
        if resource in self._entries:
            self._entries.remove(resource)

    def extend(self, resources: Iterable[Resource]) -> None:
        for resource in resources:
            if not isinstance(resource, Resource):
                raise TypeError("resources must contain Resource values")
            if resource not in self._entries:
                self._entries.append(resource)

    @property
    def created(self) -> tuple[Resource, ...]:
        return tuple(self._entries)

    def of_kind(self, kind: ResourceKind) -> tuple[Resource, ...]:
        if not isinstance(kind, ResourceKind):
            raise TypeError("kind must be a ResourceKind")
        return tuple(resource for resource in self._entries if resource.kind is kind)

    def teardown(self) -> tuple[Resource, ...]:
        return teardown_sequence(self._entries)

    @property
    def preserved(self) -> tuple[Resource, ...]:
        return tuple(resource for resource in self._entries if not resource.removable)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[Resource]:
        return iter(tuple(self._entries))

    def __contains__(self, resource: object) -> bool:
        return resource in self._entries


def teardown_sequence(resources: Sequence[Resource]) -> tuple[Resource, ...]:
    indexed: list[tuple[int, Resource]] = []
    for position, resource in enumerate(resources):
        if not isinstance(resource, Resource):
            raise TypeError("resources must contain Resource values")
        if resource.removable:
            indexed.append((position, resource))
    indexed.sort(key=lambda item: (_ORDER_INDEX[item[1].kind], item[0]))
    return tuple(resource for _, resource in indexed)
