"""Immutable planning for one ASF runtime session.

This module centralises topology decisions without creating Podman resources.
The planner consumes validated models plus explicit host-resolved inputs and
returns a deterministic plan that the runtime services execute.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import sys
from dataclasses import dataclass
from enum import Enum
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    NetmaskValueError,
)
from pathlib import Path
from typing import Any, Sequence

from .errors import ConfigurationError, ValidationError
from .identity import ResourceIdentity, validate_runtime_name
from .manifest import load_model
from .models import RuntimeManifest
from .ownership import Resource, ResourceKind
from .paths import RepoPaths
from .reset import state_volume_names
from .session import SessionRole

__all__ = [
    "ContainerPlan",
    "GeneratedFileKind",
    "GeneratedFilePlan",
    "NetworkAttachment",
    "NetworkPlan",
    "BROKER_INTERNAL_ALIAS",
    "NetworkRole",
    "PROXY_INTERNAL_ALIAS",
    "NetworkRoute",
    "PersistentVolumePlan",
    "RuntimePlan",
    "RuntimePlanError",
    "RoutedSubnetAllocation",
    "SecretFilePlan",
    "build_runtime_plan",
    "load_runtime_plan",
    "read_runtime_plan",
    "main",
    "routed_broker_address",
    "runtime_plan_path",
    "validate_runtime_plan_context",
    "write_runtime_plan",
]


class RuntimePlanError(ConfigurationError):
    """The validated inputs cannot form a safe runtime topology."""


class NetworkRole(str, Enum):
    INTERNAL = "internal"
    EGRESS = "egress"
    PROVIDER = "provider"
    SCAN = "scan"
    ROUTED_EGRESS = "routed-egress"


class GeneratedFileKind(str, Enum):
    RUNTIME_PLAN = "runtime-plan"
    DEVCONTAINER = "devcontainer"
    PROXY_POLICY = "proxy-policy"
    ROUTED_POLICY = "routed-policy"


# Short, network-scoped service endpoints. Container names remain checkout- and
# PID-scoped for ownership, but are not suitable as portable DNS labels.
PROXY_INTERNAL_ALIAS = "asf-proxy"
BROKER_INTERNAL_ALIAS = "asf-broker"


@dataclass(frozen=True, slots=True)
class NetworkRoute:
    destination: IPv4Network
    gateway: IPv4Address

    def __post_init__(self) -> None:
        if not isinstance(self.destination, IPv4Network):
            raise TypeError("route destination must be an IPv4Network")
        if not isinstance(self.gateway, IPv4Address):
            raise TypeError("route gateway must be an IPv4Address")


@dataclass(frozen=True, slots=True)
class NetworkPlan:
    role: NetworkRole
    name: str
    internal: bool
    subnet: IPv4Network | None = None
    gateway: IPv4Address | None = None
    routes: tuple[NetworkRoute, ...] = ()
    no_default_route: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "routes", tuple(self.routes))
        if not isinstance(self.role, NetworkRole):
            raise TypeError("network role must be a NetworkRole")
        if not isinstance(self.name, str) or not self.name:
            raise ValidationError("planned network needs a name")
        if not isinstance(self.internal, bool):
            raise TypeError("network internal flag must be boolean")
        if not isinstance(self.no_default_route, bool):
            raise TypeError("network no-default-route flag must be boolean")
        if self.no_default_route and self.subnet is None:
            raise RuntimePlanError(
                "no_default_route requires an explicitly addressed network"
            )
        if (self.subnet is None) != (self.gateway is None):
            raise RuntimePlanError("network subnet and gateway must be supplied together")
        if self.subnet is not None and self.gateway not in self.subnet:
            raise RuntimePlanError(
                f"gateway {self.gateway} is outside planned network {self.subnet}"
            )
        if not all(isinstance(route, NetworkRoute) for route in self.routes):
            raise TypeError("network routes must contain NetworkRoute values")


@dataclass(frozen=True, slots=True)
class NetworkAttachment:
    network: str
    address: IPv4Address | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.network, str) or not self.network:
            raise ValidationError("network attachment needs a network name")


@dataclass(frozen=True, slots=True)
class ContainerPlan:
    role: SessionRole
    name: str
    attachments: tuple[NetworkAttachment, ...] = ()
    capabilities: frozenset[str] = frozenset()
    network_namespace_of: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "attachments", tuple(self.attachments))
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        if not isinstance(self.role, SessionRole):
            raise TypeError("container role must be a SessionRole")
        if not isinstance(self.name, str) or not self.name:
            raise ValidationError("planned container needs a name")
        if not all(isinstance(item, NetworkAttachment) for item in self.attachments):
            raise TypeError("attachments must contain NetworkAttachment values")
        if self.network_namespace_of is not None and self.attachments:
            raise RuntimePlanError(
                "a container sharing another network namespace cannot attach networks"
            )
        if not all(isinstance(value, str) and value for value in self.capabilities):
            raise TypeError("container capabilities must be non-empty strings")

    @property
    def networks(self) -> tuple[str, ...]:
        """Names of the networks this container joins, in attachment order."""

        return tuple(item.network for item in self.attachments)


@dataclass(frozen=True, slots=True)
class PersistentVolumePlan:
    name: str
    target: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValidationError("persistent volume needs a name")
        if not isinstance(self.target, str) or not self.target.startswith("/"):
            raise ValidationError("persistent volume target must be absolute")


@dataclass(frozen=True, slots=True)
class SecretFilePlan:
    filename: str
    source: Path

    def __post_init__(self) -> None:
        if not isinstance(self.filename, str) or not self.filename:
            raise ValidationError("secret file plan needs a filename")
        if not isinstance(self.source, Path):
            raise TypeError("secret file source must be a Path")


@dataclass(frozen=True, slots=True)
class GeneratedFilePlan:
    kind: GeneratedFileKind
    destination: Path

    def __post_init__(self) -> None:
        if not isinstance(self.kind, GeneratedFileKind):
            raise TypeError("generated file kind must be a GeneratedFileKind")
        if not isinstance(self.destination, Path):
            raise TypeError("generated file destination must be a Path")


@dataclass(frozen=True, slots=True)
class RoutedSubnetAllocation:
    internal: IPv4Network
    scan: IPv4Network
    egress: IPv4Network

    def __post_init__(self) -> None:
        values = (self.internal, self.scan, self.egress)
        if not all(isinstance(value, IPv4Network) for value in values):
            raise TypeError("routed allocation must contain IPv4Network values")
        if any(value.prefixlen > 28 for value in values):
            raise RuntimePlanError(
                "routed subnets must be /28 or larger for fixed ASF addresses"
            )
        for index, left in enumerate(values):
            if any(left.overlaps(right) for right in values[index + 1 :]):
                raise RuntimePlanError("routed subnets must not overlap")

    @classmethod
    def parse(cls, values: Sequence[str]) -> "RoutedSubnetAllocation":
        if len(values) != 3:
            raise RuntimePlanError("routed planning requires exactly three subnets")
        try:
            parsed = tuple(IPv4Network(value, strict=True) for value in values)
        except ValueError as exc:
            raise RuntimePlanError(f"invalid routed subnet: {exc}") from exc
        return cls(*parsed)


@dataclass(frozen=True, slots=True)
class RuntimePlan:
    runtime: str
    resource_prefix: str
    session_key: str
    session_label: str
    sandbox_label: str
    owner_pid: int
    adapter: str
    runtime_mode: str
    runtime_isolation: str
    network_mode: str
    command: tuple[str, ...]
    broker_enabled: bool
    runtime_container: ContainerPlan
    support_containers: tuple[ContainerPlan, ...]
    networks: tuple[NetworkPlan, ...]
    persistent_volumes: tuple[PersistentVolumePlan, ...]
    secret_files: tuple[SecretFilePlan, ...]
    generated_files: tuple[GeneratedFilePlan, ...]
    ephemeral_resources: tuple[Resource, ...]

    def __post_init__(self) -> None:
        validate_runtime_name(self.runtime)
        object.__setattr__(self, "command", tuple(self.command))
        object.__setattr__(self, "support_containers", tuple(self.support_containers))
        object.__setattr__(self, "networks", tuple(self.networks))
        object.__setattr__(self, "persistent_volumes", tuple(self.persistent_volumes))
        object.__setattr__(self, "secret_files", tuple(self.secret_files))
        object.__setattr__(self, "generated_files", tuple(self.generated_files))
        object.__setattr__(self, "ephemeral_resources", tuple(self.ephemeral_resources))
        if (
            isinstance(self.owner_pid, bool)
            or not isinstance(self.owner_pid, int)
            or self.owner_pid <= 0
        ):
            raise ValidationError("runtime plan owner PID must be positive")
        if not isinstance(self.broker_enabled, bool):
            raise TypeError("broker_enabled must be boolean")
        if self.runtime_isolation not in {"container", "microvm"}:
            raise ValidationError(
                f"unsupported runtime isolation: {self.runtime_isolation!r}"
            )
        _validate_runtime_plan(self)

    @property
    def containers(self) -> tuple[ContainerPlan, ...]:
        return (self.runtime_container, *self.support_containers)

    def container(self, role: SessionRole) -> ContainerPlan | None:
        """Return the planned container for ``role``, when that role is used."""

        if not isinstance(role, SessionRole):
            raise TypeError("role must be a SessionRole")
        return next((item for item in self.containers if item.role is role), None)

    def network(self, role: NetworkRole) -> NetworkPlan | None:
        """Return the planned network for ``role``, when that role is used."""

        if not isinstance(role, NetworkRole):
            raise TypeError("role must be a NetworkRole")
        return next((item for item in self.networks if item.role is role), None)

    @property
    def needs_proxy(self) -> bool:
        return self.container(SessionRole.PROXY) is not None

    @property
    def needs_broker(self) -> bool:
        return self.container(SessionRole.BROKER) is not None

    @property
    def network_names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.networks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime": self.runtime,
            "resource_prefix": self.resource_prefix,
            "session_key": self.session_key,
            "session_label": self.session_label,
            "sandbox_label": self.sandbox_label,
            "owner_pid": self.owner_pid,
            "adapter": self.adapter,
            "runtime_mode": self.runtime_mode,
            "runtime_isolation": self.runtime_isolation,
            "network_mode": self.network_mode,
            "command": list(self.command),
            "broker_enabled": self.broker_enabled,
            "runtime_container": _container_dict(self.runtime_container),
            "support_containers": [
                _container_dict(container) for container in self.support_containers
            ],
            "networks": [_network_dict(network) for network in self.networks],
            "persistent_volumes": [
                {"name": volume.name, "target": volume.target}
                for volume in self.persistent_volumes
            ],
            "secret_files": [
                {"filename": secret.filename, "source": str(secret.source)}
                for secret in self.secret_files
            ],
            "generated_files": [
                {"kind": item.kind.value, "destination": str(item.destination)}
                for item in self.generated_files
            ],
            "ephemeral_resources": [
                {
                    "kind": item.kind.value,
                    "name": item.name,
                    "runtime": item.runtime,
                    "owner_pid": item.owner_pid,
                }
                for item in self.ephemeral_resources
            ],
        }


def routed_broker_address(plan: RuntimePlan) -> IPv4Address | None:
    """Return the broker address reachable from a routed microVM TAP guest."""

    if not (
        plan.network_mode == "routed"
        and plan.runtime_isolation == "microvm"
        and plan.broker_enabled
    ):
        return None
    scan = plan.network(NetworkRole.SCAN)
    broker = plan.container(SessionRole.BROKER)
    if scan is None or broker is None:
        raise RuntimePlanError("routed microVM broker topology is incomplete")
    for attachment in broker.attachments:
        if attachment.network == scan.name:
            if attachment.address is None:
                raise RuntimePlanError("routed microVM broker needs a fixed scan address")
            return attachment.address
    raise RuntimePlanError("routed microVM broker is not attached to the scan network")


def runtime_plan_path(paths: RepoPaths, runtime: str) -> Path:
    return paths.session_artifact(runtime, "runtime-plan.json")


def build_runtime_plan(
    manifest: RuntimeManifest,
    *,
    paths: RepoPaths,
    owner_pid: int,
    broker_globally_enabled: bool,
    routed_subnets: RoutedSubnetAllocation | None = None,
) -> RuntimePlan:
    """Resolve one complete, immutable topology without external mutation."""

    if not isinstance(manifest, RuntimeManifest):
        raise TypeError("manifest must be a RuntimeManifest")
    if isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid <= 0:
        raise ValidationError("plan owner PID must be a positive integer")
    if not isinstance(broker_globally_enabled, bool):
        raise TypeError("broker_globally_enabled must be boolean")

    identity = paths.identity
    runtime = validate_runtime_name(manifest.name)
    names = identity.network_names(runtime)
    mode = manifest.network.mode
    broker_enabled = bool(
        broker_globally_enabled and manifest.llm and manifest.llm.broker
    )

    if mode == "routed" and routed_subnets is None:
        raise RuntimePlanError("routed mode requires an explicit subnet allocation")
    if mode != "routed" and routed_subnets is not None:
        raise RuntimePlanError("routed subnets are valid only for routed mode")

    networks: list[NetworkPlan] = []
    runtime_attachments: list[NetworkAttachment] = []

    if mode in ("isolated", "proxy"):
        networks.append(NetworkPlan(NetworkRole.INTERNAL, names.internal, True))
        runtime_attachments.append(NetworkAttachment(names.internal))
        if mode == "proxy":
            networks.append(NetworkPlan(NetworkRole.EGRESS, names.egress, False))
        if broker_enabled:
            networks.append(NetworkPlan(NetworkRole.PROVIDER, names.provider, False))
    else:
        assert routed_subnets is not None
        internal_gateway = _fixed_address(routed_subnets.internal, 1)
        scan_gateway = _fixed_address(routed_subnets.scan, 1)
        scan_router = _fixed_address(routed_subnets.scan, 2)
        runtime_scan = _fixed_address(routed_subnets.scan, 10)
        egress_gateway = _fixed_address(routed_subnets.egress, 1)
        egress_router = _fixed_address(routed_subnets.egress, 2)
        routes = tuple(
            NetworkRoute(destination, scan_router)
            for destination in _routed_route_destinations(manifest)
        )
        networks.extend(
            (
                NetworkPlan(
                    NetworkRole.INTERNAL,
                    names.internal,
                    True,
                    routed_subnets.internal,
                    internal_gateway,
                    no_default_route=True,
                ),
                NetworkPlan(
                    NetworkRole.SCAN,
                    names.scan,
                    True,
                    routed_subnets.scan,
                    scan_gateway,
                    routes,
                    no_default_route=True,
                ),
                NetworkPlan(
                    NetworkRole.ROUTED_EGRESS,
                    names.routed_egress,
                    False,
                    routed_subnets.egress,
                    egress_gateway,
                ),
            )
        )
        if broker_enabled:
            networks.append(NetworkPlan(NetworkRole.PROVIDER, names.provider, False))
        runtime_attachments.extend(
            (
                NetworkAttachment(names.internal),
                NetworkAttachment(names.scan, runtime_scan),
            )
        )

    runtime_container = ContainerPlan(
        SessionRole.RUNTIME,
        identity.container_name(runtime),
        tuple(runtime_attachments),
        frozenset(manifest.capabilities),
    )

    support: list[ContainerPlan] = []
    if broker_enabled:
        broker_attachments = [
            NetworkAttachment(names.internal),
            NetworkAttachment(names.provider),
        ]
        if mode == "routed" and manifest.runtime.isolation == "microvm":
            assert routed_subnets is not None
            broker_attachments.append(
                NetworkAttachment(names.scan, _fixed_address(routed_subnets.scan, 3))
            )
        support.append(
            ContainerPlan(
                SessionRole.BROKER,
                identity.ephemeral_container(runtime, "litellm", owner_pid),
                tuple(broker_attachments),
            )
        )
    if mode == "proxy":
        support.append(
            ContainerPlan(
                SessionRole.PROXY,
                identity.ephemeral_container(runtime, "proxy", owner_pid),
                (
                    NetworkAttachment(names.internal),
                    NetworkAttachment(names.egress),
                ),
            )
        )
    elif mode == "routed":
        assert routed_subnets is not None
        gateway_name = identity.ephemeral_container(runtime, "gateway", owner_pid)
        support.extend(
            (
                ContainerPlan(
                    SessionRole.ROUTED_GATEWAY,
                    gateway_name,
                    (
                        NetworkAttachment(names.scan, _fixed_address(routed_subnets.scan, 2)),
                        NetworkAttachment(
                            names.routed_egress,
                            _fixed_address(routed_subnets.egress, 2),
                        ),
                    ),
                ),
                ContainerPlan(
                    SessionRole.ROUTED_INIT,
                    identity.gateway_init_container(runtime, owner_pid),
                    network_namespace_of=gateway_name,
                    capabilities=frozenset({"net_admin"}),
                ),
            )
        )
        if manifest.observability.network_activity:
            support.append(
                ContainerPlan(
                    SessionRole.NETWORK_OBSERVER,
                    identity.ephemeral_container(runtime, "network-observer", owner_pid),
                    network_namespace_of=gateway_name,
                    capabilities=frozenset({"net_raw"}),
                )
            )

    volume_names = state_volume_names(identity, runtime, manifest)
    volume_targets = tuple(entry.target for entry in manifest.state_volumes) + (
        "/commandhistory",
    )
    volumes = tuple(
        PersistentVolumePlan(name, target)
        for name, target in zip(volume_names, volume_targets, strict=True)
    )
    secrets = tuple(
        SecretFilePlan(filename, paths.secrets_dir / filename)
        for filename in manifest.secret_files
    )

    generated = [
        GeneratedFilePlan(GeneratedFileKind.RUNTIME_PLAN, runtime_plan_path(paths, runtime)),
    ]
    if manifest.runtime.isolation == "container":
        generated.append(
            GeneratedFilePlan(GeneratedFileKind.DEVCONTAINER, identity.config_json(runtime))
        )
    if mode == "proxy":
        generated.append(
            GeneratedFilePlan(
                GeneratedFileKind.PROXY_POLICY,
                identity.proxy_config_dir(runtime) / "Caddyfile",
            )
        )
    if mode == "routed":
        generated.append(
            GeneratedFilePlan(
                GeneratedFileKind.ROUTED_POLICY,
                identity.session_dir(runtime) / "routed.nft",
            )
        )

    resources = _ephemeral_resources(
        identity,
        runtime,
        owner_pid,
        runtime_container,
        support,
        networks,
        broker_enabled,
        mode,
    )

    return RuntimePlan(
        runtime=runtime,
        resource_prefix=identity.prefix,
        session_key=identity.session_key(runtime),
        session_label=identity.session_label(runtime),
        sandbox_label=identity.sandbox_label,
        owner_pid=owner_pid,
        adapter=manifest.adapter,
        runtime_mode=manifest.runtime.mode,
        runtime_isolation=manifest.runtime.isolation,
        network_mode=mode,
        command=manifest.runtime.command,
        broker_enabled=broker_enabled,
        runtime_container=runtime_container,
        support_containers=tuple(support),
        networks=tuple(networks),
        persistent_volumes=volumes,
        secret_files=secrets,
        generated_files=tuple(generated),
        ephemeral_resources=resources,
    )



def read_runtime_plan(path: str | os.PathLike[str]) -> RuntimePlan:
    """Load and validate one persisted runtime plan.

    The JSON file is treated as untrusted session state.  Unknown fields,
    malformed types, unsafe enum values, and invalid topology all fail closed
    before a renderer or lifecycle consumer can use the plan.
    """

    target = Path(path)
    try:
        if target.is_symlink():
            raise RuntimePlanError(f"runtime plan must not be a symlink: {target}")
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimePlanError(f"runtime plan not found: {target}") from exc
    except UnicodeDecodeError as exc:
        raise RuntimePlanError(f"runtime plan is not valid UTF-8: {target}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimePlanError(f"invalid runtime plan JSON in {target}: {exc}") from exc
    except OSError as exc:
        raise RuntimePlanError(f"cannot read runtime plan {target}: {exc}") from exc

    if not isinstance(payload, dict):
        raise RuntimePlanError("runtime plan must be a JSON object")
    return _runtime_plan_from_dict(payload)


def validate_runtime_plan_context(
    plan: RuntimePlan,
    manifest: RuntimeManifest,
    paths: RepoPaths,
) -> None:
    """Prove that a persisted plan still matches this checkout and manifest."""

    if not isinstance(plan, RuntimePlan):
        raise TypeError("plan must be a RuntimePlan")
    if not isinstance(manifest, RuntimeManifest):
        raise TypeError("manifest must be a RuntimeManifest")
    if not isinstance(paths, RepoPaths):
        raise TypeError("paths must be RepoPaths")
    if plan.runtime != manifest.name:
        raise RuntimePlanError(
            f"runtime plan is for {plan.runtime!r}, not {manifest.name!r}"
        )

    routed: RoutedSubnetAllocation | None = None
    if plan.network_mode == "routed":
        internal = plan.network(NetworkRole.INTERNAL)
        scan = plan.network(NetworkRole.SCAN)
        egress = plan.network(NetworkRole.ROUTED_EGRESS)
        if any(item is None or item.subnet is None for item in (internal, scan, egress)):
            raise RuntimePlanError("routed runtime plan is missing its allocated subnets")
        assert internal is not None and internal.subnet is not None
        assert scan is not None and scan.subnet is not None
        assert egress is not None and egress.subnet is not None
        routed = RoutedSubnetAllocation(internal.subnet, scan.subnet, egress.subnet)

    expected = build_runtime_plan(
        manifest,
        paths=paths,
        owner_pid=plan.owner_pid,
        broker_globally_enabled=plan.broker_enabled,
        routed_subnets=routed,
    )
    if plan != expected:
        raise RuntimePlanError(
            "persisted runtime plan does not match the current manifest and checkout"
        )


def _runtime_plan_from_dict(payload: dict[str, Any]) -> RuntimePlan:
    expected_keys = {
        "runtime",
        "resource_prefix",
        "session_key",
        "session_label",
        "sandbox_label",
        "owner_pid",
        "adapter",
        "runtime_mode",
        "runtime_isolation",
        "network_mode",
        "command",
        "broker_enabled",
        "runtime_container",
        "support_containers",
        "networks",
        "persistent_volumes",
        "secret_files",
        "generated_files",
        "ephemeral_resources",
    }
    _require_exact_keys(payload, expected_keys, "runtime plan")

    runtime = _require_text(payload, "runtime", "runtime plan")
    owner_pid = _require_int(payload, "owner_pid", "runtime plan")
    return RuntimePlan(
        runtime=runtime,
        resource_prefix=_require_text(payload, "resource_prefix", "runtime plan"),
        session_key=_require_text(payload, "session_key", "runtime plan"),
        session_label=_require_text(payload, "session_label", "runtime plan"),
        sandbox_label=_require_text(payload, "sandbox_label", "runtime plan"),
        owner_pid=owner_pid,
        adapter=_require_text(payload, "adapter", "runtime plan"),
        runtime_mode=_require_text(payload, "runtime_mode", "runtime plan"),
        runtime_isolation=_require_text(payload, "runtime_isolation", "runtime plan"),
        network_mode=_require_text(payload, "network_mode", "runtime plan"),
        command=tuple(_require_text_list(payload, "command", "runtime plan")),
        broker_enabled=_require_bool(payload, "broker_enabled", "runtime plan"),
        runtime_container=_parse_container(
            _require_mapping(payload, "runtime_container", "runtime plan")
        ),
        support_containers=tuple(
            _parse_container(item)
            for item in _require_mapping_list(
                payload, "support_containers", "runtime plan"
            )
        ),
        networks=tuple(
            _parse_network(item)
            for item in _require_mapping_list(payload, "networks", "runtime plan")
        ),
        persistent_volumes=tuple(
            _parse_volume(item)
            for item in _require_mapping_list(
                payload, "persistent_volumes", "runtime plan"
            )
        ),
        secret_files=tuple(
            _parse_secret(item)
            for item in _require_mapping_list(payload, "secret_files", "runtime plan")
        ),
        generated_files=tuple(
            _parse_generated_file(item)
            for item in _require_mapping_list(
                payload, "generated_files", "runtime plan"
            )
        ),
        ephemeral_resources=tuple(
            _parse_resource(item)
            for item in _require_mapping_list(
                payload, "ephemeral_resources", "runtime plan"
            )
        ),
    )


def _parse_container(payload: dict[str, Any]) -> ContainerPlan:
    _require_exact_keys(
        payload,
        {"role", "name", "attachments", "capabilities", "network_namespace_of"},
        "container plan",
    )
    try:
        role = SessionRole(_require_text(payload, "role", "container plan"))
    except ValueError as exc:
        raise RuntimePlanError(f"invalid container role: {payload.get('role')!r}") from exc
    namespace = payload["network_namespace_of"]
    if namespace is not None and not isinstance(namespace, str):
        raise RuntimePlanError("container network_namespace_of must be text or null")
    return ContainerPlan(
        role=role,
        name=_require_text(payload, "name", "container plan"),
        attachments=tuple(
            _parse_attachment(item)
            for item in _require_mapping_list(payload, "attachments", "container plan")
        ),
        capabilities=frozenset(
            _require_text_list(payload, "capabilities", "container plan")
        ),
        network_namespace_of=namespace,
    )


def _parse_attachment(payload: dict[str, Any]) -> NetworkAttachment:
    _require_exact_keys(payload, {"network", "address"}, "network attachment")
    raw_address = payload["address"]
    if raw_address is not None and not isinstance(raw_address, str):
        raise RuntimePlanError("network attachment address must be text or null")
    try:
        address = None if raw_address is None else IPv4Address(raw_address)
    except AddressValueError as exc:
        raise RuntimePlanError(f"invalid attachment address: {raw_address!r}") from exc
    return NetworkAttachment(
        _require_text(payload, "network", "network attachment"), address
    )


def _parse_network(payload: dict[str, Any]) -> NetworkPlan:
    _require_exact_keys(
        payload,
        {
            "role",
            "name",
            "internal",
            "subnet",
            "gateway",
            "routes",
            "no_default_route",
        },
        "network plan",
    )
    try:
        role = NetworkRole(_require_text(payload, "role", "network plan"))
    except ValueError as exc:
        raise RuntimePlanError(f"invalid network role: {payload.get('role')!r}") from exc
    raw_subnet = payload["subnet"]
    raw_gateway = payload["gateway"]
    if raw_subnet is not None and not isinstance(raw_subnet, str):
        raise RuntimePlanError("network subnet must be text or null")
    if raw_gateway is not None and not isinstance(raw_gateway, str):
        raise RuntimePlanError("network gateway must be text or null")
    try:
        subnet = None if raw_subnet is None else IPv4Network(raw_subnet, strict=True)
        gateway = None if raw_gateway is None else IPv4Address(raw_gateway)
    except (AddressValueError, NetmaskValueError) as exc:
        raise RuntimePlanError(
            f"invalid planned network address data: {raw_subnet!r}, {raw_gateway!r}"
        ) from exc
    return NetworkPlan(
        role=role,
        name=_require_text(payload, "name", "network plan"),
        internal=_require_bool(payload, "internal", "network plan"),
        subnet=subnet,
        gateway=gateway,
        routes=tuple(
            _parse_route(item)
            for item in _require_mapping_list(payload, "routes", "network plan")
        ),
        no_default_route=_require_bool(
            payload, "no_default_route", "network plan"
        ),
    )


def _parse_route(payload: dict[str, Any]) -> NetworkRoute:
    _require_exact_keys(payload, {"destination", "gateway"}, "network route")
    try:
        return NetworkRoute(
            IPv4Network(_require_text(payload, "destination", "network route"), strict=True),
            IPv4Address(_require_text(payload, "gateway", "network route")),
        )
    except (AddressValueError, NetmaskValueError) as exc:
        raise RuntimePlanError(f"invalid planned route: {exc}") from exc


def _parse_volume(payload: dict[str, Any]) -> PersistentVolumePlan:
    _require_exact_keys(payload, {"name", "target"}, "persistent volume")
    return PersistentVolumePlan(
        _require_text(payload, "name", "persistent volume"),
        _require_text(payload, "target", "persistent volume"),
    )


def _parse_secret(payload: dict[str, Any]) -> SecretFilePlan:
    _require_exact_keys(payload, {"filename", "source"}, "secret file")
    return SecretFilePlan(
        _require_text(payload, "filename", "secret file"),
        Path(_require_text(payload, "source", "secret file")),
    )


def _parse_generated_file(payload: dict[str, Any]) -> GeneratedFilePlan:
    _require_exact_keys(payload, {"kind", "destination"}, "generated file")
    raw_kind = _require_text(payload, "kind", "generated file")
    try:
        kind = GeneratedFileKind(raw_kind)
    except ValueError as exc:
        raise RuntimePlanError(f"invalid generated file kind: {raw_kind!r}") from exc
    return GeneratedFilePlan(
        kind,
        Path(_require_text(payload, "destination", "generated file")),
    )


def _parse_resource(payload: dict[str, Any]) -> Resource:
    _require_exact_keys(
        payload,
        {"kind", "name", "runtime", "owner_pid"},
        "ephemeral resource",
    )
    raw_kind = _require_text(payload, "kind", "ephemeral resource")
    try:
        kind = ResourceKind(raw_kind)
    except ValueError as exc:
        raise RuntimePlanError(f"invalid ephemeral resource kind: {raw_kind!r}") from exc
    raw_owner = payload["owner_pid"]
    if raw_owner is not None and (
        isinstance(raw_owner, bool) or not isinstance(raw_owner, int)
    ):
        raise RuntimePlanError(
            "ephemeral resource owner_pid must be an integer or null"
        )
    return Resource(
        kind,
        _require_text(payload, "name", "ephemeral resource"),
        _require_text(payload, "runtime", "ephemeral resource"),
        raw_owner,
    )


def _require_exact_keys(
    payload: dict[str, Any], expected: set[str], context: str
) -> None:
    actual = set(payload)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise RuntimePlanError(f"invalid {context} fields: {'; '.join(details)}")


def _require_text(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload[key]
    if not isinstance(value, str):
        raise RuntimePlanError(f"{context} {key} must be text")
    return value


def _require_int(payload: dict[str, Any], key: str, context: str) -> int:
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimePlanError(f"{context} {key} must be an integer")
    return value


def _require_bool(payload: dict[str, Any], key: str, context: str) -> bool:
    value = payload[key]
    if not isinstance(value, bool):
        raise RuntimePlanError(f"{context} {key} must be boolean")
    return value


def _require_mapping(
    payload: dict[str, Any], key: str, context: str
) -> dict[str, Any]:
    value = payload[key]
    if not isinstance(value, dict):
        raise RuntimePlanError(f"{context} {key} must be an object")
    if not all(isinstance(item, str) for item in value):
        raise RuntimePlanError(f"{context} {key} keys must be text")
    return value


def _require_text_list(
    payload: dict[str, Any], key: str, context: str
) -> list[str]:
    value = payload[key]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimePlanError(f"{context} {key} must be a list of text values")
    return value


def _require_mapping_list(
    payload: dict[str, Any], key: str, context: str
) -> list[dict[str, Any]]:
    value = payload[key]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RuntimePlanError(f"{context} {key} must be a list of objects")
    if any(not all(isinstance(name, str) for name in item) for item in value):
        raise RuntimePlanError(f"{context} {key} object keys must be text")
    return value


load_runtime_plan = read_runtime_plan


def write_runtime_plan(plan: RuntimePlan, destination: Path | None = None) -> Path:
    """Write a deterministic JSON plan atomically."""

    if not isinstance(plan, RuntimePlan):
        raise TypeError("plan must be a RuntimePlan")
    target = (
        next(
            item.destination
            for item in plan.generated_files
            if item.kind is GeneratedFileKind.RUNTIME_PLAN
        )
        if destination is None
        else Path(destination)
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            delete=False,
        ) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        temporary.replace(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target


def _fixed_address(network: IPv4Network, offset: int) -> IPv4Address:
    address = network.network_address + offset
    if address not in network or address == network.broadcast_address:
        raise RuntimePlanError(f"{network} cannot provide fixed address offset {offset}")
    return address


def _unique_destinations(manifest: RuntimeManifest) -> tuple[IPv4Network, ...]:
    seen: set[IPv4Network] = set()
    destinations: list[IPv4Network] = []
    for rule in manifest.network.routed_rules:
        if rule.destination not in seen:
            seen.add(rule.destination)
            destinations.append(rule.destination)
    return tuple(destinations)


def _routed_route_destinations(
    manifest: RuntimeManifest,
) -> tuple[IPv4Network, ...]:
    destinations = list(_unique_destinations(manifest))
    verification = manifest.network.routed_verification
    if verification is None:
        return tuple(destinations)
    denied = verification.denied_address
    if not any(denied in destination for destination in destinations):
        destinations.append(IPv4Network(f"{denied}/32"))
    return tuple(destinations)


def _ephemeral_resources(
    identity: ResourceIdentity,
    runtime: str,
    owner_pid: int,
    runtime_container: ContainerPlan,
    support: Sequence[ContainerPlan],
    networks: Sequence[NetworkPlan],
    broker_enabled: bool,
    mode: str,
) -> tuple[Resource, ...]:
    kind_for_role = {
        SessionRole.RUNTIME: ResourceKind.RUNTIME_CONTAINER,
        SessionRole.BROKER: ResourceKind.BROKER_CONTAINER,
        SessionRole.PROXY: ResourceKind.PROXY_CONTAINER,
        SessionRole.ROUTED_GATEWAY: ResourceKind.GATEWAY_CONTAINER,
        SessionRole.ROUTED_INIT: ResourceKind.GATEWAY_INIT_CONTAINER,
        SessionRole.NETWORK_OBSERVER: ResourceKind.NETWORK_OBSERVER_CONTAINER,
    }
    resources = [
        Resource(kind_for_role[runtime_container.role], runtime_container.name, runtime),
        *(
            Resource(kind_for_role[container.role], container.name, runtime)
            for container in support
        ),
    ]
    if broker_enabled:
        resources.extend(
            (
                Resource(
                    ResourceKind.SECRET,
                    identity.broker_secret(runtime, owner_pid),
                    runtime,
                ),
                Resource(ResourceKind.BROKER_STATE, str(identity.broker_state(runtime)), runtime),
            )
        )
    resources.extend(
        Resource(ResourceKind.NETWORK, network.name, runtime) for network in networks
    )
    if mode == "routed":
        resources.append(
            Resource(
                ResourceKind.SUBNET_RESERVATION,
                identity.subnet_reservation_session(runtime),
                runtime,
                owner_pid,
            )
        )
    resources.append(
        Resource(
            ResourceKind.SESSION_LOCK,
            str(identity.session_lock(runtime)),
            runtime,
            owner_pid,
        )
    )
    return tuple(resources)


def _validate_runtime_plan(plan: RuntimePlan) -> None:
    container_names = [container.name for container in plan.containers]
    if len(container_names) != len(set(container_names)):
        raise RuntimePlanError("planned container names must be unique")
    network_names = [network.name for network in plan.networks]
    if len(network_names) != len(set(network_names)):
        raise RuntimePlanError("planned network names must be unique")

    network_by_name = {network.name: network for network in plan.networks}
    for network in plan.networks:
        should_be_internal = network.role in {
            NetworkRole.INTERNAL,
            NetworkRole.SCAN,
        }
        if network.internal is not should_be_internal:
            raise RuntimePlanError(
                f"network {network.name} has an invalid internal flag"
            )
        if network.routes and network.subnet is None:
            raise RuntimePlanError(
                f"network {network.name} cannot have routes without a subnet"
            )
        expected_no_default = (
            plan.network_mode == "routed"
            and network.role in {NetworkRole.INTERNAL, NetworkRole.SCAN}
        )
        if network.no_default_route is not expected_no_default:
            raise RuntimePlanError(
                f"network {network.name} has an invalid no-default-route flag"
            )
        for route in network.routes:
            if network.subnet is None or route.gateway not in network.subnet:
                raise RuntimePlanError(
                    f"route gateway {route.gateway} is outside network {network.name}"
                )

    used_addresses: set[tuple[str, IPv4Address]] = set()
    external_roles = {
        NetworkRole.EGRESS,
        NetworkRole.PROVIDER,
        NetworkRole.ROUTED_EGRESS,
    }
    for container in plan.containers:
        for attachment in container.attachments:
            network = network_by_name.get(attachment.network)
            if network is None:
                raise RuntimePlanError(
                    f"container {container.name} references unplanned network "
                    f"{attachment.network}"
                )
            if container.role is SessionRole.RUNTIME and network.role in external_roles:
                raise RuntimePlanError(
                    f"runtime container cannot attach to external network {network.name}"
                )
            if attachment.address is not None:
                if network.subnet is None or attachment.address not in network.subnet:
                    raise RuntimePlanError(
                        f"address {attachment.address} is outside network {network.name}"
                    )
                if attachment.address == network.gateway:
                    raise RuntimePlanError(
                        f"address {attachment.address} collides with the gateway of "
                        f"{network.name}"
                    )
                key = (network.name, attachment.address)
                if key in used_addresses:
                    raise RuntimePlanError(
                        f"address {attachment.address} is duplicated on {network.name}"
                    )
                used_addresses.add(key)

    runtime_caps = {value.lower() for value in plan.runtime_container.capabilities}
    if "net_admin" in runtime_caps:
        raise RuntimePlanError("NET_ADMIN is never permitted on the runtime container")
    for container in plan.support_containers:
        caps = {value.lower() for value in container.capabilities}
        if "net_admin" in caps and container.role is not SessionRole.ROUTED_INIT:
            raise RuntimePlanError("only the short-lived routed initializer may use NET_ADMIN")

    resource_keys = [(item.kind, item.name) for item in plan.ephemeral_resources]
    if len(resource_keys) != len(set(resource_keys)):
        raise RuntimePlanError("planned ephemeral resources must be unique")
    if any(not resource.removable for resource in plan.ephemeral_resources):
        raise RuntimePlanError("every ephemeral resource needs a teardown identity")
    owner_scoped_kinds = {
        ResourceKind.SUBNET_RESERVATION,
        ResourceKind.SESSION_LOCK,
    }
    for resource in plan.ephemeral_resources:
        if resource.runtime != plan.runtime:
            raise RuntimePlanError(
                f"ephemeral resource {resource.name} belongs to another runtime"
            )
        expected_owner = (
            plan.owner_pid if resource.kind in owner_scoped_kinds else None
        )
        if resource.owner_pid != expected_owner:
            raise RuntimePlanError(
                f"ephemeral resource {resource.name} has an invalid owner PID"
            )

    volume_names = {volume.name for volume in plan.persistent_volumes}
    if any(resource.name in volume_names for resource in plan.ephemeral_resources):
        raise RuntimePlanError("persistent volumes cannot be ephemeral resources")


def _container_dict(container: ContainerPlan) -> dict[str, Any]:
    return {
        "role": container.role.value,
        "name": container.name,
        "attachments": [
            {
                "network": item.network,
                "address": None if item.address is None else str(item.address),
            }
            for item in container.attachments
        ],
        "capabilities": sorted(container.capabilities),
        "network_namespace_of": container.network_namespace_of,
    }


def _network_dict(network: NetworkPlan) -> dict[str, Any]:
    return {
        "role": network.role.value,
        "name": network.name,
        "internal": network.internal,
        "no_default_route": network.no_default_route,
        "subnet": None if network.subnet is None else str(network.subnet),
        "gateway": None if network.gateway is None else str(network.gateway),
        "routes": [
            {"destination": str(route.destination), "gateway": str(route.gateway)}
            for route in network.routes
        ],
    }


def _bool_text(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--owner-pid", required=True, type=int)
    parser.add_argument("--broker-enabled", required=True, type=_bool_text)
    parser.add_argument("--routed-subnet", action="append", default=[])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args(argv)

    try:
        paths = RepoPaths.for_root(args.root)
        manifest = load_model(paths.identity.runtime_manifest(args.runtime))
        routed = (
            RoutedSubnetAllocation.parse(args.routed_subnet)
            if args.routed_subnet
            else None
        )
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=args.owner_pid,
            broker_globally_enabled=args.broker_enabled,
            routed_subnets=routed,
        )
        if args.stdout:
            print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
        else:
            write_runtime_plan(plan, args.output)
    except (ConfigurationError, ValidationError, OSError, ValueError) as exc:
        print(f"runtime planning failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
