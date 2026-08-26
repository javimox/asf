"""Immutable typed models for ASF's host-side services.

The YAML manifest is the external representation.  :mod:`asf.manifest`
validates it and converts it into these models for all callers.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Literal, TypeAlias

__all__ = [
    "BuildArgument",
    "EnvironmentVariable",
    "LlmSettings",
    "NetworkPolicy",
    "ObservabilitySettings",
    "PortPolicy",
    "RoutedRule",
    "RoutedVerification",
    "RuntimeManifest",
    "RuntimeIsolation",
    "RuntimeSettings",
    "StateVolume",
]

RuntimeMode: TypeAlias = Literal["interactive", "service"]
RuntimeIsolation: TypeAlias = Literal["container", "microvm"]
NetworkMode: TypeAlias = Literal["isolated", "proxy", "routed"]
LlmProtocol: TypeAlias = Literal["anthropic", "openai"]
RoutedProtocol: TypeAlias = Literal["tcp", "udp", "icmp_echo"]
PortPolicy: TypeAlias = tuple[int, ...] | Literal["any"] | None


@dataclass(frozen=True, slots=True)
class BuildArgument:
    name: str
    value: str


@dataclass(frozen=True, slots=True)
class EnvironmentVariable:
    name: str
    value: str


@dataclass(frozen=True, slots=True)
class StateVolume:
    key: str
    target: str


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    mode: RuntimeMode = "interactive"
    command: tuple[str, ...] = ()
    build_arguments: tuple[BuildArgument, ...] = ()
    isolation: RuntimeIsolation = "container"


@dataclass(frozen=True, slots=True)
class LlmSettings:
    broker: bool
    protocol: LlmProtocol | None = None
    provider: str | None = None
    api_key_env: str = ""
    direct_domain: str = ""
    models: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RoutedRule:
    destination: IPv4Network
    protocol: RoutedProtocol | None = None
    ports: PortPolicy = None

    def permits(
        self,
        address: IPv4Address,
        protocol: RoutedProtocol,
        port: int | None = None,
    ) -> bool:
        """Return whether this one rule permits the concrete destination."""

        if address not in self.destination:
            return False
        if self.protocol is None:
            return True
        if protocol != self.protocol:
            return False
        if protocol == "icmp_echo":
            return port is None
        if port is None:
            return False
        return self.ports == "any" or (
            isinstance(self.ports, tuple) and port in self.ports
        )


@dataclass(frozen=True, slots=True)
class RoutedVerification:
    address: IPv4Address
    protocol: Literal["tcp"]
    allowed_port: int
    blocked_port: int
    blocked_address: IPv4Address | None = None

    @property
    def denied_address(self) -> IPv4Address:
        return self.address if self.blocked_address is None else self.blocked_address


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    mode: NetworkMode = "proxy"
    allow_domains: tuple[str, ...] = ()
    verify_domain: str | None = None
    routed_rules: tuple[RoutedRule, ...] = ()
    routed_verification: RoutedVerification | None = None


@dataclass(frozen=True, slots=True)
class ObservabilitySettings:
    llm_prompts: bool = False


@dataclass(frozen=True, slots=True)
class RuntimeManifest:
    name: str
    description: str = ""
    adapter: str = "generic"
    runtime: RuntimeSettings = RuntimeSettings()
    state_volumes: tuple[StateVolume, ...] = ()
    llm: LlmSettings | None = None
    secret_files: tuple[str, ...] = ()
    network: NetworkPolicy = NetworkPolicy()
    observability: ObservabilitySettings = ObservabilitySettings()
    environment: tuple[EnvironmentVariable, ...] = ()
    capabilities: frozenset[str] = frozenset()

    def environment_dict(self) -> dict[str, str]:
        """Return an insertion-ordered mutable copy for process boundaries."""

        return {entry.name: entry.value for entry in self.environment}

    def build_arguments_dict(self) -> dict[str, str]:
        """Return an insertion-ordered mutable copy of manifest build args."""

        return {
            entry.name: entry.value
            for entry in self.runtime.build_arguments
        }
