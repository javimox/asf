"""Immutable, protocol-specific verification probe specifications.

Probe objects describe *what* ASF should observe. Executors own *how* the
observation is collected in a host, runtime, ephemeral-container, or inspect
context. No probe accepts an arbitrary shell command.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias
from urllib.parse import urlsplit

from ..errors import ValidationError
from ..secrets import SecretValue

__all__ = [
    "ContainerCondition",
    "DnsProbe",
    "ContainerInspectProbe",
    "ContainerPolicyCondition",
    "ContainerPolicyProbe",
    "NetworkFamily",
    "PlainHttpProxyProbe",
    "Probe",
    "ProbeValidationError",
    "ProxyConnectProbe",
    "RouteProbe",
    "RuntimeSecurityCondition",
    "RuntimeSecurityProbe",
    "TcpProbe",
]

_DEFAULT_TIMEOUT = 8.0


class ProbeValidationError(ValidationError):
    """A typed probe specification is incomplete or unsafe."""


class NetworkFamily(str, Enum):
    """Address family used by a route query."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class ContainerCondition(str, Enum):
    """A supported, inspect-only container predicate."""

    EXISTS = "exists"
    RUNNING = "running"
    HEALTHY = "healthy"


class ContainerPolicyCondition(str, Enum):
    """Inspect-only predicates needed by the live security report."""

    NETWORKS_EXACT = "networks_exact"
    NO_PUBLISHED_PORTS = "no_published_ports"
    READ_ONLY_ROOT = "read_only_root"
    USER_EQUALS = "user_equals"


class RuntimeSecurityCondition(str, Enum):
    """Fixed in-container assertions; no arbitrary command text is accepted."""

    CAPABILITIES_EQUAL = "capabilities_equal"
    UID_GID_1000 = "uid_gid_1000"
    NO_NEW_PRIVILEGES = "no_new_privileges"
    SUDO_ABSENT = "sudo_absent"
    PODMAN_SOCKET_ABSENT = "podman_socket_absent"
    SECRETS_MASKED_EMPTY = "secrets_masked_empty"
    CHECKOUT_READ_ONLY = "checkout_read_only"
    SYSTEM_DIRS_READ_ONLY = "system_dirs_read_only"
    SSH_PRIVATE_KEYS_ABSENT = "ssh_private_keys_absent"
    IPV4_FORWARDING_DISABLED = "ipv4_forwarding_disabled"
    IPV4_FORWARDING_ENABLED = "ipv4_forwarding_enabled"
    IPV6_FORWARDING_DISABLED = "ipv6_forwarding_disabled"
    ROUTED_CIDR_PRESENT = "routed_cidr_present"
    CADDY_POLICY_MATCHES = "caddy_policy_matches"
    PROVIDER_CREDENTIAL_ABSENT = "provider_credential_absent"
    EXTERNAL_DNS_UNAVAILABLE = "external_dns_unavailable"


@dataclass(frozen=True, slots=True)
class DnsProbe:
    """Test whether an external hostname can be resolved."""

    hostname: str
    timeout_seconds: float = _DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "hostname", _validate_host(self.hostname, "DNS hostname")
        )
        object.__setattr__(
            self,
            "timeout_seconds",
            _validate_timeout(self.timeout_seconds),
        )


@dataclass(frozen=True, slots=True)
class TcpProbe:
    """Test whether a TCP connection can be established."""

    address: str
    port: int
    timeout_seconds: float = _DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _validate_host(self.address, "address"))
        object.__setattr__(self, "port", _validate_port(self.port, "port"))
        object.__setattr__(
            self,
            "timeout_seconds",
            _validate_timeout(self.timeout_seconds),
        )


@dataclass(frozen=True, slots=True)
class ProxyConnectProbe:
    """Test an HTTP proxy CONNECT decision for one destination authority."""

    proxy_host: str
    proxy_port: int
    destination_host: str
    destination_port: int
    timeout_seconds: float = _DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "proxy_host",
            _validate_host(self.proxy_host, "proxy host"),
        )
        object.__setattr__(
            self,
            "proxy_port",
            _validate_port(self.proxy_port, "proxy port"),
        )
        object.__setattr__(
            self,
            "destination_host",
            _validate_host(self.destination_host, "destination host"),
        )
        object.__setattr__(
            self,
            "destination_port",
            _validate_port(self.destination_port, "destination port"),
        )
        object.__setattr__(
            self,
            "timeout_seconds",
            _validate_timeout(self.timeout_seconds),
        )


@dataclass(frozen=True, slots=True)
class PlainHttpProxyProbe:
    """Test a plain-HTTP request through an HTTP proxy."""

    proxy_host: str
    proxy_port: int
    url: str
    timeout_seconds: float = _DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "proxy_host",
            _validate_host(self.proxy_host, "proxy host"),
        )
        object.__setattr__(
            self,
            "proxy_port",
            _validate_port(self.proxy_port, "proxy port"),
        )
        object.__setattr__(self, "url", _validate_http_url(self.url))
        object.__setattr__(
            self,
            "timeout_seconds",
            _validate_timeout(self.timeout_seconds),
        )


@dataclass(frozen=True, slots=True)
class RouteProbe:
    """Test whether the selected network namespace has a route."""

    destination: str | None = None
    family: NetworkFamily = NetworkFamily.IPV4
    timeout_seconds: float = _DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        if self.destination is not None:
            object.__setattr__(
                self,
                "destination",
                _validate_host(self.destination, "route destination"),
            )
        if not isinstance(self.family, NetworkFamily):
            try:
                family = NetworkFamily(self.family)
            except (TypeError, ValueError) as exc:
                raise ProbeValidationError(
                    "route family must be 'ipv4' or 'ipv6'"
                ) from exc
            object.__setattr__(self, "family", family)
        object.__setattr__(
            self,
            "timeout_seconds",
            _validate_timeout(self.timeout_seconds),
        )

    @property
    def queries_default_route(self) -> bool:
        return self.destination is None


@dataclass(frozen=True, slots=True)
class ContainerInspectProbe:
    """Inspect one existing container and evaluate a fixed predicate.

    A missing container is an infrastructure failure, not a policy denial. The
    predicate can produce ``DENIED`` only after the container was inspected
    successfully and the requested condition was explicitly false.
    """

    reference: str
    condition: ContainerCondition = ContainerCondition.EXISTS
    timeout_seconds: float = _DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reference",
            _validate_token(self.reference, "container reference"),
        )
        if not isinstance(self.condition, ContainerCondition):
            try:
                condition = ContainerCondition(self.condition)
            except (TypeError, ValueError) as exc:
                raise ProbeValidationError(
                    "unsupported container inspection condition"
                ) from exc
            object.__setattr__(self, "condition", condition)
        object.__setattr__(
            self,
            "timeout_seconds",
            _validate_timeout(self.timeout_seconds),
        )


@dataclass(frozen=True, slots=True)
class ContainerPolicyProbe:
    """Evaluate one fixed property from typed Podman inspection data."""

    reference: str
    condition: ContainerPolicyCondition
    expected_text: str = ""
    expected_items: tuple[str, ...] = ()
    timeout_seconds: float = _DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reference",
            _validate_token(self.reference, "container reference"),
        )
        if not isinstance(self.condition, ContainerPolicyCondition):
            try:
                condition = ContainerPolicyCondition(self.condition)
            except (TypeError, ValueError) as exc:
                raise ProbeValidationError(
                    "unsupported container policy condition"
                ) from exc
            object.__setattr__(self, "condition", condition)
        if not isinstance(self.expected_text, str):
            raise TypeError("expected_text must be text")
        if any(character in self.expected_text for character in ("\x00", "\n", "\r")):
            raise ProbeValidationError("expected_text must be one-line text")
        if isinstance(self.expected_items, (str, bytes)):
            raise TypeError("expected_items must be a sequence")
        items = tuple(
            _validate_token(item, "expected item") for item in self.expected_items
        )
        object.__setattr__(self, "expected_items", items)
        if self.condition is ContainerPolicyCondition.NETWORKS_EXACT:
            if not items:
                raise ProbeValidationError("network expectation must not be empty")
        elif self.condition is ContainerPolicyCondition.USER_EQUALS:
            if not self.expected_text:
                raise ProbeValidationError("user expectation must not be empty")
        elif self.expected_text or items:
            raise ProbeValidationError(
                "this container policy condition accepts no expected value"
            )
        object.__setattr__(
            self,
            "timeout_seconds",
            _validate_timeout(self.timeout_seconds),
        )


@dataclass(frozen=True, slots=True)
class RuntimeSecurityProbe:
    """One fixed runtime assertion executed in a named container."""

    reference: str
    condition: RuntimeSecurityCondition
    expected_text: str = ""
    expected_items: tuple[str, ...] = ()
    secret: SecretValue | None = None
    timeout_seconds: float = _DEFAULT_TIMEOUT

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "reference",
            _validate_token(self.reference, "container reference"),
        )
        if not isinstance(self.condition, RuntimeSecurityCondition):
            try:
                condition = RuntimeSecurityCondition(self.condition)
            except (TypeError, ValueError) as exc:
                raise ProbeValidationError(
                    "unsupported runtime security condition"
                ) from exc
            object.__setattr__(self, "condition", condition)
        if not isinstance(self.expected_text, str):
            raise TypeError("expected_text must be text")
        if any(character in self.expected_text for character in ("\x00", "\n", "\r")):
            raise ProbeValidationError("expected_text must be one-line text")
        if isinstance(self.expected_items, (str, bytes)):
            raise TypeError("expected_items must be a sequence")
        items = tuple(
            _validate_token(item, "expected item") for item in self.expected_items
        )
        object.__setattr__(self, "expected_items", items)
        if self.secret is not None and not isinstance(self.secret, SecretValue):
            raise TypeError("secret must be a SecretValue or None")

        text_conditions = {
            RuntimeSecurityCondition.CAPABILITIES_EQUAL,
            RuntimeSecurityCondition.ROUTED_CIDR_PRESENT,
            RuntimeSecurityCondition.PROVIDER_CREDENTIAL_ABSENT,
        }
        item_conditions = {RuntimeSecurityCondition.CADDY_POLICY_MATCHES}
        if self.condition in text_conditions and not self.expected_text:
            raise ProbeValidationError(
                f"{self.condition.value} requires expected_text"
            )
        if self.condition in item_conditions:
            object.__setattr__(self, "expected_items", tuple(sorted(set(items))))
        elif items:
            raise ProbeValidationError(
                f"{self.condition.value} accepts no expected_items"
            )
        if self.condition is RuntimeSecurityCondition.PROVIDER_CREDENTIAL_ABSENT:
            if self.secret is None:
                raise ProbeValidationError(
                    "provider credential probe requires a secret"
                )
        elif self.secret is not None:
            raise ProbeValidationError(
                f"{self.condition.value} accepts no secret"
            )
        if self.condition not in text_conditions and self.expected_text:
            raise ProbeValidationError(
                f"{self.condition.value} accepts no expected_text"
            )
        object.__setattr__(
            self,
            "timeout_seconds",
            _validate_timeout(self.timeout_seconds),
        )


Probe: TypeAlias = (
    DnsProbe
    | TcpProbe
    | ProxyConnectProbe
    | PlainHttpProxyProbe
    | RouteProbe
    | ContainerInspectProbe
    | ContainerPolicyProbe
    | RuntimeSecurityProbe
)


def _validate_token(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{description} must be text")
    if not value:
        raise ProbeValidationError(f"{description} must not be empty")
    if value != value.strip():
        raise ProbeValidationError(
            f"{description} must not contain surrounding whitespace"
        )
    if any(character in value for character in ("\x00", "\n", "\r")):
        raise ProbeValidationError(f"{description} contains invalid characters")
    if any(character.isspace() for character in value):
        raise ProbeValidationError(f"{description} contains whitespace")
    return value


def _validate_host(value: object, description: str) -> str:
    value = _validate_token(value, description)
    if any(character.isspace() for character in value):
        raise ProbeValidationError(f"{description} contains whitespace")
    if "/" in value:
        raise ProbeValidationError(f"{description} must identify one host")
    return value


def _validate_port(value: object, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{description} must be an integer")
    if not 1 <= value <= 65535:
        raise ProbeValidationError(f"{description} must be between 1 and 65535")
    return value


def _validate_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("probe timeout must be a number")
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ProbeValidationError("probe timeout must be finite and positive")
    return timeout


def _validate_http_url(value: object) -> str:
    value = _validate_token(value, "proxy URL")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        parsed.port
    except ValueError as exc:
        raise ProbeValidationError("proxy URL is malformed") from exc
    if parsed.scheme.lower() != "http":
        raise ProbeValidationError("plain HTTP proxy probe requires an http URL")
    if not hostname:
        raise ProbeValidationError("proxy URL must contain a hostname")
    if username is not None or password is not None:
        raise ProbeValidationError("proxy URL must not contain credentials")
    if parsed.fragment:
        raise ProbeValidationError("proxy URL must not contain a fragment")
    return value
