"""Typed Podman inspection and execution boundary for ASF.

Discovery and inspection remain strict and read-only. Lifecycle modules may
submit their own fixed argument vectors through :meth:`PodmanClient.observe`;
this module does not expose a generic shell-command path.

The distinction between *absence* and *infrastructure failure* is deliberate:
no matching container is an ordinary discovery result, while a missing or
failed Podman engine must never be interpreted as an empty session.
"""

from __future__ import annotations

import json
import math
import os
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, TypeAlias

from .errors import InfrastructureError, ValidationError
from .process import (
    CommandError,
    CommandNotFoundError,
    CommandResult,
    CommandStartError,
    probe,
)

__all__ = [
    "ContainerInspection",
    "ContainerState",
    "HealthStatus",
    "ObjectKind",
    "ObjectNotFoundError",
    "PodmanClient",
    "PodmanCommandError",
    "PodmanError",
    "PodmanOutputError",
    "PodmanUnavailableError",
    "PodmanValidationError",
]

_DEFAULT_TIMEOUT = 20.0
CommandRunner: TypeAlias = Callable[..., CommandResult]
_EMPTY_LABELS: Mapping[str, str] = MappingProxyType({})


class PodmanError(InfrastructureError):
    """Base class for Podman discovery and inspection failures."""


class PodmanUnavailableError(PodmanError):
    """The configured Podman executable cannot be started."""


class PodmanCommandError(PodmanError):
    """Podman ran unsuccessfully or a process-level failure occurred."""


class PodmanOutputError(PodmanCommandError):
    """Podman returned malformed or internally inconsistent output."""


class ObjectNotFoundError(PodmanError):
    """A requested Podman object does not exist."""


class PodmanValidationError(ValidationError):
    """A caller supplied an invalid Podman reference or label."""


class ObjectKind(str, Enum):
    CONTAINER = "container"
    NETWORK = "network"
    VOLUME = "volume"
    SECRET = "secret"


class ContainerState(str, Enum):
    CREATED = "created"
    INITIALIZED = "initialized"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    EXITED = "exited"
    STOPPED = "stopped"
    REMOVING = "removing"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: object) -> "ContainerState":
        if isinstance(value, str):
            try:
                return cls(value.strip().lower())
            except ValueError:
                return cls.UNKNOWN
        return cls.UNKNOWN


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"
    NONE = "none"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: object) -> "HealthStatus":
        if value in (None, ""):
            return cls.NONE
        if isinstance(value, str):
            try:
                return cls(value.strip().lower())
            except ValueError:
                return cls.UNKNOWN
        return cls.UNKNOWN


@dataclass(frozen=True, slots=True)
class ContainerInspection:
    """Stable, immutable subset of one ``podman inspect`` document.

    The Bash-compatible text and Boolean fields remain public. Typed views are
    exposed through :attr:`state` and :attr:`health_status` so later commands
    do not need to compare free-form strings.
    """

    container_id: str
    name: str
    image: str
    status: str
    running: bool
    health: str | None
    # default_factory keeps Python 3.11 happy: its dataclass mutability check
    # rejects a MappingProxyType default. __post_init__ still normalises to an
    # immutable proxy.
    labels: Mapping[str, str] = field(default_factory=dict, repr=False)
    networks: tuple[str, ...] = ()
    exit_code: int | None = None
    user: str = ""
    read_only_rootfs: bool = False
    published_ports: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "labels", MappingProxyType(dict(self.labels)))
        object.__setattr__(self, "networks", tuple(self.networks))
        if not isinstance(self.user, str):
            raise TypeError("container user must be text")
        if not isinstance(self.read_only_rootfs, bool):
            raise TypeError("read_only_rootfs must be Boolean")
        if not isinstance(self.published_ports, bool):
            raise TypeError("published_ports must be Boolean")

    @property
    def state(self) -> ContainerState:
        return ContainerState.parse(self.status)

    @property
    def health_status(self) -> HealthStatus:
        return HealthStatus.parse(self.health)

    @property
    def is_running(self) -> bool:
        return self.running

    @property
    def short_id(self) -> str:
        return self.container_id[:12]

    def label(self, name: str, default: str | None = None) -> str | None:
        return self.labels.get(name, default)

    def labels_dict(self) -> dict[str, str]:
        return dict(self.labels)


@dataclass(frozen=True, slots=True)
class PodmanClient:
    """Podman command adapter with strict discovery and execution validation."""

    engine: str | os.PathLike[str] = "podman"
    timeout: float = _DEFAULT_TIMEOUT
    runner: CommandRunner = field(default=probe, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            engine = os.fspath(self.engine)
        except TypeError as exc:
            raise TypeError("Podman engine must be path-like text") from exc
        if not isinstance(engine, str):
            raise TypeError("Podman engine must resolve to text")
        if not engine:
            raise PodmanValidationError("Podman engine must not be empty")
        if any(character in engine for character in ("\x00", "\n", "\r")):
            raise PodmanValidationError(
                "Podman engine contains invalid characters"
            )
        if isinstance(self.timeout, bool) or not isinstance(
            self.timeout, (int, float)
        ):
            raise TypeError("Podman timeout must be a number")
        timeout = float(self.timeout)
        if not math.isfinite(timeout) or timeout <= 0:
            raise PodmanValidationError(
                "Podman timeout must be finite and positive"
            )
        object.__setattr__(self, "engine", engine)
        object.__setattr__(self, "timeout", timeout)

    def is_available(self) -> bool:
        return shutil.which(str(self.engine)) is not None

    def require_available(self) -> None:
        if not self.is_available():
            raise PodmanUnavailableError(
                f"cannot find Podman executable: {self.engine}"
            )

    def version(self) -> str:
        result = self._execute(
            (self.engine, "version", "--format", "{{.Client.Version}}")
        )
        return result.stdout.strip()

    def container_ids(
        self,
        labels: Mapping[str, str] | Sequence[str] = (),
        *,
        include_stopped: bool = False,
    ) -> tuple[str, ...]:
        """Return container IDs matching every supplied label.

        At least one label is mandatory so a caller cannot accidentally enumerate
        unrelated containers from the host.
        """

        normalised = _normalise_labels(labels)
        if not normalised:
            raise PodmanValidationError(
                "at least one Podman label filter is required"
            )

        argv: list[str | os.PathLike[str]] = [self.engine, "ps"]
        if include_stopped:
            argv.append("--all")
        argv.append("-q")
        for label in normalised:
            argv.extend(("--filter", f"label={label}"))

        result = self._execute(argv)
        identifiers: list[str] = []
        seen: set[str] = set()
        for line_number, line in enumerate(result.stdout.splitlines(), 1):
            identifier = line.strip()
            if not identifier:
                continue
            _validate_reference(
                identifier,
                description=f"container ID on output line {line_number}",
                output=True,
            )
            if identifier not in seen:
                seen.add(identifier)
                identifiers.append(identifier)
        return tuple(identifiers)

    def all_container_ids(
        self, labels: Mapping[str, str] | Sequence[str]
    ) -> tuple[str, ...]:
        return self.container_ids(labels, include_stopped=True)

    def inspect_containers(
        self,
        references: Sequence[str],
        *,
        timeout: float | None = None,
    ) -> tuple[ContainerInspection, ...]:
        if isinstance(references, (str, bytes)):
            raise TypeError("container references must be a sequence")
        refs = tuple(
            _validate_reference(
                reference,
                description="container reference",
                output=False,
            )
            for reference in references
        )
        if not refs:
            raise PodmanValidationError(
                "at least one container reference is required"
            )

        argv: tuple[str | os.PathLike[str], ...] = (
            self.engine,
            "inspect",
            "--type",
            ObjectKind.CONTAINER.value,
            *refs,
        )
        result = self._execute(
            argv,
            missing_kind=ObjectKind.CONTAINER,
            timeout=timeout,
        )
        try:
            document = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise PodmanOutputError(
                f"Podman inspect returned invalid JSON: {exc.msg}"
            ) from exc
        if not isinstance(document, list):
            raise PodmanOutputError(
                "Podman inspect output must be a JSON array"
            )
        if len(document) != len(refs):
            raise PodmanOutputError(
                "Podman inspect returned an unexpected number of containers: "
                f"expected {len(refs)}, got {len(document)}"
            )
        return tuple(
            _parse_inspection(item, index=index)
            for index, item in enumerate(document)
        )

    def inspect_container(
        self,
        reference: str,
        *,
        timeout: float | None = None,
    ) -> ContainerInspection:
        return self.inspect_containers((reference,), timeout=timeout)[0]

    # Alternate names used by the attached implementation.
    def inspect(
        self,
        reference: str,
        *,
        timeout: float | None = None,
    ) -> ContainerInspection:
        return self.inspect_container(reference, timeout=timeout)

    def inspect_many(
        self,
        references: Sequence[str],
        *,
        timeout: float | None = None,
    ) -> tuple[ContainerInspection, ...]:
        return self.inspect_containers(references, timeout=timeout)

    def inspect_present(
        self, references: Sequence[str]
    ) -> tuple[ContainerInspection, ...]:
        found: list[ContainerInspection] = []
        for reference in references:
            try:
                found.append(self.inspect_container(reference))
            except ObjectNotFoundError:
                continue
        return tuple(found)

    def exists(
        self,
        reference: str,
        kind: ObjectKind = ObjectKind.CONTAINER,
    ) -> bool:
        reference = _validate_reference(
            reference, description=f"{kind.value} reference", output=False
        )

        # Podman exposes an explicit existence command for networks.  Its
        # return-code contract is stable and avoids version-specific inspect
        # error text: 0 means present, 1 means absent, and every other status
        # is an infrastructure failure.
        if kind is ObjectKind.NETWORK:
            result = self._observe(
                (self.engine, "network", "exists", reference)
            )
            if result.returncode == 0:
                return True
            if result.returncode == 1:
                return False
            raise PodmanCommandError(
                "Podman command exited with status "
                f"{result.returncode}: {result.command}"
            )

        argv = _existence_argv(self.engine, kind, reference)
        try:
            self._execute(argv, missing_kind=kind)
        except ObjectNotFoundError:
            return False
        return True

    def exec_container(
        self,
        reference: str,
        command: Sequence[str | os.PathLike[str]],
        *,
        check: bool = True,
        timeout: float | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        """Execute a read-only diagnostic command inside one container."""

        reference = _validate_reference(
            reference, description="container reference", output=False
        )
        if isinstance(command, (str, bytes)):
            raise TypeError("container command must be a sequence")
        arguments = tuple(command)
        if not arguments:
            raise PodmanValidationError("container command must not be empty")
        if input_text is not None and not isinstance(input_text, str):
            raise TypeError("input_text must be text or None")
        interactive = ("-i",) if input_text is not None else ()
        argv: tuple[str | os.PathLike[str], ...] = (
            self.engine,
            "exec",
            *interactive,
            reference,
            *arguments,
        )
        if check:
            return self._execute(
                argv,
                missing_kind=ObjectKind.CONTAINER,
                timeout=timeout,
                input_text=input_text,
            )
        return self._observe(
            argv,
            missing_kind=ObjectKind.CONTAINER,
            timeout=timeout,
            input_text=input_text,
        )

    def secret_names(self) -> tuple[str, ...]:
        """Return every Podman secret name known to the engine.

        Podman does not support reliable secret label filtering across all ASF
        versions, so callers apply the deterministic ASF name prefix.
        """

        result = self._execute(
            [self.engine, "secret", "ls", "--format", "{{.Name}}"]
        )
        names: list[str] = []
        for line in result.stdout.splitlines():
            name = line.strip()
            if not name:
                continue
            names.append(
                _validate_reference(
                    name, description="secret name", output=True
                )
            )
        return tuple(names)

    def logs_argv(
        self,
        reference: str,
        *,
        tail: int,
        follow: bool = False,
    ) -> tuple[str, ...]:
        """Return a validated ``podman logs`` argument vector."""

        reference = _validate_reference(
            reference, description="container reference", output=False
        )
        if isinstance(tail, bool) or not isinstance(tail, int) or tail < 0:
            raise PodmanValidationError("log tail must be a non-negative integer")
        argv = [str(self.engine), "logs", "--tail", str(tail)]
        if follow:
            argv.append("-f")
        argv.append(reference)
        return tuple(argv)

    def container_logs(
        self,
        reference: str,
        *,
        tail: int,
    ) -> CommandResult:
        """Read a finite tail of container logs."""

        return self._execute(self.logs_argv(reference, tail=tail))

    def observe(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        timeout: float | None = None,
        missing_kind: ObjectKind | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        """Run one validated Podman command as an observation.

        Nonzero status is returned to the caller. Process start failures and
        missing objects remain typed Podman errors. This is the execution
        boundary used by typed probe executors.
        """

        if isinstance(argv, (str, bytes)):
            raise TypeError("Podman argv must be a sequence")
        arguments = tuple(argv)
        if not arguments:
            raise PodmanValidationError("Podman argv must not be empty")
        if str(arguments[0]) != str(self.engine):
            raise PodmanValidationError(
                "Podman observation must use the configured engine"
            )
        if missing_kind is not None and not isinstance(missing_kind, ObjectKind):
            raise TypeError("missing_kind must be an ObjectKind or None")
        if input_text is not None and not isinstance(input_text, str):
            raise TypeError("input_text must be text or None")
        return self._observe(
            arguments,
            missing_kind=missing_kind,
            timeout=timeout,
            input_text=input_text,
        )

    def _observe(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        missing_kind: ObjectKind | None = None,
        timeout: float | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        effective_timeout = _normalise_timeout(timeout, self.timeout)
        try:
            if input_text is None:
                result = self.runner(argv, timeout=effective_timeout)
            else:
                result = self.runner(
                    argv,
                    timeout=effective_timeout,
                    input_text=input_text,
                )
        except (CommandNotFoundError, CommandStartError) as exc:
            raise PodmanUnavailableError(
                f"cannot run Podman executable {self.engine!s}"
            ) from exc
        except CommandError as exc:
            raise PodmanCommandError(f"Podman command failed: {exc}") from exc
        if (
            not result.succeeded
            and missing_kind is not None
            and _is_missing_object(result.stderr, missing_kind)
        ):
            raise ObjectNotFoundError(f"no such {missing_kind.value}")
        return result

    def _execute(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        missing_kind: ObjectKind | None = None,
        timeout: float | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        result = self._observe(
            argv,
            missing_kind=missing_kind,
            timeout=timeout,
            input_text=input_text,
        )
        if result.succeeded:
            return result
        raise PodmanCommandError(
            "Podman command exited with status "
            f"{result.returncode}: {result.command}"
        )


def _normalise_timeout(value: float | None, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("Podman timeout must be a number")
    timeout = float(value)
    if not math.isfinite(timeout) or timeout <= 0:
        raise PodmanValidationError(
            "Podman timeout must be finite and positive"
        )
    return timeout


def _normalise_labels(
    labels: Mapping[str, str] | Sequence[str],
) -> tuple[str, ...]:
    if isinstance(labels, Mapping):
        values: list[str] = []
        for key, value in labels.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("Podman label keys and values must be strings")
            _validate_label_component(key, "key")
            _validate_label_component(value, "value")
            values.append(f"{key}={value}")
        return tuple(values)
    if isinstance(labels, (str, bytes)):
        raise TypeError("labels must be a mapping or sequence of strings")
    values = []
    for label in labels:
        if not isinstance(label, str):
            raise TypeError("Podman labels must be strings")
        if "=" not in label:
            raise PodmanValidationError(
                "Podman label filters must use key=value"
            )
        key, value = label.split("=", 1)
        _validate_label_component(key, "key")
        _validate_label_component(value, "value")
        values.append(label)
    return tuple(values)


def _validate_label_component(value: str, description: str) -> None:
    if not value:
        raise PodmanValidationError(
            f"Podman label {description} must not be empty"
        )
    if any(character in value for character in ("\x00", "\n", "\r")):
        raise PodmanValidationError(
            f"Podman label {description} contains invalid characters"
        )


def _validate_reference(
    reference: object,
    *,
    description: str,
    output: bool,
) -> str:
    error_type = PodmanOutputError if output else PodmanValidationError
    if not isinstance(reference, str):
        if output:
            raise PodmanOutputError(f"{description} must be text")
        raise TypeError(f"{description} must be text")
    if not reference:
        raise error_type(f"{description} must not be empty")
    if any(character in reference for character in ("\x00", "\n", "\r")):
        raise error_type(f"{description} contains invalid characters")
    if reference != reference.strip() or any(
        character.isspace() for character in reference
    ):
        raise error_type(f"{description} contains whitespace")
    return reference


def _parse_inspection(item: Any, *, index: int) -> ContainerInspection:
    context = f"Podman inspect item {index}"
    mapping = _require_mapping(item, context)
    state = _require_mapping(mapping.get("State"), f"{context}.State")
    config = _require_mapping(mapping.get("Config"), f"{context}.Config")
    host_config_value = mapping.get("HostConfig")
    host_config = (
        {}
        if host_config_value is None
        else _require_mapping(host_config_value, f"{context}.HostConfig")
    )

    container_id = _require_text(
        mapping.get("Id", mapping.get("ID")), f"{context}.Id"
    )
    _validate_reference(
        container_id, description=f"{context}.Id", output=True
    )
    name = _require_text(mapping.get("Name"), f"{context}.Name").lstrip("/")
    _validate_reference(name, description=f"{context}.Name", output=True)
    image = _require_text(config.get("Image"), f"{context}.Config.Image")

    status_text = _require_text(
        state.get("Status"), f"{context}.State.Status"
    )
    state_value = ContainerState.parse(status_text)
    running_value = state.get("Running")
    if running_value is None:
        running = state_value is ContainerState.RUNNING
    elif isinstance(running_value, bool):
        # Podman may report transitional states such as ``stopping`` while the
        # Boolean remains true. Preserve both observations rather than forcing
        # them into a consistency rule Podman itself does not guarantee.
        running = running_value
    else:
        raise PodmanOutputError(
            f"{context}.State.Running must be Boolean"
        )

    health_value = _parse_health(state, context)
    labels = _parse_labels(config.get("Labels"), context)
    networks = _parse_networks(mapping.get("NetworkSettings"), context)
    exit_code = _parse_exit_code(state.get("ExitCode"), context)
    user_value = config.get("User", "")
    if not isinstance(user_value, str):
        raise PodmanOutputError(f"{context}.Config.User must be text")
    read_only_value = host_config.get("ReadonlyRootfs", False)
    if not isinstance(read_only_value, bool):
        raise PodmanOutputError(
            f"{context}.HostConfig.ReadonlyRootfs must be Boolean"
        )
    port_bindings = host_config.get("PortBindings")
    if port_bindings is None:
        published_ports = False
    elif isinstance(port_bindings, Mapping):
        published_ports = bool(port_bindings)
    else:
        raise PodmanOutputError(
            f"{context}.HostConfig.PortBindings must be an object or null"
        )

    return ContainerInspection(
        container_id=container_id,
        name=name,
        image=image,
        status=status_text,
        running=running,
        health=None if health_value is HealthStatus.NONE else health_value.value,
        labels=labels,
        networks=networks,
        exit_code=exit_code,
        user=user_value,
        read_only_rootfs=read_only_value,
        published_ports=published_ports,
    )


def _parse_health(
    state: Mapping[str, Any], context: str
) -> HealthStatus:
    for key in ("Health", "Healthcheck"):
        value = state.get(key)
        if value is None:
            continue
        mapping = _require_mapping(value, f"{context}.State.{key}")
        status = mapping.get("Status")
        if status is None:
            return HealthStatus.NONE
        return HealthStatus.parse(
            _require_text(status, f"{context}.State.{key}.Status")
        )
    return HealthStatus.NONE


def _parse_labels(value: Any, context: str) -> Mapping[str, str]:
    if value is None:
        return _EMPTY_LABELS
    mapping = _require_mapping(value, f"{context}.Config.Labels")
    labels: dict[str, str] = {}
    for key, item in mapping.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise PodmanOutputError(
                f"{context}.Config.Labels must contain text keys and values"
            )
        labels[key] = item
    return MappingProxyType(labels) if labels else _EMPTY_LABELS


def _parse_networks(value: Any, context: str) -> tuple[str, ...]:
    if value is None:
        return ()
    settings = _require_mapping(value, f"{context}.NetworkSettings")
    networks_value = settings.get("Networks")
    if networks_value is None:
        return ()
    networks = _require_mapping(
        networks_value, f"{context}.NetworkSettings.Networks"
    )
    names: list[str] = []
    for name in networks:
        if not isinstance(name, str) or not name:
            raise PodmanOutputError(
                f"{context}.NetworkSettings.Networks keys must be text"
            )
        names.append(name)
    return tuple(sorted(names))


def _parse_exit_code(value: Any, context: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise PodmanOutputError(f"{context}.State.ExitCode must be an integer")
    return value


def _require_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PodmanOutputError(f"{context} must be an object")
    return value


def _require_text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise PodmanOutputError(f"{context} must be non-empty text")
    return value


def _existence_argv(
    engine: str | os.PathLike[str], kind: ObjectKind, reference: str
) -> tuple[str | os.PathLike[str], ...]:
    if kind is ObjectKind.CONTAINER:
        return (engine, "inspect", "--type", kind.value, reference)
    if kind is ObjectKind.SECRET:
        return (engine, "secret", "inspect", reference)
    return (engine, kind.value, "inspect", reference)


def _is_missing_object(stderr: str, kind: ObjectKind) -> bool:
    lowered = stderr.lower()
    phrases = {
        ObjectKind.CONTAINER: ("no such container", "no such object"),
        ObjectKind.NETWORK: ("no such network",),
        ObjectKind.VOLUME: ("no such volume",),
        ObjectKind.SECRET: ("no such secret",),
    }
    return any(phrase in lowered for phrase in phrases[kind])
