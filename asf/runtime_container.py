"""Direct Podman runtime backend for ASF container isolation."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .errors import ConfigurationError, ValidationError
from .models import RuntimeManifest
from .paths import RepoPaths
from .repositories import RepositoryEntry
from .runtime_image import runtime_image_name
from .runtime_plan import (
    BROKER_INTERNAL_ALIAS,
    PROXY_INTERNAL_ALIAS,
    RuntimePlan,
    routed_broker_address,
    validate_runtime_plan_context,
)
from .session import SessionRole

__all__ = [
    "ContainerRequest",
    "apply_egress_environment",
    "build_container_environment",
    "build_container_exec_argv",
    "build_container_run_argv",
    "build_mounts",
]

_DEFAULT_PROXY_PORT = 3128
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


@dataclass(frozen=True, slots=True)
class ContainerRequest:
    paths: RepoPaths
    plan: RuntimePlan
    manifest: RuntimeManifest
    repositories: tuple[RepositoryEntry, ...] = ()
    run_arguments: tuple[str, ...] = ()
    ssh_agent_socket: Path | None = None
    proxy_port: int = _DEFAULT_PROXY_PORT
    broker_default_model: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.paths, RepoPaths):
            raise TypeError("paths must be RepoPaths")
        if not isinstance(self.plan, RuntimePlan):
            raise TypeError("plan must be RuntimePlan")
        if not isinstance(self.manifest, RuntimeManifest):
            raise TypeError("manifest must be RuntimeManifest")
        object.__setattr__(self, "repositories", tuple(self.repositories))
        object.__setattr__(self, "run_arguments", tuple(self.run_arguments))
        if any(not isinstance(item, RepositoryEntry) for item in self.repositories):
            raise TypeError("repositories must contain RepositoryEntry values")
        if not all(isinstance(item, str) and "\x00" not in item for item in self.run_arguments):
            raise ValidationError("run arguments must be NUL-free text")
        if self.ssh_agent_socket is not None:
            socket = Path(self.ssh_agent_socket).expanduser()
            if not socket.is_socket():
                raise ConfigurationError(
                    f"SSH agent socket not found (or not a socket): {socket}"
                )
            object.__setattr__(self, "ssh_agent_socket", socket)
        if not 1 <= self.proxy_port <= 65535:
            raise ValidationError("proxy port must be between 1 and 65535")
        validate_runtime_plan_context(self.plan, self.manifest, self.paths)
        if self.manifest.runtime.isolation != "container":
            raise ConfigurationError("container request requires runtime.isolation: container")
        _validate_capability_arguments(self.plan, self.run_arguments)


def _render_mounts(
    persistent_volumes: Sequence[tuple[str, str]],
    repositories: Sequence[RepositoryEntry],
    ssh_agent_socket: Path | None,
) -> list[str]:
    mounts: list[str] = []
    for name, target in persistent_volumes:
        if "," in target:
            raise ConfigurationError(
                f"Invalid state mount target (commas are not allowed): {target}"
            )
        mounts.append(f"source={name},target={target},type=volume")

    if ssh_agent_socket is not None:
        mounts.append(f"source={ssh_agent_socket},target=/ssh-agent,type=bind")

    seen_targets: set[str] = set()
    for repo in repositories:
        expanded = Path(os.path.abspath(os.path.expanduser(repo.path)))
        if not expanded.is_dir():
            continue
        target_name = expanded.name
        if target_name in seen_targets:
            raise ConfigurationError(
                f"Duplicate repository basename in repos.yml: {target_name}"
            )
        seen_targets.add(target_name)
        mount = (
            f"source={expanded},target=/workspace/repos/{target_name},"
            "type=bind,consistency=cached"
        )
        if repo.mode == "ro":
            mount += ",readonly"
        mounts.append(mount)
    return mounts


def build_mounts(
    plan: RuntimePlan,
    repositories: Sequence[RepositoryEntry],
    ssh_agent_socket: Path | None,
) -> list[str]:
    return _render_mounts(
        tuple((item.name, item.target) for item in plan.persistent_volumes),
        repositories,
        ssh_agent_socket,
    )


def apply_egress_environment(
    environment: dict[str, str],
    *,
    plan: RuntimePlan,
    manifest: RuntimeManifest,
    proxy_port: int,
    broker_default_model: str,
    broker_token: str,
) -> None:
    proxy = plan.container(SessionRole.PROXY)
    if proxy is not None:
        proxy_url = f"http://{PROXY_INTERNAL_ALIAS}:{proxy_port}"
        for variable in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            environment[variable] = proxy_url
        environment["NO_PROXY"] = "localhost,127.0.0.1"
        environment["no_proxy"] = "localhost,127.0.0.1"
        environment["ASF_PROXY"] = proxy_url

    broker = plan.container(SessionRole.BROKER)
    if broker is None:
        return
    llm = manifest.llm
    if llm is None or llm.protocol is None:
        raise ConfigurationError(
            "broker-enabled runtime plan requires an LLM wire protocol"
        )
    if not broker_token:
        raise ConfigurationError("broker-enabled runtime requires a session token")
    environment["ASF_BROKER_ENABLED"] = "true"
    broker_address = (
        routed_broker_address(plan)
        if manifest.runtime.isolation == "microvm" and manifest.network.mode == "routed"
        else None
    )
    broker_host = str(broker_address) if broker_address is not None else BROKER_INTERNAL_ALIAS
    if proxy is not None:
        no_proxy = environment.get("NO_PROXY", "localhost,127.0.0.1")
        no_proxy = f"{no_proxy},{broker_host}"
        environment["NO_PROXY"] = no_proxy
        environment["no_proxy"] = no_proxy
    if llm.protocol == "anthropic":
        environment["ANTHROPIC_BASE_URL"] = f"http://{broker_host}:4000"
        environment["ANTHROPIC_AUTH_TOKEN"] = broker_token
        environment["ANTHROPIC_API_KEY"] = ""
    else:
        base_url = f"http://{broker_host}:4000/v1"
        environment["OPENAI_BASE_URL"] = base_url
        environment["OPENAI_API_BASE"] = base_url
        environment["OPENAI_API_KEY"] = broker_token
        if broker_default_model:
            environment["ASF_DEFAULT_MODEL"] = broker_default_model


def build_container_environment(
    request: ContainerRequest,
    *,
    broker_token: str = "",
) -> dict[str, str]:
    """Return non-secret environment persisted in the container config.

    Values loaded from ASF secret files intentionally do not enter this mapping.
    They are injected only into workload ``podman exec`` processes.
    """

    environment = {
        "NODE_OPTIONS": "--max-old-space-size=4096",
        "POWERLEVEL9K_DISABLE_GITSTATUS": "true",
    }
    environment.update(request.manifest.environment_dict())
    apply_egress_environment(
        environment,
        plan=request.plan,
        manifest=request.manifest,
        proxy_port=request.proxy_port,
        broker_default_model=request.broker_default_model,
        broker_token=broker_token,
    )
    if request.ssh_agent_socket is not None:
        environment["SSH_AUTH_SOCK"] = "/ssh-agent"
    environment["ASF_AGENT"] = request.plan.runtime
    environment["ASF_ISOLATION"] = "container"
    for key, value in environment.items():
        if not isinstance(key, str) or not key:
            raise ValidationError("runtime environment names must be non-empty text")
        if not isinstance(value, str) or "\x00" in value:
            raise ValidationError(f"runtime environment {key} must be NUL-free text")
        if "\n" in value or "\r" in value:
            raise ValidationError(
                f"runtime environment {key} cannot contain line breaks"
            )
    return environment


def build_container_run_argv(
    request: ContainerRequest,
    *,
    env_file: Path,
    engine: str = "podman",
) -> tuple[str, ...]:
    args: list[str] = [
        engine,
        "run",
        "--detach",
        f"--name={request.plan.runtime_container.name}",
        f"--label={request.plan.session_label}",
        "--userns=keep-id:uid=1000,gid=1000",
        "--user=1000:1000",
        "--workdir=/workspace",
        "--http-proxy=false",
        # PID 1 is `sleep infinity`, which cannot reap children. Every workload
        # runs under `podman exec`, so any process it orphans reparents to PID 1
        # and would linger as a zombie for the life of the session. catatonit
        # reaps them and forwards signals.
        "--init",
        "--env-file",
        str(env_file),
    ]
    for attachment in request.plan.runtime_container.attachments:
        suffix = "" if attachment.address is None else f":ip={attachment.address}"
        args.append(f"--network={attachment.network}{suffix}")
    args.extend(
        (
            "--mount",
            f"type=bind,source={request.paths.root},target=/workspace/sandbox,readonly",
        )
    )
    for mount in build_mounts(request.plan, request.repositories, request.ssh_agent_socket):
        args.extend(("--mount", mount))
    args.extend(request.run_arguments)
    args.extend(
        (
            runtime_image_name(request.paths, request.plan.runtime),
            "sleep",
            "infinity",
        )
    )
    return tuple(args)


def build_container_exec_argv(
    request: ContainerRequest,
    *,
    command: Sequence[str] | None = None,
    environment_names: Sequence[str] = (),
    interactive: bool = False,
    engine: str = "podman",
) -> tuple[str, ...]:
    selected = tuple(command) if command is not None else (
        request.plan.command if request.plan.runtime_mode == "service" else ("zsh",)
    )
    if not selected:
        raise ConfigurationError(
            f"Runtime {request.plan.runtime} sets mode: service but no runtime.command"
        )
    if not all(isinstance(item, str) and item and "\x00" not in item for item in selected):
        raise ValidationError("container command must contain non-empty NUL-free text")
    args = [engine, "exec"]
    if interactive:
        args.extend(("--interactive", "--tty"))
    seen: set[str] = set()
    for name in environment_names:
        if not isinstance(name, str) or _ENV_NAME_RE.fullmatch(name) is None:
            raise ValidationError("container exec environment names must be valid")
        if name in seen:
            continue
        seen.add(name)
        # Podman resolves --env NAME from its own host process environment.
        # Keeping the value out of argv also keeps it out of the persistent
        # container configuration.
        args.extend(("--env", name))
    args.extend((request.plan.runtime_container.name, *selected))
    return tuple(args)


def _validate_capability_arguments(
    plan: RuntimePlan,
    run_arguments: Sequence[str],
) -> None:
    expected = {item.lower() for item in plan.runtime_container.capabilities}
    observed: set[str] = set()
    for argument in run_arguments:
        if argument.startswith("--cap-add="):
            value = argument.partition("=")[2]
            if not value:
                raise ConfigurationError("empty --cap-add value")
            observed.add(value.lower())
    if observed != expected:
        raise ConfigurationError(
            "runtime capability arguments do not match the expected policy: "
            f"expected {sorted(expected)}, got {sorted(observed)}"
        )
