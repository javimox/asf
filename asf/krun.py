"""Minimal libkrun runtime backend for ASF agent workloads.

The krun backend keeps ASF's trusted support services (Caddy, LiteLLM and
routed helpers) as ordinary rootless Podman containers. Only the untrusted
agent workload uses ``--runtime=krun``.

krun cannot currently inject a second process into an already-running microVM,
so the agent command is the initial foreground workload. ASF therefore does not
use the Dev Container CLI on this path.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .errors import ConfigurationError, InfrastructureError, ValidationError
from .devcontainer import apply_egress_environment, build_mounts
from .models import RuntimeManifest
from .paths import RepoPaths
from .repositories import RepositoryEntry
from .routed import ROUTED_TAP_NAME, routed_tap_addresses
from .session import SessionRole
from .runtime_plan import (
    NetworkRole,
    RuntimePlan,
    routed_broker_address,
    validate_runtime_plan_context,
)

__all__ = [
    "KrunError",
    "KrunRequest",
    "build_krun_build_argv",
    "build_krun_image_argv",
    "build_krun_environment",
    "build_krun_run_argv",
    "krun_image_name",
    "krun_runtime_name",
    "require_krun_host",
    "validate_krun_beta",
]

_BUILD_ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DEFAULT_PROXY_PORT = 3128

# krun keeps secret values off the Podman argv by exporting them through the
# host-side Podman/VMM process environment and passing only ``--env NAME``.
# The same mechanism means a manifest or secret env file could otherwise
# reconfigure the *host* process that launches the microVM. These names
# control process execution (loader, lookup paths) or Podman itself and are
# therefore rejected, fail closed, before a krun session starts. The container
# backend is unaffected: its environment never enters a host tool's process.
_HOST_PROCESS_ENVIRONMENT = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "CONTAINER_HOST",
        "CONTAINER_CONNECTION",
        "CONTAINER_SSHKEY",
        "STORAGE_DRIVER",
        "STORAGE_OPTS",
        "REGISTRY_AUTH_FILE",
        "DOCKER_HOST",
        "GLIBC_TUNABLES",
    }
)
_HOST_PROCESS_ENVIRONMENT_PREFIXES = (
    "LD_",
    "CONTAINERS_",
    "PODMAN_",
)


def _validate_krun_environment_name(name: str) -> None:
    """Reject guest environment names that would reconfigure host Podman/VMM."""

    if not _BUILD_ARG_NAME.fullmatch(name):
        raise ValidationError(f"invalid runtime environment name: {name!r}")
    if (
        name in _HOST_PROCESS_ENVIRONMENT
        or name.startswith(_HOST_PROCESS_ENVIRONMENT_PREFIXES)
    ):
        raise ConfigurationError(
            f"runtime environment name {name} is reserved: krun supplies "
            "session values through the host Podman process environment, "
            "and this name would reconfigure that host process"
        )


class KrunError(InfrastructureError):
    """The krun runtime cannot be started safely on this host."""


@dataclass(frozen=True, slots=True)
class KrunRequest:
    paths: RepoPaths
    plan: RuntimePlan
    manifest: RuntimeManifest
    repositories: tuple[RepositoryEntry, ...] = ()
    run_arguments: tuple[str, ...] = ()
    build_arguments: tuple[str, ...] = ()
    proxy_port: int = _DEFAULT_PROXY_PORT
    broker_default_model: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.paths, RepoPaths):
            raise TypeError("paths must be RepoPaths")
        if not isinstance(self.plan, RuntimePlan):
            raise TypeError("plan must be a RuntimePlan")
        if not isinstance(self.manifest, RuntimeManifest):
            raise TypeError("manifest must be a RuntimeManifest")
        object.__setattr__(self, "repositories", tuple(self.repositories))
        object.__setattr__(self, "run_arguments", tuple(self.run_arguments))
        object.__setattr__(self, "build_arguments", tuple(self.build_arguments))
        if any(not isinstance(item, RepositoryEntry) for item in self.repositories):
            raise TypeError("repositories must contain RepositoryEntry values")
        for label, values in (
            ("run arguments", self.run_arguments),
            ("build arguments", self.build_arguments),
        ):
            if not all(isinstance(item, str) and "\x00" not in item for item in values):
                raise ValidationError(f"{label} must be NUL-free text")
        if (
            isinstance(self.proxy_port, bool)
            or not isinstance(self.proxy_port, int)
            or not 1 <= self.proxy_port <= 65535
        ):
            raise ValidationError("proxy port must be between 1 and 65535")
        if not isinstance(self.broker_default_model, str) or "\x00" in self.broker_default_model:
            raise ValidationError("broker default model must be NUL-free text")
        validate_runtime_plan_context(self.plan, self.manifest, self.paths)
        validate_krun_beta(self.manifest)
        if "--cap-drop=ALL" not in self.run_arguments:
            raise ConfigurationError("krun runtime requires --cap-drop=ALL")
        if "--ulimit=core=0:0" not in self.run_arguments:
            raise ConfigurationError("krun runtime requires core dumps disabled")
        # The trailing comma (against the argument plus a sentinel comma)
        # makes this an exact mount-option segment match, so a mount targeting
        # e.g. /workspace/sandbox/secretsX cannot satisfy the requirement.
        secret_mask = "target=/workspace/sandbox/secrets,"
        if not any(
            argument.startswith("--mount=type=tmpfs,")
            and secret_mask in f"{argument},"
            for argument in self.run_arguments
        ):
            raise ConfigurationError("krun runtime requires the host secrets tmpfs mask")


def validate_krun_beta(
    manifest: RuntimeManifest,
    *,
    ssh_agent: bool = False,
    broker_enabled: bool = False,
) -> None:
    """Reject unsupported combinations for the krun backend."""

    if manifest.runtime.isolation != "microvm":
        raise ConfigurationError("krun request requires runtime.isolation: microvm")
    if manifest.capabilities and manifest.network.mode != "routed":
        raise ConfigurationError(
            "runtime.isolation: microvm supports NET_RAW only with routed TAP networking"
        )
    if ssh_agent:
        raise ConfigurationError(
            "runtime.isolation: microvm does not support SSH-agent forwarding"
        )


def krun_runtime_name(paths: RepoPaths, manifest: RuntimeManifest) -> str:
    """Return the OCI runtime used for this krun workload."""

    if manifest.network.mode != "routed":
        return "krun"
    configured = os.environ.get("CRUN_TAP_RUNTIME")
    if configured:
        return configured
    return os.fspath(paths.root / "tools/experiments/.krun-tap-runtime/bin/crun")


def require_krun_host(
    paths: RepoPaths | None = None,
    manifest: RuntimeManifest | None = None,
) -> None:
    """Fail early when the host cannot launch a KVM-backed krun workload."""

    routed_tap = manifest is not None and manifest.network.mode == "routed"
    if routed_tap:
        if paths is None:
            raise TypeError("routed microVM host checks require repository paths")
        runtime = Path(krun_runtime_name(paths, manifest))
        if not runtime.is_file() or not os.access(runtime, os.X_OK):
            raise KrunError(
                f"TAP-capable krun runtime not found: {runtime}. Run "
                "tools/experiments/build-krun-tap-runtime.sh or set "
                "CRUN_TAP_RUNTIME to an equivalent executable."
            )
        tun = Path("/dev/net/tun")
        if not tun.exists() or not os.access(tun, os.R_OK | os.W_OK):
            raise KrunError(
                "/dev/net/tun is not readable and writable by the current user"
            )
    elif shutil.which("krun") is None:
        raise KrunError(
            "krun runtime not found on PATH. Install crun with libkrun support "
            "and make the 'krun' runtime available to Podman. If your "
            "distribution installs the binary outside PATH, register it in "
            "containers.conf under [engine.runtimes] and symlink it into PATH "
            "so ASF can verify the host; confirm with: "
            "podman run --rm --runtime=krun alpine uname -a"
        )
    kvm = Path("/dev/kvm")
    if not kvm.exists():
        raise KrunError("/dev/kvm not found; krun requires KVM on the host")
    if not os.access(kvm, os.R_OK | os.W_OK):
        raise KrunError("/dev/kvm is not readable and writable by the current user")


def krun_image_name(plan: RuntimePlan) -> str:
    """Return a checkout-scoped local image tag for the agent workload."""

    return f"localhost/{plan.session_key.lower()}:krun"


def _krun_image_name_for_runtime(paths: RepoPaths, runtime: str) -> str:
    return f"localhost/{paths.identity.session_key(runtime).lower()}:krun"


def build_krun_image_argv(
    paths: RepoPaths,
    manifest: RuntimeManifest,
    *,
    build_arguments: Sequence[str] = (),
    engine: str = "podman",
) -> tuple[str, ...]:
    """Build a krun image without constructing a runtime/network plan."""

    validate_krun_beta(manifest)
    args: list[str] = [
        engine,
        "build",
        "--tag",
        _krun_image_name_for_runtime(paths, manifest.name),
        "--file",
        str(paths.devcontainer_dir / "Dockerfile"),
    ]
    values: dict[str, str] = {
        "TZ": os.environ.get("TZ", "UTC") or "UTC",
        "AGENT": manifest.adapter,
    }
    for item in manifest.runtime.build_arguments:
        values[item.name] = item.value
    for raw in build_arguments:
        name, separator, value = raw.partition("=")
        if not separator or not _BUILD_ARG_NAME.fullmatch(name):
            raise ConfigurationError(
                f"Invalid build argument (expected NAME=VALUE): {raw}"
            )
        values[name] = value
    for name, value in values.items():
        args.extend(("--build-arg", f"{name}={value}"))
    args.append(str(paths.root))
    return tuple(args)


def build_krun_build_argv(request: KrunRequest, *, engine: str = "podman") -> tuple[str, ...]:
    """Build the same ASF agent image without depending on Dev Containers."""

    return build_krun_image_argv(
        request.paths,
        request.manifest,
        build_arguments=request.build_arguments,
        engine=engine,
    )


def build_krun_environment(
    request: KrunRequest,
    *,
    broker_token: str = "",
    runtime_environment: Sequence[tuple[str, str]] = (),
) -> dict[str, str]:
    """Build the environment for the krun workload.

    Values are returned separately from the Podman argv. The caller passes only
    ``--env NAME`` to Podman and supplies these values through its own process
    environment, keeping secret values out of the command line.
    """

    environment: dict[str, str] = {
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

    for key, value in runtime_environment:
        environment[key] = value

    # Runtime identity is framework-owned. A manifest or secret env file must
    # not be able to make a krun guest look like a Dev Container.
    environment.pop("DEVCONTAINER", None)
    environment["ASF_AGENT"] = request.plan.runtime
    environment["ASF_ISOLATION"] = "microvm"
    environment["ASF_KRUN_CAPABILITIES"] = ",".join(
        sorted(request.manifest.capabilities)
    )
    if request.manifest.network.mode == "routed":
        tap_gateway, tap_guest = routed_tap_addresses(request.plan)
        scan = request.plan.network(NetworkRole.SCAN)
        if scan is None:
            raise ConfigurationError("routed microVM plan is missing the scan network")
        environment["ASF_KRUN_TAP_ADDRESS"] = f"{tap_guest}/30"
        environment["ASF_KRUN_TAP_GATEWAY"] = str(tap_gateway)
        routes = [str(route.destination) for route in scan.routes]
        broker_address = routed_broker_address(request.plan)
        if broker_address is not None:
            routes.append(f"{broker_address}/32")
        environment["ASF_KRUN_TAP_ROUTES"] = " ".join(routes)

    for key, value in environment.items():
        if not isinstance(key, str):
            raise ValidationError(f"invalid runtime environment name: {key!r}")
        _validate_krun_environment_name(key)
        if not isinstance(value, str) or "\x00" in value:
            raise ValidationError(f"runtime environment {key} must be NUL-free text")
    return environment


def build_krun_run_argv(
    request: KrunRequest,
    environment: Mapping[str, str],
    *,
    engine: str = "podman",
    command: Sequence[str] | None = None,
) -> tuple[str, ...]:
    """Return the foreground Podman argv for one krun microVM session."""

    selected = tuple(command) if command is not None else (
        request.plan.command
        if request.plan.runtime_mode == "service"
        else ("zsh",)
    )
    if not selected:
        raise ConfigurationError(
            f"Runtime {request.plan.runtime} sets mode: service but no runtime.command"
        )
    if not all(isinstance(item, str) and item and "\x00" not in item for item in selected):
        raise ValidationError("krun command must contain non-empty NUL-free text")

    # keep-id remains relevant to host-side bind/virtio-fs ownership. Current
    # krun may still enter the guest as root despite --user/--cap-drop; the
    # on-start bootstrap enforces the guest UID/GID and capability state.
    runtime = krun_runtime_name(request.paths, request.manifest)
    args: list[str] = [
        engine,
        "run",
        f"--runtime={runtime}",
        "--rm",
        f"--name={request.plan.runtime_container.name}",
        f"--label={request.plan.session_label}",
        "--userns=keep-id:uid=1000,gid=1000",
        "--user=1000:1000",
        "--workdir=/workspace",
        "--unsetenv=DEVCONTAINER",
        # Podman otherwise copies proxy variables from its host environment
        # into the guest implicitly. ASF injects only the intended values.
        "--http-proxy=false",
    ]
    if request.plan.runtime_mode == "interactive":
        args.extend(
            (
                "--interactive",
                "--tty",
                "--detach-keys=ctrl-p,ctrl-q",
            )
        )

    if request.manifest.network.mode == "routed":
        gateway = request.plan.container(SessionRole.ROUTED_GATEWAY)
        if gateway is None:
            raise ConfigurationError("routed microVM plan is missing the gateway")
        args.extend(
            (
                "--annotation",
                "run.oci.handler=krun",
                "--annotation",
                f"krun.tap_name={ROUTED_TAP_NAME}",
                f"--network=container:{gateway.name}",
                "--device",
                "/dev/net/tun",
            )
        )
    else:
        for attachment in request.plan.runtime_container.attachments:
            suffix = "" if attachment.address is None else f":ip={attachment.address}"
            args.append(f"--network={attachment.network}{suffix}")

    args.extend(
        (
            "--mount",
            f"type=bind,source={request.paths.root},target=/workspace/sandbox,readonly",
        )
    )
    for mount in build_mounts(request.plan, request.repositories, None):
        args.extend(("--mount", mount))

    # Keep hardening after the checkout bind so the nested secrets tmpfs mask
    # is part of the final OCI mount set seen by krun.
    #
    # ASF's container nofile limit must not bind the VMM: virtio-fs consumes
    # thousands of host-side descriptors. Process-count limiting is handled
    # globally by the cgroup --pids-limit; ASF does not use RLIMIT_NPROC.
    # core=0 remains mandatory because a VMM core could contain guest memory,
    # including brokered credentials.
    routed_tap = request.manifest.network.mode == "routed"
    args.extend(
        argument
        for argument in request.run_arguments
        if not argument.startswith("--ulimit=nofile=")
        # Runtime capabilities belong to the guest kernel, not the VMM
        # container. on-start.sh applies the validated guest capability set.
        and not argument.startswith("--cap-add=")
        # The VMM shares the routed gateway network namespace. Do not let
        # generic runtime hardening overwrite the gateway forwarding state.
        and not (
            routed_tap
            and argument
            in {
                "--sysctl=net.ipv4.ip_forward=0",
                "--sysctl=net.ipv6.conf.all.forwarding=0",
            }
        )
    )

    for key, value in environment.items():
        if not isinstance(key, str):
            raise ValidationError(f"invalid runtime environment name: {key!r}")
        _validate_krun_environment_name(key)
        if not isinstance(value, str) or "\x00" in value:
            raise ValidationError(f"runtime environment {key} must be NUL-free text")
        args.extend(("--env", key))

    args.extend(
        (
            krun_image_name(request.plan),
            "bash",
            "/workspace/sandbox/.devcontainer/on-start.sh",
            *selected,
        )
    )
    return tuple(args)
