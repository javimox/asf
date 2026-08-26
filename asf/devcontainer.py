"""Render one ASF Dev Container configuration from a persisted runtime plan.

Runtime planning decides the session topology. This module consumes that exact plan
plus the validated runtime manifest and host-resolved build/hardening inputs;
it does not recalculate container names, networks, volumes, or broker/proxy
membership.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .errors import ConfigurationError, ValidationError
from .manifest import load_model
from .models import RuntimeManifest
from .paths import RepoPaths
from .repositories import RepositoryEntry
from .runtime_plan import (
    BROKER_INTERNAL_ALIAS,
    GeneratedFileKind,
    PROXY_INTERNAL_ALIAS,
    RuntimePlan,
    routed_broker_address,
    load_runtime_plan,
    runtime_plan_path,
    validate_runtime_plan_context,
)
from .session import SessionRole

__all__ = [
    "DevcontainerError",
    "BuildDevcontainerRequest",
    "DevcontainerRequest",
    "apply_egress_environment",
    "build_build_config",
    "build_devcontainer_config",
    "build_mounts",
    "load_base",
    "load_build_request",
    "load_request",
    "reanchor_build_paths",
    "write_atomic",
]

_BUILD_ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DEFAULT_PROXY_PORT = 3128


class DevcontainerError(ConfigurationError):
    """A safe Dev Container configuration could not be rendered."""


@dataclass(frozen=True, slots=True)
class BuildDevcontainerRequest:
    """Inputs for ``sandbox.sh build`` without creating a session plan.

    The generated file is usable only as a Dev Container build description.
    Session opening never uses this path: ``open`` requires a persisted and
    context-validated :class:`RuntimePlan`.
    """

    paths: RepoPaths
    manifest: RuntimeManifest
    repositories: tuple[RepositoryEntry, ...] = ()
    run_arguments: tuple[str, ...] = ()
    build_arguments: tuple[str, ...] = ()
    ssh_agent_socket: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.paths, RepoPaths):
            raise TypeError("paths must be RepoPaths")
        if not isinstance(self.manifest, RuntimeManifest):
            raise TypeError("manifest must be a RuntimeManifest")
        object.__setattr__(
            self, "repositories", _normalise_repositories(self.repositories)
        )
        object.__setattr__(self, "run_arguments", tuple(self.run_arguments))
        object.__setattr__(self, "build_arguments", tuple(self.build_arguments))
        _validate_text_arguments("run arguments", self.run_arguments)
        _validate_text_arguments("build arguments", self.build_arguments)
        if self.ssh_agent_socket is not None:
            socket_path = Path(self.ssh_agent_socket).expanduser()
            if not socket_path.is_socket():
                raise DevcontainerError(
                    f"SSH agent socket not found (or not a socket): {socket_path}"
                )
            object.__setattr__(self, "ssh_agent_socket", socket_path)

    @property
    def base_path(self) -> Path:
        return self.paths.devcontainer_base

    @property
    def output_path(self) -> Path:
        return self.paths.session_artifact(self.manifest.name, "devcontainer.json")


@dataclass(frozen=True, slots=True)
class DevcontainerRequest:
    paths: RepoPaths
    plan: RuntimePlan
    manifest: RuntimeManifest
    repositories: tuple[RepositoryEntry, ...] = ()
    run_arguments: tuple[str, ...] = ()
    build_arguments: tuple[str, ...] = ()
    ssh_agent_socket: Path | None = None
    proxy_port: int = _DEFAULT_PROXY_PORT
    broker_default_model: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.paths, RepoPaths):
            raise TypeError("paths must be RepoPaths")
        if not isinstance(self.plan, RuntimePlan):
            raise TypeError("plan must be a RuntimePlan")
        if not isinstance(self.manifest, RuntimeManifest):
            raise TypeError("manifest must be a RuntimeManifest")
        object.__setattr__(
            self, "repositories", _normalise_repositories(self.repositories)
        )
        object.__setattr__(self, "run_arguments", tuple(self.run_arguments))
        object.__setattr__(self, "build_arguments", tuple(self.build_arguments))
        _validate_text_arguments("run arguments", self.run_arguments)
        _validate_text_arguments("build arguments", self.build_arguments)
        if self.ssh_agent_socket is not None:
            socket_path = Path(self.ssh_agent_socket).expanduser()
            if not socket_path.is_socket():
                raise DevcontainerError(
                    f"SSH agent socket not found (or not a socket): {socket_path}"
                )
            object.__setattr__(self, "ssh_agent_socket", socket_path)
        if (
            isinstance(self.proxy_port, bool)
            or not isinstance(self.proxy_port, int)
            or not 1 <= self.proxy_port <= 65535
        ):
            raise ValidationError("proxy port must be between 1 and 65535")
        if not isinstance(self.broker_default_model, str) or "\x00" in self.broker_default_model:
            raise ValidationError("broker default model must be NUL-free text")
        validate_runtime_plan_context(self.plan, self.manifest, self.paths)

    @property
    def base_path(self) -> Path:
        return self.paths.devcontainer_base

    @property
    def output_path(self) -> Path:
        # Resolve through RepoPaths at write time so a newly planted session
        # symlink cannot redirect the generated configuration outside checkout.
        return self.paths.session_artifact(self.plan.runtime, "devcontainer.json")


def _normalise_repositories(
    values: Sequence[str | os.PathLike[str] | RepositoryEntry],
) -> tuple[RepositoryEntry, ...]:
    entries: list[RepositoryEntry] = []
    for value in values:
        if isinstance(value, RepositoryEntry):
            entries.append(value)
            continue
        raw = os.fspath(value)
        if not isinstance(raw, str):
            raise TypeError("repository paths must resolve to text")
        entries.append(RepositoryEntry(raw, "rw"))
    return tuple(entries)


def _validate_text_arguments(label: str, values: Sequence[str]) -> None:
    if not all(isinstance(item, str) and "\x00" not in item for item in values):
        raise ValidationError(f"{label} must be NUL-free text")


def load_build_request(
    *,
    root: str | os.PathLike[str],
    runtime: str,
    repositories: Sequence[str | os.PathLike[str] | RepositoryEntry] = (),
    run_arguments: Sequence[str] = (),
    build_arguments: Sequence[str] = (),
    ssh_agent_socket: str | os.PathLike[str] | None = None,
) -> BuildDevcontainerRequest:
    """Load the manifest for a build-only Dev Container configuration."""

    paths = RepoPaths.for_root(root)
    manifest = load_model(paths.identity.runtime_manifest(runtime))
    return BuildDevcontainerRequest(
        paths=paths,
        manifest=manifest,
        repositories=_normalise_repositories(repositories),
        run_arguments=tuple(run_arguments),
        build_arguments=tuple(build_arguments),
        ssh_agent_socket=None if ssh_agent_socket is None else Path(ssh_agent_socket),
    )


def load_request(
    *,
    root: str | os.PathLike[str],
    runtime: str,
    repositories: Sequence[str | os.PathLike[str] | RepositoryEntry] = (),
    run_arguments: Sequence[str] = (),
    build_arguments: Sequence[str] = (),
    ssh_agent_socket: str | os.PathLike[str] | None = None,
    proxy_port: int = _DEFAULT_PROXY_PORT,
    broker_default_model: str = "",
) -> DevcontainerRequest:
    """Load the manifest and persisted plan for one active opening session."""

    paths = RepoPaths.for_root(root)
    manifest = load_model(paths.identity.runtime_manifest(runtime))
    plan = load_runtime_plan(runtime_plan_path(paths, runtime))
    return DevcontainerRequest(
        paths=paths,
        plan=plan,
        manifest=manifest,
        repositories=_normalise_repositories(repositories),
        run_arguments=tuple(run_arguments),
        build_arguments=tuple(build_arguments),
        ssh_agent_socket=None if ssh_agent_socket is None else Path(ssh_agent_socket),
        proxy_port=proxy_port,
        broker_default_model=broker_default_model,
    )


def load_base(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise DevcontainerError(f"Base devcontainer config not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise DevcontainerError(f"Base devcontainer config is not valid UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise DevcontainerError(f"Invalid JSON in {path}: {exc}") from exc
    except OSError as exc:
        raise DevcontainerError(f"Cannot read base devcontainer config {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise DevcontainerError(
            f"Base devcontainer config must be a JSON object: {path}"
        )
    return data


def _render_mounts(
    persistent_volumes: Sequence[tuple[str, str]],
    repositories: Sequence[RepositoryEntry],
    ssh_agent_socket: Path | None,
) -> list[str]:
    mounts: list[str] = []
    for name, target in persistent_volumes:
        if "," in target:
            raise DevcontainerError(
                "Invalid state mount target (commas are not allowed): "
                f"{target}"
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
            raise DevcontainerError(
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
    """Render persistent plan volumes plus explicit host bind mounts."""

    return _render_mounts(
        tuple((item.name, item.target) for item in plan.persistent_volumes),
        repositories,
        ssh_agent_socket,
    )


def _build_only_mounts(request: BuildDevcontainerRequest) -> list[str]:
    identity = request.paths.identity
    runtime = request.manifest.name
    persistent = tuple(
        (identity.state_volume(runtime, item.key), item.target)
        for item in request.manifest.state_volumes
    ) + ((identity.shell_history_volume(runtime), "/commandhistory"),)
    return _render_mounts(
        persistent, request.repositories, request.ssh_agent_socket
    )


def reanchor_build_paths(cfg: dict[str, Any], base: Path, output: Path) -> None:
    """Rewrite relative build paths for the generated file's location."""

    build = cfg.get("build")
    if not isinstance(build, dict):
        return
    base_dir = base.resolve().parent
    out_dir = output.resolve().parent
    for key in ("context", "dockerfile"):
        value = build.get(key)
        if not isinstance(value, str) or os.path.isabs(value):
            continue
        resolved = (base_dir / value).resolve()
        build[key] = os.path.relpath(resolved, out_dir)


def _apply_manifest_and_build_inputs(
    cfg: dict[str, Any],
    *,
    manifest: RuntimeManifest,
    runtime: str,
    adapter: str,
    build_arguments: Sequence[str],
    ssh_agent_socket: Path | None,
) -> None:
    environment = cfg.setdefault("containerEnv", {})
    if not isinstance(environment, dict):
        raise DevcontainerError("base containerEnv must be a JSON object")
    for item in manifest.environment:
        environment[item.name] = item.value
    if ssh_agent_socket is not None:
        environment["SSH_AUTH_SOCK"] = "/ssh-agent"
    environment["ASF_AGENT"] = runtime
    environment["ASF_ISOLATION"] = "container"

    build = cfg.setdefault("build", {})
    if not isinstance(build, dict):
        raise DevcontainerError("base build must be a JSON object")
    build_args = build.setdefault("args", {})
    if not isinstance(build_args, dict):
        raise DevcontainerError("base build.args must be a JSON object")
    build_args["AGENT"] = adapter
    for item in manifest.runtime.build_arguments:
        build_args[item.name] = item.value
    for raw in build_arguments:
        name, separator, value = raw.partition("=")
        if not separator or not _BUILD_ARG_NAME.fullmatch(name):
            raise DevcontainerError(
                f"Invalid build argument (expected NAME=VALUE): {raw}"
            )
        build_args[name] = value


def build_build_config(request: BuildDevcontainerRequest) -> dict[str, Any]:
    """Render the non-session configuration used only by ``devcontainer build``."""

    cfg = load_base(request.base_path)
    reanchor_build_paths(cfg, request.base_path, request.output_path)
    manifest = request.manifest
    identity = request.paths.identity
    _apply_manifest_and_build_inputs(
        cfg,
        manifest=manifest,
        runtime=manifest.name,
        adapter=manifest.adapter,
        build_arguments=request.build_arguments,
        ssh_agent_socket=request.ssh_agent_socket,
    )

    run_args = cfg.setdefault("runArgs", [])
    if not isinstance(run_args, list) or not all(isinstance(item, str) for item in run_args):
        raise DevcontainerError("base runArgs must be a list of text values")
    run_args.extend(
        (
            f"--label={identity.session_label(manifest.name)}",
            f"--name={identity.container_name(manifest.name)}",
            f"--network={identity.network_names(manifest.name).internal}",
        )
    )
    _validate_capability_set(manifest.capabilities, request.run_arguments)
    run_args.extend(request.run_arguments)
    cfg["mounts"] = _build_only_mounts(request)
    return cfg


def apply_egress_environment(
    environment: dict[str, str],
    *,
    plan: "RuntimePlan",
    manifest: RuntimeManifest,
    proxy_port: int,
    broker_default_model: str,
    broker_token: str,
) -> None:
    """Apply the proxy/broker session environment to ``environment``.

    Single source of truth for the security-relevant egress wiring, shared by
    the devcontainer path (which passes the ``${localEnv:…}`` placeholder so
    the token never persists in generated configuration) and the krun path
    (which passes the real session token and keeps values out of argv).
    """

    proxy = plan.container(SessionRole.PROXY)
    if proxy is not None:
        proxy_url = f"http://{PROXY_INTERNAL_ALIAS}:{proxy_port}"
        for variable in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            environment[variable] = proxy_url
        environment["NO_PROXY"] = "localhost,127.0.0.1"
        environment["no_proxy"] = "localhost,127.0.0.1"
        environment["ASF_PROXY"] = proxy_url

    broker = plan.container(SessionRole.BROKER)
    if broker is not None:
        llm = manifest.llm
        if llm is None or llm.protocol is None:
            raise DevcontainerError(
                "broker-enabled runtime plan requires an LLM wire protocol"
            )
        if not broker_token:
            raise DevcontainerError(
                "broker-enabled runtime requires a session token"
            )
        environment["ASF_BROKER_ENABLED"] = "true"
        broker_address = (
            routed_broker_address(plan)
            if (
                manifest.runtime.isolation == "microvm"
                and manifest.network.mode == "routed"
            )
            else None
        )
        broker_host = (
            str(broker_address)
            if broker_address is not None
            else BROKER_INTERNAL_ALIAS
        )
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


def build_devcontainer_config(request: DevcontainerRequest) -> dict[str, Any]:
    """Return the deterministic configuration for one validated request."""

    cfg = load_base(request.base_path)
    reanchor_build_paths(cfg, request.base_path, request.output_path)

    _apply_manifest_and_build_inputs(
        cfg,
        manifest=request.manifest,
        runtime=request.plan.runtime,
        adapter=request.plan.adapter,
        build_arguments=request.build_arguments,
        ssh_agent_socket=request.ssh_agent_socket,
    )
    environment = cfg["containerEnv"]

    run_args = cfg.setdefault("runArgs", [])
    if not isinstance(run_args, list) or not all(isinstance(item, str) for item in run_args):
        raise DevcontainerError("base runArgs must be a list of text values")
    run_args.append(f"--label={request.plan.session_label}")
    run_args.append(f"--name={request.plan.runtime_container.name}")
    for attachment in request.plan.runtime_container.attachments:
        suffix = "" if attachment.address is None else f":ip={attachment.address}"
        run_args.append(f"--network={attachment.network}{suffix}")
    _validate_capability_arguments(request.plan, request.run_arguments)
    run_args.extend(request.run_arguments)

    apply_egress_environment(
        environment,
        plan=request.plan,
        manifest=request.manifest,
        proxy_port=request.proxy_port,
        broker_default_model=request.broker_default_model,
        broker_token="${localEnv:ASF_BROKER_TOKEN}",
    )

    cfg["mounts"] = build_mounts(
        request.plan,
        request.repositories,
        request.ssh_agent_socket,
    )
    return cfg


def _validate_capability_set(
    capabilities: Sequence[str],
    run_arguments: Sequence[str],
) -> None:
    expected = {item.lower() for item in capabilities}
    observed: set[str] = set()
    for argument in run_arguments:
        if argument.startswith("--cap-add="):
            value = argument.partition("=")[2]
            if not value:
                raise DevcontainerError("empty --cap-add value")
            observed.add(value.lower())
    if observed != expected:
        raise DevcontainerError(
            "runtime capability arguments do not match the expected policy: "
            f"expected {sorted(expected)}, got {sorted(observed)}"
        )


def _validate_capability_arguments(
    plan: RuntimePlan,
    run_arguments: Sequence[str],
) -> None:
    """Ensure Bash hardening inputs cannot contradict the persisted plan."""

    _validate_capability_set(plan.runtime_container.capabilities, run_arguments)


def write_atomic(path: Path, cfg: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "// GENERATED by sandbox.sh from devcontainer.base.json — DO NOT EDIT.\n"
        "// Re-run ./sandbox.sh open <agent> to regenerate.\n"
    )
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(header)
            json.dump(cfg, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _generated_destination(plan: RuntimePlan, kind: GeneratedFileKind) -> Path:
    matches = [item.destination for item in plan.generated_files if item.kind is kind]
    if len(matches) != 1:
        raise DevcontainerError(
            f"runtime plan must contain exactly one {kind.value} destination"
        )
    return matches[0]
