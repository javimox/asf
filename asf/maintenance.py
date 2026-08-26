"""Small user-facing maintenance commands outside the session lifecycle.

The main runtime lifecycle lives in :mod:`asf.runtime`.  This module owns the
remaining bounded utilities: build one runtime image and run Semgrep inside an
already-running runtime.  Both use the same typed manifest, configuration,
identity and persisted-plan boundaries as ``open``.
"""
from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from typing import Sequence, TextIO

from .config import AsfConfig
from .devcontainer import BuildDevcontainerRequest, build_build_config, write_atomic
from .errors import ConfigurationError, InfrastructureError, UsageError
from .krun import build_krun_image_argv
from .manifest import load_model
from .paths import RepoPaths
from .podman import PodmanClient
from .process import run
from .repositories import RepositoryStore
from .runtime_plan import (
    load_runtime_plan,
    runtime_plan_path,
    validate_runtime_plan_context,
)
from .session import SessionDiscovery

__all__ = ["MaintenanceResult", "run_maintenance_command"]

_BLUE = "\033[0;34m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[1;33m"
_RED = "\033[0;31m"
_DIM = "\033[2m"
_RESET = "\033[0m"


class MaintenanceError(InfrastructureError):
    """A build or scan command could not complete safely."""


class MaintenanceUsageError(UsageError):
    """A build or scan command has invalid arguments."""


@dataclass(frozen=True, slots=True)
class MaintenanceResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


def run_maintenance_command(
    arguments: Sequence[str],
    paths: RepoPaths,
    *,
    podman: PodmanClient | None = None,
    output: TextIO = sys.stdout,
    error: TextIO = sys.stderr,
) -> MaintenanceResult:
    if isinstance(arguments, (str, bytes)):
        raise TypeError("maintenance arguments must be a sequence")
    argv = tuple(arguments)
    if not argv or argv[0] not in {"build", "scan"}:
        raise MaintenanceUsageError("unsupported maintenance command")

    client = PodmanClient() if podman is None else podman
    client.require_available()
    if argv[0] == "build":
        return _build(argv[1:], paths, client, output=output, error=error)
    return _scan(argv[1:], paths, client, output=output)


def _build(
    arguments: tuple[str, ...],
    paths: RepoPaths,
    podman: PodmanClient,
    *,
    output: TextIO,
    error: TextIO,
) -> MaintenanceResult:
    if len(arguments) != 1:
        return MaintenanceResult(1, stderr="Usage: ./sandbox.sh build <agent>\n")
    runtime = arguments[0]
    manifest = load_model(paths.identity.runtime_manifest(runtime))
    config = AsfConfig.load(paths.config_file)
    if manifest.runtime.isolation == "microvm":
        output.write(f"{_BLUE}Building {runtime} krun image...{_RESET}\n")
        result = run(
            build_krun_image_argv(
                paths,
                manifest,
                build_arguments=config.build_arguments(),
                engine=os.fspath(podman.engine),
            ),
            timeout=1800,
            capture=False,
        )
        if result.returncode != 0:  # ``run`` raises; retained for custom runners.
            raise MaintenanceError("Build failed.")
        output.write(
            f"{_GREEN}Done.{_RESET} Run {_BLUE}./sandbox.sh open {runtime}{_RESET} "
            "to start a session.\n"
        )
        return MaintenanceResult()

    _require_devcontainer()

    repositories = []
    store = RepositoryStore.for_file(
        paths.agent_repos_file(runtime),
        runtime=runtime,
    )
    for entry in store.entries():
        if entry.exists:
            access = "read-only" if entry.mode == "ro" else "read-write"
            output.write(
                f"  {_GREEN}+{_RESET} {entry.name} {_DIM}({access}){_RESET}\n"
            )
            repositories.append(entry)
        else:
            output.write(
                f"  {_YELLOW}⚠{_RESET} skipping (not found): "
                f"{_DIM}{entry.path}{_RESET}\n"
            )
    if not repositories:
        output.write(
            f"  {_YELLOW}no repos configured for {runtime}{_RESET} — run: "
            f"./sandbox.sh repo add {runtime} ~/path/to/repo\n"
        )

    socket = config.ssh_agent_socket()
    if socket is not None:
        error.write(
            f"  {_YELLOW}⚠ SSH agent forwarding ENABLED{_RESET} "
            f"{_DIM}({socket}){_RESET}\n"
            f"    {_DIM}every identity this agent holds is usable by the "
            f"container for the whole build{_RESET}\n"
        )

    request = BuildDevcontainerRequest(
        paths,
        manifest,
        repositories=tuple(repositories),
        run_arguments=config.hardening_arguments(manifest),
        build_arguments=config.build_arguments(),
        ssh_agent_socket=socket,
    )
    write_atomic(request.output_path, build_build_config(request))
    output.write(f"Wrote {request.output_path}\n")
    output.write(f"{_BLUE}Building {runtime} image...{_RESET}\n")
    result = run(
        (
            "devcontainer",
            "build",
            "--docker-path",
            str(podman.engine),
            "--config",
            str(request.output_path),
            "--workspace-folder",
            str(paths.root),
        ),
        timeout=1800,
        capture=False,
    )
    if result.returncode != 0:  # ``run`` raises; retained for custom runners.
        raise MaintenanceError("Build failed.")
    output.write(
        f"{_GREEN}Done.{_RESET} Run {_BLUE}./sandbox.sh open {runtime}{_RESET} "
        "to start a session.\n"
    )
    return MaintenanceResult()


def _scan(
    arguments: tuple[str, ...],
    paths: RepoPaths,
    podman: PodmanClient,
    *,
    output: TextIO,
) -> MaintenanceResult:
    discovery = SessionDiscovery.from_paths(paths, podman=podman)
    requested, remaining = discovery.extract_runtime_argument(arguments)
    if len(remaining) > 1:
        return MaintenanceResult(1, stderr="Usage: ./sandbox.sh scan [repo] [agent]\n")
    runtime = discovery.resolve_runtime(requested or None)
    match = discovery.unique_match(runtime)
    if match is None:
        return MaintenanceResult(
            1,
            stderr=(
                f"{_RED}No running {runtime} container.{_RESET}\n"
                f"  Start one first: ./sandbox.sh open {runtime}\n"
            ),
        )

    manifest = load_model(paths.identity.runtime_manifest(runtime))
    plan = load_runtime_plan(runtime_plan_path(paths, runtime))
    validate_runtime_plan_context(plan, manifest, paths)
    if plan.runtime_isolation == "microvm":
        return MaintenanceResult(
            1,
            stderr=(
                "scan is unavailable for runtime.isolation: microvm; "
                "the krun backend cannot start Semgrep as a second process.\n"
            ),
        )
    _require_devcontainer()

    configured = {
        entry.name
        for entry in RepositoryStore.for_file(
            paths.agent_repos_file(runtime),
            runtime=runtime,
        ).entries()
    }
    repository = remaining[0] if remaining else ""
    if repository and repository not in configured:
        raise ConfigurationError(
            f"Repository is not configured for scanning: {repository}"
        )
    target = f"/workspace/repos/{repository}" if repository else "/workspace/repos"
    output.write(
        f"{_BLUE}Scanning {repository if repository else 'all repos'}...{_RESET}\n"
    )
    run(
        (
            "devcontainer",
            "exec",
            "--docker-path",
            str(podman.engine),
            "--config",
            str(paths.session_artifact(runtime, "devcontainer.json")),
            "--id-label",
            plan.session_label,
            "--workspace-folder",
            str(paths.root),
            "--",
            "semgrep",
            "scan",
            "--config",
            "auto",
            target,
        ),
        timeout=3600,
        capture=False,
    )
    return MaintenanceResult()


def _require_devcontainer() -> None:
    if shutil.which("devcontainer") is None:
        raise MaintenanceError(
            "devcontainer CLI not found. Install: npm install -g @devcontainers/cli"
        )
