"""Read-only proxy and broker diagnostic commands."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .egress_evidence import EgressEvidenceError, current_egress_session
from .errors import AsfError, InfrastructureError, UsageError
from .paths import RepoPaths
from .podman import (
    ObjectKind,
    PodmanClient,
    PodmanError,
    PodmanValidationError,
)
from .session import (
    AmbiguousSessionError,
    MultipleRunningSessionsError,
    NoRunningSessionError,
    SessionDiscovery,
    SessionRole,
)

__all__ = [
    "DiagnosticResult",
    "DiagnosticsError",
    "DiagnosticsUsageError",
    "run_diagnostic_command",
]

_RED = "\033[0;31m"
_YELLOW = "\033[1;33m"
_RESET = "\033[0m"
_PROXY_USAGE = "Usage: ./sandbox.sh proxy {status|logs [-f]|config} [agent]\n"
_BROKER_USAGE = (
    "Usage: ./sandbox.sh broker [status|logs [--follow]|test [model]] [agent]\n"
)
_LIVE_MODELS_SCRIPT = '''
import json, os, urllib.request
request = urllib.request.Request(
    "http://127.0.0.1:4000/v1/models",
    headers={"Authorization": "Bearer " + os.environ["LITELLM_MASTER_KEY"]},
)
with urllib.request.urlopen(request, timeout=5) as response:
    data = json.load(response)
print(", ".join(sorted(item["id"] for item in data.get("data", []) if item.get("id"))))
'''


class DiagnosticsError(InfrastructureError):
    """A read-only diagnostic command could not be completed safely."""


class DiagnosticsUsageError(UsageError):
    """A diagnostic command has invalid arguments."""


@dataclass(frozen=True, slots=True)
class DiagnosticResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    replace_argv: tuple[str, ...] | None = None


def run_diagnostic_command(
    arguments: Sequence[str],
    paths: RepoPaths,
    *,
    podman: PodmanClient | None = None,
    require_available: bool = True,
) -> DiagnosticResult:
    """Run one proxy or broker diagnostic command."""

    if isinstance(arguments, (str, bytes)):
        raise TypeError("diagnostic arguments must be a sequence")
    argv = tuple(arguments)
    if not argv or argv[0] not in {"proxy", "broker"}:
        raise DiagnosticsUsageError("unsupported diagnostic command")

    client = PodmanClient() if podman is None else podman
    if require_available:
        client.require_available()
    discovery = SessionDiscovery.from_paths(paths, podman=client)
    if argv[0] == "proxy":
        return _run_proxy(argv[1:], paths, discovery, client)
    return _run_broker(argv[1:], paths, discovery, client)


def _run_proxy(
    arguments: tuple[str, ...],
    paths: RepoPaths,
    discovery: SessionDiscovery,
    podman: PodmanClient,
) -> DiagnosticResult:
    action = arguments[0] if arguments else "status"
    rest = arguments[1:] if arguments else ()
    if action not in {"status", "logs", "config"}:
        return DiagnosticResult(1, stderr=_PROXY_USAGE)

    requested, remaining = discovery.extract_runtime_argument(rest)
    for argument in remaining:
        if action != "logs" or argument not in {"-f", "--follow"}:
            return DiagnosticResult(1, stderr=_PROXY_USAGE)

    runtime = _resolve_runtime(discovery, requested)
    container_id = _unique_role_container(
        discovery, runtime, SessionRole.PROXY, include_stopped=False
    )
    if container_id is None:
        return DiagnosticResult(
            1,
            stderr=(
                f"{_RED}No running Caddy proxy for {runtime}.{_RESET}\n"
            ),
        )
    inspection = podman.inspect_container(container_id)

    if action == "config":
        result = podman.exec_container(
            container_id, ("cat", "/etc/caddy/Caddyfile")
        )
        return DiagnosticResult(stdout=result.stdout, stderr=result.stderr)

    if action == "logs":
        if inspection.label("asf.access-logs") == "true":
            try:
                context = current_egress_session(paths, runtime)
            except EgressEvidenceError as exc:
                return DiagnosticResult(1, stderr=f"{exc}\n")
            if context is not None and context.access_log_path.is_file():
                # Preserve the accepted Bash quirk: --follow is accepted, but
                # only -f activates follow mode.
                follow = "-f" in remaining
                if follow:
                    return DiagnosticResult(
                        replace_argv=(
                            "tail",
                            "-n",
                            "100",
                            "-f",
                            "--",
                            str(context.access_log_path),
                        )
                    )
                return DiagnosticResult(
                    stdout=_tail_text_file(context.access_log_path, lines=100)
                )
        stderr = (
            "Caddy access logs are unavailable; showing runtime logs only.\n"
            "  Set CADDY_ACCESS_LOGS=true and reopen the session to enable them.\n"
        )
        follow = "-f" in remaining
        if follow:
            return DiagnosticResult(
                stderr=stderr,
                replace_argv=podman.logs_argv(
                    container_id, tail=100, follow=True
                ),
            )
        result = podman.container_logs(container_id, tail=100)
        return DiagnosticResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=stderr + result.stderr,
        )

    policy_result = podman.exec_container(
        container_id, ("cat", "/etc/caddy/Caddyfile")
    )
    port, domains = _parse_caddy_policy(policy_result.stdout)
    lines = [
        f"Caddy proxy for {runtime}",
        f"  container: {inspection.name}",
        f"  status:    {inspection.status}",
        f"  access logs: {inspection.label('asf.access-logs') or 'unknown'}",
        "  networks:",
    ]
    lines.extend(f"    {network}" for network in inspection.networks)
    lines.append(f"  permitted port: {port or 'unknown'}")
    lines.append("  allowed hosts:")
    if domains:
        lines.extend(f"    {domain}" for domain in domains)
    else:
        lines.append("    (none)")
    return DiagnosticResult(stdout="\n".join(lines) + "\n")


def _tail_text_file(path: Path, *, lines: int) -> str:
    if path.is_symlink() or not path.is_file():
        raise DiagnosticsError(f"Caddy access log is unavailable or unsafe: {path}")
    text = path.read_text(encoding="utf-8")
    selected = text.splitlines()[-lines:]
    return "\n".join(selected) + ("\n" if selected else "")


def _run_broker(
    arguments: tuple[str, ...],
    paths: RepoPaths,
    discovery: SessionDiscovery,
    podman: PodmanClient,
) -> DiagnosticResult:
    action = arguments[0] if arguments else "status"
    rest = arguments[1:] if arguments else ()
    if action not in {"status", "logs", "test"}:
        return DiagnosticResult(1, stderr=_BROKER_USAGE)

    requested, remaining = discovery.extract_runtime_argument(rest)
    if action == "test" and len(remaining) > 1:
        return DiagnosticResult(1, stderr=_BROKER_USAGE)
    follow_arg = remaining[0] if remaining else ""
    runtime = _resolve_runtime(discovery, requested)
    container_id = _broker_container_id(paths, discovery, podman, runtime)
    if container_id is None:
        return DiagnosticResult(
            1,
            stdout=(
                f"{_YELLOW}No LiteLLM broker container is running for "
                f"{runtime}.{_RESET}\n"
            ),
        )

    if action == "logs":
        follow = follow_arg in {"-f", "--follow"}
        if follow:
            return DiagnosticResult(
                replace_argv=podman.logs_argv(
                    container_id, tail=200, follow=True
                )
            )
        result = podman.container_logs(container_id, tail=200)
        return DiagnosticResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    inspection = podman.inspect_container(container_id)
    if action == "test":
        model = follow_arg
        if not model and runtime == "hermes":
            model = inspection.label("asf.default-model") or ""
        provider = inspection.label("asf.provider") or ""
        if provider and model.startswith(provider + "/"):
            model = model[len(provider) + 1 :]
        if not model:
            return DiagnosticResult(
                1,
                stderr=(
                    "Usage: ./sandbox.sh broker test <model>\n"
                    "  Claude model selection is owned by Claude Code, so "
                    "specify the model to test.\n"
                ),
            )
        script = _read_broker_probe_tool(paths.broker_probe_tool)
        result = podman.observe(
            (
                podman.engine,
                "exec",
                "-e",
                f"LITELLM_TEST_MODEL={model}",
                "-i",
                container_id,
                "python",
                "-",
            ),
            timeout=90,
            input_text=script,
        )
        intro = (
            "\033[0;34mSending a small diagnostic request through "
            f"LiteLLM\033[0m \033[2m(model: {model})\033[0m\n"
        )
        return DiagnosticResult(
            returncode=result.returncode,
            stdout=intro + result.stdout,
            stderr=result.stderr,
        )
    route = inspection.label("asf.model-route") or ""
    live = podman.exec_container(
        container_id,
        ("python", "-c", _LIVE_MODELS_SCRIPT),
        check=False,
    )
    live_models = live.stdout.strip() if live.succeeded else ""
    if live_models:
        route = live_models
    provider = inspection.label("asf.provider") or ""
    runtime_label = inspection.label("asf.agent") or ""
    default_model = inspection.label("asf.default-model") or ""
    lines = [
        "LiteLLM broker",
        f"  container: {inspection.name.lstrip('/')}",
        f"  status:    {inspection.status}",
        f"  image:     {inspection.image}",
        f"  agent:     {runtime_label}",
        f"  provider:  {provider}",
        f"  models:    {route}",
    ]
    if default_model:
        lines.append(f"  default:   {default_model}")
    return DiagnosticResult(stdout="\n".join(lines) + "\n")


def _resolve_runtime(
    discovery: SessionDiscovery, requested: str
) -> str:
    try:
        return discovery.resolve_runtime(requested or None)
    except NoRunningSessionError as exc:
        raise DiagnosticsError(
            f"{_RED}No running session in this checkout.{_RESET}\n"
            "  Start one: ./sandbox.sh open <agent>"
        ) from exc
    except MultipleRunningSessionsError as exc:
        listing = "\n".join(f"    {runtime}" for runtime in exc.runtimes)
        raise DiagnosticsError(
            f"{_RED}Several sessions are running — name the agent.{_RESET}\n"
            f"{listing}"
        ) from exc


def _unique_role_container(
    discovery: SessionDiscovery,
    runtime: str,
    role: SessionRole,
    *,
    include_stopped: bool,
) -> str | None:
    identifiers = discovery.role_container_ids(
        runtime, role, include_stopped=include_stopped
    )
    if not identifiers:
        return None
    if len(identifiers) > 1:
        raise AmbiguousSessionError(runtime, identifiers, role=role.value)
    return identifiers[0]


def _broker_container_id(
    paths: RepoPaths,
    discovery: SessionDiscovery,
    podman: PodmanClient,
    runtime: str,
) -> str | None:
    state = paths.identity.broker_state(runtime)
    try:
        if state.is_file() and state.stat().st_size > 0:
            reference = state.read_text(encoding="utf-8").splitlines()[0]
            if reference and podman.exists(reference, ObjectKind.CONTAINER):
                return reference
    except (OSError, UnicodeError, IndexError, PodmanValidationError):
        pass
    return _unique_role_container(
        discovery, runtime, SessionRole.BROKER, include_stopped=True
    )


def _read_broker_probe_tool(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise DiagnosticsError(f"Broker probe is missing or unsafe: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise DiagnosticsError(f"Cannot read broker probe: {path}: {exc}") from exc


def _parse_caddy_policy(policy: str) -> tuple[str, tuple[str, ...]]:
    port = ""
    domains: list[str] = []
    for line in policy.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        if not port and fields[0] == "ports":
            port = fields[1]
        if fields[0] == "allow":
            domains.append(fields[1])
    return port, tuple(domains)
