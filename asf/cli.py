"""ASF command-line entry point."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Sequence
from typing import NoReturn, TextIO

from .diagnostics import DiagnosticResult, run_diagnostic_command
from .egress_evidence import run_advise_command
from .errors import AsfError
from .observability import run_observe_command
from .network_observer import run_capture_command
from .maintenance import run_maintenance_command
from .paths import RepoPaths
from .podman import PodmanClient, PodmanUnavailableError
from .process import replace as replace_process_command
from .repositories import (
    RepositoryCommandResult,
    RepositoryStore,
    run_repository_command,
)
from .reset import run_reset_command
from .runtime import run_runtime_command
from .security_test import SecurityTestResult, run_security_test_command
from .session import SessionDiscovery, SessionStatus
from .stop import StopCommandResult, run_stop_command
from .version import __version__

__all__ = ["main"]

_REPOSITORY_COMMANDS = frozenset({"repo", "repository"})
_SESSION_COMMANDS = frozenset({"ls", "observe", "capture"})
_DIAGNOSTIC_COMMANDS = frozenset({"proxy", "broker"})
_LIFECYCLE_COMMANDS = frozenset({"stop", "reset", "open", "shell"})
_EVIDENCE_COMMANDS = frozenset({"advise"})
_MAINTENANCE_COMMANDS = frozenset({"build", "scan"})
_USAGE = (
    "Usage: python3 -m asf "
    "{open|shell|ls|observe|capture|repo|repository|build|scan|proxy|broker|test|advise|stop|reset} "
    "[argument]\n"
)
_PODMAN_NOT_FOUND = (
    "\033[0;31mPodman not found.\033[0m\n"
    "  This sandbox runs on rootless Podman. Install it:\n"
    "    Arch:          sudo pacman -S podman\n"
    "    Debian/Ubuntu: sudo apt-get install podman\n"
    "    Fedora/RHEL:   sudo dnf install podman\n"
    "    macOS:         brew install podman && podman machine init && podman machine start\n"
    "  Docs: https://podman.io/docs/installation\n"
)
ReplaceProcess = Callable[[Sequence[str]], NoReturn]

# Commands whose handlers share the plain (arguments, paths, podman, out, err)
# shape. Streaming commands (test, stop) and process-replacing ones (open,
# shell) keep explicit branches in main().
_DISPATCH: dict[str, Callable[..., object]] = {
    **{
        name: (lambda a, p, _pod, _out, _err: _run_repository(a, p))
        for name in _REPOSITORY_COMMANDS
    },
    "ls": lambda a, p, pod, _out, _err: _run_session_list(a, p, pod),
    "observe": lambda a, p, pod, _out, _err: run_observe_command(
        a, p, podman=pod, require_available=True
    ),
    "capture": lambda a, p, pod, _out, _err: run_capture_command(
        a, p, podman=pod, require_available=True
    ),
    **{
        name: (
            lambda a, p, pod, _out, _err: run_diagnostic_command(
                a, p, podman=pod, require_available=True
            )
        )
        for name in _DIAGNOSTIC_COMMANDS
    },
    **{
        name: (
            lambda a, p, pod, out, err: run_maintenance_command(
                a, p, podman=pod, output=out, error=err
            )
        )
        for name in _MAINTENANCE_COMMANDS
    },
    "advise": lambda a, p, _pod, _out, _err: run_advise_command(a, p),
}

_HELP = """
  ./sandbox.sh open <agent>        start a sandbox session
  ./sandbox.sh shell [agent]       attach to a running agent session
  ./sandbox.sh ls                  show running and deployed agent sessions
  ./sandbox.sh observe [agent]     show host-side session and privilege state
  ./sandbox.sh capture start [agent]  start routed microVM packet capture
  ./sandbox.sh capture stop [agent]   stop packet capture and finalize the PCAP
  ./sandbox.sh stop [agent]        stop one session, or all of them
  ./sandbox.sh broker status [agent]        LiteLLM status and exposed models
  ./sandbox.sh broker logs [-f] [agent]     show or follow LiteLLM logs
  ./sandbox.sh broker test [model] [agent]  minimal provider test (uses quota)
  ./sandbox.sh proxy status [agent]         Caddy status and policy
  ./sandbox.sh proxy logs [-f] [agent]      show or follow Caddy logs
  ./sandbox.sh proxy config [agent]         show the active Caddyfile
  ./sandbox.sh test [agent]        test a running session's security boundaries
  ./sandbox.sh advise <agent>      suggest allowlist changes from recent evidence
  ./sandbox.sh reset <agent>       clear one agent's persistent state volume
  ./sandbox.sh build <agent>       build one agent image
  ./sandbox.sh scan [repo] [agent] run Semgrep on all repos, or one named repo
  ./sandbox.sh repo add <agent> <path> [--mode ro|rw]
                                  add or update an agent repository
  ./sandbox.sh repo remove <agent> <name>
                                  remove an agent repository by basename
  ./sandbox.sh repo list <agent> show repositories available to one agent
  ./sandbox.sh repository ...     long-form alias for repo

  Repository access is per agent. New entries are read-write unless --mode ro
  is supplied.

  Agents run side by side. Each gets its own containers, networks and state.
  [agent] is optional whenever exactly one session is running.

  Runs on rootless Podman. See README.md for the security model.

"""


def main(
    argv: Sequence[str] | None = None,
    *,
    root: str | os.PathLike[str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    podman: PodmanClient | None = None,
    replace_process: ReplaceProcess = replace_process_command,
) -> int:
    """Run the Python CLI and return a Bash-compatible process status."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    security_streamed = False
    stop_streamed = False

    def emit_event(event) -> None:
        target = output if event.stream.value == "stdout" else errors
        target.write(event.text)
        target.flush()

    if not arguments or arguments[0] in {"help", "--help", "-h"}:
        output.write(_HELP)
        return 0
    if arguments[0] in {"--version", "version"}:
        output.write(f"ASF {__version__}\n")
        return 0

    commands = (
        _REPOSITORY_COMMANDS
        | _SESSION_COMMANDS
        | _DIAGNOSTIC_COMMANDS
        | _LIFECYCLE_COMMANDS
        | _MAINTENANCE_COMMANDS
        | _EVIDENCE_COMMANDS
        | {"test"}
    )
    if arguments[0] not in commands:
        errors.write(_USAGE)
        return 1

    try:
        paths = RepoPaths.discover() if root is None else RepoPaths.for_root(root)
        command = arguments[0]
        if command in _LIFECYCLE_COMMANDS and command != "stop":
            if command == "reset":
                result = run_reset_command(
                    arguments, paths, podman=podman, require_available=True
                )
            else:
                return run_runtime_command(
                    arguments,
                    paths,
                    podman=podman,
                    output=output,
                    error=errors,
                    replace_process=replace_process,
                )
        elif command == "test":
            security_streamed = True
            result = run_security_test_command(
                arguments,
                paths,
                podman=podman,
                require_available=True,
                event_sink=emit_event,
            )
        elif command == "stop":
            stop_streamed = True
            result = run_stop_command(
                arguments,
                paths,
                podman=podman,
                require_available=True,
                event_sink=emit_event,
            )
        else:
            result = _DISPATCH[command](arguments, paths, podman, output, errors)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
    except PodmanUnavailableError:
        output.write(_PODMAN_NOT_FOUND)
        return 1
    except AsfError as exc:
        errors.write(f"{exc}\n")
        return exc.exit_code
    except OSError as exc:
        errors.write(f"{exc}\n")
        return 1

    try:
        if isinstance(result, SecurityTestResult):
            if not security_streamed:
                result.write_to(output, errors)
            return result.returncode
        if not (isinstance(result, StopCommandResult) and stop_streamed):
            output.write(result.stdout)
            errors.write(result.stderr)
        output.flush()
        errors.flush()
        if isinstance(result, DiagnosticResult) and result.replace_argv:
            replace_process(result.replace_argv)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
    return result.returncode


def _run_repository(
    arguments: list[str],
    paths: RepoPaths,
) -> RepositoryCommandResult:
    usage = (
        "Usage:\n"
        "  ./sandbox.sh repo add <agent> <path> [--mode ro|rw]\n"
        "  ./sandbox.sh repo remove <agent> <repo-name>\n"
        "  ./sandbox.sh repo list <agent>\n"
    )
    if len(arguments) < 3 or arguments[1] not in {"add", "remove", "list"}:
        return RepositoryCommandResult(1, stderr=usage)

    command = arguments[1]
    runtime = arguments[2]
    discovery = SessionDiscovery.from_paths(paths)
    runtime = discovery.validate_runtime(runtime)
    operand = ""
    mode = "rw"

    if command == "list":
        if len(arguments) != 3:
            return RepositoryCommandResult(1, stderr=usage)
    elif command == "remove":
        if len(arguments) != 4:
            return RepositoryCommandResult(1, stderr=usage)
        operand = arguments[3]
    else:
        if len(arguments) == 4:
            operand = arguments[3]
        elif len(arguments) == 6 and arguments[4] == "--mode":
            operand = arguments[3]
            mode = arguments[5]
        elif len(arguments) == 5 and arguments[4].startswith("--mode="):
            operand = arguments[3]
            mode = arguments[4].partition("=")[2]
        else:
            return RepositoryCommandResult(1, stderr=usage)

    store = RepositoryStore.for_file(
        paths.agent_repos_file(runtime),
        runtime=runtime,
        home=os.environ.get("HOME", ""),
    )
    return run_repository_command(command, operand, store, mode=mode)


def _run_session_list(
    arguments: list[str],
    paths: RepoPaths,
    podman: PodmanClient | None,
) -> RepositoryCommandResult:
    if len(arguments) != 1:
        return RepositoryCommandResult(1, stderr="Usage: ./sandbox.sh ls\n")

    client = PodmanClient() if podman is None else podman
    client.require_available()
    discovery = SessionDiscovery.from_paths(paths, podman=client)
    sessions = tuple(
        session
        for session in discovery.sessions()
        if session.status is not SessionStatus.ABSENT
    )
    if not sessions:
        return RepositoryCommandResult(
            0,
            stdout="\n  No agent sessions are running or deployed.\n\n",
        )

    lines = ["\n  Agent sessions\n\n"]
    for session in sessions:
        container = session.container
        detail = f"  {container.name}" if container is not None else ""
        lines.append(
            f"  {session.runtime:<24} {session.status.value:<10}{detail}\n"
        )
    lines.append("\n")
    return RepositoryCommandResult(0, stdout="".join(lines))
