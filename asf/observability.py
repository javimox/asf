"""Host-side, read-only observation of one running ASF session."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .broker_metadata import read_broker_requests
from .errors import InfrastructureError
from .runs import (
    current_run,
    run_artifact,
    read_run_policy,
)
from .paths import RepoPaths
from .podman import ContainerInspection, PodmanClient
from .session import (
    NoRunningSessionError,
    SessionDiscovery,
    SessionRole,
    SessionStatus,
)
from .session_events import read_session_events

__all__ = ["ObservationResult", "run_observe_command"]

# Linux capability bit numbers (include/uapi/linux/capability.h), only the
# ones ASF ever grants or expects to see on its own processes.
_CAPABILITY_BITS = {
    12: "net_admin",
    13: "net_raw",
}

_USAGE = "Usage: ./sandbox.sh observe [agent]\n"


class ObservationError(InfrastructureError):
    """A host-side session observation could not be completed."""


@dataclass(frozen=True, slots=True)
class ObservationResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


def run_observe_command(
    arguments: Sequence[str],
    paths: RepoPaths,
    *,
    podman: PodmanClient | None = None,
    require_available: bool = True,
) -> ObservationResult:
    """Return one host-authoritative snapshot for a running session."""

    if isinstance(arguments, (str, bytes)):
        raise TypeError("observe arguments must be a sequence")
    argv = tuple(arguments)
    if not argv or argv[0] != "observe" or len(argv) > 2:
        return ObservationResult(1, stderr=_USAGE)

    client = PodmanClient() if podman is None else podman
    if require_available:
        client.require_available()
    discovery = SessionDiscovery.from_paths(paths, podman=client)
    requested = argv[1] if len(argv) == 2 else None
    runtime = discovery.resolve_runtime(requested)
    session = discovery.session(runtime)
    if session.status is not SessionStatus.RUNNING:
        raise NoRunningSessionError(f"no running session for {runtime}")

    runtime_container = session.container
    if runtime_container is None:
        raise ObservationError(f"cannot identify the running runtime for {runtime}")
    try:
        policy = read_run_policy(paths, runtime)
    except ValueError as exc:
        raise ObservationError(
            f"cannot read the policy snapshot for running session {runtime}; "
            "restart the session to restore authoritative observation"
        ) from exc

    run = current_run(paths, runtime)
    session_id = run.session_id if run is not None else "unavailable"
    lines = [
        f"\n  ASF observation [{runtime}]\n",
        f"\n  session:   {session.status.value}\n",
        f"  run id:    {session_id}\n",
        f"  isolation: {policy.isolation}\n",
        f"  network:   {policy.network_mode}\n",
        f"  broker:    {'enabled' if policy.broker_enabled else 'disabled'}\n",
        f"  llm prompts: {'enabled' if policy.llm_prompts else 'disabled'}\n",
        "\n  declared guest boundary\n",
        f"    capabilities: {_guest_capabilities(policy.capabilities)}\n",
    ]

    if policy.network_mode == "routed":
        lines.append("    routed allow:\n")
        for rule in policy.routed_rules:
            lines.append(f"      {_format_routed_rule(rule)}\n")

    lines.extend(
        [
            "\n  host-side processes\n",
            _format_process("runtime/VMM", runtime_container.inspect),
            _format_role(session, SessionRole.BROKER, "LiteLLM broker"),
            _format_role(session, SessionRole.ROUTED_GATEWAY, "routed gateway"),
            _format_network_observer(session),
            _format_initializer(session),
            "\n  recent lifecycle\n",
            _format_events(read_session_events(paths, runtime)),
            "\n  recent broker requests\n",
            _format_broker_requests(read_broker_requests(paths, runtime)),
            _prompt_capture_note(paths, runtime, policy.llm_prompts),
            (
                _network_capture_summary(paths, runtime, session)
                if policy.isolation == "microvm" and policy.network_mode == "routed"
                else ""
            ),
            "\n  Host-side snapshot only; guest command execution and LLM responses "
            "are not traced.\n\n",
        ]
    )
    return ObservationResult(stdout="".join(lines))


def _safe(value: object) -> str:
    """Render one file-sourced field without letting it drive the terminal.

    ``events.jsonl`` and ``broker-requests.jsonl`` are written by ASF and by
    the LiteLLM container respectively. Neither is trusted to emit clean text,
    so control characters (including ESC) are escaped before display.
    """

    text = str(value)
    return "".join(
        char if char.isprintable() or char == " " else f"\\x{ord(char):02x}"
        for char in text
    )


def _format_events(events: Sequence[dict[str, object]]) -> str:
    if not events:
        return "    no events recorded yet\n"
    lines: list[str] = []
    for event in events:
        timestamp = _safe(event.get("ts", "?"))
        name = _safe(event.get("event", "?"))
        disposition = event.get("disposition")
        suffix = f" ({_safe(disposition)})" if disposition else ""
        lines.append(f"    {timestamp}  {name}{suffix}\n")
    return "".join(lines)


def _format_broker_requests(requests: Sequence[dict[str, object]]) -> str:
    if not requests:
        return "    no broker request metadata recorded yet\n"
    lines: list[str] = []
    for request in requests:
        timestamp = _safe(request.get("ts", "?"))
        event = _safe(request.get("event", "?"))
        model = request.get("model")
        latency = request.get("latency_ms")
        total_tokens = request.get("total_tokens")
        parts = [timestamp, event]
        if model:
            parts.append(f"model={_safe(model)}")
        if isinstance(latency, (int, float)) and not isinstance(latency, bool):
            parts.append(f"latency={latency}ms")
        if isinstance(total_tokens, int) and not isinstance(total_tokens, bool):
            parts.append(f"tokens={total_tokens}")
        lines.append("    " + "  ".join(parts) + "\n")
    return "".join(lines)


def _network_capture_summary(paths: RepoPaths, runtime: str, session) -> str:
    run = current_run(paths, runtime)
    captures: tuple[Path, ...] = ()
    if run is not None:
        captures = tuple(
            path
            for path in run.directory.glob("network-*.pcap")
            if path.is_file() and not path.is_symlink()
        )

    observer = session.role(SessionRole.NETWORK_OBSERVER)
    active = observer is not None and observer.is_running
    lines = [
        "\n  network capture\n",
        f"    status:   {'active' if active else 'inactive'}\n",
        f"    captures: {len(captures)}\n",
    ]
    if captures:
        latest = max(
            captures, key=lambda path: (path.stat().st_mtime_ns, path.name)
        )
        try:
            display = latest.relative_to(paths.root)
        except ValueError:
            display = latest
        label = "current" if active else "latest"
        lines.append(
            f"    {label}:   {display} ({_format_size(latest.stat().st_size)})\n"
        )
        lines.append(f"    inspect:  tcpdump -nn -r {display}\n")
    return "".join(lines)


def _format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def _format_network_observer(session) -> str:
    observer = session.role(SessionRole.NETWORK_OBSERVER)
    if observer is None:
        return ""
    return _format_process("packet capture", observer.inspect)

def _prompt_capture_note(paths: RepoPaths, runtime: str, enabled: bool) -> str:
    if not enabled:
        return ""
    try:
        path = run_artifact(paths, runtime, "llm-prompts.jsonl")
    except OSError:
        return "\n  LLM prompt log path is unavailable.\n"
    try:
        display = path.relative_to(paths.root)
    except ValueError:
        display = path
    return f"\n  LLM prompts are recorded in {display} (mode 0600).\n"


def _guest_capabilities(capabilities: frozenset[str]) -> str:
    return ", ".join(sorted(capabilities)) if capabilities else "none"


def _format_routed_rule(rule) -> str:
    if rule.protocol is None:
        return f"{rule.destination} all IP traffic"
    if rule.protocol == "icmp_echo":
        return f"{rule.destination} icmp_echo"
    ports = (
        "any"
        if rule.ports == "any"
        else ",".join(str(port) for port in rule.ports)
    )
    return f"{rule.destination} {rule.protocol} ports={ports}"


def _format_role(session, role: SessionRole, label: str) -> str:
    container = session.role(role)
    if container is None:
        return f"    {label:<18} absent\n"
    return _format_process(label, container.inspect)


def _format_initializer(session) -> str:
    initializer = session.role(SessionRole.ROUTED_INIT)
    if initializer is None:
        return "    routed initializer  absent (expected after setup)\n"
    return _format_process("routed initializer", initializer.inspect)


def _format_process(label: str, inspection: ContainerInspection) -> str:
    if not inspection.running:
        return f"    {label:<18} {inspection.status}\n"
    if not inspection.pid:
        return f"    {label:<18} running; host pid unavailable\n"
    status = _read_proc_status(inspection.pid)
    effective = status.get("CapEff", "?")
    bounding = status.get("CapBnd", "?")
    nnp = status.get("NoNewPrivs", "?")
    caps = _describe_capabilities(effective, bounding)
    return f"    {label:<18} running pid={inspection.pid} caps={caps} no-new-privs={nnp}\n"


def _describe_capabilities(effective: str, bounding: str) -> str:
    """Decode CapEff/CapBnd hex masks into readable capability names."""

    try:
        eff_mask = int(effective, 16)
        bnd_mask = int(bounding, 16)
    except ValueError:
        return f"eff={effective} bnd={bounding}"
    if eff_mask == 0 and bnd_mask == 0:
        return "none"
    names = []
    for mask in (eff_mask, bnd_mask):
        for bit in range(64):
            if mask & (1 << bit):
                names.append(_CAPABILITY_BITS.get(bit, f"cap_{bit}"))
    if eff_mask == bnd_mask:
        return ",".join(dict.fromkeys(names))
    return f"eff={effective} bnd={bounding}"


def _read_proc_status(pid: int) -> dict[str, str]:
    path = Path("/proc") / str(pid) / "status"
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, OSError) as exc:
        raise ObservationError(
            f"cannot read host process status for pid {pid}: {exc}"
        ) from exc
    wanted = {"CapEff", "CapBnd", "NoNewPrivs"}
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in wanted:
            values[key] = value.strip()
    missing = wanted.difference(values)
    if missing:
        raise ObservationError(
            f"host process status for pid {pid} is missing: {', '.join(sorted(missing))}"
        )
    return values
