"""Host-side, read-only observation of one running ASF session."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .broker_metadata import read_broker_requests
from .network_activity import read_network_activity
from .errors import InfrastructureError
from .observation_sessions import (
    ObservationPolicy,
    current_observation_session,
    observation_artifact,
    read_observation_policy,
)
from .paths import RepoPaths
from .podman import ContainerInspection, PodmanClient
from .session import NoRunningSessionError, SessionDiscovery, SessionRole, SessionStatus
from .session_events import read_session_events

__all__ = ["ObservationResult", "run_observe_command"]

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
        policy = read_observation_policy(paths, runtime)
    except ValueError as exc:
        raise ObservationError(
            f"cannot read the policy snapshot for running session {runtime}; "
            "restart the session to restore authoritative observation"
        ) from exc

    observation_session = current_observation_session(paths, runtime)
    observation_id = (
        observation_session.session_id if observation_session is not None else "unavailable"
    )
    lines = [
        f"\n  ASF observation [{runtime}]\n",
        f"\n  session:   {session.status.value}\n",
        f"  run id:    {observation_id}\n",
        f"  isolation: {policy.isolation}\n",
        f"  network:   {policy.network_mode}\n",
        f"  broker:    {'enabled' if policy.broker_enabled else 'disabled'}\n",
        f"  llm prompts: {'enabled' if policy.llm_prompts else 'disabled'}\n",
        f"  network activity: {'enabled' if policy.network_activity else 'disabled'}\n",
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
            "\n  recent network activity\n",
            _format_network_activity(read_network_activity(paths, runtime), policy),
            _prompt_capture_note(paths, runtime, policy.llm_prompts),
            _network_capture_note(paths, runtime, policy.network_activity),
            "\n  Host-side snapshot only; guest output, LLM responses, and packet contents are not captured.\n\n",
        ]
    )
    return ObservationResult(stdout="".join(lines))


def _format_events(events: Sequence[dict[str, object]]) -> str:
    if not events:
        return "    no events recorded yet\n"
    lines: list[str] = []
    for event in events:
        timestamp = str(event.get("ts", "?"))
        name = str(event.get("event", "?"))
        disposition = event.get("disposition")
        suffix = f" ({disposition})" if disposition else ""
        lines.append(f"    {timestamp}  {name}{suffix}\n")
    return "".join(lines)



def _format_broker_requests(requests: Sequence[dict[str, object]]) -> str:
    if not requests:
        return "    no broker request metadata recorded yet\n"
    lines: list[str] = []
    for request in requests:
        timestamp = str(request.get("ts", "?"))
        event = str(request.get("event", "?"))
        model = request.get("model")
        latency = request.get("latency_ms")
        total_tokens = request.get("total_tokens")
        parts = [timestamp, event]
        if model:
            parts.append(f"model={model}")
        if isinstance(latency, (int, float)) and not isinstance(latency, bool):
            parts.append(f"latency={latency}ms")
        if isinstance(total_tokens, int) and not isinstance(total_tokens, bool):
            parts.append(f"tokens={total_tokens}")
        lines.append("    " + "  ".join(parts) + "\n")
    return "".join(lines)


def _format_network_activity(
    records: Sequence[dict[str, object]], policy: ObservationPolicy
) -> str:
    if not policy.network_activity:
        return "    disabled\n"
    if not records:
        return "    no network attempts recorded yet\n"
    lines: list[str] = []
    for record in records:
        if record.get("event") == "network_activity_truncated":
            lines.append("    capture stopped: 64 MiB per-session limit reached\n")
            continue
        timestamp = str(record.get("ts", "?"))
        destination = str(record.get("destination", "?"))
        protocol = str(record.get("protocol", "?"))
        destination_port = record.get("destination_port")
        endpoint = f"{protocol}/{destination_port}" if isinstance(destination_port, int) else protocol
        match = _network_policy_match(policy, record)
        lines.append(
            f"    {timestamp}  {destination}  {endpoint}  policy-match={match}\n"
        )
    return "".join(lines)


def _network_policy_match(
    policy: ObservationPolicy, record: dict[str, object]
) -> str:
    from ipaddress import IPv4Address, AddressValueError

    try:
        address = IPv4Address(str(record.get("destination", "")))
    except AddressValueError:
        return "unknown"
    protocol = record.get("protocol")
    if protocol not in {"tcp", "udp", "icmp_echo"}:
        return "unknown"
    port = record.get("destination_port")
    port_value = port if isinstance(port, int) and not isinstance(port, bool) else None
    return "allow" if any(
        rule.permits(address, protocol, port_value)
        for rule in policy.routed_rules
    ) else "deny"


def _network_capture_note(paths: RepoPaths, runtime: str, enabled: bool) -> str:
    if not enabled:
        return ""
    try:
        path = observation_artifact(paths, runtime, "network-activity.jsonl")
    except OSError:
        return "\n  Network activity log path is unavailable.\n"
    try:
        display = path.relative_to(paths.root)
    except ValueError:
        display = path
    return (
        f"\n  Network attempts are recorded in {display} (mode 0600).\n"
        "  policy-match is derived from the session-start policy; "
        "it is not an observed nftables verdict.\n"
    )


def _format_network_observer(session) -> str:
    observer = session.role(SessionRole.NETWORK_OBSERVER)
    if observer is None:
        return "    network observer   absent\n"
    line = _format_process("network observer", observer.inspect)
    return line.replace(
        "caps=eff=0000000000002000 bnd=0000000000002000",
        "caps=net_raw",
    )

def _prompt_capture_note(paths: RepoPaths, runtime: str, enabled: bool) -> str:
    if not enabled:
        return ""
    try:
        path = observation_artifact(paths, runtime, "llm-prompts.jsonl")
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
    ports = "any" if rule.ports == "any" else ",".join(str(port) for port in rule.ports)
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
    caps = "none" if effective == "0000000000000000" and bounding == "0000000000000000" else f"eff={effective} bnd={bounding}"
    return f"    {label:<18} running pid={inspection.pid} caps={caps} no-new-privs={nnp}\n"


def _read_proc_status(pid: int) -> dict[str, str]:
    path = Path("/proc") / str(pid) / "status"
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError, OSError) as exc:
        raise ObservationError(f"cannot read host process status for pid {pid}: {exc}") from exc
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
