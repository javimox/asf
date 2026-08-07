"""Execution contexts for typed ASF verification probes.

Executors translate known probe dataclasses into fixed command vectors or typed
Podman inspection calls. They never accept an arbitrary command string.
"""

from __future__ import annotations

import math
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol, TypeAlias
from urllib.parse import urlsplit

from ..errors import InfrastructureError
from ..podman import (
    HealthStatus,
    ObjectNotFoundError,
    PodmanClient,
    PodmanError,
)
from ..process import CommandError, CommandResult, probe as run_probe
from .checks import ProbeObservation, ProbeResult
from .probes import (
    ContainerCondition,
    ContainerInspectProbe,
    ContainerPolicyCondition,
    ContainerPolicyProbe,
    DnsProbe,
    NetworkFamily,
    PlainHttpProxyProbe,
    Probe,
    ProxyConnectProbe,
    RouteProbe,
    RuntimeSecurityCondition,
    RuntimeSecurityProbe,
    TcpProbe,
)

__all__ = [
    "EphemeralProbeExecutor",
    "HostProbeExecutor",
    "PodmanInspectExecutor",
    "ProbeExecutor",
    "RuntimeExecExecutor",
]

CommandRunner: TypeAlias = Callable[..., CommandResult]

_DNS_FAILURE_MARKERS = (
    "name or service not known",
    "temporary failure in name resolution",
    "nodename nor servname",
    "could not resolve",
    "bad address",
    "unknown host",
)
_ROUTE_DENIAL_MARKERS = (
    "network is unreachable",
    "no route to host",
    "unreachable",
    "prohibit",
    "blackhole",
)
# Proxy and default-route verdicts are computed where the response bytes
# live and carried in the exit code. Podman's attached output stream is not
# a reliable evidence channel for containers that exit within milliseconds
# (observed on podman-remote: a leading blank line in one release, a
# response missing its status line in the next), and a deny check must
# never pass or fail on mangled evidence. Exit codes survive every Podman
# transport intact — the Bash implementation relied on exactly this.
#
# The scripts are frozen constants that take only pre-validated positional
# arguments, the same rule `_security_invocation` already follows; no probe
# accepts arbitrary command text. Only the first response line is examined,
# in-container where it cannot be truncated: body text is never scanned for
# status-shaped strings. All codes stay below the 124/125+ range reserved
# for infrastructure failure.
_PROXY_EXIT_HTTP_403 = 40
_PROXY_EXIT_HTTP_407 = 41
_PROXY_EXIT_HTTP_2XX = 20
_PROXY_EXIT_HTTP_OTHER = 30  # 1xx, 3xx, and non-denial 4xx
_PROXY_EXIT_HTTP_5XX = 50
_PROXY_EXIT_NO_STATUS = 61

_PROXY_PROBE_SCRIPT = """\
resp="${TMPDIR:-/tmp}/asf-probe-response"
"$1" -q 1 -w 6 "$2" "$3" > "$resp"
status="$(head -n 1 "$resp" | tr -d "\\r")"
[ -n "$status" ] && printf '%s\\n' "$status"
case "$status" in
    "HTTP/"*" 403"|"HTTP/"*" 403 "*) exit 40 ;;
    "HTTP/"*" 407"|"HTTP/"*" 407 "*) exit 41 ;;
    "HTTP/"*) ;;
    *) exit 61 ;;
esac
code="${status#HTTP/* }"
code="${code%% *}"
case "$code" in
    2[0-9][0-9]) exit 20 ;;
    [134][0-9][0-9]) exit 30 ;;
    5[0-9][0-9]) exit 50 ;;
esac
exit 61
"""

_ROUTE_EXIT_PRESENT = 21
_ROUTE_EXIT_ABSENT = 22
_ROUTE_EXIT_QUERY_FAILED = 2

_DEFAULT_ROUTE_SCRIPT = """\
routes="$("$1" "$2" route show default)" || exit 2
printf '%s\\n' "$routes"
[ -n "$routes" ] && exit 21
exit 22
"""


class ProbeExecutor(Protocol):
    """Execution context understood by :class:`VerificationEngine`."""

    def supports(self, probe: Probe) -> bool:
        """Return whether this executor understands the probe type."""

    def execute(self, probe: Probe) -> ProbeResult:
        """Collect one observation without raising expected infrastructure errors."""


@dataclass(frozen=True, slots=True)
class HostProbeExecutor:
    """Execute TCP, proxy, and route probes directly on the host."""

    runner: CommandRunner = field(default=run_probe, repr=False, compare=False)
    netcat: str | os.PathLike[str] = "nc"
    ip: str | os.PathLike[str] = "ip"
    nslookup: str | os.PathLike[str] = "nslookup"

    def __post_init__(self) -> None:
        for name in ("netcat", "ip", "nslookup"):
            value = _validate_executable(getattr(self, name), name)
            object.__setattr__(self, name, value)

    def supports(self, probe: Probe) -> bool:
        return isinstance(
            probe,
            (DnsProbe, TcpProbe, ProxyConnectProbe, PlainHttpProxyProbe, RouteProbe),
        )

    def execute(self, probe: Probe) -> ProbeResult:
        if not self.supports(probe):
            return _unsupported(self, probe)
        argv, input_text = _probe_invocation(
            probe, self.netcat, self.ip, self.nslookup
        )
        return _run_command_probe(
            self.runner,
            argv,
            probe.timeout_seconds,
            probe,
            input_text=input_text,
        )


@dataclass(frozen=True, slots=True)
class RuntimeExecExecutor:
    """Execute fixed diagnostic probes inside one existing runtime container."""

    podman: PodmanClient
    container: str
    netcat: str = "nc"
    ip: str = "ip"
    nslookup: str = "nslookup"

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")
        object.__setattr__(self, "container", _validate_reference(self.container))
        for name in ("netcat", "ip", "nslookup"):
            object.__setattr__(
                self,
                name,
                _validate_executable(getattr(self, name), name),
            )

    def supports(self, probe: Probe) -> bool:
        if isinstance(probe, RuntimeSecurityProbe):
            return probe.reference == self.container
        return isinstance(
            probe,
            (DnsProbe, TcpProbe, ProxyConnectProbe, PlainHttpProxyProbe, RouteProbe),
        )

    def execute(self, probe: Probe) -> ProbeResult:
        if not self.supports(probe):
            return _unsupported(self, probe)
        if isinstance(probe, RuntimeSecurityProbe):
            command, input_text = _security_invocation(probe)
        else:
            command, input_text = _probe_invocation(
                probe, self.netcat, self.ip, self.nslookup
            )
        try:
            result = self.podman.exec_container(
                self.container,
                command,
                check=False,
                timeout=probe.timeout_seconds,
                input_text=input_text,
            )
        except ObjectNotFoundError:
            return _infrastructure("runtime container is missing")
        except PodmanError as exc:
            return _infrastructure(f"runtime probe could not execute: {exc}")
        if isinstance(probe, RuntimeSecurityProbe):
            return _classify_security_result(result, probe)
        return _classify_command_result(result, probe)


@dataclass(frozen=True, slots=True)
class EphemeralProbeExecutor:
    """Execute fixed probes in a hardened throwaway container."""

    podman: PodmanClient
    network: str
    image: str
    netcat: str = "nc"
    ip: str = "ip"
    nslookup: str = "nslookup"
    additional_networks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")
        object.__setattr__(self, "network", _validate_reference(self.network))
        object.__setattr__(self, "image", _validate_reference(self.image))
        object.__setattr__(
            self,
            "additional_networks",
            tuple(_validate_reference(item) for item in self.additional_networks),
        )
        for name in ("netcat", "ip", "nslookup"):
            object.__setattr__(
                self,
                name,
                _validate_executable(getattr(self, name), name),
            )

    def supports(self, probe: Probe) -> bool:
        return isinstance(
            probe,
            (DnsProbe, TcpProbe, ProxyConnectProbe, PlainHttpProxyProbe, RouteProbe),
        )

    def execute(self, probe: Probe) -> ProbeResult:
        if not self.supports(probe):
            return _unsupported(self, probe)
        command, input_text = _probe_invocation(
            probe, self.netcat, self.ip, self.nslookup
        )
        argv: tuple[str, ...] = (
            str(self.podman.engine),
            "run",
            "--rm",
            "--network",
            self.network,
            *(
                value
                for network in self.additional_networks
                for value in ("--network", network)
            ),
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=4m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=32",
            "--memory=64m",
            "--sysctl",
            "net.ipv4.ip_forward=0",
            "--sysctl",
            "net.ipv6.conf.all.forwarding=0",
            *(("-i",) if input_text is not None else ()),
            self.image,
            *command,
        )
        try:
            # Container creation and start share this budget with the probe
            # itself; grant startup headroom so a slow Podman machine cannot
            # turn a decisive probe into a timeout (the Bash implementation
            # used a 40-second envelope around an 8-second netcat window).
            result = self.podman.observe(
                argv,
                timeout=probe.timeout_seconds + 30.0,
                input_text=input_text,
            )
        except PodmanError as exc:
            return _infrastructure(f"ephemeral probe could not execute: {exc}")
        return _classify_command_result(result, probe)


@dataclass(frozen=True, slots=True)
class PodmanInspectExecutor:
    """Evaluate fixed predicates from a typed container inspection."""

    podman: PodmanClient

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")

    def supports(self, probe: Probe) -> bool:
        return isinstance(probe, (ContainerInspectProbe, ContainerPolicyProbe))

    def execute(self, probe: Probe) -> ProbeResult:
        if not isinstance(probe, (ContainerInspectProbe, ContainerPolicyProbe)):
            return _unsupported(self, probe)
        try:
            inspected = self.podman.inspect_container(
                probe.reference,
                timeout=probe.timeout_seconds,
            )
        except ObjectNotFoundError:
            return _infrastructure("container is missing")
        except PodmanError as exc:
            return _infrastructure(f"container inspection failed: {exc}")

        if isinstance(probe, ContainerPolicyProbe):
            return _evaluate_container_policy(inspected, probe)

        if probe.condition is ContainerCondition.EXISTS:
            return ProbeResult(
                ProbeObservation.REACHED,
                "container exists",
                metadata={"container": inspected.name},
            )
        if probe.condition is ContainerCondition.RUNNING:
            if inspected.running:
                return ProbeResult(
                    ProbeObservation.REACHED,
                    "container is running",
                    metadata={"container": inspected.name},
                )
            return ProbeResult(
                ProbeObservation.DENIED,
                "container exists but is not running",
                metadata={"container": inspected.name},
            )
        if inspected.health_status is HealthStatus.HEALTHY:
            return ProbeResult(
                ProbeObservation.REACHED,
                "container is healthy",
                metadata={"container": inspected.name},
            )
        return ProbeResult(
            ProbeObservation.DENIED,
            f"container health is {inspected.health_status.value}",
            metadata={"container": inspected.name},
        )


def _evaluate_container_policy(inspected, probe: ContainerPolicyProbe) -> ProbeResult:
    condition = probe.condition
    if condition is ContainerPolicyCondition.NETWORKS_EXACT:
        expected = tuple(sorted(probe.expected_items))
        actual = tuple(sorted(inspected.networks))
        if actual == expected:
            return ProbeResult(
                ProbeObservation.REACHED,
                "container networks match",
                metadata={"expected": " ".join(expected), "actual": " ".join(actual)},
            )
        return ProbeResult(
            ProbeObservation.DENIED,
            "container networks differ",
            metadata={"expected": " ".join(expected), "actual": " ".join(actual) or "none"},
        )
    if condition is ContainerPolicyCondition.NO_PUBLISHED_PORTS:
        if not inspected.published_ports:
            return ProbeResult(ProbeObservation.REACHED, "container publishes no ports")
        return ProbeResult(ProbeObservation.DENIED, "container publishes host ports")
    if condition is ContainerPolicyCondition.READ_ONLY_ROOT:
        if inspected.read_only_rootfs:
            return ProbeResult(ProbeObservation.REACHED, "container root is read-only")
        return ProbeResult(ProbeObservation.DENIED, "container root is writable")
    if inspected.user == probe.expected_text:
        return ProbeResult(
            ProbeObservation.REACHED,
            "container user matches",
            metadata={"expected": probe.expected_text, "actual": inspected.user},
        )
    return ProbeResult(
        ProbeObservation.DENIED,
        "container user differs",
        metadata={"expected": probe.expected_text, "actual": inspected.user or "none"},
    )


def _security_invocation(
    probe: RuntimeSecurityProbe,
) -> tuple[tuple[str, ...], str | None]:
    c = probe.condition
    if c is RuntimeSecurityCondition.CAPABILITIES_EQUAL:
        return (
            "sh", "-c",
            "eff=$(awk '/^CapEff:/ {print $2; exit}' /proc/self/status); "
            "bnd=$(awk '/^CapBnd:/ {print $2; exit}' /proc/self/status); "
            '[ -n "$eff" ] && [ -n "$bnd" ] && [ "$eff" = "$1" ] && [ "$bnd" = "$1" ]',
            "sh", probe.expected_text,
        ), None
    fixed: dict[RuntimeSecurityCondition, tuple[str, ...]] = {
        RuntimeSecurityCondition.UID_GID_1000: (
            "sh", "-c", 'test "$(id -u)" = 1000 && test "$(id -g)" = 1000'
        ),
        RuntimeSecurityCondition.NO_NEW_PRIVILEGES: (
            "sh", "-c", "grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status"
        ),
        RuntimeSecurityCondition.SUDO_ABSENT: (
            "sh", "-c", "if command -v sudo >/dev/null 2>&1; then exit 1; else exit 0; fi"
        ),
        RuntimeSecurityCondition.PODMAN_SOCKET_ABSENT: (
            "sh", "-c", "test ! -S /run/podman/podman.sock && test ! -S /var/run/docker.sock"
        ),
        RuntimeSecurityCondition.SECRETS_MASKED_EMPTY: (
            "sh",
            "-c",
            'test "$(stat -f -c %T /workspace/sandbox/secrets)" = tmpfs '
            "&& ! find /workspace/sandbox/secrets -mindepth 1 "
            "-print -quit | grep -q .",
        ),
        RuntimeSecurityCondition.CHECKOUT_READ_ONLY: (
            "sh", "-c", "touch /workspace/sandbox/.asf-write-test-$$"
        ),
        RuntimeSecurityCondition.SYSTEM_DIRS_READ_ONLY: (
            "sh", "-c", "touch /etc/.asf-write-test-$$"
        ),
        RuntimeSecurityCondition.SSH_PRIVATE_KEYS_ABSENT: (
            "sh",
            "-c",
            "test ! -d /home/node/.ssh || ! find /home/node/.ssh "
            '-maxdepth 1 -type f -name "id_*" ! -name "*.pub" '
            "-print -quit | grep -q .",
        ),
        RuntimeSecurityCondition.IPV4_FORWARDING_DISABLED: (
            "sh", "-c", 'test "$(cat /proc/sys/net/ipv4/ip_forward)" = 0'
        ),
        RuntimeSecurityCondition.IPV4_FORWARDING_ENABLED: (
            "sh", "-c", 'test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1'
        ),
        RuntimeSecurityCondition.IPV6_FORWARDING_DISABLED: (
            "sh", "-c", 'test "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" = 0'
        ),
        RuntimeSecurityCondition.EXTERNAL_DNS_UNAVAILABLE: (
            "sh", "-c",
            'command -v getent >/dev/null 2>&1 || exit 125; '
            'test -s /etc/resolv.conf || exit 125; '
            'getent ahostsv4 example.com >/dev/null 2>&1; rc=$?; '
            '[ "$rc" -eq 0 ] && exit 0; [ "$rc" -eq 2 ] && exit 1; exit 125'
        ),
    }
    if c in fixed:
        return fixed[c], None
    if c is RuntimeSecurityCondition.ROUTED_CIDR_PRESENT:
        return (
            "sh", "-c",
            'route=$(ip -4 route show "$1") || exit 125; '
            'printf "%s\n" "$route"; '
            'printf "%s\n" "$route" | grep -Eq "(^|[[:space:]])via[[:space:]]+"',
            "sh", probe.expected_text,
        ), None
    if c is RuntimeSecurityCondition.CADDY_POLICY_MATCHES:
        return ("cat", "/etc/caddy/Caddyfile"), None
    if c is RuntimeSecurityCondition.PROVIDER_CREDENTIAL_ABSENT:
        return ("printenv", probe.expected_text), None
    raise TypeError(f"unsupported runtime security condition: {c.value}")


def _classify_security_result(
    result: CommandResult,
    probe: RuntimeSecurityProbe,
) -> ProbeResult:
    if result.returncode == 124 or result.returncode >= 125 or result.returncode < 0:
        return _infrastructure(
            f"probe command failed with infrastructure status {result.returncode}",
            result,
        )
    if probe.condition is RuntimeSecurityCondition.CADDY_POLICY_MATCHES:
        return _classify_caddy_policy(result, probe)
    if probe.condition is RuntimeSecurityCondition.PROVIDER_CREDENTIAL_ABSENT:
        if result.returncode not in (0, 1):
            return _infrastructure("provider credential query failed", result)
        actual = result.stdout.rstrip("\n") if result.returncode == 0 else ""
        assert probe.secret is not None
        expected = probe.secret.reveal()
        if expected and actual != expected:
            return _reached("provider credential is absent from runtime", result)
        return _denied("provider credential is exposed or unavailable", result)
    if result.returncode == 0:
        return _reached("runtime security condition is satisfied", result)
    return _denied("runtime security condition is explicitly false", result)


def _classify_caddy_policy(
    result: CommandResult,
    probe: RuntimeSecurityProbe,
) -> ProbeResult:
    if result.returncode != 0:
        return _infrastructure("could not read the running Caddyfile", result)
    policy = result.stdout
    actual = tuple(sorted({
        fields[1]
        for line in policy.splitlines()
        if len((fields := line.split())) >= 2 and fields[0] == "allow"
    }))
    expected = tuple(sorted(probe.expected_items))
    required = (
        "ports 443" in policy,
        "deny 10.0.0.0/8" in policy,
        "deny 169.254.0.0/16" in policy,
        "deny all" in policy,
    )
    if actual == expected and all(required):
        return _reached("Caddy policy matches", result)
    return ProbeResult(
        ProbeObservation.DENIED,
        "Caddy policy differs",
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        metadata={"expected": " ".join(expected), "actual": " ".join(actual)},
    )


def _run_command_probe(
    runner: CommandRunner,
    argv: Sequence[str | os.PathLike[str]],
    timeout: float,
    probe: Probe,
    *,
    input_text: str | None = None,
) -> ProbeResult:
    try:
        if input_text is None:
            result = runner(argv, timeout=timeout)
        else:
            result = runner(
                argv,
                timeout=timeout,
                input_text=input_text,
            )
    except CommandError as exc:
        return _infrastructure(f"probe command could not execute: {exc}")
    except InfrastructureError as exc:
        return _infrastructure(f"probe infrastructure failed: {exc}")
    return _classify_command_result(result, probe)


def _probe_invocation(
    probe: Probe,
    netcat: str | os.PathLike[str],
    ip: str | os.PathLike[str],
    nslookup: str | os.PathLike[str] = "nslookup",
) -> tuple[tuple[str, ...], str | None]:
    if isinstance(probe, DnsProbe):
        return (str(nslookup), probe.hostname), None
    if isinstance(probe, TcpProbe):
        # Keep the connection attempt bounded inside the probe process.  The
        # outer timeout is an infrastructure guard; relying on it alone can
        # kill ``podman run`` before ``--rm`` completes and leave a fixed-IP
        # probe container behind, poisoning every subsequent routed check.
        netcat_timeout = max(1, math.floor(probe.timeout_seconds))
        return (
            str(netcat),
            "-z",
            "-w",
            str(netcat_timeout),
            probe.address,
            str(probe.port),
        ), None
    if isinstance(probe, RouteProbe):
        family_flag = "-4" if probe.family is NetworkFamily.IPV4 else "-6"
        if probe.queries_default_route:
            return (
                "sh",
                "-c",
                _DEFAULT_ROUTE_SCRIPT,
                "asf-route-probe",
                str(ip),
                family_flag,
            ), None
        assert probe.destination is not None
        return (
            str(ip),
            family_flag,
            "route",
            "get",
            probe.destination,
        ), None
    if isinstance(probe, ProxyConnectProbe):
        authority = _authority(
            probe.destination_host,
            probe.destination_port,
        )
        request = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "X-ASF-Probe: verification\r\n"
            "Connection: close\r\n\r\n"
        )
        return _proxy_script_argv(netcat, probe.proxy_host, probe.proxy_port), request
    if isinstance(probe, PlainHttpProxyProbe):
        request = (
            f"GET {probe.url} HTTP/1.1\r\n"
            f"Host: {_http_host_header(probe.url)}\r\n"
            "X-ASF-Probe: verification\r\n"
            "Connection: close\r\n\r\n"
        )
        return _proxy_script_argv(netcat, probe.proxy_host, probe.proxy_port), request
    raise TypeError(f"unsupported probe type: {type(probe).__name__}")


def _proxy_script_argv(
    netcat: str | os.PathLike[str],
    proxy_host: str,
    proxy_port: int,
) -> tuple[str, ...]:
    return (
        "sh",
        "-c",
        _PROXY_PROBE_SCRIPT,
        "asf-proxy-probe",
        str(netcat),
        proxy_host,
        str(proxy_port),
    )


def _classify_command_result(result: CommandResult, probe: Probe) -> ProbeResult:
    if result.returncode == 124 or result.returncode >= 125 or result.returncode < 0:
        return _infrastructure(
            f"probe command failed with infrastructure status {result.returncode}",
            result,
        )
    if isinstance(probe, DnsProbe):
        if result.returncode == 0:
            return _reached("hostname resolved", result)
        if result.returncode in {1, 2}:
            return _denied("hostname did not resolve", result)
        return _infrastructure("DNS probe failed", result)
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if any(marker in combined for marker in _DNS_FAILURE_MARKERS):
        if isinstance(probe, TcpProbe):
            return _infrastructure(
                f"could not resolve {probe.address}; reachability untested",
                result,
            )
        return _infrastructure("probe name resolution failed", result)

    if isinstance(probe, (ProxyConnectProbe, PlainHttpProxyProbe)):
        return _classify_proxy_result(result, probe)
    if isinstance(probe, RouteProbe):
        if probe.queries_default_route:
            if result.returncode == _ROUTE_EXIT_PRESENT:
                return _reached("default route exists", result)
            if result.returncode == _ROUTE_EXIT_ABSENT:
                return _denied("no default route is present", result)
            return _infrastructure("default-route query failed", result)
        if result.returncode == 0:
            return _reached("route exists", result)
        if any(marker in combined for marker in _ROUTE_DENIAL_MARKERS):
            return _denied("route lookup explicitly reported no route", result)
        return _infrastructure("route probe failed without explicit denial", result)
    if isinstance(probe, TcpProbe):
        if result.returncode == 0:
            return _reached("TCP connection succeeded", result)
        return _denied("TCP connection was explicitly unsuccessful", result)
    return _infrastructure("executor returned an unsupported result", result)


def _classify_proxy_result(
    result: CommandResult,
    probe: ProxyConnectProbe | PlainHttpProxyProbe,
) -> ProbeResult:
    """Map the probe script's exit code to an observation.

    The status line is read in-container from the first response line only;
    stdout carries that line back for diagnostics but is never evidence.
    """

    code = result.returncode
    if code == _PROXY_EXIT_HTTP_403:
        return _denied("proxy explicitly returned HTTP 403", result)
    if code == _PROXY_EXIT_HTTP_407:
        return _denied("proxy explicitly returned HTTP 407", result)
    if code == _PROXY_EXIT_HTTP_2XX:
        if isinstance(probe, ProxyConnectProbe):
            return _reached("proxy CONNECT returned HTTP 2xx", result)
        return _reached("proxy request returned HTTP 2xx", result)
    if code == _PROXY_EXIT_HTTP_OTHER:
        if isinstance(probe, PlainHttpProxyProbe):
            return _reached("proxy request returned a non-denial status", result)
        return _infrastructure("proxy CONNECT returned a non-tunnel status", result)
    if code == _PROXY_EXIT_HTTP_5XX:
        return _infrastructure("proxy returned an upstream failure (5xx)", result)
    return _infrastructure(
        f"no HTTP response from {probe.proxy_host}:{probe.proxy_port}",
        result,
    )


def _reached(summary: str, result: CommandResult) -> ProbeResult:
    return ProbeResult(
        ProbeObservation.REACHED,
        summary,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _denied(summary: str, result: CommandResult) -> ProbeResult:
    return ProbeResult(
        ProbeObservation.DENIED,
        summary,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _infrastructure(
    summary: str,
    result: CommandResult | None = None,
) -> ProbeResult:
    return ProbeResult(
        ProbeObservation.INFRASTRUCTURE_FAILURE,
        summary,
        returncode=None if result is None else result.returncode,
        stdout="" if result is None else result.stdout,
        stderr="" if result is None else result.stderr,
    )


def _unsupported(executor: object, probe: Probe) -> ProbeResult:
    return _infrastructure(
        f"{type(executor).__name__} does not support {type(probe).__name__}"
    )


def _validate_executable(value: object, description: str) -> str:
    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise TypeError(f"{description} executable must be path-like text") from exc
    if not isinstance(text, str):
        raise TypeError(f"{description} executable must resolve to text")
    if not text or any(character in text for character in ("\x00", "\n", "\r")):
        raise ValueError(f"invalid {description} executable")
    return text


def _validate_reference(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("reference must be text")
    if not value or value != value.strip() or any(
        character.isspace() or character in "\x00\n\r" for character in value
    ):
        raise ValueError("invalid Podman reference")
    return value


def _timeout_text(value: float) -> str:
    if not math.isfinite(value) or value <= 0:
        raise ValueError("timeout must be finite and positive")
    return f"{value:g}"


def _authority(host: str, port: int) -> str:
    bracketed = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{bracketed}:{port}"


def _http_host_header(url: str) -> str:
    parsed = urlsplit(url)
    assert parsed.hostname is not None
    port = parsed.port
    if port is None or port == 80:
        return f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return _authority(parsed.hostname, port)
