"""Live ASF security verification command built on the shared engine."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Sequence, TextIO

from .errors import ConfigurationError, InfrastructureError, UsageError
from .manifest import load_model
from .models import RuntimeManifest
from .paths import RepoPaths
from .podman import PodmanClient, PodmanError
from .secrets import SecretValue
from .session import (
    AmbiguousSessionError,
    MultipleRunningSessionsError,
    NoRunningSessionError,
    SessionDiscovery,
    SessionRole,
    UnknownRuntimeError,
)
from .verification import (
    ContainerPolicyCondition,
    ContainerPolicyProbe,
    EphemeralProbeExecutor,
    HostProbeExecutor,
    NetworkFamily,
    PlainHttpProxyProbe,
    PodmanInspectExecutor,
    PolicyExpectation,
    ProbeObservation,
    ProxyConnectProbe,
    RouteProbe,
    RuntimeExecExecutor,
    RuntimeSecurityCondition,
    RuntimeSecurityProbe,
    TcpProbe,
    VerificationCheck,
    VerificationEngine,
)

__all__ = [
    "OutputEvent",
    "OutputStream",
    "SecurityTestError",
    "SecurityTestResult",
    "run_security_test_command",
]

_G = "\033[0;32m"
_Y = "\033[1;33m"
_R = "\033[0;31m"
_B = "\033[0;34m"
_D = "\033[2m"
_N = "\033[0m"
_PROXY_PORT = 3128
_BROKER_PORT = 4000
_PROBE_REVISION = "v2"
_DENY_CANDIDATES = (
    "example.com",
    "example.org",
    "example.net",
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
)
_PROVIDER_DOMAINS = {
    "openai": "api.openai.com",
    "anthropic": "api.anthropic.com",
    "openrouter": "openrouter.ai",
    "mistral": "api.mistral.ai",
    "groq": "api.groq.com",
    "deepseek": "api.deepseek.com",
}
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SecurityTestError(InfrastructureError):
    """The live security report could not be assembled safely."""


class SecurityTestUsageError(UsageError):
    """The security-test command has invalid arguments."""


class OutputStream(str, Enum):
    STDOUT = "stdout"
    STDERR = "stderr"


@dataclass(frozen=True, slots=True)
class OutputEvent:
    stream: OutputStream
    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.stream, OutputStream):
            raise TypeError("output stream must be an OutputStream")
        if not isinstance(self.text, str):
            raise TypeError("output event text must be text")


@dataclass(frozen=True, slots=True)
class SecurityTestResult:
    returncode: int
    events: tuple[OutputEvent, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.returncode, int) or isinstance(
            self.returncode, bool
        ):
            raise TypeError("security-test return code must be an integer")
        if self.returncode < 0:
            raise ValueError("security-test return code must not be negative")
        if isinstance(self.events, (str, bytes)):
            raise TypeError("security-test events must be a sequence")
        events = tuple(self.events)
        if any(not isinstance(event, OutputEvent) for event in events):
            raise TypeError("security-test events must contain OutputEvent values")
        object.__setattr__(self, "events", events)

    def write_to(self, stdout: TextIO, stderr: TextIO) -> None:
        for event in self.events:
            target = stdout if event.stream is OutputStream.STDOUT else stderr
            target.write(event.text)
            target.flush()


class _Report:
    def __init__(
        self,
        event_sink: Callable[[OutputEvent], None] | None = None,
    ) -> None:
        self.events: list[OutputEvent] = []
        self.passed = 0
        self.failed = 0
        self.partial = False
        self._event_sink = event_sink

    def _append(self, event: OutputEvent) -> None:
        self.events.append(event)
        if self._event_sink is not None:
            self._event_sink(event)

    def out(self, text: str) -> None:
        self._append(OutputEvent(OutputStream.STDOUT, text))

    def err(self, text: str) -> None:
        self._append(OutputEvent(OutputStream.STDERR, text))

    def ok(self, description: str) -> None:
        self.passed += 1
        self.out(f"  {_G}✓{_N} {description}\n")

    def bad(self, description: str) -> None:
        self.failed += 1
        self.err(f"  {_R}✗{_N} {description}\n")

    def warning(self, text: str) -> None:
        self.err(f"  {_Y}⚠ {text}{_N}\n")

    def skip(self, text: str) -> None:
        self.out(f"  {_D}– {text}{_N}\n")

    def mark_partial(self, text: str) -> None:
        self.partial = True
        self.warning(text)

    def finish(self) -> SecurityTestResult:
        self.out("\n")
        if self.failed:
            self.err(
                f"{_R}Security test failed: {self.failed} failed, "
                f"{self.passed} passed.{_N}\n"
            )
            return SecurityTestResult(1, tuple(self.events))
        if self.partial:
            self.out(
                f"{_Y}Security test partial: {self.passed} host-side/support "
                f"checks passed; in-guest checks were unavailable.{_N}\n"
            )
            # Partial security coverage must not be indistinguishable from a
            # complete pass to scripts consuming the command status.
            return SecurityTestResult(2, tuple(self.events))
        self.out(f"{_G}Security test passed: {self.passed} checks.{_N}\n")
        return SecurityTestResult(0, tuple(self.events))


def run_security_test_command(
    arguments: Sequence[str],
    paths: RepoPaths,
    *,
    podman: PodmanClient | None = None,
    require_available: bool = True,
    event_sink: Callable[[OutputEvent], None] | None = None,
) -> SecurityTestResult:
    """Run ``sandbox.sh test`` without changing any lifecycle resource."""

    if isinstance(arguments, (str, bytes)):
        raise TypeError("security-test arguments must be a sequence")
    argv = tuple(arguments)
    if not argv or argv[0] != "test":
        raise SecurityTestUsageError("unsupported security-test command")

    client = PodmanClient() if podman is None else podman
    if require_available:
        client.require_available()
    discovery = SessionDiscovery.from_paths(paths, podman=client)
    requested = argv[1] if len(argv) > 1 else ""
    runtime = _resolve_runtime(discovery, requested)
    match = discovery.unique_match(runtime)
    if match is None:
        result = SecurityTestResult(
            1,
            (
                OutputEvent(
                    OutputStream.STDERR,
                    f"{_R}No running {runtime} container.{_N}\n",
                ),
            ),
        )
        if event_sink is not None:
            for event in result.events:
                event_sink(event)
        return result

    manifest = load_model(paths.identity.runtime_manifest(runtime))
    names = paths.identity.network_names(runtime)
    mode = manifest.network.mode
    runtime_id = match.container_id

    role_ids = {
        role: _unique_role(discovery, runtime, role)
        for role in (
            SessionRole.PROXY,
            SessionRole.BROKER,
            SessionRole.ROUTED_GATEWAY,
            SessionRole.ROUTED_INIT,
        )
    }
    support_executors: list[RuntimeExecExecutor] = []
    for role in (
        SessionRole.BROKER,
        SessionRole.PROXY,
        SessionRole.ROUTED_GATEWAY,
    ):
        reference = role_ids[role]
        if reference:
            support_executors.append(RuntimeExecExecutor(client, reference))
    network_probe = EphemeralProbeExecutor(
        client,
        names.internal,
        paths.identity.probe_image(_PROBE_REVISION),
    )
    if manifest.runtime.isolation == "microvm":
        # The krun backend cannot exec a diagnostic process in the running
        # microVM. Generic network probes therefore use a short-lived container
        # on the same ASF internal network. This proves the surrounding Podman
        # policy, not the guest itself, so the final verdict is explicitly partial.
        executors = (
            network_probe,
            *support_executors,
            PodmanInspectExecutor(client),
            HostProbeExecutor(),
        )
    else:
        executors = (
            RuntimeExecExecutor(client, runtime_id),
            *support_executors,
            network_probe,
            PodmanInspectExecutor(client),
            HostProbeExecutor(),
        )
    engine = VerificationEngine(executors)

    report = _Report(event_sink)
    report.out(
        f"{_B}Testing {runtime} security boundaries "
        f"{_D}({mode}){_N}\n"
    )
    _run_common_checks(
        report,
        engine,
        manifest,
        runtime_id,
        names.internal,
        names.scan,
    )

    broker = role_ids[SessionRole.BROKER]
    broker_expected = bool(
        manifest.llm
        and manifest.llm.broker
        and _config_boolean(paths.config_file, "BROKER_ENABLED", False)
    )
    broker_settings = _broker_settings(manifest) if broker else None
    if broker_expected and not broker:
        report.bad("LiteLLM broker is running")
    elif broker:
        assert broker_settings is not None
        report.ok("LiteLLM broker is running")
        _check(
            report,
            engine,
            "LiteLLM is reachable on the internal network",
            PolicyExpectation.ALLOW,
            TcpProbe(broker, _BROKER_PORT),
        )
        broker_networks = [names.internal, names.provider]
        broker_network_description = (
            "LiteLLM is attached only to internal and provider networks"
        )
        if mode == "routed" and manifest.runtime.isolation == "microvm":
            broker_networks.append(names.scan)
            broker_network_description = (
                "LiteLLM is attached only to internal, provider, and scan networks"
            )
        _container_check(
            report,
            engine,
            broker_network_description,
            broker,
            ContainerPolicyCondition.NETWORKS_EXACT,
            expected_items=tuple(broker_networks),
        )
        _runtime_check(
            report,
            engine,
            "LiteLLM has no capabilities",
            broker,
            RuntimeSecurityCondition.CAPABILITIES_EQUAL,
            expected_text="0000000000000000",
        )
        _runtime_check(
            report,
            engine,
            "LiteLLM has no-new-privileges",
            broker,
            RuntimeSecurityCondition.NO_NEW_PRIVILEGES,
        )
        _container_check(
            report,
            engine,
            "LiteLLM root filesystem is read-only",
            broker,
            ContainerPolicyCondition.READ_ONLY_ROOT,
        )
        _container_check(
            report,
            engine,
            "LiteLLM publishes no host ports",
            broker,
            ContainerPolicyCondition.NO_PUBLISHED_PORTS,
        )
        key_name, _direct_domain = broker_settings
        if not key_name:
            report.bad("provider credential name is available")
        else:
            provider_value = _read_secret(paths, manifest, key_name)
            if manifest.runtime.isolation == "microvm":
                report.skip(
                    "provider credential absence inside the microVM guest "
                    "requires in-guest execution"
                )
            else:
                _runtime_check(
                    report,
                    engine,
                    "provider credential is not present in the agent",
                    runtime_id,
                    RuntimeSecurityCondition.PROVIDER_CREDENTIAL_ABSENT,
                    expected_text=key_name,
                    secret=provider_value,
                )

    if mode == "proxy":
        _run_proxy_checks(
            report,
            engine,
            paths,
            manifest,
            runtime_id,
            role_ids[SessionRole.PROXY],
            broker,
            broker_settings,
            names.internal,
            names.egress,
        )
    elif mode == "isolated":
        _run_isolated_checks(report, engine, manifest, runtime_id)
    elif mode == "routed":
        _run_routed_checks(
            report,
            engine,
            manifest,
            runtime_id,
            role_ids[SessionRole.ROUTED_GATEWAY],
            role_ids[SessionRole.ROUTED_INIT],
            names.scan,
            names.routed_egress,
            client,
        )
    return report.finish()


def _resolve_runtime(discovery: SessionDiscovery, requested: str) -> str:
    try:
        return discovery.resolve_runtime(requested or None)
    except UnknownRuntimeError as exc:
        listing = "".join(f"    {name}\n" for name in exc.available)
        raise SecurityTestUsageError(
            f"{_R}Unknown agent: {requested}{_N}\n"
            f"  Available agents:\n{listing.rstrip()}"
        ) from exc
    except NoRunningSessionError as exc:
        raise SecurityTestError(
            f"{_R}No running session in this checkout.{_N}\n"
            "  Start one: ./sandbox.sh open <agent>"
        ) from exc
    except MultipleRunningSessionsError as exc:
        listing = "\n".join(f"    {name}" for name in exc.runtimes)
        raise SecurityTestError(
            f"{_R}Several sessions are running — name the agent.{_N}\n{listing}"
        ) from exc


def _unique_role(
    discovery: SessionDiscovery,
    runtime: str,
    role: SessionRole,
) -> str | None:
    identifiers = discovery.role_container_ids(
        runtime,
        role,
        include_stopped=False,
    )
    if not identifiers:
        return None
    if len(identifiers) > 1:
        raise AmbiguousSessionError(runtime, identifiers, role=role.value)
    return identifiers[0]


def _run_common_checks(
    report: _Report,
    engine: VerificationEngine,
    manifest: RuntimeManifest,
    runtime_id: str,
    internal_network: str,
    scan_network: str,
) -> None:
    if manifest.runtime.isolation == "microvm":
        # The Podman object is the VMM process, not the guest network stack.
        # krun also provides no exec transport into a running guest, so the
        # in-guest assertions cannot be collected on demand. Host-side,
        # inspect-based, and ephemeral-probe checks below still run; the
        # per-session egress verdicts live in verification-report.json.
        report.mark_partial(
            "microVM has no exec transport; in-guest runtime checks are "
            "skipped (see docs/KRUN.md)"
        )
    else:
        expected_caps = 1 << 13 if "net_raw" in manifest.capabilities else 0
        networks = (
            (internal_network, scan_network)
            if manifest.network.mode == "routed"
            else (internal_network,)
        )
        description = (
            "agent is attached only to internal and scan networks"
            if manifest.network.mode == "routed"
            else "agent is attached only to the internal network"
        )
        _container_check(
            report,
            engine,
            description,
            runtime_id,
            ContainerPolicyCondition.NETWORKS_EXACT,
            expected_items=networks,
        )
        _runtime_check(
            report,
            engine,
            "effective capabilities match the manifest",
            runtime_id,
            RuntimeSecurityCondition.CAPABILITIES_EQUAL,
            expected_text=f"{expected_caps:016x}",
        )
        for description, condition, expectation in (
            (
                "runtime user is UID/GID 1000",
                RuntimeSecurityCondition.UID_GID_1000,
                PolicyExpectation.ALLOW,
            ),
            (
                "no-new-privileges is enabled",
                RuntimeSecurityCondition.NO_NEW_PRIVILEGES,
                PolicyExpectation.ALLOW,
            ),
            (
                "sudo is absent",
                RuntimeSecurityCondition.SUDO_ABSENT,
                PolicyExpectation.ALLOW,
            ),
            (
                "Podman socket is absent",
                RuntimeSecurityCondition.PODMAN_SOCKET_ABSENT,
                PolicyExpectation.ALLOW,
            ),
            (
                "host secrets are masked by tmpfs",
                RuntimeSecurityCondition.SECRETS_MASKED_EMPTY,
                PolicyExpectation.ALLOW,
            ),
            (
                "framework checkout is read-only",
                RuntimeSecurityCondition.CHECKOUT_READ_ONLY,
                PolicyExpectation.DENY,
            ),
            (
                "system directories are not writable",
                RuntimeSecurityCondition.SYSTEM_DIRS_READ_ONLY,
                PolicyExpectation.DENY,
            ),
            (
                "SSH private-key files are absent",
                RuntimeSecurityCondition.SSH_PRIVATE_KEYS_ABSENT,
                PolicyExpectation.ALLOW,
            ),
            (
                "IPv4 forwarding is disabled",
                RuntimeSecurityCondition.IPV4_FORWARDING_DISABLED,
                PolicyExpectation.ALLOW,
            ),
            (
                "IPv6 forwarding is disabled",
                RuntimeSecurityCondition.IPV6_FORWARDING_DISABLED,
                PolicyExpectation.ALLOW,
            ),
        ):
            _runtime_check(
                report,
                engine,
                description,
                runtime_id,
                condition,
                expectation=expectation,
            )
    _container_check(
        report,
        engine,
        "agent publishes no host ports",
        runtime_id,
        ContainerPolicyCondition.NO_PUBLISHED_PORTS,
    )


def _run_proxy_checks(
    report: _Report,
    engine: VerificationEngine,
    paths: RepoPaths,
    manifest: RuntimeManifest,
    runtime_id: str,
    proxy: str | None,
    broker: str | None,
    broker_settings: tuple[str, str] | None,
    internal_network: str,
    egress_network: str,
) -> None:
    if not proxy:
        report.bad("Caddy proxy is running")
    else:
        report.ok("Caddy proxy is running")
        _container_check(
            report,
            engine,
            "Caddy is attached only to internal and egress networks",
            proxy,
            ContainerPolicyCondition.NETWORKS_EXACT,
            expected_items=(egress_network, internal_network),
        )
        _container_check(
            report,
            engine,
            "Caddy runs as an unprivileged user",
            proxy,
            ContainerPolicyCondition.USER_EQUALS,
            expected_text="10001:10001",
        )
        _runtime_check(
            report,
            engine,
            "Caddy has no capabilities",
            proxy,
            RuntimeSecurityCondition.CAPABILITIES_EQUAL,
            expected_text="0000000000000000",
        )
        _runtime_check(
            report,
            engine,
            "Caddy has no-new-privileges",
            proxy,
            RuntimeSecurityCondition.NO_NEW_PRIVILEGES,
        )
        _container_check(
            report,
            engine,
            "Caddy root filesystem is read-only",
            proxy,
            ContainerPolicyCondition.READ_ONLY_ROOT,
        )
        _container_check(
            report,
            engine,
            "Caddy publishes no host ports",
            proxy,
            ContainerPolicyCondition.NO_PUBLISHED_PORTS,
        )

        blocked_domain = broker_settings[1] if broker and broker_settings else ""
        allowed = tuple(
            sorted(
                domain
                for domain in manifest.network.allow_domains
                if domain != blocked_domain
            )
        )
        _runtime_check(
            report,
            engine,
            "Caddy policy matches the effective manifest",
            proxy,
            RuntimeSecurityCondition.CADDY_POLICY_MATCHES,
            expected_items=allowed,
        )
        verify_domain = manifest.network.verify_domain
        if verify_domain:
            _check(
                report,
                engine,
                f"allowlisted {verify_domain}:443 is reachable through Caddy",
                PolicyExpectation.ALLOW,
                ProxyConnectProbe(proxy, _PROXY_PORT, verify_domain, 443, 10),
            )
            _check(
                report,
                engine,
                "Caddy rejects CONNECT to an undeclared port",
                PolicyExpectation.DENY,
                ProxyConnectProbe(proxy, _PROXY_PORT, verify_domain, 22),
            )
            _check(
                report,
                engine,
                "Caddy rejects plain HTTP to an undeclared port",
                PolicyExpectation.DENY,
                PlainHttpProxyProbe(
                    proxy,
                    _PROXY_PORT,
                    f"http://{verify_domain}:9000/",
                ),
            )
        else:
            report.skip(
                "no external allow path declared; positive and port controls skipped"
            )

        deny_target = _deny_target(allowed)
        for description, host in (
            ("Caddy rejects an undeclared destination", deny_target),
            ("Caddy rejects IPv4 loopback destinations", "127.0.0.1"),
            ("Caddy rejects IPv6 loopback destinations", "::1"),
            ("Caddy rejects private IPv4 destinations", "10.0.0.1"),
            ("Caddy rejects private IPv6 destinations", "fc00::1"),
            ("Caddy rejects the link-local metadata address", "169.254.169.254"),
        ):
            _check(
                report,
                engine,
                description,
                PolicyExpectation.DENY,
                ProxyConnectProbe(proxy, _PROXY_PORT, host, 443),
            )
        if broker and blocked_domain:
            _check(
                report,
                engine,
                "Caddy rejects the direct provider API while brokered",
                PolicyExpectation.DENY,
                ProxyConnectProbe(proxy, _PROXY_PORT, blocked_domain, 443),
            )

    _route_boundary_checks(
        report,
        engine,
        runtime_id,
        dns=False,
        microvm=manifest.runtime.isolation == "microvm",
    )


def _run_isolated_checks(
    report: _Report,
    engine: VerificationEngine,
    manifest: RuntimeManifest,
    runtime_id: str,
) -> None:
    _route_boundary_checks(
        report,
        engine,
        runtime_id,
        dns=True,
        microvm=manifest.runtime.isolation == "microvm",
    )


def _route_boundary_checks(
    report: _Report,
    engine: VerificationEngine,
    runtime_id: str,
    *,
    dns: bool,
    microvm: bool = False,
) -> None:
    subject = "runtime network probe" if microvm else "agent"
    _check(
        report,
        engine,
        f"{subject} has no IPv4 default route",
        PolicyExpectation.DENY,
        RouteProbe(family=NetworkFamily.IPV4),
    )
    _check(
        report,
        engine,
        f"{subject} has no IPv6 default route",
        PolicyExpectation.DENY,
        RouteProbe(family=NetworkFamily.IPV6),
    )
    _check(
        report,
        engine,
        f"{subject} has no direct public route",
        PolicyExpectation.DENY,
        RouteProbe("1.1.1.1"),
    )
    _check(
        report,
        engine,
        f"{subject} has no direct private-network route",
        PolicyExpectation.DENY,
        RouteProbe("192.168.1.1"),
    )
    if dns:
        if microvm:
            report.skip(
                "external DNS state inside the microVM guest requires in-guest execution"
            )
        else:
            _runtime_check(
                report,
                engine,
                "external DNS is unavailable",
                runtime_id,
                RuntimeSecurityCondition.EXTERNAL_DNS_UNAVAILABLE,
                expectation=PolicyExpectation.DENY,
            )


def _run_routed_checks(
    report: _Report,
    engine: VerificationEngine,
    manifest: RuntimeManifest,
    runtime_id: str,
    gateway: str | None,
    initializer: str | None,
    scan_network: str,
    routed_egress_network: str,
    podman: PodmanClient,
) -> None:
    if gateway:
        report.ok("routed gateway is running")
        _container_check(
            report,
            engine,
            "gateway is attached only to scan and routed-egress networks",
            gateway,
            ContainerPolicyCondition.NETWORKS_EXACT,
            expected_items=(routed_egress_network, scan_network),
        )
        try:
            inspection = podman.inspect_container(gateway)
        except PodmanError as exc:
            report.bad(
                "routed gateway capability mode is inspectable "
                f"(test infrastructure failed: {exc})"
            )
        else:
            if inspection.label("asf.persistent-net-admin") == "true":
                report.warning("routed gateway uses persistent NET_ADMIN")
            else:
                _runtime_check(
                    report,
                    engine,
                    "routed gateway has no capabilities",
                    gateway,
                    RuntimeSecurityCondition.CAPABILITIES_EQUAL,
                    expected_text="0000000000000000",
                )
        _runtime_check(
            report,
            engine,
            "routed gateway has no-new-privileges",
            gateway,
            RuntimeSecurityCondition.NO_NEW_PRIVILEGES,
        )
        _container_check(
            report,
            engine,
            "routed gateway root filesystem is read-only",
            gateway,
            ContainerPolicyCondition.READ_ONLY_ROOT,
        )
        _container_check(
            report,
            engine,
            "routed gateway publishes no host ports",
            gateway,
            ContainerPolicyCondition.NO_PUBLISHED_PORTS,
        )
        _runtime_check(
            report,
            engine,
            "routed gateway has IPv4 forwarding enabled",
            gateway,
            RuntimeSecurityCondition.IPV4_FORWARDING_ENABLED,
        )
        _runtime_check(
            report,
            engine,
            "routed gateway keeps IPv6 forwarding disabled",
            gateway,
            RuntimeSecurityCondition.IPV6_FORWARDING_DISABLED,
        )
        if initializer:
            report.bad("NET_ADMIN initializer has exited")
        else:
            report.ok("NET_ADMIN initializer has exited")
    else:
        report.bad("routed gateway is running")

    if manifest.runtime.isolation == "microvm":
        report.skip(
            "routed microVM guest connectivity, routes, and DNS require "
            "in-guest execution; use the session startup verification evidence"
        )
        return

    verification = manifest.network.routed_verification
    if verification is not None:
        address = str(verification.address)
        _check(
            report,
            engine,
            "allowed routed TCP control is reachable",
            PolicyExpectation.ALLOW,
            TcpProbe(address, verification.allowed_port),
        )
        _check(
            report,
            engine,
            "known-open blocked routed port is denied",
            PolicyExpectation.DENY,
            TcpProbe(str(verification.denied_address), verification.blocked_port),
        )
    seen: set[str] = set()
    policy_destinations = tuple(rule.destination for rule in manifest.network.routed_rules)
    for rule in manifest.network.routed_rules:
        cidr = str(rule.destination)
        if cidr in seen:
            continue
        seen.add(cidr)
        _runtime_check(
            report,
            engine,
            f"route {cidr} is present without a default path",
            runtime_id,
            RuntimeSecurityCondition.ROUTED_CIDR_PRESENT,
            expected_text=cidr,
        )
    if verification is not None:
        denied = verification.denied_address
        if not any(denied in destination for destination in policy_destinations):
            cidr = f"{denied}/32"
            _runtime_check(
                report,
                engine,
                f"verification route {cidr} is present",
                runtime_id,
                RuntimeSecurityCondition.ROUTED_CIDR_PRESENT,
                expected_text=cidr,
            )
    _check(
        report,
        engine,
        "agent has no IPv4 default route",
        PolicyExpectation.DENY,
        RouteProbe(family=NetworkFamily.IPV4),
    )
    _check(
        report,
        engine,
        "agent has no IPv6 default route",
        PolicyExpectation.DENY,
        RouteProbe(family=NetworkFamily.IPV6),
    )
    _runtime_check(
        report,
        engine,
        "external DNS is unavailable",
        runtime_id,
        RuntimeSecurityCondition.EXTERNAL_DNS_UNAVAILABLE,
        expectation=PolicyExpectation.DENY,
    )


def _container_check(
    report: _Report,
    engine: VerificationEngine,
    description: str,
    reference: str,
    condition: ContainerPolicyCondition,
    *,
    expected_text: str = "",
    expected_items: tuple[str, ...] = (),
) -> None:
    _check(
        report,
        engine,
        description,
        PolicyExpectation.ALLOW,
        ContainerPolicyProbe(
            reference,
            condition,
            expected_text=expected_text,
            expected_items=expected_items,
        ),
    )


def _runtime_check(
    report: _Report,
    engine: VerificationEngine,
    description: str,
    reference: str,
    condition: RuntimeSecurityCondition,
    *,
    expectation: PolicyExpectation = PolicyExpectation.ALLOW,
    expected_text: str = "",
    expected_items: tuple[str, ...] = (),
    secret: SecretValue | None = None,
) -> None:
    _check(
        report,
        engine,
        description,
        expectation,
        RuntimeSecurityProbe(
            reference,
            condition,
            expected_text=expected_text,
            expected_items=expected_items,
            secret=secret,
        ),
    )


def _check(
    report: _Report,
    engine: VerificationEngine,
    description: str,
    expectation: PolicyExpectation,
    probe,
) -> None:
    result = engine.run_check(VerificationCheck(description, expectation, probe))
    if result.passed:
        report.ok(description)
        return
    observed = result.probe_result
    if observed.observation is ProbeObservation.INFRASTRUCTURE_FAILURE:
        # Preserve the accepted numeric diagnostics for command/Podman
        # infrastructure statuses, but use the classifier's explanation for
        # ordinary status 1 failures such as DNS resolution, an unreachable
        # proxy, or an unreadable policy file.
        detail = (
            str(observed.returncode)
            if observed.returncode in {124, 125, 126, 127}
            else observed.summary
        )
        report.bad(f"{description} (test infrastructure failed: {detail})")
    else:
        # The accepted human report printed one cross for a policy mismatch.
        # Structured expected/actual metadata remains available to callers, but
        # it is intentionally not added to the public text contract yet.
        report.bad(description)
    evidence = observed.stdout or observed.stderr
    if evidence and observed.observation is ProbeObservation.INFRASTRUCTURE_FAILURE:
        report.err(f"    {evidence.rstrip()}\n")


def _broker_settings(manifest: RuntimeManifest) -> tuple[str, str]:
    if manifest.llm is None:
        return "", ""
    provider = manifest.llm.provider or ""
    key = manifest.llm.api_key_env
    if not key and provider:
        key = provider.upper().replace("-", "_") + "_API_KEY"
    domain = manifest.llm.direct_domain or _PROVIDER_DOMAINS.get(provider, "")
    return key, domain


def _read_secret(
    paths: RepoPaths,
    manifest: RuntimeManifest,
    wanted: str,
) -> SecretValue:
    if not _ENV_NAME.fullmatch(wanted):
        raise ConfigurationError(f"invalid provider credential name: {wanted}")
    result = ""
    for filename in manifest.secret_files:
        secret_file = paths.secrets_dir / filename
        try:
            lines = secret_file.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError) as exc:
            raise ConfigurationError(f"cannot read secret file: {secret_file}") from exc
        for line in lines:
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.rstrip()
            if not _ENV_NAME.fullmatch(key):
                raise ConfigurationError(
                    f"invalid environment variable name in {secret_file}: {key}"
                )
            if key == wanted:
                result = value
    return SecretValue(result)


def _config_boolean(path: Path, name: str, default: bool) -> bool:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ConfigurationError(f"cannot read ASF configuration: {path}") from exc
    value: str | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, candidate = stripped.split("=", 1)
        if key.strip() == name:
            value = candidate.split("#", 1)[0].strip().strip('"\'')
    if value is None:
        return default
    if value == "true":
        return True
    if value == "false":
        return False
    raise ConfigurationError(f"{name} must be true or false")


def _deny_target(allowed: Iterable[str]) -> str:
    values = set(allowed)
    for candidate in _DENY_CANDIDATES:
        if candidate not in values:
            return candidate
    raise ConfigurationError(
        "could not select a deny-probe destination outside the allowlist"
    )
