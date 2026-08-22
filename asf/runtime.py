"""Runtime opening and shell attachment for every supported network mode.

This module only sequences existing focused components: planning, allocation,
network creation, broker, proxy, routed gateway, Dev Container rendering,
verification, supervision, and cleanup.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import signal
import socket
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from pathlib import Path
from typing import Callable, NoReturn, Sequence, TextIO

from .atomic import write_text_atomic
from .broker import (
    BrokerRequest,
    BrokerService,
    BrokerSettings,
    generate_session_token,
    provider_api_key_name,
)
from .config import AsfConfig
from .devcontainer import DevcontainerRequest, build_devcontainer_config, write_atomic
from .egress_evidence import (
    EgressEvidenceError,
    finalize_egress_session,
    mark_egress_session_active,
)
from .errors import AsfError, ConfigurationError, InfrastructureError, ValidationError
from .manifest import load_model
from .krun import (
    KrunRequest,
    build_krun_build_argv,
    build_krun_environment,
    build_krun_run_argv,
    krun_image_name,
    require_krun_host,
    validate_krun_beta,
)
from .models import RuntimeManifest
from .networks import NetworkService
from .network_observer import NetworkObserverService
from .observation_sessions import begin_observation_session, write_observation_policy
from .open_lifecycle import (
    OpenCleanupService,
    OpenSignal,
    SessionProcessSupervisor,
    restore_terminal,
    run_open_session,
)
from .ownership import ResourceKind
from .paths import RepoPaths
from .podman import ObjectKind, ObjectNotFoundError, PodmanClient
from .process import CommandError
from .process import replace as replace_process_command
from .process import run_streaming
from .proxy import PROXY_PORT, ProxyRequest, ProxyService
from .repositories import RepositoryEntry, RepositoryStore
from .routed import RoutedRequest, RoutedService
from .routed_allocation import RoutedAllocator
from .runtime_plan import (
    BROKER_INTERNAL_ALIAS,
    NetworkRole,
    PROXY_INTERNAL_ALIAS,
    RuntimePlan,
    build_runtime_plan,
    load_runtime_plan,
    runtime_plan_path,
    validate_runtime_plan_context,
    write_runtime_plan,
)
from .session import SessionDiscovery, SessionRole, SessionStatus
from .session_lock import SessionAlreadyRunningError
from .session_events import record_session_event
from .stop import (
    StopEmitter,
    StopEvent,
    StopService,
    StopStream,
    stop_service_from_environment,
)
from .verification.checks import PolicyExpectation, VerificationCheck
from .verification.engine import VerificationEngine, VerificationReport
from .verification.executors import RuntimeExecExecutor
from .verification.probes import (
    DnsProbe,
    NetworkFamily,
    PlainHttpProxyProbe,
    ProxyConnectProbe,
    RouteProbe,
    TcpProbe,
)

__all__ = [
    "NetworkService",
    "RuntimeOpenError",
    "RuntimeService",
    "StartupVerificationError",
    "StartupVerifier",
    "load_runtime_environment",
    "run_runtime_command",
]

_BLUE = "\033[0;34m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[1;33m"
_RED = "\033[0;31m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_PROBE_REVISION = "v2"
_PROBE_BASE_IMAGE = (
    "docker.io/library/alpine@sha256:"
    "d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
)
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ReplaceProcess = Callable[[Sequence[str]], NoReturn]


class RuntimeOpenError(InfrastructureError):
    """A proxy/isolated runtime could not be opened safely."""


class StartupVerificationError(InfrastructureError):
    """The pre-runtime network policy was not proven."""


@dataclass(frozen=True, slots=True)
class StartupVerifier:
    podman: PodmanClient

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")

    def verify(
        self,
        plan: RuntimePlan,
        manifest: RuntimeManifest,
        *,
        proxy: ProxyRequest | None,
        broker: BrokerRequest | None,
        routed: RoutedRequest | None = None,
        output: TextIO = sys.stdout,
        report_path: Path | None = None,
    ) -> None:
        internal = plan.network(NetworkRole.INTERNAL)
        if internal is None:
            raise StartupVerificationError("runtime plan has no internal network")
        image = self._ensure_probe_image(plan, output=output)
        if plan.network_mode == "routed":
            if routed is None:
                raise StartupVerificationError("routed mode has no gateway request")
            self._verify_routed(
                plan,
                manifest,
                routed,
                image=image,
                output=output,
                report_path=report_path,
            )
            return

        checks: list[VerificationCheck] = []

        if plan.network_mode == "isolated":
            output.write(f"  {_BLUE}→{_RESET} Verifying isolation\n")
            checks.extend(self._no_bypass_checks())
            if broker is not None:
                checks.append(
                    VerificationCheck(
                        "broker is reachable on the internal network",
                        PolicyExpectation.ALLOW,
                        TcpProbe(BROKER_INTERNAL_ALIAS, 4000),
                    )
                )
        elif plan.network_mode == "proxy":
            if proxy is None:
                raise StartupVerificationError("proxy mode has no proxy request")
            output.write(f"  {_BLUE}→{_RESET} Verifying egress policy\n")
            domains = proxy.domains
            target = manifest.network.verify_domain or (domains[0] if domains else "")
            if target:
                if target not in domains:
                    raise StartupVerificationError(
                        f"network.verify_domain {target!r} is not in the "
                        "effective allowlist"
                    )
                checks.extend(
                    (
                        # Advisory: reachability of the positive control is an
                        # availability property. If it fails *inconclusively*
                        # (upstream down / 5xx) startup continues with a
                        # warning; an explicit proxy DENIAL of an allowlisted
                        # host remains a blocking policy failure, and every
                        # deny check below is always fatal.
                        VerificationCheck(
                            f"allowlisted host {target} is reachable through CONNECT",
                            PolicyExpectation.ALLOW,
                            ProxyConnectProbe(
                                PROXY_INTERNAL_ALIAS, proxy.port, target, 443
                            ),
                            advisory=True,
                        ),
                        VerificationCheck(
                            f"plain HTTP to a forbidden port on {target} is denied",
                            PolicyExpectation.DENY,
                            PlainHttpProxyProbe(
                                PROXY_INTERNAL_ALIAS,
                                proxy.port,
                                f"http://{target}:9000/",
                            ),
                        ),
                    )
                )
            else:
                output.write(
                    f"  {_YELLOW}⚠{_RESET} {plan.runtime} has an empty effective "
                    f"allowlist {_DIM}(deny/no-bypass verification only){_RESET}\n"
                )

            # Startup verifies only the critical deny path. The exhaustive
            # loopback/private/metadata matrix belongs to `sandbox.sh test` so
            # interactive opens stay fail-closed without repeating the full
            # security suite on every session.
            if broker is not None:
                checks.append(
                    VerificationCheck(
                        f"Caddy denies direct provider API {broker.direct_domain}",
                        PolicyExpectation.DENY,
                        ProxyConnectProbe(
                            PROXY_INTERNAL_ALIAS,
                            proxy.port,
                            broker.direct_domain,
                            443,
                        ),
                    )
                )
            else:
                checks.append(
                    VerificationCheck(
                        "Caddy denies a non-allowlisted destination",
                        PolicyExpectation.DENY,
                        ProxyConnectProbe(
                            PROXY_INTERNAL_ALIAS,
                            proxy.port,
                            _deny_target(domains),
                            443,
                        ),
                    )
                )
            checks.extend(self._no_bypass_checks())
        else:
            raise StartupVerificationError(
                f"startup verifier does not support {plan.network_mode!r}"
            )

        verification_started = time.monotonic()
        with self._probe_executor(
            plan,
            image,
            network=internal.name,
        ) as executor:
            report = self._run_timed_checks(
                executor, tuple(checks), output=output
            )
        verification_elapsed = time.monotonic() - verification_started
        _persist_verification_report(report, report_path, output)
        for warning in report.advisory_failures:
            output.write(
                f"  {_YELLOW}⚠{_RESET} {warning.check.description}: "
                f"{warning.probe_result.summary} "
                f"{_DIM}(availability control unavailable — continuing; "
                f"deny checks remain enforced){_RESET}\n"
            )
        if report.blocking_failures:
            for failure in report.blocking_failures:
                summary = failure.probe_result.summary
                if (
                    failure.probe_result.infrastructure_failed
                    and failure.probe_result.returncode is not None
                ):
                    summary = (
                        "probe infrastructure failed "
                        f"({failure.probe_result.returncode})"
                    )
                    detail = _probe_failure_detail(failure.probe_result)
                    if detail:
                        summary = f"{summary}: {detail}"
                elif (
                    isinstance(failure.check.probe, PlainHttpProxyProbe)
                    and failure.check.expectation is PolicyExpectation.DENY
                ):
                    summary = (
                        "proxy did not reject plain HTTP to a forbidden port"
                    )
                output.write(
                    f"    {_RED}✗{_RESET} {failure.check.description}: "
                    f"{summary}\n"
                )
            raise StartupVerificationError(
                f"{plan.network_mode.capitalize()} verification failed — "
                "not starting the agent"
            )
        if plan.network_mode == "isolated":
            suffix = (
                "no external path; internal service reachable"
                if broker is not None
                else "no external path; no internal positive control available"
            )
            output.write(
                f"  {_GREEN}✓{_RESET} Isolation verified "
                f"{_DIM}({suffix}; {verification_elapsed:.1f}s){_RESET}\n"
            )
        elif proxy is not None and proxy.domains:
            deny_scope = (
                "direct-provider denial"
                if broker is not None
                else "non-allowlisted denial"
            )
            proven = (
                f"{deny_scope}, port restriction, and no-bypass; "
                "positive control unavailable"
                if report.advisory_failures
                else f"allow, {deny_scope}, port restriction, and no-bypass"
            )
            output.write(
                f"  {_GREEN}✓{_RESET} Egress policy verified "
                f"{_DIM}({proven}; {verification_elapsed:.1f}s){_RESET}\n"
            )
        else:
            output.write(
                f"  {_GREEN}✓{_RESET} Egress policy verified "
                f"{_DIM}(deny and no-bypass only; "
                f"{verification_elapsed:.1f}s){_RESET}\n"
            )

    @staticmethod
    def _run_timed_checks(
        executor: RuntimeExecExecutor,
        checks: tuple[VerificationCheck, ...],
        *,
        output: TextIO,
    ) -> VerificationReport:
        engine = VerificationEngine((executor,))
        results = []
        for check in checks:
            output.write(f"    {_DIM}→{_RESET} {check.description} ...")
            output.flush()
            started = time.monotonic()
            result = engine.run_check(check)
            elapsed = time.monotonic() - started
            output.write(f" {_DIM}{elapsed:.1f}s{_RESET}\n")
            results.append(result)
        return VerificationReport(tuple(results))

    def _verify_routed(
        self,
        plan: RuntimePlan,
        manifest: RuntimeManifest,
        routed: RoutedRequest,
        *,
        image: str,
        output: TextIO,
        report_path: Path | None = None,
    ) -> None:
        verification = manifest.network.routed_verification
        if verification is not None:
            output.write(f"  {_BLUE}→{_RESET} Checking routed target baseline\n")
            address = str(verification.address)
            if not _host_tcp_open(address, verification.allowed_port):
                raise StartupVerificationError(
                    f"Host cannot reach routed positive control "
                    f"{address}:{verification.allowed_port}"
                )
            denied_address = str(verification.denied_address)
            if not _host_tcp_open(denied_address, verification.blocked_port):
                raise StartupVerificationError(
                    f"Host cannot reach known-open blocked endpoint "
                    f"{denied_address}:{verification.blocked_port}; a closed service "
                    "cannot prove gateway enforcement"
                )

        internal = plan.network(NetworkRole.INTERNAL)
        scan = plan.network(NetworkRole.SCAN)
        if internal is None or scan is None:
            raise StartupVerificationError("routed plan is missing probe networks")

        checks: list[VerificationCheck] = []
        if verification is not None:
            checks.extend(
                (
                    VerificationCheck(
                        "allowed routed TCP control is reachable",
                        PolicyExpectation.ALLOW,
                        TcpProbe(str(verification.address), verification.allowed_port),
                    ),
                    VerificationCheck(
                        "known-open blocked routed port is denied",
                        PolicyExpectation.DENY,
                        TcpProbe(
                            str(verification.denied_address), verification.blocked_port
                        ),
                    ),
                )
            )

        checks.extend(
            (
                VerificationCheck(
                    "runtime has no IPv4 default route",
                    PolicyExpectation.DENY,
                    RouteProbe(family=NetworkFamily.IPV4),
                ),
                VerificationCheck(
                    "runtime has no IPv6 default route",
                    PolicyExpectation.DENY,
                    RouteProbe(family=NetworkFamily.IPV6),
                ),
            )
        )

        seen: set[IPv4Network] = set()
        for rule in manifest.network.routed_rules:
            if rule.destination in seen:
                continue
            seen.add(rule.destination)
            checks.append(
                VerificationCheck(
                    f"route {rule.destination} is present",
                    PolicyExpectation.ALLOW,
                    RouteProbe(str(rule.destination.network_address)),
                )
            )

        if verification is not None:
            denied_route = IPv4Network(f"{verification.denied_address}/32")
            if not any(verification.denied_address in network for network in seen):
                checks.append(
                    VerificationCheck(
                        f"verification route {denied_route} is present",
                        PolicyExpectation.ALLOW,
                        RouteProbe(str(verification.denied_address)),
                    )
                )
                seen.add(denied_route)

        checks.extend(
            (
                VerificationCheck(
                    "undeclared destination has no route",
                    PolicyExpectation.DENY,
                    RouteProbe(_routed_deny_address(seen)),
                ),
                VerificationCheck(
                    "runtime cannot resolve external DNS",
                    PolicyExpectation.DENY,
                    DnsProbe("example.com"),
                ),
            )
        )
        output.write(f"  {_BLUE}→{_RESET} Verifying routed policy\n")
        verification_started = time.monotonic()
        with self._probe_executor(
            plan,
            image,
            network=internal.name,
            additional_networks=(
                f"{scan.name}:ip={routed.runtime_scan_ip}",
            ),
        ) as executor:
            report = self._run_timed_checks(executor, tuple(checks), output=output)
        verification_elapsed = time.monotonic() - verification_started
        _persist_verification_report(report, report_path, output)
        if report.failed:
            for failure in report.failures:
                output.write(
                    f"    {_RED}✗{_RESET} {failure.check.description}: "
                    f"{failure.probe_result.summary}\n"
                )
            raise StartupVerificationError(
                "Routed verification failed — not starting the agent"
            )

        scope = (
            "live allow/deny controls, routes, and no default path"
            if verification is not None
            else "routes and no default path"
        )
        output.write(
            f"  {_GREEN}✓{_RESET} Routed policy verified "
            f"{_DIM}({scope}; {verification_elapsed:.1f}s){_RESET}\n"
        )

    @staticmethod
    def _no_bypass_checks() -> tuple[VerificationCheck, ...]:
        return (
            VerificationCheck(
                "no undeclared IPv4 default route",
                PolicyExpectation.DENY,
                RouteProbe(family=NetworkFamily.IPV4),
            ),
            VerificationCheck(
                "no undeclared IPv6 default route",
                PolicyExpectation.DENY,
                RouteProbe(family=NetworkFamily.IPV6),
            ),
            VerificationCheck(
                "no undeclared route to the public internet",
                PolicyExpectation.DENY,
                RouteProbe("1.1.1.1", NetworkFamily.IPV4),
            ),
            VerificationCheck(
                "external DNS is unavailable",
                PolicyExpectation.DENY,
                DnsProbe("example.com"),
            ),
        )

    @contextlib.contextmanager
    def _probe_executor(
        self,
        plan: RuntimePlan,
        image: str,
        *,
        network: str,
        additional_networks: tuple[str, ...] = (),
    ):
        """Run all startup probes from one short-lived hardened container."""

        # Deliberately unlabeled: session discovery matches containers by the
        # session label alone, so labeling the verifier would make `shell`,
        # `stop`, and residue scans ambiguous during the verification window.
        # If ASF dies uncleanly, `sleep 300` + `--rm` + `--stop-timeout=0`
        # self-expire the container within five minutes instead.
        name = f"{plan.resource_prefix}-verify-{os.getpid()}"
        argv: tuple[str, ...] = (
            str(self.podman.engine),
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "--stop-timeout=0",
            "--network",
            network,
            *(
                value
                for item in additional_networks
                for value in ("--network", item)
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
            image,
            "sleep",
            "300",
        )
        started = self.podman.observe(argv, timeout=40)
        if started.returncode != 0:
            raise StartupVerificationError(
                "Could not start the egress verification container"
            )
        try:
            yield RuntimeExecExecutor(self.podman, name)
        finally:
            try:
                removed = self.podman.observe(
                    (self.podman.engine, "rm", "-f", name),
                    timeout=20,
                    missing_kind=ObjectKind.CONTAINER,
                )
            except ObjectNotFoundError:
                pass
            else:
                if removed.returncode != 0 and sys.exc_info()[0] is None:
                    raise StartupVerificationError(
                        "Could not remove the egress verification container"
                    )

    def _ensure_probe_image(
        self, plan: RuntimePlan, *, output: TextIO
    ) -> str:
        # Probe revision belongs to the verifier, not ResourceIdentity.
        image = f"{plan.resource_prefix}-probe:{_PROBE_REVISION}"
        exists = self.podman.observe(
            (self.podman.engine, "image", "exists", image), timeout=20
        )
        if exists.returncode == 0:
            return image
        if exists.returncode != 1:
            raise StartupVerificationError(
                "Could not inspect egress probe image "
                f"(Podman status {exists.returncode})"
            )
        output.write(f"  {_BLUE}→{_RESET} Building egress probe image\n")
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="asf-probe-") as directory:
            containerfile = Path(directory) / "Containerfile"
            containerfile.write_text(
                f"FROM {_PROBE_BASE_IMAGE}\n"
                "RUN apk add --no-cache netcat-openbsd iproute2 bind-tools\n",
                encoding="utf-8",
            )
            result = self.podman.observe(
                (
                    self.podman.engine,
                    "build",
                    "-q",
                    "-t",
                    image,
                    directory,
                ),
                timeout=900,
            )
        if result.returncode != 0:
            raise StartupVerificationError("Could not build the egress probe image")
        output.write(
            f"  {_GREEN}✓{_RESET} Egress probe image ready "
            f"{_DIM}({time.monotonic() - started:.1f}s){_RESET}\n"
        )
        return image


@dataclass(slots=True)
class RuntimeService:
    paths: RepoPaths
    podman: PodmanClient = field(default_factory=PodmanClient)
    output: TextIO = sys.stdout
    error: TextIO = sys.stderr
    proxy_service: ProxyService | None = None
    broker_service: BrokerService | None = None
    network_service: NetworkService | None = None
    routed_service: RoutedService | None = None
    network_observer_service: NetworkObserverService | None = None
    routed_allocator: RoutedAllocator | None = None
    verifier: StartupVerifier | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.paths, RepoPaths):
            raise TypeError("paths must be RepoPaths")
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")
        self.proxy_service = self.proxy_service or ProxyService(self.podman)
        self.broker_service = self.broker_service or BrokerService(self.podman)
        self.network_service = self.network_service or NetworkService(self.podman)
        self.routed_service = self.routed_service or RoutedService(self.podman)
        self.network_observer_service = (
            self.network_observer_service or NetworkObserverService(self.podman)
        )
        self.routed_allocator = self.routed_allocator or RoutedAllocator(self.podman)
        self.verifier = self.verifier or StartupVerifier(self.podman)

    def open(self, runtime: str) -> int:
        manifest = load_model(self.paths.identity.runtime_manifest(runtime))
        if manifest.network.mode not in {"proxy", "isolated", "routed"}:
            raise ConfigurationError(
                f"unsupported network.mode: {manifest.network.mode}"
            )
        config = AsfConfig.load(self.paths.config_file)
        self._require_tools(manifest, config)
        if manifest.network.mode == "proxy":
            config.require_caddy()
        if manifest.network.mode == "routed":
            assert self.routed_service is not None
            self.routed_service.require_host()
        owner_pid = os.getpid()
        stop_service = stop_service_from_environment(self.paths, podman=self.podman)
        discovery = stop_service.discovery
        if manifest.runtime.isolation == "microvm":
            existing = discovery.inspect(runtime)
            if existing is not None and existing.container.is_running:
                raise RuntimeOpenError(
                    f"A {runtime} session is already running.\n"
                    f"  Attach to it: ./sandbox.sh shell {runtime}"
                )
        lock_manager = discovery.lock_manager()
        previous = lock_manager.inspect(runtime)
        try:
            lock_manager.acquire(runtime, owner_pid=owner_pid)
        except SessionAlreadyRunningError as exc:
            owner = "unknown" if exc.pid is None else str(exc.pid)
            hint = f"  Attach to it: ./sandbox.sh shell {runtime}"
            raise RuntimeOpenError(
                f"A {runtime} session (PID {owner}) is already running.\n{hint}"
            ) from exc
        cleanup = OpenCleanupService(stop_service)
        cleanup_completed = False
        received_signal: OpenSignal | None = None
        token = None
        broker_request: BrokerRequest | None = None
        proxy_request: ProxyRequest | None = None
        routed_request: RoutedRequest | None = None
        try:
            with _startup_signals() as signal_state:
                if previous is not None and previous.is_stale:
                    self.output.write(
                        f"  {_YELLOW}Removing stale session lock "
                        f"(PID {previous.pid or 'unknown'} is gone){_RESET}\n"
                    )
                self._clear_previous_resources(runtime, stop_service)
                begin_observation_session(self.paths, runtime)
                record_session_event(
                    self.paths,
                    runtime,
                    "session_start",
                    isolation=manifest.runtime.isolation,
                    network=manifest.network.mode,
                )
                broker_enabled = bool(
                    config.broker_enabled
                    and manifest.llm is not None
                    and manifest.llm.broker
                )
                plan = self._build_and_create_plan(
                    manifest, config, owner_pid, broker_enabled
                )
                write_observation_policy(self.paths, plan, manifest)

                if broker_enabled:
                    broker_request = BrokerRequest(
                        self.paths,
                        manifest,
                        plan,
                        BrokerSettings(
                            config.broker_image,
                            config.broker_startup_timeout,
                            config.broker_detailed_debug,
                        ),
                    )
                    token = generate_session_token()
                    assert self.broker_service is not None
                    self.broker_service.start(
                        broker_request,
                        token,
                        output=self.output,
                        error=self.error,
                    )
                    record_session_event(self.paths, runtime, "broker_started")

                if manifest.network.mode == "proxy":
                    proxy_request = ProxyRequest(
                        self.paths,
                        manifest,
                        plan,
                        access_logs=config.caddy_access_logs,
                    )
                    assert self.proxy_service is not None
                    self.proxy_service.start(proxy_request, output=self.output)

                if manifest.network.mode == "routed":
                    routed_request = RoutedRequest(
                        manifest,
                        plan,
                        allow_persistent_net_admin=(
                            config.routed_allow_persistent_net_admin
                        ),
                    )
                    assert self.routed_service is not None
                    self.routed_service.start(routed_request, output=self.output)
                    record_session_event(self.paths, runtime, "gateway_ready")
                    if manifest.observability.network_activity:
                        assert self.network_observer_service is not None
                        self.network_observer_service.start(
                            self.paths, plan, output=self.output
                        )
                        record_session_event(
                            self.paths, runtime, "network_observer_ready"
                        )

                if manifest.network.mode == "isolated" and broker_request is not None:
                    assert self.broker_service is not None
                    self.broker_service.wait_ready(
                        broker_request,
                        output=self.output,
                        error=self.error,
                    )
                    record_session_event(self.paths, runtime, "broker_ready")

                assert self.verifier is not None
                self.verifier.verify(
                    plan,
                    manifest,
                    proxy=proxy_request,
                    broker=broker_request,
                    routed=routed_request,
                    output=self.output,
                    report_path=self.paths.session_artifact(
                        manifest.name, "verification-report.json"
                    ),
                )
                session_environment: dict[str, str] | None = None
                if manifest.runtime.isolation == "microvm":
                    repositories = self._load_repositories(manifest)
                    krun_request = KrunRequest(
                        self.paths,
                        plan,
                        manifest,
                        repositories=repositories,
                        run_arguments=config.hardening_arguments(manifest),
                        build_arguments=config.build_arguments(),
                        proxy_port=PROXY_PORT,
                        broker_default_model=(
                            broker_request.models.default_model
                            if broker_request is not None
                            else ""
                        ),
                    )
                    self._ensure_krun_image(krun_request)
                    if (
                        broker_request is not None
                        and manifest.network.mode != "isolated"
                    ):
                        assert self.broker_service is not None
                        self.broker_service.wait_ready(
                            broker_request,
                            output=self.output,
                            error=self.error,
                        )
                        record_session_event(self.paths, runtime, "broker_ready")
                    excluded = (
                        provider_api_key_name(manifest)
                        if broker_request is not None
                        else ""
                    )
                    remote_environment = load_runtime_environment(
                        plan,
                        excluded_key=excluded,
                        output=self.output,
                        error=self.error,
                    )
                    session_environment = build_krun_environment(
                        krun_request,
                        broker_token=(token.reveal() if token is not None else ""),
                        runtime_environment=remote_environment,
                    )
                    child = build_krun_run_argv(
                        krun_request,
                        session_environment,
                        engine=os.fspath(self.podman.engine),
                    )
                    self.output.write(
                        f"{_BLUE}Starting krun microVM...{_RESET}\n"
                    )
                    if plan.runtime_mode == "interactive":
                        self.output.write(
                            f"  {_DIM}Detach without stopping: "
                            f"Ctrl-P, Ctrl-Q{_RESET}\n"
                        )
                    self.output.write("\n")
                else:
                    self._generate_devcontainer(
                        plan,
                        manifest,
                        config,
                        broker_request,
                    )
                    environment = {}
                    if token is not None:
                        environment["ASF_BROKER_TOKEN"] = token.reveal()
                    self.output.write(f"{_BLUE}Starting container...{_RESET}\n")
                    self.output.write(
                        f"  {_DIM}(first run builds the image — takes ~1 min; "
                        f"subsequent runs are fast){_RESET}\n\n"
                    )
                    self._start_devcontainer(plan, environment)
                    if (
                        broker_request is not None
                        and manifest.network.mode != "isolated"
                    ):
                        assert self.broker_service is not None
                        self.broker_service.wait_ready(
                            broker_request,
                            output=self.output,
                            error=self.error,
                        )
                        record_session_event(self.paths, runtime, "broker_ready")

                    excluded = (
                        provider_api_key_name(manifest)
                        if broker_request is not None
                        else ""
                    )
                    remote_environment = load_runtime_environment(
                        plan,
                        excluded_key=excluded,
                        output=self.output,
                        error=self.error,
                    )
                    child = self._devcontainer_exec_argv(
                        plan,
                        remote_environment,
                    )
                if plan.runtime_mode == "service":
                    self.output.write(
                        f"  {_DIM}running: {' '.join(plan.command)}{_RESET}\n"
                    )
                if proxy_request is not None and proxy_request.access_logs:
                    mark_egress_session_active(self.paths, manifest.name)
                # Container sessions already hold broker credentials after
                # `devcontainer up`. krun sessions instead pass their complete
                # environment to the initial foreground Podman process.
                signal_state.disable()
                record_session_event(self.paths, runtime, "runtime_starting")
                result = run_open_session(
                    child,
                    cleanup=cleanup,
                    runtime=runtime,
                    owner_pid=owner_pid,
                    supervisor=SessionProcessSupervisor(
                        signal_grace_seconds=stop_service.cleanup.stop_timeout
                    ),
                    event_sink=self._emit_stop_event,
                    stdout=self.output,
                    stderr=self.error,
                    environment=session_environment,
                    # Known race, accepted: a guest that exits normally is
                    # being auto-removed (--rm) while this runs, and a very
                    # narrow window can still report it as running. The result
                    # is a skipped cleanup, which explicit `stop` or the next
                    # `open`'s residue pass reclaims — the documented behavior
                    # for detached sessions. Not worth a supervisor.
                    preserve_if_running=(
                        lambda: self._runtime_container_running(
                            plan.runtime_container.name
                        )
                    )
                    if manifest.runtime.isolation == "microvm"
                    else None,
                )
                cleanup_completed = True
                return result
        except _StartupInterrupted as exc:
            received_signal = exc.signal
        finally:
            if not cleanup_completed:
                try:
                    cleanup.cleanup(
                        runtime,
                        owner_pid,
                        event_sink=self._emit_stop_event,
                    )
                except AsfError as cleanup_error:
                    self.error.write(
                        f"{_RED}ASF session cleanup failed for {runtime}.{_RESET}\n"
                        f"  {cleanup_error}\n"
                    )
        assert received_signal is not None
        return received_signal.exit_code

    def _build_and_create_plan(
        self,
        manifest: RuntimeManifest,
        config: AsfConfig,
        owner_pid: int,
        broker_enabled: bool,
    ) -> RuntimePlan:
        assert self.network_service is not None
        if manifest.network.mode != "routed":
            plan = build_runtime_plan(
                manifest,
                paths=self.paths,
                owner_pid=owner_pid,
                broker_globally_enabled=broker_enabled,
            )
            write_runtime_plan(plan, runtime_plan_path(self.paths, manifest.name))
            self.network_service.create(plan, output=self.output)
            return plan

        assert self.routed_allocator is not None
        self._print_routed_policy(manifest)
        session = self.paths.identity.subnet_reservation_session(manifest.name)
        avoid = tuple(rule.destination for rule in manifest.network.routed_rules)
        self.output.write(f"  {_BLUE}→{_RESET} Reserving routed subnets\n")
        try:
            pool = config.routed_subnet_pool
            prefix = config.routed_subnet_prefix
            if prefix < pool.prefixlen:
                raise ConfigurationError(
                    f"ASF_SUBNET_PREFIX /{prefix} is wider than pool {pool}"
                )
        except ConfigurationError as exc:
            raise RuntimeOpenError(f"subnet allocation failed: {exc}") from exc
        with self.routed_allocator.reserve(
            session=session,
            owner_pid=owner_pid,
            pool=pool,
            prefix=prefix,
            avoid=avoid,
        ) as allocation:
            plan = build_runtime_plan(
                manifest,
                paths=self.paths,
                owner_pid=owner_pid,
                broker_globally_enabled=broker_enabled,
                routed_subnets=allocation,
            )
            write_runtime_plan(plan, runtime_plan_path(self.paths, manifest.name))
            self.network_service.create(plan, output=self.output)
        return plan

    def _print_routed_policy(self, manifest: RuntimeManifest) -> None:
        self.output.write(f"  {_DIM}Routed policy for {manifest.name}:{_RESET}\n")
        for rule in manifest.network.routed_rules:
            if rule.protocol is None:
                self.output.write(f"    {rule.destination} all IP traffic\n")
                continue
            ports = (
                "echo-request/reply"
                if rule.ports is None
                else (
                    ",".join(str(port) for port in rule.ports)
                    if isinstance(rule.ports, tuple)
                    else rule.ports
                )
            )
            self.output.write(
                f"    {rule.destination} {rule.protocol} ports={ports}\n"
            )
        verify = manifest.network.routed_verification
        if verify is not None:
            self.output.write(
                f"    verify: allow {verify.address}:{verify.allowed_port}; "
                f"block known-open {verify.denied_address}:{verify.blocked_port}\n"
            )
        else:
            self.output.write(
                "    verify: structural checks only (no live target probes)\n"
            )

    def shell(
        self,
        requested: str = "",
        *,
        replace_process: ReplaceProcess = replace_process_command,
    ) -> int:
        discovery = SessionDiscovery.from_paths(self.paths, podman=self.podman)
        runtime = discovery.resolve_runtime(requested or None)
        match = discovery.unique_match(runtime)
        if match is None:
            raise RuntimeOpenError(f"No running {runtime} container")
        manifest = load_model(self.paths.identity.runtime_manifest(runtime))
        plan = load_runtime_plan(runtime_plan_path(self.paths, runtime))
        validate_runtime_plan_context(plan, manifest, self.paths)
        if plan.runtime_isolation == "microvm":
            return self._attach_krun(runtime, match.container_id)
        self._require_tools()
        broker_active = plan.container(SessionRole.BROKER) is not None
        excluded = provider_api_key_name(manifest) if broker_active else ""
        remote_environment = load_runtime_environment(
            plan,
            excluded_key=excluded,
            output=self.output,
            error=self.error,
        )
        replace_process(
            self._devcontainer_exec_argv(
                plan,
                remote_environment,
                command=("zsh",),
            )
        )
        raise AssertionError("replace_process returned")

    def _attach_krun(self, runtime: str, container_id: str) -> int:
        manager = SessionDiscovery.from_paths(
            self.paths, podman=self.podman
        ).lock_manager()
        try:
            attach_lock = manager.acquire(runtime, owner_pid=os.getpid())
        except SessionAlreadyRunningError as exc:
            owner = "unknown" if exc.pid is None else str(exc.pid)
            raise RuntimeOpenError(
                f"The {runtime} krun session is already attached by PID {owner}.\n"
                "  Detach that client first with Ctrl-P, Ctrl-Q."
            ) from exc

        self.output.write(
            f"{_BLUE}Attaching to krun microVM...{_RESET}\n"
            f"  {_DIM}Detach without stopping: Ctrl-P, Ctrl-Q{_RESET}\n"
            f"  {_DIM}Press Enter if the prompt is not visible after attach.{_RESET}\n\n"
        )
        self.output.flush()
        command = (
            os.fspath(self.podman.engine),
            "attach",
            "--detach-keys=ctrl-p,ctrl-q",
            "--sig-proxy=false",
            container_id,
        )
        release_attach_lock = True
        try:
            try:
                result = SessionProcessSupervisor().run(command)
            finally:
                restore_terminal(self.error)

            if self._runtime_container_running(container_id):
                self.output.write(
                    f"\n{_YELLOW}Detached from {runtime}; the krun microVM is still running.{_RESET}\n"
                    f"  Reattach: ./sandbox.sh shell {runtime}\n"
                    f"  Stop:     ./sandbox.sh stop {runtime}\n"
                )
                self.output.flush()
                return result.returncode

            stop_service = stop_service_from_environment(
                self.paths, podman=self.podman
            )
            report = stop_service.stop_runtime(
                runtime,
                emitter=StopEmitter(self._emit_stop_event),
                acquired_lock=attach_lock,
            )
            # StopService now owns exact-lock cleanup. Do not race a new opener
            # by trying to release the old token again after it returns.
            release_attach_lock = False
            if result.signal is not None:
                return result.returncode
            if result.returncode != 0:
                return result.returncode
            return 0 if report.succeeded else 1
        finally:
            # Detach preserves the runtime but not ownership of the terminal.
            if release_attach_lock:
                manager.release(attach_lock)

    def _runtime_container_running(self, reference: str) -> bool:
        try:
            return self.podman.inspect_container(reference).is_running
        except ObjectNotFoundError:
            return False

    def _clear_previous_resources(
        self, runtime: str, stop_service: StopService
    ) -> None:
        """Remove abandoned session resources while preserving our new lock."""

        residue = stop_service.scanner.scan(runtime)
        if residue.inconclusive:
            raise RuntimeOpenError(
                f"Could not inspect previous {runtime} session resources: "
                + "; ".join(residue.unreadable)
            )
        resources = tuple(
            resource
            for resource in residue.resources()
            if resource.kind is not ResourceKind.SESSION_LOCK
        )
        if not resources:
            self._finalize_previous_egress_evidence(runtime)
            return
        report = stop_service.cleanup.cleanup(resources)
        if not report.succeeded:
            detail = "; ".join(
                result.detail or str(result.resource) for result in report.failures
            )
            raise RuntimeOpenError(
                f"Could not remove previous {runtime} session resources"
                + (f": {detail}" if detail else "")
            )
        remaining = stop_service.scanner.scan(runtime)
        leftovers = tuple(
            resource
            for resource in remaining.resources()
            if resource.kind is not ResourceKind.SESSION_LOCK
        )
        if remaining.inconclusive or leftovers:
            details = list(remaining.unreadable)
            details.extend(str(resource) for resource in leftovers)
            raise RuntimeOpenError(
                f"Previous {runtime} session resources remain: "
                + "; ".join(details)
            )
        self._finalize_previous_egress_evidence(runtime)

    def _finalize_previous_egress_evidence(self, runtime: str) -> None:
        try:
            evidence = finalize_egress_session(self.paths, runtime)
        except (OSError, ValidationError, EgressEvidenceError) as exc:
            self.error.write(
                f"  {_YELLOW}⚠{_RESET} Could not recover previous egress "
                f"evidence {_DIM}({exc}){_RESET}\n"
            )
            return
        if evidence is not None:
            noun = "CONNECT" if evidence.connect_attempts == 1 else "CONNECTs"
            self.output.write(
                f"  {_GREEN}✓{_RESET} Previous egress evidence recovered "
                f"{_DIM}({evidence.connect_attempts} agent {noun}){_RESET}\n"
            )

    def _require_tools(
        self,
        manifest: RuntimeManifest | None = None,
        config: AsfConfig | None = None,
    ) -> None:
        self.podman.require_available()
        if manifest is not None and manifest.runtime.isolation == "microvm":
            if config is None:
                raise TypeError("krun tool checks require ASF configuration")
            validate_krun_beta(
                manifest,
                ssh_agent=config.ssh_agent_socket() is not None,
                broker_enabled=bool(
                    config.broker_enabled
                    and manifest.llm is not None
                    and manifest.llm.broker
                ),
            )
            require_krun_host(self.paths, manifest)
            return
        self._require_devcontainer()

    def _require_devcontainer(self) -> None:
        if shutil.which("devcontainer") is None:
            raise RuntimeOpenError(
                "devcontainer CLI not found. Install: "
                "npm install -g @devcontainers/cli"
            )

    def _load_repositories(
        self, manifest: RuntimeManifest
    ) -> tuple[RepositoryEntry, ...]:
        repositories: list[RepositoryEntry] = []
        store = RepositoryStore.for_file(
            self.paths.agent_repos_file(manifest.name),
            runtime=manifest.name,
        )
        for entry in store.entries():
            if entry.exists:
                access = "read-only" if entry.mode == "ro" else "read-write"
                self.output.write(
                    f"  {_GREEN}+{_RESET} {entry.name} {_DIM}({access}){_RESET}\n"
                )
                repositories.append(entry)
            else:
                self.output.write(
                    f"  {_YELLOW}⚠{_RESET} skipping (not found): "
                    f"{_DIM}{entry.path}{_RESET}\n"
                )
        if not repositories:
            self.output.write(
                f"  {_YELLOW}no repos configured for {manifest.name}{_RESET} — run: "
                f"./sandbox.sh repo add {manifest.name} ~/path/to/repo\n"
            )
        return tuple(repositories)

    def _ensure_krun_image(self, request: KrunRequest) -> None:
        image = krun_image_name(request.plan)
        started = time.monotonic()
        result = self.podman.observe(
            (os.fspath(self.podman.engine), "image", "exists", image)
        )
        if result.returncode == 0:
            self.output.write(
                f"{_GREEN}✓ Krun agent image available{_RESET} "
                f"{_DIM}(cached; {time.monotonic() - started:.1f}s){_RESET}\n"
            )
            return
        if result.returncode != 1:
            raise RuntimeOpenError(
                f"could not determine whether krun agent image exists: {image}"
            )
        self._build_krun_image(request)

    def _build_krun_image(self, request: KrunRequest) -> None:
        self.output.write(f"{_BLUE}Building krun agent image...{_RESET}\n")
        started = time.monotonic()
        try:
            run_streaming(
                build_krun_build_argv(
                    request, engine=os.fspath(self.podman.engine)
                ),
                timeout=1800,
                output=self.output,
                error=self.error,
                inherit_stdin=False,
            )
        except CommandError as exc:
            raise RuntimeOpenError("krun agent image failed to build") from exc
        self.output.write(
            f"{_GREEN}Krun agent image ready{_RESET} "
            f"{_DIM}({time.monotonic() - started:.1f}s){_RESET}\n"
        )

    def _generate_devcontainer(
        self,
        plan: RuntimePlan,
        manifest: RuntimeManifest,
        config: AsfConfig,
        broker: BrokerRequest | None,
    ) -> DevcontainerRequest:
        repositories = self._load_repositories(manifest)
        ssh_socket = config.ssh_agent_socket()
        if ssh_socket is not None:
            self.error.write(
                f"  {_YELLOW}⚠ SSH agent forwarding ENABLED{_RESET} "
                f"{_DIM}({ssh_socket}){_RESET}\n"
                f"    {_DIM}every identity this agent holds is usable by the "
                f"container for the whole session{_RESET}\n"
            )
        self.output.write(f"{_BLUE}Updating mounts...{_RESET}\n")
        request = DevcontainerRequest(
            self.paths,
            plan,
            manifest,
            repositories=tuple(repositories),
            run_arguments=config.hardening_arguments(manifest),
            build_arguments=config.build_arguments(),
            ssh_agent_socket=ssh_socket,
            proxy_port=PROXY_PORT,
            broker_default_model=(broker.models.default_model if broker else ""),
        )
        write_atomic(request.output_path, build_devcontainer_config(request))
        self.output.write(f"Wrote {request.output_path}\n\n")
        return request

    def _devcontainer_flags(self, plan: RuntimePlan) -> tuple[str, ...]:
        config_path = self.paths.session_artifact(plan.runtime, "devcontainer.json")
        return (
            "--docker-path",
            str(self.podman.engine),
            "--config",
            str(config_path),
            "--id-label",
            plan.session_label,
        )

    def _devcontainer_up_argv(self, plan: RuntimePlan) -> tuple[str, ...]:
        return (
            "devcontainer",
            "up",
            *self._devcontainer_flags(plan),
            "--workspace-folder",
            str(self.paths.root),
            "--remove-existing-container",
        )

    def _start_devcontainer(
        self, plan: RuntimePlan, environment: dict[str, str]
    ) -> None:
        started = time.monotonic()
        try:
            run_streaming(
                self._devcontainer_up_argv(plan),
                timeout=1800,
                output=self.output,
                error=self.error,
                inherit_stdin=False,
                env=environment,
                redact_values=tuple(environment.values()),
            )
        except CommandError as exc:
            raise RuntimeOpenError("Container failed to start.") from exc
        self.output.write(
            f"{_GREEN}Container ready{_RESET} "
            f"{_DIM}({time.monotonic() - started:.1f}s){_RESET}\n"
        )

    def _devcontainer_exec_argv(
        self,
        plan: RuntimePlan,
        remote_environment: Sequence[tuple[str, str]],
        *,
        command: Sequence[str] | None = None,
    ) -> tuple[str, ...]:
        selected = tuple(command) if command is not None else (
            plan.command if plan.runtime_mode == "service" else ("zsh",)
        )
        if not selected:
            raise RuntimeOpenError(
                f"Runtime {plan.runtime} sets mode: service but no runtime.command"
            )
        env_args: list[str] = []
        for key, value in remote_environment:
            env_args.extend(("--remote-env", f"{key}={value}"))
        return (
            "devcontainer",
            "exec",
            *self._devcontainer_flags(plan),
            "--workspace-folder",
            str(self.paths.root),
            *env_args,
            "--",
            *selected,
        )

    def _emit_stop_event(self, event: StopEvent) -> None:
        target = self.output if event.stream is StopStream.STDOUT else self.error
        target.write(event.text)
        target.flush()


@dataclass(slots=True)
class _StartupSignalState:
    active: bool = True

    def disable(self) -> None:
        self.active = False


class _StartupInterrupted(BaseException):
    def __init__(self, received: OpenSignal) -> None:
        self.signal = received
        super().__init__(received.value)


@contextlib.contextmanager
def _startup_signals():
    state = _StartupSignalState()
    previous: dict[int, signal.Handlers] = {}

    def handler(signum: int, _frame: object) -> None:
        if not state.active:
            return
        for item in OpenSignal:
            if item.number == signum:
                raise _StartupInterrupted(item)

    for item in OpenSignal:
        previous[item.number] = signal.getsignal(item.number)
        signal.signal(item.number, handler)
    try:
        yield state
    finally:
        for signum, old in previous.items():
            signal.signal(signum, old)


def load_runtime_environment(
    plan: RuntimePlan,
    *,
    excluded_key: str = "",
    output: TextIO = sys.stdout,
    error: TextIO = sys.stderr,
) -> tuple[tuple[str, str], ...]:
    """Read declared env files with the accepted last-file-wins precedence."""

    if excluded_key and _ENV_RE.fullmatch(excluded_key) is None:
        raise ValidationError("excluded secret key is not a valid environment name")
    seen: set[str] = set()
    values: list[tuple[str, str]] = []
    for secret in reversed(plan.secret_files):
        path = secret.source
        if path.is_symlink():
            raise ConfigurationError(f"Secret file must not be a symlink: {path}")
        try:
            info = path.stat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ConfigurationError(
                f"Cannot inspect secret file {path}: {exc}"
            ) from exc
        if not stat.S_ISREG(info.st_mode):
            raise ConfigurationError(f"Secret path is not a regular file: {path}")
        mode = stat.S_IMODE(info.st_mode)
        if mode not in {0o400, 0o600}:
            error.write(
                f"  {_YELLOW}⚠ {path.name} is mode {mode:o} — tighten with: "
                f"chmod 600 {path}{_RESET}\n"
            )
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise ConfigurationError(f"Secret file is not valid UTF-8: {path}") from exc
        except OSError as exc:
            raise ConfigurationError(f"Cannot read secret file {path}: {exc}") from exc
        for raw in lines:
            line = raw.lstrip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.rstrip()
            if _ENV_RE.fullmatch(key) is None:
                raise ConfigurationError(
                    f"Invalid environment variable name in {path.name}: {key}"
                )
            if key in seen:
                continue
            seen.add(key)
            if key == excluded_key:
                continue
            values.append((key, value))
    if values:
        output.write(
            f"  {_DIM}secrets: injected {len(values)} key(s) for "
            f"{plan.runtime} (runtime env only){_RESET}\n"
        )
        if plan.broker_enabled:
            error.write(
                f"  {_YELLOW}⚠ broker is active, but {len(values)} non-provider "
                f"secret(s) still enter the agent env{_RESET}\n"
            )
    return tuple(values)


def run_runtime_command(
    arguments: Sequence[str],
    paths: RepoPaths,
    *,
    podman: PodmanClient | None = None,
    output: TextIO = sys.stdout,
    error: TextIO = sys.stderr,
    replace_process: ReplaceProcess = replace_process_command,
) -> int:
    if isinstance(arguments, (str, bytes)):
        raise TypeError("runtime arguments must be a sequence")
    argv = tuple(arguments)
    if not argv or argv[0] not in {"open", "shell"}:
        raise ValidationError("unsupported runtime command")
    service = RuntimeService(
        paths,
        PodmanClient() if podman is None else podman,
        output,
        error,
    )
    runtime = argv[1] if len(argv) > 1 else ""
    if argv[0] == "open":
        if not runtime:
            raise ValidationError("Usage: ./sandbox.sh open <agent>")
        return service.open(runtime)
    return service.shell(runtime, replace_process=replace_process)



def _host_tcp_open(address: str, port: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=6):
            return True
    except OSError:
        return False


def _routed_deny_address(networks) -> str:
    from ipaddress import IPv4Address

    for value in ("203.0.113.254", "198.51.100.254", "192.0.2.254", "1.1.1.1"):
        address = IPv4Address(value)
        if not any(address in network for network in networks):
            return value
    raise StartupVerificationError(
        "Could not select an undeclared routed destination"
    )



def _persist_verification_report(
    report: VerificationReport,
    report_path: Path | None,
    output: TextIO,
) -> None:
    """Write the session verification record atomically, best-effort.

    The record is diagnostic evidence, not enforcement: a failed write is
    reported but never changes the verification verdict in either direction.
    """

    if report_path is None:
        return
    try:
        payload = (
            json.dumps(report.to_json_dict(), indent=2, sort_keys=True) + "\n"
        )
        write_text_atomic(report_path, payload)
    except OSError as exc:
        output.write(
            f"  {_YELLOW}⚠{_RESET} Could not persist verification report "
            f"{_DIM}({exc}){_RESET}\n"
        )


def _probe_failure_detail(result) -> str:
    """Return one bounded diagnostic line from a failed probe."""

    text = result.stderr or result.stdout
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    detail = lines[-1].replace("\x1b", "?")
    return detail[:240]

def _deny_target(allowed: Sequence[str]) -> str:
    present = set(allowed)
    for candidate in (
        "example.com",
        "example.org",
        "example.net",
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
    ):
        if candidate not in present:
            return candidate
    raise StartupVerificationError(
        "Could not select a deny-probe destination outside the allowlist"
    )
