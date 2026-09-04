"""Runtime opening and shell access for every supported network mode.

This module only sequences existing focused components: planning, allocation,
network creation, broker, proxy, routed gateway, direct Podman runtime startup,
verification, supervision, and cleanup.
"""
from __future__ import annotations

import contextlib
import io
import os
import re
import signal
import stat
import tempfile
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, NamedTuple, NoReturn, Sequence, TextIO

from .broker import (
    BrokerRequest,
    BrokerService,
    BrokerSettings,
    generate_session_token,
    provider_api_key_name,
)
from .config import AsfConfig
from .egress_evidence import (
    EgressEvidenceError,
    finalize_egress_session,
    mark_egress_session_active,
)
from .errors import AsfError, ConfigurationError, InfrastructureError, ValidationError
from .manifest import load_model
from .krun import (
    KrunRequest,
    build_krun_environment,
    build_krun_run_argv,
    require_krun_host,
    validate_krun_beta,
)
from .models import RuntimeManifest
from .networks import NetworkService
from .open_lifecycle import (
    OpenCleanupService,
    OpenSignal,
    SessionProcessSupervisor,
    restore_terminal,
    run_open_session,
)
from .ownership import ResourceKind
from .paths import RepoPaths
from .podman import ObjectNotFoundError, PodmanClient
from .process import CommandError
from .process import replace as replace_process_command
from .process import run_streaming
from .proxy import PROXY_PORT, ProxyRequest, ProxyService
from .repositories import RepositoryEntry, RepositoryStore
from .runtime_container import (
    ContainerRequest,
    build_container_environment,
    build_container_exec_argv,
    build_container_run_argv,
)
from .runtime_image import (
    build_base_image_argv,
    build_runtime_image_argv,
)
from .routed import RoutedRequest, RoutedService
from .routed_allocation import RoutedAllocator
from .runtime_plan import (
    RuntimePlan,
    build_runtime_plan,
    load_runtime_plan,
    runtime_plan_path,
    validate_runtime_plan_context,
    write_runtime_plan,
)
from .runs import begin_run, run_artifact, write_run_policy
from .secrets import SecretValue
from .session import SessionDiscovery, SessionRole
from .session_lock import SessionAlreadyRunningError
from .session_events import record_session_event
from .startup_verification import StartupVerificationError, StartupVerifier
from .stop import (
    StopEmitter,
    StopEvent,
    StopService,
    StopStream,
    stop_service_from_environment,
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
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ReplaceProcess = Callable[..., NoReturn]


class RuntimeOpenError(InfrastructureError):
    """A proxy/isolated runtime could not be opened safely."""


class _SupportServices(NamedTuple):
    """What ``open`` starts before the agent workload itself."""

    token: SecretValue | None
    broker: BrokerRequest | None
    proxy: ProxyRequest | None
    routed: RoutedRequest | None


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
        self.routed_allocator = self.routed_allocator or RoutedAllocator(self.podman)
        self.verifier = self.verifier or StartupVerifier(self.podman)

    def open(
        self, runtime: str, *, command: Sequence[str] | None = None
    ) -> int:
        manifest = load_model(self.paths.identity.runtime_manifest(runtime))
        command_override = tuple(command) if command is not None else None
        if command_override is not None and not command_override:
            raise ValidationError("run command must not be empty")
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
                    f"  Open a shell: ./sandbox.sh shell {runtime}"
                )
        lock_manager = discovery.lock_manager()
        previous = lock_manager.inspect(runtime)
        try:
            lock_manager.acquire(runtime, owner_pid=owner_pid)
        except SessionAlreadyRunningError as exc:
            owner = "unknown" if exc.pid is None else str(exc.pid)
            hint = f"  Open a shell: ./sandbox.sh shell {runtime}"
            raise RuntimeOpenError(
                f"A {runtime} session (PID {owner}) is already running.\n{hint}"
            ) from exc
        cleanup = OpenCleanupService(stop_service)
        cleanup_completed = False
        received_signal: OpenSignal | None = None
        try:
            with _startup_signals() as signal_state:
                if previous is not None and previous.is_stale:
                    self.output.write(
                        f"  {_YELLOW}Removing stale session lock "
                        f"(PID {previous.pid or 'unknown'} is gone){_RESET}\n"
                    )
                self._clear_previous_resources(runtime, stop_service)
                begin_run(self.paths, runtime)
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
                write_run_policy(self.paths, plan, manifest)
                support = self._start_support_services(
                    manifest, config, plan, broker_enabled
                )
                assert self.verifier is not None
                self.verifier.verify(
                    plan,
                    manifest,
                    proxy=support.proxy,
                    broker=support.broker,
                    routed=support.routed,
                    output=self.output,
                    report_path=run_artifact(
                        self.paths, manifest.name, "verification-report.json"
                    ),
                )
                if manifest.runtime.isolation == "microvm":
                    child, session_environment = self._prepare_microvm(
                        manifest, config, plan, support, command=command_override
                    )
                else:
                    child, session_environment = self._prepare_container(
                        manifest, config, plan, support, command=command_override
                    )
                if command_override is not None:
                    self.output.write(
                        f"  {_DIM}running one-shot command: "
                        f"{command_override[0]}{_RESET}\n"
                    )
                elif plan.runtime_mode == "service":
                    self.output.write(
                        f"  {_DIM}running: {' '.join(plan.command)}{_RESET}\n"
                    )
                if support.proxy is not None and support.proxy.access_logs:
                    mark_egress_session_active(self.paths, manifest.name)
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

    def _start_support_services(
        self,
        manifest: RuntimeManifest,
        config: AsfConfig,
        plan: RuntimePlan,
        broker_enabled: bool,
    ) -> _SupportServices:
        """Start the broker, proxy and routed gateway the manifest asks for."""

        runtime = manifest.name
        token = None
        broker_request: BrokerRequest | None = None
        proxy_request: ProxyRequest | None = None
        routed_request: RoutedRequest | None = None
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

        # Isolated mode has no runtime-side path to the broker, so readiness
        # can only be proven before the runtime starts.
        if manifest.network.mode == "isolated" and broker_request is not None:
            self._wait_broker_ready(broker_request)

        return _SupportServices(token, broker_request, proxy_request, routed_request)

    def _wait_broker_ready(self, broker_request: BrokerRequest) -> None:
        assert self.broker_service is not None
        self.broker_service.wait_ready(
            broker_request,
            output=self.output,
            error=self.error,
        )
        record_session_event(self.paths, broker_request.plan.runtime, "broker_ready")

    def _runtime_environment(
        self,
        manifest: RuntimeManifest,
        plan: RuntimePlan,
        support: _SupportServices,
    ) -> dict[str, str]:
        """Load the agent environment, minus the provider key when brokered."""

        if support.broker is not None and manifest.network.mode != "isolated":
            self._wait_broker_ready(support.broker)
        excluded = provider_api_key_name(manifest) if support.broker is not None else ""
        return load_runtime_environment(
            plan,
            excluded_key=excluded,
            output=self.output,
            error=self.error,
        )

    def _prepare_microvm(
        self,
        manifest: RuntimeManifest,
        config: AsfConfig,
        plan: RuntimePlan,
        support: _SupportServices,
        *,
        command: Sequence[str] | None = None,
    ) -> tuple[Sequence[str], dict[str, str]]:
        """Build the foreground ``podman run --runtime=krun`` command."""

        krun_request = KrunRequest(
            self.paths,
            plan,
            manifest,
            repositories=self._load_repositories(manifest),
            run_arguments=config.hardening_arguments(manifest),
            build_arguments=config.build_arguments(),
            proxy_port=PROXY_PORT,
            broker_default_model=(
                support.broker.models.default_model
                if support.broker is not None
                else ""
            ),
        )
        self._ensure_krun_image(krun_request)
        remote_environment = self._runtime_environment(manifest, plan, support)
        # krun sessions pass their complete environment to the initial
        # foreground Podman/VMM process.
        session_environment = build_krun_environment(
            krun_request,
            broker_token=(support.token.reveal() if support.token is not None else ""),
            runtime_environment=remote_environment,
        )
        child = build_krun_run_argv(
            krun_request,
            session_environment,
            engine=os.fspath(self.podman.engine),
            command=command,
        )
        self.output.write(f"{_BLUE}Starting krun microVM...{_RESET}\n")
        if command is None and plan.runtime_mode == "interactive":
            self.output.write(
                f"  {_DIM}Detach without stopping: Ctrl-P, Ctrl-Q{_RESET}\n"
            )
        self.output.write("\n")
        return child, session_environment

    def _prepare_container(
        self,
        manifest: RuntimeManifest,
        config: AsfConfig,
        plan: RuntimePlan,
        support: _SupportServices,
        *,
        command: Sequence[str] | None = None,
    ) -> tuple[Sequence[str], dict[str, str]]:
        """Build/start the container and return its workload exec boundary."""

        request = ContainerRequest(
            self.paths,
            plan,
            manifest,
            repositories=self._load_repositories(manifest),
            run_arguments=config.hardening_arguments(manifest),
            ssh_agent_socket=config.ssh_agent_socket(),
            proxy_port=PROXY_PORT,
            broker_default_model=(
                support.broker.models.default_model
                if support.broker is not None
                else ""
            ),
        )
        if request.ssh_agent_socket is not None:
            self.error.write(
                f"  {_YELLOW}⚠ SSH agent forwarding ENABLED{_RESET} "
                f"{_DIM}({request.ssh_agent_socket}){_RESET}\n"
                f"    {_DIM}every identity this agent holds is usable by the "
                f"container for the whole session{_RESET}\n"
            )
        self._build_runtime_image(manifest, config)
        runtime_environment = self._runtime_environment(manifest, plan, support)
        environment = build_container_environment(
            request,
            broker_token=(support.token.reveal() if support.token is not None else ""),
        )
        self._start_container(request, environment)
        interactive = command is None and plan.runtime_mode == "interactive"
        workload_environment = dict(runtime_environment)
        return (
            build_container_exec_argv(
                request,
                command=command,
                environment_names=tuple(workload_environment),
                interactive=interactive,
                engine=os.fspath(self.podman.engine),
            ),
            workload_environment,
        )

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
        config = AsfConfig.load(self.paths.config_file)
        request = ContainerRequest(
            self.paths,
            plan,
            manifest,
            run_arguments=config.hardening_arguments(manifest),
        )
        broker_active = plan.container(SessionRole.BROKER) is not None
        excluded = provider_api_key_name(manifest) if broker_active else ""
        runtime_environment = dict(
            load_runtime_environment(
                plan,
                excluded_key=excluded,
                output=self.output,
                error=self.error,
            )
        )
        replace_process(
            build_container_exec_argv(
                request,
                command=("zsh",),
                environment_names=tuple(runtime_environment),
                interactive=True,
                engine=os.fspath(self.podman.engine),
            ),
            env=runtime_environment,
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
                f"The {runtime} krun console is already in use by PID {owner}.\n"
                "  Detach that client first with Ctrl-P, Ctrl-Q."
            ) from exc

        self.output.write(
            f"{_BLUE}Opening krun microVM console...{_RESET}\n"
            f"  {_DIM}Detach without stopping: Ctrl-P, Ctrl-Q{_RESET}\n"
            f"  {_DIM}Press Enter if the prompt is not visible.{_RESET}\n\n"
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
                    f"  Open a shell: ./sandbox.sh shell {runtime}\n"
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

    def _build_runtime_image(
        self, manifest: RuntimeManifest, config: AsfConfig
    ) -> None:
        self.output.write(f"{_BLUE}Preparing {manifest.name} runtime image...{_RESET}\n")
        started = time.monotonic()
        for argv in (
            build_base_image_argv(
                self.paths,
                manifest,
                build_arguments=config.build_arguments(),
                engine=os.fspath(self.podman.engine),
            ),
            build_runtime_image_argv(
                self.paths,
                manifest,
                build_arguments=config.build_arguments(),
                engine=os.fspath(self.podman.engine),
            ),
        ):
            try:
                run_streaming(
                    argv,
                    timeout=1800,
                    output=self.output,
                    error=self.error,
                    inherit_stdin=False,
                )
            except CommandError as exc:
                raise RuntimeOpenError(
                    f"{manifest.name} runtime image failed to build"
                ) from exc
        self.output.write(
            f"{_GREEN}Runtime image ready{_RESET} "
            f"{_DIM}({time.monotonic() - started:.1f}s){_RESET}\n"
        )

    def _ensure_krun_image(self, request: KrunRequest) -> None:
        config = AsfConfig.load(self.paths.config_file)
        self._build_runtime_image(request.manifest, config)

    def _start_container(
        self, request: ContainerRequest, environment: dict[str, str]
    ) -> None:
        self.output.write(f"{_BLUE}Starting container...{_RESET}\n")
        started = time.monotonic()
        temporary_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="asf-runtime-",
                delete=False,
            ) as handle:
                temporary_name = handle.name
                os.chmod(temporary_name, 0o600)
                for key, value in environment.items():
                    handle.write(f"{key}={value}\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                # Detached Podman prints the container ID on stdout. ASF already
                # tracks the deterministic container name, so keep startup output
                # focused while still streaming Podman errors to the operator.
                run_streaming(
                    build_container_run_argv(
                        request,
                        env_file=Path(temporary_name),
                        engine=os.fspath(self.podman.engine),
                    ),
                    timeout=1800,
                    output=io.StringIO(),
                    error=self.error,
                    inherit_stdin=False,
                )
            except CommandError as exc:
                raise RuntimeOpenError("Container failed to start.") from exc
        finally:
            if temporary_name is not None:
                Path(temporary_name).unlink(missing_ok=True)

        try:
            run_streaming(
                (
                    os.fspath(self.podman.engine),
                    "exec",
                    request.plan.runtime_container.name,
                    "bash",
                    "/workspace/sandbox/containers/on-start.sh",
                ),
                timeout=300,
                output=self.output,
                error=self.error,
                inherit_stdin=False,
            )
        except CommandError as exc:
            raise RuntimeOpenError("Container bootstrap failed.") from exc
        self.output.write(
            f"{_GREEN}Container ready{_RESET} "
            f"{_DIM}({time.monotonic() - started:.1f}s){_RESET}\n\n"
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
    if not argv or argv[0] not in {"open", "run", "shell"}:
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
        if len(argv) != 2:
            raise ValidationError("Usage: ./sandbox.sh open <agent>")
        return service.open(runtime)
    if argv[0] == "run":
        if len(argv) < 4 or argv[2] != "--":
            raise ValidationError(
                "Usage: ./sandbox.sh run <agent> -- <command> [args...]"
            )
        return service.open(runtime, command=argv[3:])
    return service.shell(runtime, replace_process=replace_process)


