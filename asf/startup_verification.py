"""Startup verification for ASF network policy and topology."""
from __future__ import annotations

import contextlib
import json
import os
import socket
import sys
import tempfile
import time
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Sequence, TextIO

from .atomic import write_text_atomic
from .broker import BrokerRequest
from .errors import InfrastructureError
from .models import RuntimeManifest
from .podman import ObjectKind, ObjectNotFoundError, PodmanClient
from .proxy import ProxyRequest
from .routed import RoutedRequest
from .runtime_plan import (
    BROKER_INTERNAL_ALIAS,
    NetworkRole,
    PROXY_INTERNAL_ALIAS,
    RuntimePlan,
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

__all__ = ["StartupVerificationError", "StartupVerifier"]

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


def _host_tcp_open(address: str, port: int) -> bool:
    try:
        with socket.create_connection((address, port), timeout=6):
            return True
    except OSError:
        return False


def _routed_deny_address(networks) -> str:
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
