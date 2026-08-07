"""Exhaustive executor classification tests for Phase 2C."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from asf.podman import PodmanClient
from asf.process import (
    CommandNotFoundError,
    CommandResult,
    CommandStartError,
    CommandTimeoutError,
)
from asf.verification import (
    ContainerCondition,
    DnsProbe,
    ContainerInspectProbe,
    ContainerPolicyCondition,
    ContainerPolicyProbe,
    EphemeralProbeExecutor,
    HostProbeExecutor,
    NetworkFamily,
    PlainHttpProxyProbe,
    PodmanInspectExecutor,
    ProbeObservation,
    ProxyConnectProbe,
    RouteProbe,
    RuntimeExecExecutor,
    RuntimeSecurityCondition,
    RuntimeSecurityProbe,
    TcpProbe,
)
from asf.secrets import SecretValue
from asf.verification.executors import _security_invocation


class FakeRunner:
    def __init__(
        self,
        *results: CommandResult,
        error: Exception | None = None,
    ) -> None:
        self.results = list(results)
        self.error = error
        self.calls: list[tuple[tuple[str, ...], float]] = []
        self.inputs: list[str | None] = []

    def __call__(
        self,
        argv: Sequence[str | Path],
        *,
        timeout: float,
        input_text: str | None = None,
        **_: Any,
    ) -> CommandResult:
        actual = tuple(str(value) for value in argv)
        self.calls.append((actual, timeout))
        self.inputs.append(input_text)
        if self.error is not None:
            raise self.error
        if not self.results:
            raise AssertionError("fake runner has no result")
        result = self.results.pop(0)
        return CommandResult(
            argv=actual,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


def command_result(
    returncode: int,
    *,
    stdout: str = "",
    stderr: str = "",
) -> CommandResult:
    return CommandResult(
        argv=("tool",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def inspection_json(
    *,
    running: bool = True,
    health: str | None = "healthy",
    networks: tuple[str, ...] = (),
    user: str = "",
    read_only: bool = False,
    published_ports: bool = False,
) -> str:
    state: dict[str, object] = {
        "Status": "running" if running else "exited",
        "Running": running,
        "ExitCode": 0,
    }
    if health is not None:
        state["Health"] = {"Status": health}
    return json.dumps(
        [
            {
                "Id": "0123456789abcdef",
                "Name": "runtime",
                "Config": {"Image": "image", "Labels": {}, "User": user},
                "State": state,
                "NetworkSettings": {
                    "Networks": {name: {} for name in networks}
                },
                "HostConfig": {
                    "ReadonlyRootfs": read_only,
                    "PortBindings": {"8080/tcp": [{}]} if published_ports else {},
                },
            }
        ]
    )


class HostExecutorTests(unittest.TestCase):
    def execute(self, result: CommandResult, probe: object):
        runner = FakeRunner(result)
        executor = HostProbeExecutor(runner=runner)
        return executor.execute(probe), runner

    def test_tcp_success_and_explicit_failure(self) -> None:
        reached, runner = self.execute(
            command_result(0),
            TcpProbe("192.0.2.10", 443, 3),
        )
        denied, _ = self.execute(
            command_result(1, stderr="connection refused"),
            TcpProbe("192.0.2.10", 443),
        )
        self.assertIs(reached.observation, ProbeObservation.REACHED)
        self.assertIs(denied.observation, ProbeObservation.DENIED)
        self.assertEqual(
            runner.calls[0],
            (("nc", "-z", "-w", "3", "192.0.2.10", "443"), 3.0),
        )

    def test_dns_probe_uses_nslookup_and_classifies_explicit_results(self) -> None:
        reached, runner = self.execute(command_result(0), DnsProbe("example.test", 3))
        denied, _ = self.execute(command_result(1), DnsProbe("example.test"))
        failed, _ = self.execute(command_result(125), DnsProbe("example.test"))
        self.assertIs(reached.observation, ProbeObservation.REACHED)
        self.assertIs(denied.observation, ProbeObservation.DENIED)
        self.assertIs(failed.observation, ProbeObservation.INFRASTRUCTURE_FAILURE)
        self.assertEqual(runner.calls[0], (("nslookup", "example.test"), 3.0))

    def test_dns_failure_is_infrastructure_not_denial(self) -> None:
        result, _ = self.execute(
            command_result(1, stderr="Name or service not known"),
            TcpProbe("missing.invalid", 443),
        )
        self.assertIs(
            result.observation,
            ProbeObservation.INFRASTRUCTURE_FAILURE,
        )

    def test_missing_executable_and_timeout_are_infrastructure(self) -> None:
        errors = (
            CommandNotFoundError("missing", argv=("nc",)),
            CommandStartError("could not start", argv=("nc",)),
            CommandTimeoutError(argv=("nc",), timeout=3),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                executor = HostProbeExecutor(runner=FakeRunner(error=error))
                result = executor.execute(TcpProbe("192.0.2.10", 443))
                self.assertIs(
                    result.observation,
                    ProbeObservation.INFRASTRUCTURE_FAILURE,
                )

    def test_exit_125_126_and_127_are_infrastructure(self) -> None:
        for returncode in (-9, 124, 125, 126, 127, 137):
            with self.subTest(returncode=returncode):
                result, _ = self.execute(
                    command_result(returncode),
                    TcpProbe("192.0.2.10", 443),
                )
                self.assertIs(
                    result.observation,
                    ProbeObservation.INFRASTRUCTURE_FAILURE,
                )

    def test_proxy_connect_classifies_explicit_http_evidence(self) -> None:
        # The probe script reads the first response line in-container and
        # reports the verdict in its exit code; stdout is diagnostics only.
        cases = (
            (
                command_result(20, stdout="HTTP/1.1 200 Connection Established\n"),
                ProbeObservation.REACHED,
            ),
            (
                command_result(40, stdout="HTTP/1.1 403 Forbidden\n"),
                ProbeObservation.DENIED,
            ),
            (
                command_result(41, stdout="HTTP/1.1 407 Proxy Auth Required\n"),
                ProbeObservation.DENIED,
            ),
            (
                command_result(30, stdout="HTTP/1.1 404 Not Found\n"),
                ProbeObservation.INFRASTRUCTURE_FAILURE,
            ),
            (
                command_result(50, stdout="HTTP/1.1 502 Bad Gateway\n"),
                ProbeObservation.INFRASTRUCTURE_FAILURE,
            ),
            (
                command_result(61, stderr="Name or service not known"),
                ProbeObservation.INFRASTRUCTURE_FAILURE,
            ),
        )
        for result, expected in cases:
            with self.subTest(result=result):
                actual, _ = self.execute(
                    result,
                    ProxyConnectProbe("proxy", 3128, "example.test", 443),
                )
                self.assertIs(actual.observation, expected)

        _, runner = self.execute(
            command_result(40, stdout="HTTP/1.1 403 Forbidden\n"),
            ProxyConnectProbe("proxy", 3128, "example.test", 443),
        )
        argv = runner.calls[0][0]
        self.assertEqual(argv[:2], ("sh", "-c"))
        self.assertEqual(argv[-3:], ("nc", "proxy", "3128"))
        self.assertNotIn("example.test", argv[2])
        self.assertEqual(
            runner.inputs[0],
            "CONNECT example.test:443 HTTP/1.1\r\n"
            "Host: example.test:443\r\n"
            "X-ASF-Probe: verification\r\n"
            "Connection: close\r\n\r\n",
        )

    def test_proxy_stdout_is_never_classification_evidence(self) -> None:
        # A mangled or truncated output stream must not flip the verdict:
        # an exit code that reports 2xx stays REACHED even if stdout claims
        # a denial, and an unknown exit code stays inconclusive even if
        # stdout carries a perfect status line.
        reached, _ = self.execute(
            command_result(20, stdout="HTTP/1.1 403 Forbidden\n"),
            PlainHttpProxyProbe("proxy", 3128, "http://example.test:9000/"),
        )
        self.assertIs(reached.observation, ProbeObservation.REACHED)
        inconclusive, _ = self.execute(
            command_result(0, stdout="HTTP/1.1 403 Forbidden\r\n"),
            PlainHttpProxyProbe("proxy", 3128, "http://example.test:9000/"),
        )
        self.assertIs(
            inconclusive.observation,
            ProbeObservation.INFRASTRUCTURE_FAILURE,
        )

    def test_probe_script_reads_only_the_first_response_line(self) -> None:
        # The script itself is the parser now; exercise it with a real shell
        # so the strictness rules (first line only, no body scanning) are
        # verified against the exact frozen constant that ships.
        cases = (
            ("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n", 40),
            ("HTTP/1.1 403\r\n\r\n", 40),
            ("HTTP/1.1 407 Proxy Auth Required\r\n\r\n", 41),
            ("HTTP/1.1 200 Connection Established\r\n\r\n", 20),
            ("HTTP/1.1 404 Not Found\r\n\r\n", 30),
            ("HTTP/1.1 502 Bad Gateway\r\n\r\n", 50),
            ("", 61),
            # Body text is never scanned for status-shaped strings.
            ("junk line\r\nHTTP/1.1 403 Forbidden\r\n", 61),
            ("HTTP/1.1 4033 not a status\r\n", 61),
        )
        from asf.verification.executors import _PROXY_PROBE_SCRIPT

        with tempfile.TemporaryDirectory() as directory:
            fake_nc = Path(directory) / "nc"
            canned = Path(directory) / "response"
            fake_nc.write_text(
                f'#!/bin/sh\ncat "{canned}"\n', encoding="utf-8"
            )
            fake_nc.chmod(0o755)
            for response, expected in cases:
                with self.subTest(response=response):
                    canned.write_text(response, encoding="utf-8")
                    completed = subprocess.run(
                        [
                            "sh",
                            "-c",
                            _PROXY_PROBE_SCRIPT,
                            "asf-proxy-probe",
                            str(fake_nc),
                            "proxy",
                            "3128",
                        ],
                        env={**os.environ, "TMPDIR": directory},
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(completed.returncode, expected)

    def test_plain_http_treats_non_denial_4xx_as_reached(self) -> None:
        cases = (
            (20, ProbeObservation.REACHED),
            (30, ProbeObservation.REACHED),
            (40, ProbeObservation.DENIED),
            (41, ProbeObservation.DENIED),
            (50, ProbeObservation.INFRASTRUCTURE_FAILURE),
        )
        for code, expected in cases:
            with self.subTest(code=code):
                actual, runner = self.execute(
                    command_result(code, stdout="HTTP/1.1 nnn Result\n"),
                    PlainHttpProxyProbe(
                        "proxy",
                        3128,
                        "http://example.test/path",
                    ),
                )
                self.assertIs(actual.observation, expected)
                self.assertNotIn("curl", runner.calls[0][0])
                self.assertEqual(
                    runner.inputs[0],
                    "GET http://example.test/path HTTP/1.1\r\n"
                    "Host: example.test\r\n"
                    "X-ASF-Probe: verification\r\n"
                    "Connection: close\r\n\r\n",
                )

    def test_default_route_uses_exit_code_as_explicit_evidence(self) -> None:
        # The script prints the routes for diagnostics, but only the exit
        # code decides: lost stdout must never turn "route exists" into a
        # passing no-default-route deny check.
        cases = (
            (
                command_result(21, stdout="default via 192.0.2.1\n"),
                ProbeObservation.REACHED,
            ),
            (command_result(22, stdout=""), ProbeObservation.DENIED),
            # A route that exists but whose stdout was dropped in transit
            # is still REACHED, not DENIED.
            (command_result(21, stdout=""), ProbeObservation.REACHED),
            (
                command_result(2, stderr="ip failed"),
                ProbeObservation.INFRASTRUCTURE_FAILURE,
            ),
            (command_result(0, stdout=""), ProbeObservation.INFRASTRUCTURE_FAILURE),
        )
        for command, expected in cases:
            with self.subTest(command=command):
                actual, runner = self.execute(command, RouteProbe())
                self.assertIs(actual.observation, expected)
                argv = runner.calls[0][0]
                self.assertEqual(argv[:2], ("sh", "-c"))
                self.assertEqual(argv[-2:], ("ip", "-4"))

    def test_route_requires_explicit_no_route_evidence(self) -> None:
        cases = (
            (command_result(0), ProbeObservation.REACHED),
            (
                command_result(2, stderr="RTNETLINK: Network is unreachable"),
                ProbeObservation.DENIED,
            ),
            (
                command_result(2, stderr="invalid argument"),
                ProbeObservation.INFRASTRUCTURE_FAILURE,
            ),
        )
        for result, expected in cases:
            with self.subTest(result=result):
                actual, runner = self.execute(
                    result,
                    RouteProbe("198.51.100.10", NetworkFamily.IPV4),
                )
                self.assertIs(actual.observation, expected)
                self.assertEqual(
                    runner.calls[0][0],
                    ("ip", "-4", "route", "get", "198.51.100.10"),
                )


class PodmanExecutorTests(unittest.TestCase):
    def test_runtime_exec_uses_fixed_vector_and_probe_timeout(self) -> None:
        runner = FakeRunner(command_result(0))
        podman = PodmanClient(runner=runner)
        result = RuntimeExecExecutor(podman, "runtime").execute(
            TcpProbe("192.0.2.10", 443, 4)
        )
        self.assertIs(result.observation, ProbeObservation.REACHED)
        self.assertEqual(
            runner.calls[0],
            (
                (
                    "podman",
                    "exec",
                    "runtime",
                    "nc",
                    "-z",
                    "-w",
                    "4",
                    "192.0.2.10",
                    "443",
                ),
                4.0,
            ),
        )

    def test_runtime_missing_container_and_podman_125_are_infrastructure(self) -> None:
        missing = FakeRunner(
            command_result(
                125,
                stderr="Error: no container with name or ID runtime found",
            )
        )
        missing_result = RuntimeExecExecutor(
            PodmanClient(runner=missing),
            "runtime",
        ).execute(TcpProbe("192.0.2.10", 443))
        self.assertIs(
            missing_result.observation,
            ProbeObservation.INFRASTRUCTURE_FAILURE,
        )

        failed = FakeRunner(command_result(125, stderr="engine failure"))
        failed_result = RuntimeExecExecutor(
            PodmanClient(runner=failed),
            "runtime",
        ).execute(TcpProbe("192.0.2.10", 443))
        self.assertIs(
            failed_result.observation,
            ProbeObservation.INFRASTRUCTURE_FAILURE,
        )

    def test_runtime_security_probe_uses_only_fixed_commands(self) -> None:
        runner = FakeRunner(command_result(0))
        result = RuntimeExecExecutor(
            PodmanClient(runner=runner), "runtime"
        ).execute(
            RuntimeSecurityProbe(
                "runtime",
                RuntimeSecurityCondition.CAPABILITIES_EQUAL,
                expected_text="0000000000000000",
            )
        )
        self.assertIs(result.observation, ProbeObservation.REACHED)
        argv = runner.calls[0][0]
        self.assertEqual(argv[:3], ("podman", "exec", "runtime"))
        self.assertEqual(argv[3:5], ("sh", "-c"))
        self.assertIn("0000000000000000", argv)

    def test_capability_probe_preserves_awk_field_reference(self) -> None:
        probe = RuntimeSecurityProbe(
            "runtime",
            RuntimeSecurityCondition.CAPABILITIES_EQUAL,
            expected_text="0000000000000000",
        )
        command, input_text = _security_invocation(probe)
        self.assertIsNone(input_text)

        with tempfile.TemporaryDirectory() as tmp:
            status = Path(tmp) / "status"
            status.write_text(
                "CapEff:\t0000000000000000\n"
                "CapBnd:\t0000000000000000\n",
                encoding="utf-8",
            )
            script = command[2].replace("/proc/self/status", str(status))
            result = subprocess.run(
                (command[0], command[1], script, *command[3:]),
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("awk '/^CapEff:/ {print $2; exit}'", script)
        self.assertIn("awk '/^CapBnd:/ {print $2; exit}'", script)

    def test_external_dns_denial_requires_preflight_and_known_status(self) -> None:
        for returncode, expected in (
            (0, ProbeObservation.REACHED),
            (1, ProbeObservation.DENIED),
            (125, ProbeObservation.INFRASTRUCTURE_FAILURE),
        ):
            with self.subTest(returncode=returncode):
                runner = FakeRunner(command_result(returncode))
                result = RuntimeExecExecutor(
                    PodmanClient(runner=runner), "runtime"
                ).execute(
                    RuntimeSecurityProbe(
                        "runtime",
                        RuntimeSecurityCondition.EXTERNAL_DNS_UNAVAILABLE,
                    )
                )
                self.assertIs(result.observation, expected)
                self.assertIn("command -v getent", " ".join(runner.calls[0][0]))

    def test_provider_credential_comparison_never_exposes_secret(self) -> None:
        runner = FakeRunner(command_result(1))
        result = RuntimeExecExecutor(
            PodmanClient(runner=runner), "runtime"
        ).execute(
            RuntimeSecurityProbe(
                "runtime",
                RuntimeSecurityCondition.PROVIDER_CREDENTIAL_ABSENT,
                expected_text="OPENAI_API_KEY",
                secret=SecretValue("provider-secret"),
            )
        )
        self.assertIs(result.observation, ProbeObservation.REACHED)
        self.assertNotIn("provider-secret", repr(result))
        self.assertNotIn("provider-secret", " ".join(runner.calls[0][0]))

    def test_caddy_policy_requires_allowlist_port_and_fixed_denials(self) -> None:
        policy = """ports 443
deny 10.0.0.0/8
deny 169.254.0.0/16
allow example.test
deny all
"""
        runner = FakeRunner(command_result(0, stdout=policy))
        result = RuntimeExecExecutor(
            PodmanClient(runner=runner), "proxy"
        ).execute(
            RuntimeSecurityProbe(
                "proxy",
                RuntimeSecurityCondition.CADDY_POLICY_MATCHES,
                expected_items=("example.test",),
            )
        )
        self.assertIs(result.observation, ProbeObservation.REACHED)

    def test_ephemeral_executor_hardens_container_without_shell(self) -> None:
        runner = FakeRunner(command_result(1, stderr="connection refused"))
        podman = PodmanClient(runner=runner)
        result = EphemeralProbeExecutor(
            podman,
            "asf-internal",
            "asf-probe:1",
        ).execute(TcpProbe("192.0.2.10", 443, 5))
        argv, timeout = runner.calls[0]
        self.assertIs(result.observation, ProbeObservation.DENIED)
        # Probe window plus fixed container-startup headroom.
        self.assertEqual(timeout, 35.0)
        self.assertEqual(argv[:3], ("podman", "run", "--rm"))
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--security-opt=no-new-privileges", argv)
        self.assertNotIn("sh", argv)
        self.assertEqual(
            argv[-6:],
            ("nc", "-z", "-w", "5", "192.0.2.10", "443"),
        )

    def test_ephemeral_proxy_probe_enables_stdin_without_curl(self) -> None:
        runner = FakeRunner(
            command_result(40, stdout="HTTP/1.1 403 Forbidden\n")
        )
        result = EphemeralProbeExecutor(
            PodmanClient(runner=runner),
            "asf-internal",
            "asf-probe:1",
        ).execute(
            ProxyConnectProbe("proxy", 3128, "example.test", 443)
        )
        argv, _ = runner.calls[0]
        self.assertIs(result.observation, ProbeObservation.DENIED)
        self.assertIn("-i", argv)
        self.assertNotIn("curl", argv)
        self.assertEqual(argv[-3:], ("nc", "proxy", "3128"))
        script = argv[-5]
        self.assertEqual(argv[-7:-5], ("sh", "-c"))
        # The request stays on stdin; the frozen script receives only the
        # validated netcat path, proxy host, and proxy port.
        self.assertNotIn("example.test", script)
        self.assertIsNotNone(runner.inputs[0])

    def test_ephemeral_podman_exit_125_is_infrastructure(self) -> None:
        runner = FakeRunner(command_result(125, stderr="network missing"))
        result = EphemeralProbeExecutor(
            PodmanClient(runner=runner),
            "asf-internal",
            "asf-probe:1",
        ).execute(RouteProbe("192.0.2.10"))
        self.assertIs(
            result.observation,
            ProbeObservation.INFRASTRUCTURE_FAILURE,
        )


class InspectExecutorTests(unittest.TestCase):
    def execute(self, stdout: str, condition: ContainerCondition):
        runner = FakeRunner(command_result(0, stdout=stdout))
        executor = PodmanInspectExecutor(PodmanClient(runner=runner))
        return executor.execute(ContainerInspectProbe("runtime", condition))

    def test_exists_running_and_healthy_conditions(self) -> None:
        for condition in ContainerCondition:
            with self.subTest(condition=condition):
                result = self.execute(inspection_json(), condition)
                self.assertIs(result.observation, ProbeObservation.REACHED)

    def test_existing_but_false_condition_is_denied(self) -> None:
        stopped = self.execute(
            inspection_json(running=False, health=None),
            ContainerCondition.RUNNING,
        )
        unhealthy = self.execute(
            inspection_json(health="unhealthy"),
            ContainerCondition.HEALTHY,
        )
        self.assertIs(stopped.observation, ProbeObservation.DENIED)
        self.assertIs(unhealthy.observation, ProbeObservation.DENIED)

    def test_missing_or_malformed_container_is_infrastructure(self) -> None:
        missing_runner = FakeRunner(
            command_result(125, stderr="Error: no such container runtime")
        )
        missing = PodmanInspectExecutor(
            PodmanClient(runner=missing_runner)
        ).execute(ContainerInspectProbe("runtime"))
        malformed = PodmanInspectExecutor(
            PodmanClient(runner=FakeRunner(command_result(0, stdout="not-json")))
        ).execute(ContainerInspectProbe("runtime"))
        for result in (missing, malformed):
            self.assertIs(
                result.observation,
                ProbeObservation.INFRASTRUCTURE_FAILURE,
            )

    def test_container_policy_predicates_use_typed_inspection(self) -> None:
        stdout = inspection_json(
            networks=("egress", "internal"),
            user="10001:10001",
            read_only=True,
            published_ports=False,
        )
        executor = PodmanInspectExecutor(
            PodmanClient(runner=FakeRunner(command_result(0, stdout=stdout)))
        )
        networks = executor.execute(
            ContainerPolicyProbe(
                "runtime",
                ContainerPolicyCondition.NETWORKS_EXACT,
                expected_items=("internal", "egress"),
            )
        )
        self.assertIs(networks.observation, ProbeObservation.REACHED)

        for condition in (
            ContainerPolicyCondition.NO_PUBLISHED_PORTS,
            ContainerPolicyCondition.READ_ONLY_ROOT,
        ):
            runner = FakeRunner(command_result(0, stdout=stdout))
            result = PodmanInspectExecutor(PodmanClient(runner=runner)).execute(
                ContainerPolicyProbe("runtime", condition)
            )
            self.assertIs(result.observation, ProbeObservation.REACHED)

        runner = FakeRunner(command_result(0, stdout=stdout))
        user = PodmanInspectExecutor(PodmanClient(runner=runner)).execute(
            ContainerPolicyProbe(
                "runtime",
                ContainerPolicyCondition.USER_EQUALS,
                expected_text="10001:10001",
            )
        )
        self.assertIs(user.observation, ProbeObservation.REACHED)


if __name__ == "__main__":
    unittest.main()
