#!/usr/bin/env python3
"""Focused startup network verification tests."""
from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.podman import PodmanClient
from asf.process import CommandResult
from asf.routed import RoutedRequest
from asf.runtime_plan import RoutedSubnetAllocation, build_runtime_plan
from asf.startup_verification import StartupVerifier, _persist_verification_report
from asf.verification.checks import PolicyExpectation, VerificationCheck
from asf.verification.engine import VerificationEngine, VerificationReport
from asf.verification.probes import TcpProbe

ROOT = Path(__file__).resolve().parents[1]


class RecordingRunner:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, **kwargs) -> CommandResult:
        del kwargs
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        return CommandResult(command, self.returncode, "", "")


class VerificationReportPersistenceTests(unittest.TestCase):
    def test_report_is_persisted_without_temporary_residue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "session" / "verification-report.json"
            output = io.StringIO()

            _persist_verification_report(
                VerificationReport(()), destination, output
            )

            self.assertTrue(destination.exists())
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(
                list(destination.parent.glob(".verification-report.json.*")),
                [],
            )


class StartupVerifierTests(unittest.TestCase):
    def test_startup_probes_reuse_one_hardened_container(self) -> None:
        runner = RecordingRunner()
        podman = PodmanClient(runner=runner)
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(ROOT / "agents" / "claude" / "runtime.yml")
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=False,
        )
        verifier = StartupVerifier(podman)
        internal = plan.networks[0].name

        checks = (
            VerificationCheck(
                "first", PolicyExpectation.ALLOW, TcpProbe("192.0.2.10", 443)
            ),
            VerificationCheck(
                "second", PolicyExpectation.ALLOW, TcpProbe("192.0.2.11", 443)
            ),
        )
        with verifier._probe_executor(
            plan, "asf-probe:v2", network=internal
        ) as executor:
            report = VerificationEngine((executor,)).run(checks)

        self.assertTrue(report.passed)
        run_calls = [call for call in runner.calls if call[1:3] == ("run", "-d")]
        exec_calls = [call for call in runner.calls if call[1] == "exec"]
        remove_calls = [call for call in runner.calls if call[1:3] == ("rm", "-f")]
        self.assertEqual(len(run_calls), 1)
        self.assertEqual(len(exec_calls), 2)
        self.assertEqual(len(remove_calls), 1)
        run_argv = run_calls[0]
        self.assertIn("--read-only", run_argv)
        self.assertIn("--cap-drop=ALL", run_argv)
        self.assertIn("--security-opt=no-new-privileges", run_argv)
        self.assertIn("--pids-limit=32", run_argv)
        self.assertIn("--memory=64m", run_argv)
        self.assertIn("--stop-timeout=0", run_argv)
        container = run_argv[run_argv.index("--name") + 1]
        self.assertTrue(all(call[2] == container for call in exec_calls))
        self.assertEqual(remove_calls[0][-1], container)


    def test_routed_startup_without_live_verify_keeps_structural_checks(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=False,
            routed_subnets=RoutedSubnetAllocation.parse(
                ("10.90.0.0/24", "10.91.0.0/24", "10.92.0.0/24")
            ),
        )
        verifier = StartupVerifier(PodmanClient(runner=RecordingRunner()))
        routed = RoutedRequest(manifest, plan)
        captured: list[VerificationCheck] = []

        @contextmanager
        def probe_executor(*args, **kwargs):
            yield object()

        def run_checks(executor, checks, *, output):
            captured.extend(checks)
            return SimpleNamespace(failed=False, failures=())

        with (
            mock.patch.object(StartupVerifier, "_ensure_probe_image", return_value="probe"),
            mock.patch.object(StartupVerifier, "_probe_executor", side_effect=probe_executor),
            mock.patch.object(StartupVerifier, "_run_timed_checks", side_effect=run_checks),
            mock.patch("asf.startup_verification._host_tcp_open") as host_tcp_open,
        ):
            verifier.verify(
                plan,
                manifest,
                proxy=None,
                broker=None,
                routed=routed,
                output=io.StringIO(),
            )

        host_tcp_open.assert_not_called()
        descriptions = {check.description for check in captured}
        self.assertIn("runtime has no IPv4 default route", descriptions)
        self.assertIn("runtime has no IPv6 default route", descriptions)
        self.assertIn("route 192.0.2.10/32 is present", descriptions)
        self.assertIn("undeclared destination has no route", descriptions)
        self.assertIn("runtime cannot resolve external DNS", descriptions)
        self.assertNotIn("allowed routed TCP control is reachable", descriptions)
        self.assertNotIn("known-open blocked routed port is denied", descriptions)

    def _startup_descriptions(self, manifest_path: Path, *, brokered: bool) -> set[str]:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(manifest_path)
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=brokered,
        )
        verifier = StartupVerifier(PodmanClient(runner=RecordingRunner()))
        captured: list[VerificationCheck] = []

        @contextmanager
        def probe_executor(*args, **kwargs):
            yield object()

        def run_checks(executor, checks, *, output):
            captured.extend(checks)
            return VerificationReport(())

        proxy = SimpleNamespace(
            domains=tuple(manifest.network.allow_domains),
            port=3128,
        )
        broker = (
            SimpleNamespace(direct_domain="api.openai.com")
            if brokered
            else None
        )
        with (
            mock.patch.object(StartupVerifier, "_ensure_probe_image", return_value="probe"),
            mock.patch.object(StartupVerifier, "_probe_executor", side_effect=probe_executor),
            mock.patch.object(StartupVerifier, "_run_timed_checks", side_effect=run_checks),
        ):
            verifier.verify(
                plan, manifest, proxy=proxy, broker=broker, output=io.StringIO()
            )
        return {check.description for check in captured}

    def test_brokered_proxy_startup_uses_only_critical_deny_checks(self) -> None:
        descriptions = self._startup_descriptions(
            ROOT / "agents" / "hermes" / "runtime.yml", brokered=True
        )
        self.assertIn(
            "Caddy denies direct provider API api.openai.com", descriptions
        )
        self.assertFalse(any("loopback" in value for value in descriptions))
        self.assertFalse(any("private IPv" in value for value in descriptions))
        self.assertFalse(any("metadata" in value for value in descriptions))
        self.assertFalse(any("non-allowlisted" in value for value in descriptions))

    def test_unbrokered_proxy_startup_keeps_one_generic_deny_check(self) -> None:
        descriptions = self._startup_descriptions(
            ROOT / "agents" / "claude" / "runtime.yml", brokered=False
        )
        self.assertIn("Caddy denies a non-allowlisted destination", descriptions)
        self.assertFalse(any("loopback" in value for value in descriptions))
        self.assertFalse(any("private IPv" in value for value in descriptions))
        self.assertFalse(any("metadata" in value for value in descriptions))




if __name__ == "__main__":
    unittest.main()
