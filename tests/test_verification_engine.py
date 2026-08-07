"""Tests for shared verification dispatch and aggregation."""

from __future__ import annotations

import unittest
from dataclasses import dataclass

from asf.errors import InfrastructureError
from asf.verification import (
    PolicyExpectation,
    ProbeObservation,
    ProbeResult,
    RouteProbe,
    TcpProbe,
    VerificationCheck,
    VerificationEngine,
)
from asf.verification.checks import CheckResult
from asf.verification.engine import VerificationReport


@dataclass
class FakeExecutor:
    supported_type: type
    result: object

    def supports(self, probe: object) -> bool:
        return isinstance(probe, self.supported_type)

    def execute(self, probe: object) -> object:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class EngineTests(unittest.TestCase):
    def test_dispatches_to_first_supporting_executor(self) -> None:
        first = FakeExecutor(RouteProbe, ProbeResult(ProbeObservation.REACHED, "route"))
        second = FakeExecutor(TcpProbe, ProbeResult(ProbeObservation.REACHED, "tcp"))
        engine = VerificationEngine((first, second))
        result = engine.run_check(
            VerificationCheck(
                "tcp allowed",
                PolicyExpectation.ALLOW,
                TcpProbe("192.0.2.10", 443),
            )
        )
        self.assertTrue(result.passed)
        self.assertEqual(result.probe_result.summary, "tcp")

    def test_missing_executor_is_infrastructure_failure(self) -> None:
        engine = VerificationEngine(
            (
                FakeExecutor(
                    RouteProbe,
                    ProbeResult(ProbeObservation.REACHED, "route"),
                ),
            )
        )
        result = engine.run_check(
            VerificationCheck(
                "tcp denied",
                PolicyExpectation.DENY,
                TcpProbe("192.0.2.10", 443),
            )
        )
        self.assertFalse(result.passed)
        self.assertIs(
            result.probe_result.observation,
            ProbeObservation.INFRASTRUCTURE_FAILURE,
        )

    def test_expected_executor_infrastructure_error_is_fail_closed(self) -> None:
        engine = VerificationEngine(
            (FakeExecutor(TcpProbe, InfrastructureError("podman failed")),)
        )
        result = engine.run_check(
            VerificationCheck(
                "blocked target",
                PolicyExpectation.DENY,
                TcpProbe("192.0.2.10", 443),
            )
        )
        self.assertFalse(result.passed)
        self.assertIs(
            result.probe_result.observation,
            ProbeObservation.INFRASTRUCTURE_FAILURE,
        )

    def test_invalid_executor_result_is_infrastructure_failure(self) -> None:
        engine = VerificationEngine((FakeExecutor(TcpProbe, True),))
        result = engine.run_check(
            VerificationCheck(
                "allowed target",
                PolicyExpectation.ALLOW,
                TcpProbe("192.0.2.10", 443),
            )
        )
        self.assertFalse(result.passed)
        self.assertIn("invalid result", result.probe_result.summary)

    def test_report_aggregates_pass_fail_and_infrastructure(self) -> None:
        reached = FakeExecutor(
            TcpProbe,
            ProbeResult(ProbeObservation.REACHED, "reached"),
        )
        engine = VerificationEngine((reached,))
        report = engine.run(
            (
                VerificationCheck(
                    "allowed",
                    PolicyExpectation.ALLOW,
                    TcpProbe("192.0.2.10", 443),
                ),
                VerificationCheck(
                    "blocked",
                    PolicyExpectation.DENY,
                    TcpProbe("192.0.2.10", 443),
                ),
                VerificationCheck(
                    "unsupported route",
                    PolicyExpectation.DENY,
                    RouteProbe("198.51.100.10"),
                ),
            )
        )
        self.assertFalse(report.passed)
        self.assertTrue(report.failed)
        self.assertEqual(report.passed_count, 1)
        self.assertEqual(report.failed_count, 2)
        self.assertEqual(report.infrastructure_failure_count, 1)
        self.assertEqual(len(report.failures), 2)
        self.assertEqual(len(report.inconclusive_results), 1)
        self.assertEqual(report.summary(), "2 failed, 1 passed, 1 inconclusive")

    def test_report_constructor_normalises_and_validates_results(self) -> None:
        from asf.verification import CheckResult, VerificationReport

        check = VerificationCheck(
            "allowed",
            PolicyExpectation.ALLOW,
            TcpProbe("192.0.2.10", 443),
        )
        result = CheckResult(
            check, ProbeResult(ProbeObservation.REACHED, "reached")
        )
        report = VerificationReport([result])  # type: ignore[arg-type]
        self.assertEqual(report.results, (result,))
        with self.assertRaises(TypeError):
            VerificationReport((True,))  # type: ignore[arg-type]

    def test_empty_report_fails_closed(self) -> None:
        from asf.verification import VerificationReport

        report = VerificationReport(())
        self.assertFalse(report.passed)
        self.assertTrue(report.failed)

    def test_empty_or_invalid_engine_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            VerificationEngine(())
        with self.assertRaises(TypeError):
            VerificationEngine((object(),))  # type: ignore[arg-type]


class AdvisoryControlTests(unittest.TestCase):
    """The availability/security split introduced for the positive control."""

    @staticmethod
    def _advisory_check() -> VerificationCheck:
        return VerificationCheck(
            "allowlisted host is reachable through CONNECT",
            PolicyExpectation.ALLOW,
            TcpProbe("192.0.2.10", 443),
            advisory=True,
        )

    def test_inconclusive_advisory_failure_is_not_blocking(self) -> None:
        result = CheckResult(
            self._advisory_check(),
            ProbeResult(
                ProbeObservation.INFRASTRUCTURE_FAILURE, "upstream returned 502"
            ),
        )
        self.assertTrue(result.failed)
        self.assertFalse(result.blocking)
        report = VerificationReport((result,))
        self.assertTrue(report.failed)
        self.assertEqual(report.blocking_failures, ())
        self.assertEqual(report.advisory_failures, (result,))

    def test_explicit_denial_of_advisory_allow_stays_blocking(self) -> None:
        # A proxy DENYING an allowlisted host is a policy misconfiguration,
        # not an availability problem. The advisory downgrade must not apply.
        result = CheckResult(
            self._advisory_check(),
            ProbeResult(ProbeObservation.DENIED, "proxy returned HTTP 403"),
        )
        self.assertTrue(result.blocking)
        report = VerificationReport((result,))
        self.assertEqual(report.blocking_failures, (result,))
        self.assertEqual(report.advisory_failures, ())

    def test_non_advisory_failures_always_block(self) -> None:
        deny_check = VerificationCheck(
            "private destination is denied",
            PolicyExpectation.DENY,
            TcpProbe("10.0.0.1", 443),
        )
        for observation in (
            ProbeObservation.REACHED,
            ProbeObservation.INFRASTRUCTURE_FAILURE,
        ):
            with self.subTest(observation=observation):
                result = CheckResult(
                    deny_check, ProbeResult(observation, "observation")
                )
                self.assertTrue(result.blocking)

    def test_advisory_flag_must_be_boolean(self) -> None:
        with self.assertRaises(TypeError):
            VerificationCheck(
                "bad",
                PolicyExpectation.ALLOW,
                TcpProbe("192.0.2.10", 443),
                advisory="yes",  # type: ignore[arg-type]
            )

    def test_json_report_is_structural_and_redaction_safe(self) -> None:
        import json

        result = CheckResult(
            self._advisory_check(),
            ProbeResult(
                ProbeObservation.INFRASTRUCTURE_FAILURE,
                "upstream returned 502",
                returncode=50,
                stdout="raw probe stdout that must never be persisted",
            ),
        )
        report = VerificationReport((result,))
        payload = json.dumps(report.to_json_dict(), sort_keys=True)
        self.assertIn('"advisory": true', payload)
        self.assertIn('"blocking": false', payload)
        self.assertIn('"observation": "infrastructure_failure"', payload)
        self.assertNotIn("raw probe stdout", payload)


if __name__ == "__main__":
    unittest.main()
