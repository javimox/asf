"""Exhaustive tests for verification expectations and observations."""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from asf.verification import (
    CheckResult,
    Outcome,
    PolicyExpectation,
    ProbeObservation,
    ProbeResult,
    TcpProbe,
    VerificationCheck,
    expectation_satisfied,
)


class ExpectationMatrixTests(unittest.TestCase):
    def test_every_expectation_observation_combination(self) -> None:
        expected = {
            (PolicyExpectation.ALLOW, ProbeObservation.REACHED): True,
            (PolicyExpectation.ALLOW, ProbeObservation.DENIED): False,
            (
                PolicyExpectation.ALLOW,
                ProbeObservation.INFRASTRUCTURE_FAILURE,
            ): False,
            (PolicyExpectation.DENY, ProbeObservation.REACHED): False,
            (PolicyExpectation.DENY, ProbeObservation.DENIED): True,
            (
                PolicyExpectation.DENY,
                ProbeObservation.INFRASTRUCTURE_FAILURE,
            ): False,
        }
        actual = {
            (expectation, observation): expectation_satisfied(
                expectation,
                observation,
            )
            for expectation in PolicyExpectation
            for observation in ProbeObservation
        }
        self.assertEqual(actual, expected)

    def test_expected_deny_plus_infrastructure_failure_is_a_failure(self) -> None:
        check = VerificationCheck(
            "blocked destination",
            PolicyExpectation.DENY,
            TcpProbe("192.0.2.10", 443),
        )
        result = CheckResult(
            check,
            ProbeResult(
                ProbeObservation.INFRASTRUCTURE_FAILURE,
                "probe timed out",
            ),
        )
        self.assertFalse(result.passed)
        self.assertTrue(result.failed)
        self.assertIs(result.outcome, Outcome.FAIL)
        self.assertTrue(result.inconclusive)

    def test_matrix_rejects_untyped_values(self) -> None:
        with self.assertRaises(TypeError):
            expectation_satisfied(  # type: ignore[arg-type]
                "allow", ProbeObservation.REACHED
            )
        with self.assertRaises(TypeError):
            expectation_satisfied(  # type: ignore[arg-type]
                PolicyExpectation.ALLOW, "reached"
            )


class ResultModelTests(unittest.TestCase):
    def test_models_are_immutable_and_hide_output_from_repr(self) -> None:
        probe_result = ProbeResult(
            ProbeObservation.REACHED,
            "connected",
            returncode=0,
            stdout="sensitive output",
            stderr="diagnostic output",
            metadata={"executor": "host"},
        )
        check = VerificationCheck(
            "allowed endpoint",
            PolicyExpectation.ALLOW,
            TcpProbe("example.test", 443),
        )
        result = CheckResult(check, probe_result)

        self.assertTrue(result.passed)
        self.assertNotIn("sensitive output", repr(probe_result))
        self.assertNotIn("diagnostic output", repr(probe_result))
        self.assertEqual(dict(probe_result.metadata), {"executor": "host"})
        with self.assertRaises(TypeError):
            probe_result.metadata["new"] = "value"  # type: ignore[index]
        with self.assertRaises(FrozenInstanceError):
            check.description = "changed"  # type: ignore[misc]

    def test_result_validation_is_strict(self) -> None:
        with self.assertRaises(TypeError):
            ProbeResult("reached", "ok")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ProbeResult(ProbeObservation.REACHED, " ")
        with self.assertRaises(ValueError):
            ProbeResult(ProbeObservation.REACHED, "two\nlines")
        with self.assertRaises(TypeError):
            ProbeResult(
                ProbeObservation.REACHED,
                "ok",
                metadata={"count": 1},  # type: ignore[dict-item]
            )
        with self.assertRaises(ValueError):
            VerificationCheck(
                "",
                PolicyExpectation.ALLOW,
                TcpProbe("example.test", 443),
            )
        with self.assertRaises(ValueError):
            VerificationCheck(
                "two\nlines",
                PolicyExpectation.ALLOW,
                TcpProbe("example.test", 443),
            )
        with self.assertRaises(TypeError):
            VerificationCheck(
                "invalid probe",
                PolicyExpectation.ALLOW,
                object(),  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
