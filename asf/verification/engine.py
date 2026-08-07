"""Shared, fail-closed verification engine."""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import InfrastructureError
from .checks import CheckResult, ProbeObservation, ProbeResult, VerificationCheck
from .executors import ProbeExecutor

__all__ = ["VerificationEngine", "VerificationReport"]


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Immutable aggregate of one verification run."""

    results: tuple[CheckResult, ...]

    def __post_init__(self) -> None:
        results = tuple(self.results)
        if any(not isinstance(result, CheckResult) for result in results):
            raise TypeError("verification report requires CheckResult values")
        object.__setattr__(self, "results", results)

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(
            result.passed for result in self.results
        )

    @property
    def failed(self) -> bool:
        return not self.passed

    @property
    def passed_count(self) -> int:
        return sum(result.passed for result in self.results)

    @property
    def failed_count(self) -> int:
        return len(self.results) - self.passed_count

    @property
    def infrastructure_failure_count(self) -> int:
        return sum(result.inconclusive for result in self.results)

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(result for result in self.results if result.failed)

    @property
    def blocking_failures(self) -> tuple[CheckResult, ...]:
        """Failures a fail-closed caller must abort on."""

        return tuple(result for result in self.results if result.blocking)

    @property
    def advisory_failures(self) -> tuple[CheckResult, ...]:
        """Failed advisory availability controls without policy evidence."""

        return tuple(
            result
            for result in self.results
            if result.failed and not result.blocking
        )

    def to_json_dict(self) -> dict:
        """Return one JSON-serialisable, redaction-safe report structure.

        Only the one-line probe summary and structural fields are included;
        raw probe stdout/stderr never enter the persisted record.
        """

        return {
            "passed": self.passed,
            "summary": self.summary(),
            "checks": [
                {
                    "description": result.check.description,
                    "expectation": result.check.expectation.value,
                    "advisory": result.check.advisory,
                    "observation": result.probe_result.observation.value,
                    "outcome": result.outcome.value,
                    "blocking": result.blocking,
                    "summary": result.probe_result.summary,
                    "returncode": result.probe_result.returncode,
                }
                for result in self.results
            ],
        }

    @property
    def inconclusive_results(self) -> tuple[CheckResult, ...]:
        return tuple(result for result in self.results if result.inconclusive)

    def summary(self) -> str:
        parts = [
            f"{self.failed_count} failed",
            f"{self.passed_count} passed",
        ]
        if self.infrastructure_failure_count:
            parts.append(
                f"{self.infrastructure_failure_count} inconclusive"
            )
        return ", ".join(parts)


@dataclass(frozen=True, slots=True)
class VerificationEngine:
    """Dispatch typed checks to the first executor that supports each probe."""

    executors: tuple[ProbeExecutor, ...]

    def __post_init__(self) -> None:
        executors = tuple(self.executors)
        if not executors:
            raise ValueError("verification engine requires at least one executor")
        for executor in executors:
            if not callable(getattr(executor, "supports", None)) or not callable(
                getattr(executor, "execute", None)
            ):
                raise TypeError(
                    "verification executors require supports() and execute()"
                )
        object.__setattr__(self, "executors", executors)

    def run_check(self, check: VerificationCheck) -> CheckResult:
        if not isinstance(check, VerificationCheck):
            raise TypeError("check must be a VerificationCheck")
        for executor in self.executors:
            if executor.supports(check.probe):
                try:
                    observed = executor.execute(check.probe)
                except InfrastructureError as exc:
                    observed = ProbeResult(
                        ProbeObservation.INFRASTRUCTURE_FAILURE,
                        f"verification executor failed: {exc}",
                    )
                if not isinstance(observed, ProbeResult):
                    observed = ProbeResult(
                        ProbeObservation.INFRASTRUCTURE_FAILURE,
                        "verification executor returned an invalid result",
                    )
                return CheckResult(check, observed)
        return CheckResult(
            check,
            ProbeResult(
                ProbeObservation.INFRASTRUCTURE_FAILURE,
                f"no executor supports {type(check.probe).__name__}",
            ),
        )

    def run(self, checks: tuple[VerificationCheck, ...]) -> VerificationReport:
        if not isinstance(checks, tuple):
            checks = tuple(checks)
        return VerificationReport(tuple(self.run_check(check) for check in checks))
