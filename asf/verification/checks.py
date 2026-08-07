"""Verification expectations, observations, checks, and immutable results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from collections.abc import Mapping

from .probes import (
    ContainerInspectProbe,
    DnsProbe,
    ContainerPolicyProbe,
    PlainHttpProxyProbe,
    Probe,
    ProxyConnectProbe,
    RouteProbe,
    RuntimeSecurityProbe,
    TcpProbe,
)

__all__ = [
    "CheckResult",
    "PolicyExpectation",
    "ProbeObservation",
    "Outcome",
    "ProbeResult",
    "VerificationCheck",
    "expectation_satisfied",
]


class PolicyExpectation(str, Enum):
    """The policy result a verification check expects."""

    ALLOW = "allow"
    DENY = "deny"


class ProbeObservation(str, Enum):
    """What the probe actually established."""

    REACHED = "reached"
    DENIED = "denied"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"


class Outcome(str, Enum):
    """Final result after combining expectation and observation."""

    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """One executor observation with redaction-safe diagnostic evidence."""

    observation: ProbeObservation
    summary: str
    returncode: int | None = None
    stdout: str = field(default="", repr=False)
    stderr: str = field(default="", repr=False)
    metadata: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({}),
        repr=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.observation, ProbeObservation):
            raise TypeError("observation must be a ProbeObservation")
        if not isinstance(self.summary, str):
            raise TypeError("probe result summary must be text")
        if not self.summary.strip():
            raise ValueError("probe result summary must not be empty")
        if any(character in self.summary for character in ("\x00", "\n", "\r")):
            raise ValueError("probe result summary must be one line")
        if self.returncode is not None and (
            isinstance(self.returncode, bool)
            or not isinstance(self.returncode, int)
        ):
            raise TypeError("probe return code must be an integer or None")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("probe output must be text")
        if not isinstance(self.metadata, Mapping):
            raise TypeError("probe metadata must be a mapping")
        copied: dict[str, str] = {}
        for key, value in self.metadata.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("probe metadata keys and values must be text")
            if any(
                character in key + value
                for character in ("\x00", "\n", "\r")
            ):
                raise ValueError("probe metadata must be one-line text")
            copied[key] = value
        object.__setattr__(self, "metadata", MappingProxyType(copied))

    @property
    def infrastructure_failed(self) -> bool:
        return self.observation is ProbeObservation.INFRASTRUCTURE_FAILURE


@dataclass(frozen=True, slots=True)
class VerificationCheck:
    """One named policy expectation bound to one typed probe.

    ``advisory`` marks an availability control rather than a security
    property: when such a check fails *inconclusively* (infrastructure
    failure, e.g. the upstream host is down), callers may degrade it to a
    warning. An explicit DENIED observation on an advisory ALLOW check is
    still a policy failure and remains blocking.
    """

    description: str
    expectation: PolicyExpectation
    probe: Probe
    advisory: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.advisory, bool):
            raise TypeError("check advisory flag must be boolean")
        if not isinstance(self.description, str):
            raise TypeError("check description must be text")
        if not self.description.strip():
            raise ValueError("check description must not be empty")
        if any(
            character in self.description
            for character in ("\x00", "\n", "\r")
        ):
            raise ValueError("check description must be one line")
        if not isinstance(self.expectation, PolicyExpectation):
            try:
                expectation = PolicyExpectation(self.expectation)
            except (TypeError, ValueError) as exc:
                raise ValueError("unsupported policy expectation") from exc
            object.__setattr__(self, "expectation", expectation)
        if not isinstance(
            self.probe,
            (
                DnsProbe,
                TcpProbe,
                ProxyConnectProbe,
                PlainHttpProxyProbe,
                RouteProbe,
                ContainerInspectProbe,
                ContainerPolicyProbe,
                RuntimeSecurityProbe,
            ),
        ):
            raise TypeError("check probe must be a typed verification probe")


@dataclass(frozen=True, slots=True)
class CheckResult:
    """The evaluated result of one verification check."""

    check: VerificationCheck
    probe_result: ProbeResult

    @property
    def outcome(self) -> Outcome:
        return (
            Outcome.PASS
            if expectation_satisfied(
                self.check.expectation,
                self.probe_result.observation,
            )
            else Outcome.FAIL
        )

    @property
    def passed(self) -> bool:
        return self.outcome is Outcome.PASS

    @property
    def failed(self) -> bool:
        return self.outcome is Outcome.FAIL

    @property
    def inconclusive(self) -> bool:
        """True when the probe produced no policy evidence."""

        return (
            self.probe_result.observation
            is ProbeObservation.INFRASTRUCTURE_FAILURE
        )

    @property
    def blocking(self) -> bool:
        """Whether this failure must abort a fail-closed caller.

        Advisory checks only stop blocking when they failed *without policy
        evidence*; an advisory ALLOW check that was explicitly DENIED is a
        real policy failure and stays blocking.
        """

        return self.failed and not (self.check.advisory and self.inconclusive)


_ALLOWED_MATRIX = {
    (PolicyExpectation.ALLOW, ProbeObservation.REACHED): True,
    (PolicyExpectation.ALLOW, ProbeObservation.DENIED): False,
    (PolicyExpectation.ALLOW, ProbeObservation.INFRASTRUCTURE_FAILURE): False,
    (PolicyExpectation.DENY, ProbeObservation.REACHED): False,
    (PolicyExpectation.DENY, ProbeObservation.DENIED): True,
    (PolicyExpectation.DENY, ProbeObservation.INFRASTRUCTURE_FAILURE): False,
}


def expectation_satisfied(
    expectation: PolicyExpectation,
    observation: ProbeObservation,
) -> bool:
    """Return the exhaustive policy matrix result.

    Infrastructure failure is never success, including for an expected denial.
    """

    if not isinstance(expectation, PolicyExpectation):
        raise TypeError("expectation must be a PolicyExpectation")
    if not isinstance(observation, ProbeObservation):
        raise TypeError("observation must be a ProbeObservation")
    return _ALLOWED_MATRIX[(expectation, observation)]
