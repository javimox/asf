"""Focused validation tests for protocol-specific probe specifications."""

from __future__ import annotations

import math
import unittest
from dataclasses import FrozenInstanceError

from asf.errors import ValidationError
from asf.verification import (
    ContainerCondition,
    DnsProbe,
    ContainerInspectProbe,
    ContainerPolicyCondition,
    ContainerPolicyProbe,
    NetworkFamily,
    PlainHttpProxyProbe,
    ProbeValidationError,
    ProxyConnectProbe,
    RouteProbe,
    RuntimeSecurityCondition,
    RuntimeSecurityProbe,
    TcpProbe,
)
from asf.secrets import SecretValue


class ProbeConstructionTests(unittest.TestCase):
    def test_all_probe_types_are_immutable_and_normalised(self) -> None:
        probes = (
            DnsProbe("example.test", 3),
            TcpProbe("192.0.2.10", 443, 4),
            ProxyConnectProbe("proxy", 3128, "example.test", 443, 5),
            PlainHttpProxyProbe(
                "proxy",
                3128,
                "http://example.test/path?x=1",
                6,
            ),
            RouteProbe("198.51.100.10", "ipv4", 7),
            ContainerInspectProbe("container-id", "running", 8),
            ContainerPolicyProbe(
                "container-id",
                "networks_exact",
                expected_items=("internal",),
            ),
            RuntimeSecurityProbe(
                "container-id",
                "capabilities_equal",
                expected_text="0000000000000000",
            ),
        )
        self.assertEqual(probes[0].timeout_seconds, 3.0)
        self.assertEqual(probes[1].timeout_seconds, 4.0)
        self.assertIs(probes[4].family, NetworkFamily.IPV4)
        self.assertIs(probes[5].condition, ContainerCondition.RUNNING)
        for probe in probes:
            with self.subTest(probe=type(probe).__name__):
                with self.assertRaises(FrozenInstanceError):
                    probe.timeout_seconds = 1  # type: ignore[misc]

    def test_probe_validation_errors_use_the_shared_hierarchy(self) -> None:
        self.assertTrue(issubclass(ProbeValidationError, ValidationError))

    def test_host_and_reference_validation(self) -> None:
        invalid = ("", " host", "host name", "192.0.2.0/24", "x\ny", "x\x00y")
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ProbeValidationError):
                    TcpProbe(value, 443)
        with self.assertRaises(ProbeValidationError):
            DnsProbe("host name")
        with self.assertRaises(TypeError):
            TcpProbe(1, 443)  # type: ignore[arg-type]
        with self.assertRaises(ProbeValidationError):
            ContainerInspectProbe("container id")
        with self.assertRaises(ProbeValidationError):
            ContainerPolicyProbe(
                "container",
                ContainerPolicyCondition.NETWORKS_EXACT,
            )
        with self.assertRaises(ProbeValidationError):
            RuntimeSecurityProbe(
                "container",
                RuntimeSecurityCondition.PROVIDER_CREDENTIAL_ABSENT,
                expected_text="API_KEY",
            )

    def test_port_and_timeout_validation(self) -> None:
        for port in (0, 65536, -1):
            with self.subTest(port=port):
                with self.assertRaises(ProbeValidationError):
                    TcpProbe("example.test", port)
        with self.assertRaises(TypeError):
            TcpProbe("example.test", True)  # type: ignore[arg-type]
        for timeout in (0, -1, math.inf, math.nan):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ProbeValidationError):
                    TcpProbe("example.test", 443, timeout)
        with self.assertRaises(TypeError):
            TcpProbe("example.test", 443, True)  # type: ignore[arg-type]

    def test_plain_http_url_is_constrained(self) -> None:
        invalid = (
            "",
            "https://example.test/",
            "http:///missing-host",
            "http://user:pass@example.test/",
            "http://example.test/#fragment",
            "http://example.test:99999/",
            "http://[::1",
        )
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(ProbeValidationError):
                    PlainHttpProxyProbe("proxy", 3128, url)

    def test_route_probe_can_query_the_default_route(self) -> None:
        probe = RouteProbe(family=NetworkFamily.IPV6)
        self.assertTrue(probe.queries_default_route)
        self.assertIsNone(probe.destination)

    def test_unknown_enum_values_are_rejected(self) -> None:
        with self.assertRaises(ProbeValidationError):
            RouteProbe("192.0.2.1", "other")  # type: ignore[arg-type]
        with self.assertRaises(ProbeValidationError):
            ContainerInspectProbe("container", "stopped")  # type: ignore[arg-type]
        with self.assertRaises(ProbeValidationError):
            ContainerPolicyProbe(
                "container", "other"  # type: ignore[arg-type]
            )
        with self.assertRaises(ProbeValidationError):
            RuntimeSecurityProbe(
                "container", "other"  # type: ignore[arg-type]
            )

    def test_provider_credential_probe_requires_opaque_secret(self) -> None:
        probe = RuntimeSecurityProbe(
            "runtime",
            RuntimeSecurityCondition.PROVIDER_CREDENTIAL_ABSENT,
            expected_text="OPENAI_API_KEY",
            secret=SecretValue("super-secret-token"),
        )
        self.assertNotIn("super-secret-token", repr(probe))


if __name__ == "__main__":
    unittest.main()
