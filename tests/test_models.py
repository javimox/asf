#!/usr/bin/env python3
"""Focused tests for immutable ASF manifest models."""

from __future__ import annotations

import sys
import unittest
from dataclasses import FrozenInstanceError
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asf.models import (  # noqa: E402
    BuildArgument,
    EnvironmentVariable,
    NetworkPolicy,
    RoutedRule,
    RoutedVerification,
    RuntimeManifest,
    RuntimeSettings,
    StateVolume,
)


class ImmutabilityTests(unittest.TestCase):
    def test_manifest_and_nested_models_are_frozen(self) -> None:
        manifest = RuntimeManifest(name="demo")
        with self.assertRaises(FrozenInstanceError):
            manifest.name = "changed"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            manifest.runtime.mode = "service"  # type: ignore[misc]

    def test_collection_fields_are_immutable(self) -> None:
        manifest = RuntimeManifest(
            name="demo",
            state_volumes=(StateVolume("cache", "/cache"),),
            capabilities=frozenset({"net_raw"}),
        )
        self.assertIsInstance(manifest.state_volumes, tuple)
        self.assertIsInstance(manifest.capabilities, frozenset)

    def test_mapping_helpers_return_independent_copies(self) -> None:
        manifest = RuntimeManifest(
            name="demo",
            runtime=RuntimeSettings(
                build_arguments=(BuildArgument("FEATURE", "1"),),
            ),
            environment=(EnvironmentVariable("MODE", "safe"),),
        )
        env = manifest.environment_dict()
        build = manifest.build_arguments_dict()
        env["MODE"] = "changed"
        build["FEATURE"] = "changed"
        self.assertEqual(manifest.environment[0].value, "safe")
        self.assertEqual(manifest.runtime.build_arguments[0].value, "1")


class RoutedRuleTests(unittest.TestCase):
    def test_port_rule_checks_network_protocol_and_port(self) -> None:
        rule = RoutedRule(
            IPv4Network("192.0.2.0/24"),
            "tcp",
            (443, 8443),
        )
        self.assertTrue(rule.permits(IPv4Address("192.0.2.9"), "tcp", 443))
        self.assertFalse(rule.permits(IPv4Address("192.0.2.9"), "tcp", 22))
        self.assertFalse(rule.permits(IPv4Address("198.51.100.9"), "tcp", 443))
        self.assertFalse(rule.permits(IPv4Address("192.0.2.9"), "udp", 443))

    def test_any_ports_and_icmp_are_explicit(self) -> None:
        any_rule = RoutedRule(IPv4Network("192.0.2.1/32"), "udp", "any")
        icmp_rule = RoutedRule(IPv4Network("192.0.2.1/32"), "icmp_echo")
        address = IPv4Address("192.0.2.1")
        self.assertTrue(any_rule.permits(address, "udp", 53))
        self.assertTrue(icmp_rule.permits(address, "icmp_echo"))
        self.assertFalse(icmp_rule.permits(address, "icmp_echo", 8))

    def test_destination_only_rule_allows_any_supported_ip_protocol(self) -> None:
        rule = RoutedRule(IPv4Network("192.0.2.1/32"))
        address = IPv4Address("192.0.2.1")
        self.assertTrue(rule.permits(address, "tcp", 443))
        self.assertTrue(rule.permits(address, "udp", 53))
        self.assertTrue(rule.permits(address, "icmp_echo"))
        self.assertFalse(rule.permits(IPv4Address("192.0.2.2"), "tcp", 443))

    def test_verification_uses_typed_addresses_and_ports(self) -> None:
        verification = RoutedVerification(
            address=IPv4Address("192.0.2.9"),
            protocol="tcp",
            allowed_port=443,
            blocked_port=22,
        )
        policy = NetworkPolicy(
            mode="routed",
            routed_verification=verification,
        )
        self.assertEqual(policy.routed_verification.address, IPv4Address("192.0.2.9"))


if __name__ == "__main__":
    unittest.main()
