#!/usr/bin/env python3
"""Permanent topology contract for every shipped runtime."""
from __future__ import annotations

import unittest
from ipaddress import IPv4Network
from pathlib import Path

from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.runtime_plan import NetworkRole, RoutedSubnetAllocation, build_runtime_plan
from asf.session import SessionRole

ROOT = Path(__file__).resolve().parents[2]


_ROUTED = RoutedSubnetAllocation(
    IPv4Network("10.77.10.0/24"),
    IPv4Network("10.77.11.0/24"),
    IPv4Network("10.77.12.0/24"),
)


class RuntimePlanContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.paths = RepoPaths.for_root(ROOT)

    def test_supported_mode_topologies_are_explicit(self) -> None:
        cases = (
            ("claude", True, ["internal", "egress", "provider"], ["broker", "proxy"]),
            ("claude", False, ["internal", "egress"], ["proxy"]),
            ("isolated-worker", True, ["internal", "provider"], ["broker"]),
            ("isolated-worker", False, ["internal"], []),
        )
        for runtime, broker, network_roles, support_roles in cases:
            with self.subTest(runtime=runtime, broker=broker):
                manifest = load_model(self.paths.identity.runtime_manifest(runtime))
                plan = build_runtime_plan(
                    manifest, paths=self.paths, owner_pid=4242,
                    broker_globally_enabled=broker,
                )
                self.assertEqual([item.role.value for item in plan.networks], network_roles)
                self.assertEqual(
                    [item.role.value for item in plan.support_containers], support_roles
                )
                self.assertNotIn(
                    "net_admin", {item.lower() for item in plan.runtime_container.capabilities}
                )

    def test_every_shipped_runtime_uses_identity_owned_names(self) -> None:
        identity = self.paths.identity
        for manifest_path in sorted(self.paths.agents_dir.glob("*/runtime.yml")):
            manifest = load_model(manifest_path)
            plan = build_runtime_plan(
                manifest, paths=self.paths, owner_pid=4242,
                broker_globally_enabled=True,
                routed_subnets=(
                    _ROUTED if manifest.network.mode == "routed" else None
                ),
            )
            with self.subTest(runtime=manifest.name):
                self.assertEqual(plan.resource_prefix, identity.prefix)
                self.assertEqual(plan.runtime_container.name, identity.container_name(manifest.name))
                self.assertEqual(plan.session_label, identity.session_label(manifest.name))
                self.assertEqual(
                    plan.persistent_volumes[-1].name,
                    identity.shell_history_volume(manifest.name),
                )
                for role, infix in (
                    (SessionRole.PROXY, "proxy"),
                    (SessionRole.BROKER, "litellm"),
                ):
                    container = plan.container(role)
                    if container is not None:
                        self.assertEqual(
                            container.name,
                            identity.ephemeral_container(manifest.name, infix, 4242),
                        )

    def test_routed_network_options_are_frozen(self) -> None:
        manifest = load_model(ROOT / "examples" / "routed-runtime.yml")
        plan = build_runtime_plan(
            manifest, paths=self.paths, owner_pid=4242,
            broker_globally_enabled=False,
            routed_subnets=RoutedSubnetAllocation(
                IPv4Network("10.40.0.0/24"),
                IPv4Network("10.41.0.0/24"),
                IPv4Network("10.42.0.0/24"),
            ),
        )
        networks = {item.role: item for item in plan.networks}
        self.assertTrue(networks[NetworkRole.INTERNAL].no_default_route)
        self.assertTrue(networks[NetworkRole.SCAN].no_default_route)
        self.assertFalse(networks[NetworkRole.ROUTED_EGRESS].no_default_route)
        self.assertIsNotNone(plan.container(SessionRole.ROUTED_GATEWAY))
        self.assertIsNotNone(plan.container(SessionRole.ROUTED_INIT))


if __name__ == "__main__":
    unittest.main()
