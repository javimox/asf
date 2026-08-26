#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asf.manifest import load_model  # noqa: E402
from asf.models import RoutedRule, RoutedVerification  # noqa: E402
from asf.ownership import ResourceKind  # noqa: E402
from asf.paths import PathEscapeError, RepoPaths  # noqa: E402
from asf.runtime_plan import (  # noqa: E402
    GeneratedFileKind,
    NetworkRole,
    RoutedSubnetAllocation,
    RuntimePlanError,
    build_runtime_plan,
    load_runtime_plan,
    read_runtime_plan,
    routed_broker_address,
    runtime_plan_path,
    validate_runtime_plan_context,
    write_runtime_plan,
)
from asf.session import SessionRole  # noqa: E402


ROUTED = RoutedSubnetAllocation(
    IPv4Network("10.77.10.0/24"),
    IPv4Network("10.77.11.0/24"),
    IPv4Network("10.77.12.0/24"),
)


class RuntimePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.paths = RepoPaths.for_root(ROOT)

    def plan(self, runtime: str, *, broker: bool = True):
        manifest = load_model(self.paths.identity.runtime_manifest(runtime))
        return build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=broker,
        )

    def test_proxy_topology_is_complete_and_immutable(self) -> None:
        plan = self.plan("claude")
        self.assertEqual(
            [network.role for network in plan.networks],
            [NetworkRole.INTERNAL, NetworkRole.EGRESS, NetworkRole.PROVIDER],
        )
        self.assertEqual(
            [container.role for container in plan.support_containers],
            [SessionRole.BROKER, SessionRole.PROXY],
        )
        self.assertEqual(
            [item.network for item in plan.runtime_container.attachments],
            [self.paths.identity.network_names("claude").internal],
        )
        with self.assertRaises(FrozenInstanceError):
            plan.runtime = "other"  # type: ignore[misc]

    def test_isolated_mode_has_no_runtime_egress(self) -> None:
        plan = self.plan("isolated-worker")
        self.assertEqual(
            [network.role for network in plan.networks],
            [NetworkRole.INTERNAL, NetworkRole.PROVIDER],
        )
        self.assertEqual(
            [container.role for container in plan.support_containers],
            [SessionRole.BROKER],
        )
        self.assertEqual(len(plan.runtime_container.attachments), 1)
        self.assertTrue(plan.networks[0].internal)

    def test_routed_krun_broker_gets_one_fixed_scan_endpoint(self) -> None:
        hermes = load_model(ROOT / "agents" / "hermes" / "runtime.yml")
        routed = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        manifest = replace(
            hermes,
            runtime=replace(hermes.runtime, isolation="microvm"),
            network=routed.network,
            capabilities=frozenset({"net_raw"}),
        )
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=True,
            routed_subnets=ROUTED,
        )
        broker = plan.container(SessionRole.BROKER)
        self.assertIsNotNone(broker)
        assert broker is not None
        scan = plan.network(NetworkRole.SCAN)
        self.assertIsNotNone(scan)
        assert scan is not None
        scan_attachment = next(
            item for item in broker.attachments if item.network == scan.name
        )
        self.assertEqual(str(scan_attachment.address), "10.77.11.3")
        self.assertEqual(str(routed_broker_address(plan)), "10.77.11.3")
        self.assertEqual(len(broker.attachments), 3)

    def test_global_broker_switch_removes_broker_and_provider_network(self) -> None:
        plan = self.plan("claude", broker=False)
        self.assertFalse(plan.broker_enabled)
        self.assertNotIn(NetworkRole.PROVIDER, [item.role for item in plan.networks])
        self.assertNotIn(SessionRole.BROKER, [item.role for item in plan.support_containers])
        self.assertNotIn(
            ResourceKind.SECRET,
            [item.kind for item in plan.ephemeral_resources],
        )

    def test_routed_topology_uses_the_explicit_allocation(self) -> None:
        manifest = load_model(ROOT / "agents" / "routed-scanner" / "example-runtime-ci-tested.yml")
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=True,
            routed_subnets=ROUTED,
        )
        self.assertEqual(
            [network.role for network in plan.networks],
            [NetworkRole.INTERNAL, NetworkRole.SCAN, NetworkRole.ROUTED_EGRESS],
        )
        scan = next(item for item in plan.networks if item.role is NetworkRole.SCAN)
        self.assertEqual(str(scan.gateway), "10.77.11.1")
        self.assertEqual(str(scan.routes[0].gateway), "10.77.11.2")
        self.assertEqual(str(scan.routes[0].destination), "192.0.2.10/32")
        self.assertEqual(
            str(plan.runtime_container.attachments[1].address),
            "10.77.11.10",
        )
        roles = [container.role for container in plan.support_containers]
        self.assertEqual(
            roles,
            [SessionRole.ROUTED_GATEWAY, SessionRole.ROUTED_INIT],
        )
        initializer = plan.support_containers[-1]
        self.assertEqual(initializer.capabilities, frozenset({"net_admin"}))
        self.assertEqual(
            initializer.network_namespace_of,
            plan.support_containers[-2].name,
        )
        self.assertIn(
            ResourceKind.SUBNET_RESERVATION,
            [item.kind for item in plan.ephemeral_resources],
        )

    def test_routed_krun_plan_records_gateway_resources_for_cleanup(self) -> None:
        manifest = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=False,
            routed_subnets=ROUTED,
        )

        self.assertEqual(plan.runtime_isolation, "microvm")
        self.assertEqual(
            [container.role for container in plan.support_containers],
            [SessionRole.ROUTED_GATEWAY, SessionRole.ROUTED_INIT],
        )
        kinds = {resource.kind for resource in plan.ephemeral_resources}
        self.assertIn(ResourceKind.RUNTIME_CONTAINER, kinds)
        self.assertIn(ResourceKind.GATEWAY_INIT_CONTAINER, kinds)
        self.assertIn(ResourceKind.GATEWAY_CONTAINER, kinds)
        self.assertIn(ResourceKind.SUBNET_RESERVATION, kinds)

    def test_routed_plan_routes_separate_negative_control_to_gateway(self) -> None:
        manifest = load_model(
            ROOT / "agents" / "routed-scanner" / "example-runtime-ci-tested.yml"
        )
        network = replace(
            manifest.network,
            routed_rules=(RoutedRule(IPv4Network("192.0.2.20/32")),),
            routed_verification=RoutedVerification(
                address=IPv4Address("192.0.2.20"),
                protocol="tcp",
                allowed_port=18080,
                blocked_address=IPv4Address("198.51.100.20"),
                blocked_port=18080,
            ),
        )
        plan = build_runtime_plan(
            replace(manifest, network=network),
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=False,
            routed_subnets=ROUTED,
        )
        scan = next(item for item in plan.networks if item.role is NetworkRole.SCAN)
        self.assertEqual(
            [str(route.destination) for route in scan.routes],
            ["192.0.2.20/32", "198.51.100.20/32"],
        )

    def test_routed_allocation_is_explicit_and_mode_scoped(self) -> None:
        routed = load_model(ROOT / "agents" / "routed-scanner" / "example-runtime-ci-tested.yml")
        with self.assertRaises(RuntimePlanError):
            build_runtime_plan(
                routed,
                paths=self.paths,
                owner_pid=1,
                broker_globally_enabled=False,
            )
        proxy = load_model(self.paths.identity.runtime_manifest("claude"))
        with self.assertRaises(RuntimePlanError):
            build_runtime_plan(
                proxy,
                paths=self.paths,
                owner_pid=1,
                broker_globally_enabled=False,
                routed_subnets=ROUTED,
            )

    def test_volumes_secrets_generated_files_and_ownership_share_existing_names(self) -> None:
        plan = self.plan("claude")
        identity = self.paths.identity
        self.assertEqual(
            [volume.name for volume in plan.persistent_volumes],
            [
                identity.state_volume("claude", "config"),
                identity.shell_history_volume("claude"),
            ],
        )
        self.assertEqual(plan.persistent_volumes[-1].target, "/commandhistory")
        self.assertEqual(
            [secret.filename for secret in plan.secret_files],
            ["common.env", "claude.env"],
        )
        self.assertTrue(
            all(secret.source.parent == self.paths.secrets_dir for secret in plan.secret_files)
        )
        kinds = {item.kind for item in plan.generated_files}
        self.assertEqual(
            kinds,
            {
                GeneratedFileKind.RUNTIME_PLAN,
                GeneratedFileKind.DEVCONTAINER,
                GeneratedFileKind.PROXY_POLICY,
            },
        )
        ephemeral_names = {item.name for item in plan.ephemeral_resources}
        self.assertTrue(
            {volume.name for volume in plan.persistent_volumes}.isdisjoint(ephemeral_names)
        )

    def test_every_shipped_manifest_builds_without_mutation(self) -> None:
        before = {
            runtime: runtime_plan_path(self.paths, runtime).exists()
            for runtime in (
                "claude",
                "crewai",
                "hermes",
                "isolated-worker",
                "langgraph",
                "python-agent",
                "smolagents",
            )
        }
        for runtime in before:
            with self.subTest(runtime=runtime):
                plan = self.plan(runtime)
                self.assertEqual(plan.runtime, runtime)
        after = {
            runtime: runtime_plan_path(self.paths, runtime).exists()
            for runtime in before
        }
        self.assertEqual(after, before)

    def test_json_is_deterministic_and_contains_no_secret_value(self) -> None:
        plan = self.plan("claude")
        first = json.dumps(plan.to_dict(), sort_keys=True)
        second = json.dumps(self.plan("claude").to_dict(), sort_keys=True)
        self.assertEqual(first, second)
        self.assertNotIn("API_KEY=", first)
        self.assertNotIn("provider_api_key", first)


class RuntimePlanInvariantTests(unittest.TestCase):
    """Security and ownership properties that every generated plan must keep."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.paths = RepoPaths.for_root(ROOT)

    def plan(self, runtime: str, *, broker: bool = True):
        manifest = load_model(self.paths.identity.runtime_manifest(runtime))
        return build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=broker,
        )

    def routed_plan(self):
        manifest = load_model(ROOT / "agents" / "routed-scanner" / "example-runtime-ci-tested.yml")
        return build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=False,
            routed_subnets=ROUTED,
        )

    def plans(self):
        return {
            "proxy-broker": self.plan("claude"),
            "proxy-direct": self.plan("claude", broker=False),
            "isolated-broker": self.plan("isolated-worker"),
            "isolated-offline": self.plan("isolated-worker", broker=False),
            "routed": self.routed_plan(),
        }

    def test_lookup_helpers_match_the_planned_topology(self) -> None:
        proxy = self.plan("claude")
        names = self.paths.identity.network_names("claude")
        self.assertTrue(proxy.needs_proxy)
        self.assertTrue(proxy.needs_broker)
        self.assertEqual(
            proxy.network_names,
            (names.internal, names.egress, names.provider),
        )
        self.assertEqual(
            proxy.container(SessionRole.PROXY).networks,
            (names.internal, names.egress),
        )
        self.assertIs(proxy.network(NetworkRole.INTERNAL), proxy.networks[0])

        isolated = self.plan("isolated-worker", broker=False)
        self.assertFalse(isolated.needs_proxy)
        self.assertFalse(isolated.needs_broker)
        self.assertIsNone(isolated.container(SessionRole.PROXY))
        self.assertIsNone(isolated.network(NetworkRole.EGRESS))

    def test_every_attachment_names_a_planned_network(self) -> None:
        for case, plan in self.plans().items():
            for container in plan.containers:
                for attachment in container.attachments:
                    with self.subTest(case=case, container=container.name):
                        self.assertIn(attachment.network, plan.network_names)

    def test_fixed_addresses_are_unique_inside_subnets_and_not_gateways(self) -> None:
        plan = self.routed_plan()
        by_name = {network.name: network for network in plan.networks}
        seen = set()
        checked = 0
        for container in plan.containers:
            for attachment in container.attachments:
                if attachment.address is None:
                    continue
                checked += 1
                network = by_name[attachment.network]
                with self.subTest(container=container.name, address=attachment.address):
                    self.assertIn(attachment.address, network.subnet)
                    self.assertNotEqual(attachment.address, network.gateway)
                    key = (attachment.network, attachment.address)
                    self.assertNotIn(key, seen)
                    seen.add(key)
        self.assertGreater(checked, 0)

    def test_only_internal_and_scan_networks_are_internal(self) -> None:
        confined = {NetworkRole.INTERNAL, NetworkRole.SCAN}
        for case, plan in self.plans().items():
            for network in plan.networks:
                with self.subTest(case=case, role=network.role.value):
                    self.assertEqual(network.internal, network.role in confined)

    def test_runtime_never_joins_an_external_network(self) -> None:
        external = {
            NetworkRole.EGRESS,
            NetworkRole.PROVIDER,
            NetworkRole.ROUTED_EGRESS,
        }
        for case, plan in self.plans().items():
            roles = {
                plan.networks[plan.network_names.index(name)].role
                for name in plan.runtime_container.networks
            }
            with self.subTest(case=case):
                self.assertTrue(roles.isdisjoint(external))

    def test_broker_never_joins_the_proxy_egress_network(self) -> None:
        for runtime in ("claude", "isolated-worker"):
            plan = self.plan(runtime)
            broker = plan.container(SessionRole.BROKER)
            with self.subTest(runtime=runtime):
                self.assertIsNotNone(broker)
                egress = plan.network(NetworkRole.EGRESS)
                if egress is not None:
                    self.assertNotIn(egress.name, broker.networks)

    def test_every_ephemeral_resource_is_removable_and_covers_topology(self) -> None:
        for case, plan in self.plans().items():
            recorded = {resource.name for resource in plan.ephemeral_resources}
            with self.subTest(case=case):
                self.assertTrue(
                    all(resource.removable for resource in plan.ephemeral_resources)
                )
                for container in plan.containers:
                    self.assertIn(container.name, recorded)
                for network in plan.networks:
                    self.assertIn(network.name, recorded)
                self.assertTrue(
                    {volume.name for volume in plan.persistent_volumes}.isdisjoint(
                        recorded
                    )
                )

    def test_only_the_routed_initializer_receives_net_admin(self) -> None:
        plan = self.routed_plan()
        holders = {
            container.role
            for container in plan.containers
            if "net_admin"
            in {capability.lower() for capability in container.capabilities}
        }
        self.assertEqual(holders, {SessionRole.ROUTED_INIT})

    def test_validation_rejects_an_external_runtime_attachment(self) -> None:
        plan = self.plan("claude")
        egress = plan.network(NetworkRole.EGRESS)
        self.assertIsNotNone(egress)
        runtime = replace(
            plan.runtime_container,
            attachments=(replace(plan.runtime_container.attachments[0], network=egress.name),),
        )
        with self.assertRaises(RuntimePlanError):
            replace(plan, runtime_container=runtime)

    def test_validation_rejects_an_incorrect_internal_flag(self) -> None:
        plan = self.plan("claude")
        networks = list(plan.networks)
        networks[1] = replace(networks[1], internal=True)
        with self.assertRaises(RuntimePlanError):
            replace(plan, networks=tuple(networks))

    def test_validation_rejects_a_gateway_address_collision(self) -> None:
        plan = self.routed_plan()
        scan = plan.network(NetworkRole.SCAN)
        self.assertIsNotNone(scan)
        runtime = replace(
            plan.runtime_container,
            attachments=(
                plan.runtime_container.attachments[0],
                replace(plan.runtime_container.attachments[1], address=scan.gateway),
            ),
        )
        with self.assertRaises(RuntimePlanError):
            replace(plan, runtime_container=runtime)


class RuntimePlanWriteTests(unittest.TestCase):
    @staticmethod
    def plan(runtime: str, *, broker: bool = True):
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(paths.identity.runtime_manifest(runtime))
        return build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=broker,
        )

    def test_session_symlink_cannot_redirect_the_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            outside = Path(temporary) / "outside"
            (root / "agents" / "demo").mkdir(parents=True)
            (root / ".devcontainer" / "sessions").mkdir(parents=True)
            outside.mkdir()
            (root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "agents" / "demo" / "runtime.yml").write_text(
                "name: demo\nnetwork:\n  mode: proxy\n",
                encoding="utf-8",
            )
            (root / ".devcontainer" / "sessions" / "demo").symlink_to(
                outside, target_is_directory=True
            )
            paths = RepoPaths.for_root(root)
            manifest = load_model(paths.identity.runtime_manifest("demo"))
            with self.assertRaises(PathEscapeError) as caught:
                build_runtime_plan(
                    manifest,
                    paths=paths,
                    owner_pid=17,
                    broker_globally_enabled=False,
                )
            self.assertIn("escapes", str(caught.exception))
            self.assertEqual(list(outside.iterdir()), [])

    def test_persisted_plan_round_trips_every_shipped_runtime(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        manifests = sorted((ROOT / "agents").glob("*/runtime.yml"))
        # Tripwire: adding or removing a shipped runtime must be a
        # deliberate act — update this count together with the change.
        self.assertEqual(len(manifests), 8)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for manifest_path in manifests:
                manifest = load_model(manifest_path)
                broker_states = [False]
                if manifest.llm is not None and manifest.llm.broker:
                    broker_states.append(True)
                for broker in broker_states:
                    plan = build_runtime_plan(
                        manifest,
                        paths=paths,
                        owner_pid=17,
                        broker_globally_enabled=broker,
                        routed_subnets=(
                            ROUTED
                            if manifest.network.mode == "routed"
                            else None
                        ),
                    )
                    output = directory / f"{manifest.name}-{broker}.json"
                    write_runtime_plan(plan, output)
                    loaded = read_runtime_plan(output)
                    with self.subTest(runtime=manifest.name, broker=broker):
                        self.assertEqual(loaded, plan)
                        self.assertEqual(loaded.to_dict(), plan.to_dict())
                        validate_runtime_plan_context(loaded, manifest, paths)

        self.assertIs(load_runtime_plan, read_runtime_plan)

    def test_persisted_resources_keep_runtime_and_owner_pid(self) -> None:
        plan = self.plan("claude")
        payload = plan.to_dict()
        persisted = payload["ephemeral_resources"]
        self.assertEqual(len(persisted), len(plan.ephemeral_resources))
        for encoded, resource in zip(persisted, plan.ephemeral_resources):
            self.assertEqual(encoded["runtime"], resource.runtime)
            self.assertEqual(encoded["owner_pid"], resource.owner_pid)

    def test_persisted_plan_rejects_unknown_fields_and_symlinks(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(paths.identity.runtime_manifest("claude"))
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=17,
            broker_globally_enabled=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / "plan.json"
            payload = plan.to_dict()
            payload["unexpected"] = True
            target.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(RuntimePlanError, "unknown unexpected"):
                load_runtime_plan(target)

            real = directory / "real.json"
            real.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
            link = directory / "link.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(RuntimePlanError, "must not be a symlink"):
                load_runtime_plan(link)

    def test_persisted_plan_requires_explicit_network_options(self) -> None:
        plan = self.plan("claude")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "plan.json"
            payload = plan.to_dict()
            payload["networks"][0].pop("no_default_route")
            output.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(RuntimePlanError, "missing no_default_route"):
                read_runtime_plan(output)

    def test_persisted_plan_rejects_lossy_or_tampered_resource_ownership(self) -> None:
        plan = self.plan("claude")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "plan.json"
            payload = plan.to_dict()
            resource = payload["ephemeral_resources"][0]
            resource.pop("runtime")
            output.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(RuntimePlanError, "missing runtime"):
                read_runtime_plan(output)

            payload = plan.to_dict()
            payload["ephemeral_resources"][0]["runtime"] = "hermes"
            output.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(RuntimePlanError, "another runtime"):
                read_runtime_plan(output)

            payload = plan.to_dict()
            payload["ephemeral_resources"][0]["owner_pid"] = plan.owner_pid
            output.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(RuntimePlanError, "invalid owner PID"):
                read_runtime_plan(output)

    def test_context_validation_rejects_identity_or_manifest_drift(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(paths.identity.runtime_manifest("claude"))
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=17,
            broker_globally_enabled=False,
        )
        with self.assertRaisesRegex(RuntimePlanError, "does not match"):
            validate_runtime_plan_context(
                replace(plan, runtime_container=replace(plan.runtime_container, name="other")),
                manifest,
                paths,
            )

    def test_atomic_write_and_json_round_trip(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(paths.identity.runtime_manifest("claude"))
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=17,
            broker_globally_enabled=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "plan.json"
            write_runtime_plan(plan, output)
            first = output.read_text(encoding="utf-8")
            write_runtime_plan(plan, output)
            self.assertEqual(output.read_text(encoding="utf-8"), first)
            self.assertFalse(any(output.parent.glob(f".{output.name}.*")))
        self.assertEqual(json.loads(json.dumps(plan.to_dict()))["runtime"], "claude")



if __name__ == "__main__":
    unittest.main()
