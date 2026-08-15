#!/usr/bin/env python3
"""Focused tests for plan-driven network creation."""

from __future__ import annotations

import io
import unittest
from pathlib import Path

from asf.manifest import load_model
from asf.networks import (
    CREATE_ATTEMPTS,
    NetworkCreationError,
    NetworkService,
    create_argv,
    remove_argv,
)
from asf.paths import RepoPaths
from asf.podman import PodmanClient
from asf.process import CommandResult
from asf.runtime_plan import (
    RoutedSubnetAllocation,
    build_runtime_plan,
)

ROOT = Path(__file__).resolve().parents[1]


class ScriptedRunner:
    def __init__(self, failures: int = 0, message: str = "") -> None:
        self.failures = failures
        self.message = message or "network already exists\n"
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, **_kwargs) -> CommandResult:
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        if command[1:3] == ("network", "create") and self.failures > 0:
            self.failures -= 1
            return CommandResult(command, 125, "", self.message)
        return CommandResult(command, 0, "", "")


class NetworkFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.paths = RepoPaths.for_root(ROOT)

    def plan(self, runtime: str = "claude", *, broker: bool = True):
        manifest = load_model(ROOT / "agents" / runtime / "runtime.yml")
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
            routed_subnets=RoutedSubnetAllocation.parse(
                ("10.90.0.0/24", "10.91.0.0/24", "10.92.0.0/24")
            ),
        )


class ArgvTests(NetworkFixture):
    def test_create_argv_uses_the_plan_label_internal_flag_and_name(self) -> None:
        plan = self.plan()
        for network in plan.networks:
            argv = create_argv(plan, network)
            with self.subTest(network=network.name):
                self.assertEqual(argv[:3], ("podman", "network", "create"))
                self.assertEqual(argv[3:5], ("--label", plan.sandbox_label))
                self.assertEqual("--internal" in argv, network.internal)
                self.assertEqual(argv[-1], network.name)
                self.assertEqual(argv.count("asf.sandbox="), 0)
                self.assertEqual(argv[4].count("asf.sandbox="), 1)

    def test_plain_networks_do_not_gain_routed_options(self) -> None:
        plan = self.plan()
        for network in plan.networks:
            argv = create_argv(plan, network)
            self.assertNotIn("--subnet", argv)
            self.assertNotIn("--gateway", argv)
            self.assertNotIn("--route", argv)
            self.assertNotIn("no_default_route=true", argv)

    def test_routed_network_options_match_the_accepted_topology(self) -> None:
        plan = self.routed_plan()
        by_role = {network.role.value: create_argv(plan, network) for network in plan.networks}
        internal = by_role["internal"]
        scan = by_role["scan"]
        egress = by_role["routed-egress"]
        self.assertIn("--internal", internal)
        self.assertIn("no_default_route=true", internal)
        self.assertIn("--subnet", internal)
        self.assertIn("--gateway", internal)
        self.assertNotIn("--route", internal)
        self.assertIn("--internal", scan)
        self.assertIn("no_default_route=true", scan)
        self.assertIn("--route", scan)
        self.assertNotIn("--internal", egress)
        self.assertNotIn("no_default_route=true", egress)
        self.assertIn("--subnet", egress)

    def test_removal_is_forced_and_idempotent(self) -> None:
        self.assertEqual(
            remove_argv("net-a"),
            ("podman", "network", "rm", "-f", "net-a"),
        )


class CreationTests(NetworkFixture):
    def service(self, runner: ScriptedRunner) -> NetworkService:
        return NetworkService(
            PodmanClient(runner=runner),
            sleeper=lambda _seconds: None,
        )

    def test_every_planned_network_is_removed_then_created_in_order(self) -> None:
        plan = self.plan()
        runner = ScriptedRunner()
        output = io.StringIO()
        self.service(runner).create(plan, output=output)

        for network in plan.networks:
            relevant = [call for call in runner.calls if call[-1] == network.name]
            self.assertEqual(relevant[0][1:4], ("network", "rm", "-f"))
            self.assertEqual(relevant[1][1:3], ("network", "create"))
        creates = [
            call[-1]
            for call in runner.calls
            if call[1:3] == ("network", "create")
        ]
        self.assertEqual(tuple(creates), plan.network_names)
        self.assertIn("Networks ready", output.getvalue())

    def test_isolated_and_broker_decisions_are_already_in_the_plan(self) -> None:
        for broker, expected_roles in (
            (False, {"internal"}),
            (True, {"internal", "provider"}),
        ):
            plan = self.plan("isolated-worker", broker=broker)
            runner = ScriptedRunner()
            self.service(runner).create(plan, output=io.StringIO())
            created = {
                network.role.value
                for network in plan.networks
                if any(
                    call[1:3] == ("network", "create")
                    and call[-1] == network.name
                    for call in runner.calls
                )
            }
            self.assertEqual(created, expected_roles)

    def test_rootless_name_removal_race_is_retried_and_bounded(self) -> None:
        plan = self.plan(broker=False)
        runner = ScriptedRunner(failures=CREATE_ATTEMPTS - 1)
        self.service(runner).create(plan, output=io.StringIO())
        first = plan.networks[0].name
        creates = [
            call
            for call in runner.calls
            if call[1:3] == ("network", "create") and call[-1] == first
        ]
        self.assertEqual(len(creates), CREATE_ATTEMPTS)

        failing = ScriptedRunner(failures=CREATE_ATTEMPTS + 2)
        with self.assertRaises(NetworkCreationError):
            self.service(failing).create(plan, output=io.StringIO())
        attempts = [
            call
            for call in failing.calls
            if call[1:3] == ("network", "create")
        ]
        self.assertEqual(len(attempts), CREATE_ATTEMPTS)

    def test_non_race_failure_is_not_retried_and_keeps_diagnostics(self) -> None:
        plan = self.plan(broker=False)
        runner = ScriptedRunner(failures=99, message="permission denied\n")
        with self.assertRaisesRegex(NetworkCreationError, "permission denied"):
            self.service(runner).create(plan, output=io.StringIO())
        creates = [
            call for call in runner.calls if call[1:3] == ("network", "create")
        ]
        self.assertEqual(len(creates), 1)

    def test_routed_networks_are_created_in_planned_order(self) -> None:
        plan = self.routed_plan()
        runner = ScriptedRunner()
        output = io.StringIO()
        self.service(runner).create(plan, output=output)
        created = tuple(
            call[-1]
            for call in runner.calls
            if call[1:3] == ("network", "create")
        )
        self.assertEqual(created, plan.network_names)
        self.assertIn("Routed networks ready", output.getvalue())


if __name__ == "__main__":
    unittest.main()
