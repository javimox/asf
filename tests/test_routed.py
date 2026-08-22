#!/usr/bin/env python3
from __future__ import annotations

import io
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import asf.routed as routed_module
from asf.errors import ConfigurationError
from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.podman import PodmanClient
from asf.process import CommandResult
from asf.routed import (
    GatewayHardening,
    RoutedGateway,
    RoutedGatewayError,
    RoutedRequest,
    RoutedService,
    parse_gateway_hardening,
    validate_capability_boundary,
)
from asf.runtime_plan import RoutedSubnetAllocation, build_runtime_plan

ROOT = Path(__file__).resolve().parents[1]
ZERO = "0000000000000000"
NET_ADMIN = "0000000000001000"


class RoutedFixture(unittest.TestCase):
    def request(
        self,
        root: Path | None = None,
        *,
        allow_persistent: bool = False,
    ) -> RoutedRequest:
        paths = RepoPaths.for_root(ROOT if root is None else root)
        manifest = load_model(ROOT / "agents" / "routed-scanner" / "example-runtime-ci-tested.yml")
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=False,
            routed_subnets=RoutedSubnetAllocation.parse(
                ("10.90.0.0/24", "10.91.0.0/24", "10.92.0.0/24")
            ),
        )
        return RoutedRequest(manifest, plan, allow_persistent)

    def commands(self, *, allow_persistent: bool = False) -> RoutedGateway:
        return RoutedGateway(
            self.request(allow_persistent=allow_persistent),
            "gateway-image",
        )

    def krun_request(self, root: Path | None = None) -> RoutedRequest:
        request = self.request(root)
        manifest = replace(
            request.manifest,
            runtime=replace(request.manifest.runtime, isolation="microvm"),
        )
        plan = replace(request.plan, runtime_isolation="microvm")
        return RoutedRequest(manifest, plan)


class CapabilityBoundaryTests(RoutedFixture):
    def test_gateway_holds_no_capability_by_default(self) -> None:
        argv = self.commands().gateway_argv()
        self.assertIn("--cap-drop=ALL", argv)
        self.assertNotIn("--cap-add=NET_ADMIN", argv)

    def test_only_initializer_carries_net_admin(self) -> None:
        commands = self.commands()
        holder = commands.gateway_argv()
        initializer = commands.initializer_argv()
        self.assertNotIn("--cap-add=NET_ADMIN", holder)
        self.assertIn("--cap-add=NET_ADMIN", initializer)

    def test_initializer_is_short_lived_and_borrows_gateway_namespace(self) -> None:
        commands = self.commands()
        argv = commands.initializer_argv()
        self.assertIn("--rm", argv)
        self.assertNotIn("-d", argv)
        self.assertIn(f"container:{commands.request.gateway.name}", argv)

    def test_persistent_fallback_is_explicit_and_labelled(self) -> None:
        commands = self.commands(allow_persistent=True)
        normal = commands.gateway_argv()
        persistent = commands.gateway_argv(persistent_net_admin=True)
        self.assertNotIn("--cap-add=NET_ADMIN", normal)
        self.assertIn("--cap-add=NET_ADMIN", persistent)
        self.assertIn("asf.persistent-net-admin=false", normal)
        self.assertIn("asf.persistent-net-admin=true", persistent)

    def test_no_new_privileges_is_always_set(self) -> None:
        commands = self.commands()
        for argv in (commands.gateway_argv(), commands.initializer_argv()):
            with self.subTest(argv=argv[:5]):
                self.assertIn("--security-opt=no-new-privileges", argv)

    def test_mutations_of_the_capability_boundary_fail_closed(self) -> None:
        commands = self.commands()
        holder = commands.gateway_argv()
        initializer = commands.initializer_argv()

        def remove(argv: tuple[str, ...], value: str) -> tuple[str, ...]:
            values = list(argv)
            values.remove(value)
            return tuple(values)

        mutations = {
            "gateway keeps default capabilities": (
                remove(holder, "--cap-drop=ALL"), initializer
            ),
            "gateway gains net admin": (
                holder[:-1] + ("--cap-add=NET_ADMIN", holder[-1]), initializer
            ),
            "initializer is not removed": (holder, remove(initializer, "--rm")),
            "initializer lacks net admin": (
                holder, remove(initializer, "--cap-add=NET_ADMIN")
            ),
            "initializer keeps default capabilities": (
                holder, remove(initializer, "--cap-drop=ALL")
            ),
            "initializer can gain privileges": (
                holder,
                remove(initializer, "--security-opt=no-new-privileges"),
            ),
            "initializer uses wrong namespace": (
                holder,
                tuple(
                    "container:wrong"
                    if value == f"container:{commands.request.gateway.name}"
                    else value
                    for value in initializer
                ),
            ),
        }
        for name, (mutated_holder, mutated_initializer) in mutations.items():
            with self.subTest(mutation=name):
                with self.assertRaises(ConfigurationError):
                    validate_capability_boundary(
                        mutated_holder,
                        mutated_initializer,
                        gateway_name=commands.request.gateway.name,
                        persistent=False,
                    )

    def test_generated_commands_satisfy_boundary_validation(self) -> None:
        commands = self.commands()
        validate_capability_boundary(
            commands.gateway_argv(),
            commands.initializer_argv(),
            gateway_name=commands.request.gateway.name,
            persistent=False,
        )
        validate_capability_boundary(
            commands.gateway_argv(persistent_net_admin=True),
            None,
            gateway_name=commands.request.gateway.name,
            persistent=True,
        )

    def test_krun_tap_device_is_only_given_to_short_lived_initializer(self) -> None:
        commands = RoutedGateway(self.krun_request(), "gateway-image")
        holder = commands.gateway_argv()
        initializer = commands.initializer_argv()
        self.assertNotIn("/dev/net/tun", holder)
        self.assertIn("/dev/net/tun", initializer)
        self.assertIn("ASF_TAP_NAME=tap0", initializer)
        self.assertIn("ASF_TAP_GATEWAY=10.90.0.1", initializer)


class HardeningVerificationTests(unittest.TestCase):
    def clean(self) -> GatewayHardening:
        return parse_gateway_hardening(f"{ZERO} {ZERO} 1", "1", "0")

    def test_clean_gateway_is_acceptable(self) -> None:
        hardening = self.clean()
        self.assertTrue(hardening.capability_less)
        self.assertTrue(hardening.acceptable)
        self.assertEqual(hardening.reasons(), ())

    def test_raw_proc_status_is_parsed_directly(self) -> None:
        status = (
            f"CapEff:\t{ZERO}\n"
            f"CapBnd:\t{ZERO}\n"
            "NoNewPrivs:\t1\n"
        )
        self.assertTrue(parse_gateway_hardening(status, "1", "0").acceptable)

    def test_each_security_mutation_is_rejected(self) -> None:
        mutations = (
            (f"{NET_ADMIN} {ZERO} 1", "1", "0"),
            (f"{ZERO} {NET_ADMIN} 1", "1", "0"),
            (f"{ZERO} {ZERO} 0", "1", "0"),
            (f"{ZERO} {ZERO} 1", "0", "0"),
            (f"{ZERO} {ZERO} 1", "1", "1"),
            ("malformed", "1", "0"),
        )
        for status, v4, v6 in mutations:
            with self.subTest(status=status, v4=v4, v6=v6):
                hardening = parse_gateway_hardening(status, v4, v6)
                self.assertFalse(hardening.acceptable)
                self.assertTrue(hardening.reasons())

    def test_persistent_gateway_must_really_have_net_admin(self) -> None:
        good = parse_gateway_hardening(f"{NET_ADMIN} {NET_ADMIN} 1", "1", "0")
        missing = parse_gateway_hardening(f"{ZERO} {ZERO} 1", "1", "0")
        self.assertTrue(good.persistent_acceptable)
        self.assertFalse(missing.persistent_acceptable)
        self.assertTrue(missing.reasons(persistent=True))


class GatewayCommandTests(RoutedFixture):
    def test_names_and_addresses_come_from_the_plan(self) -> None:
        commands = self.commands()
        argv = commands.gateway_argv()
        request = commands.request
        self.assertIn(request.gateway.name, argv)
        self.assertIn(
            f"{request.scan_network.name}:ip={request.gateway_scan_ip}", argv
        )
        self.assertIn(
            f"{request.egress_network.name}:ip={request.gateway_egress_ip}", argv
        )

    def test_gateway_joins_exactly_scan_and_routed_egress(self) -> None:
        argv = self.commands().gateway_argv()
        networks = [
            argv[index + 1]
            for index, value in enumerate(argv)
            if value == "--network"
        ]
        self.assertEqual(len(networks), 2)
        self.assertTrue(any("-scan:ip=" in value for value in networks))
        self.assertTrue(any("-routed-egress:ip=" in value for value in networks))

    def test_forwarding_sysctls_and_hardening_are_pinned(self) -> None:
        argv = self.commands().gateway_argv()
        for value in (
            "net.ipv4.ip_forward=1",
            "net.ipv6.conf.all.forwarding=0",
            "--read-only",
            "--pids-limit=32",
            "--memory=64m",
            "--stop-timeout=2",
        ):
            with self.subTest(value=value):
                self.assertIn(value, argv)

    def test_no_host_port_is_published(self) -> None:
        commands = self.commands()
        for argv in (commands.gateway_argv(), commands.initializer_argv()):
            self.assertFalse([value for value in argv if value in {"-p", "--publish"}])

    def test_inspection_reads_proc_status_directly(self) -> None:
        argv = self.commands().inspect_argv()
        self.assertEqual(argv[-2:], ("cat", "/proc/1/status"))
        self.assertNotIn("sh", argv)
        self.assertNotIn("awk", argv)

    def test_forwarding_is_read_per_family(self) -> None:
        commands = self.commands()
        self.assertIn("/proc/sys/net/ipv4/ip_forward", commands.forwarding_argv(4))
        self.assertIn(
            "/proc/sys/net/ipv6/conf/all/forwarding", commands.forwarding_argv(6)
        )
        with self.assertRaises(ValueError):
            commands.forwarding_argv(5)


class ScriptedRunner:
    def __init__(
        self,
        *,
        status_lines: tuple[str, ...] = (f"{ZERO} {ZERO} 1\n",),
        status_codes: tuple[int, ...] = (0,),
        forwarding_v4_status: int = 0,
        forwarding_v6_status: int = 0,
        initializer_exists_status: int = 1,
    ) -> None:
        self.status_lines = status_lines
        self.status_codes = status_codes
        self.status_index = 0
        self.forwarding_v4_status = forwarding_v4_status
        self.forwarding_v6_status = forwarding_v6_status
        self.initializer_exists_status = initializer_exists_status
        self.calls: list[tuple[str, ...]] = []
        self.inputs: list[str | None] = []

    def _status_result(self) -> tuple[int, str]:
        index = min(self.status_index, len(self.status_lines) - 1)
        code_index = min(self.status_index, len(self.status_codes) - 1)
        self.status_index += 1
        return self.status_codes[code_index], self.status_lines[index]

    def __call__(self, argv, **kwargs) -> CommandResult:
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        self.inputs.append(kwargs.get("input_text"))
        if command[1:3] == ("image", "exists"):
            return CommandResult(command, 0, "", "")
        if command[1:3] == ("container", "exists"):
            return CommandResult(command, self.initializer_exists_status, "", "")
        if command[-1:] == ("/proc/1/status",):
            status, output = self._status_result()
            return CommandResult(command, status, output, "")
        if command[-1:] == ("/proc/sys/net/ipv4/ip_forward",):
            return CommandResult(command, self.forwarding_v4_status, "1\n", "")
        if command[-1:] == ("/proc/sys/net/ipv6/conf/all/forwarding",):
            return CommandResult(command, self.forwarding_v6_status, "0\n", "")
        if command[-5:] == ("ip", "-o", "-4", "addr", "show"):
            return CommandResult(
                command,
                0,
                "2: eth0    inet 10.91.0.2/24 scope global eth0\n"
                "3: eth1    inet 10.92.0.2/24 scope global eth1\n",
                "",
            )
        if command[-7:] == (
            "ip", "-o", "-4", "addr", "show", "dev", "tap0"
        ):
            return CommandResult(
                command,
                0,
                "4: tap0    inet 10.90.0.1/30 scope global tap0\n",
                "",
            )
        return CommandResult(command, 0, "", "")


class LifecycleTests(RoutedFixture):
    def checkout(self, root: Path) -> Path:
        (root / "agents").mkdir(parents=True)
        (root / ".devcontainer").mkdir()
        (root / "secrets").mkdir()
        (root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        return root

    def test_start_writes_policy_runs_initializer_and_proves_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.checkout(Path(temporary) / "checkout")
            runner = ScriptedRunner(status_lines=(f"{ZERO} {ZERO} 1\n",) * 2)
            request = self.request(root)
            RoutedService(PodmanClient(runner=runner)).start(
                request, output=io.StringIO()
            )
            self.assertTrue(request.policy_path.is_file())
            policy = request.policy_path.read_text(encoding="utf-8")
            self.assertIn("policy drop", policy)
            self.assertIn(str(request.runtime_scan_ip), policy)
            initializer_calls = [
                call for call in runner.calls if request.initializer.name in call
            ]
            run_calls = [call for call in initializer_calls if "run" in call]
            self.assertEqual(len(run_calls), 1)
            index = runner.calls.index(run_calls[0])
            self.assertEqual(runner.inputs[index], policy)
            self.assertTrue(
                any(call[1:3] == ("container", "exists") for call in runner.calls)
            )

    def test_krun_start_creates_tap_and_writes_guest_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.checkout(Path(temporary) / "checkout")
            runner = ScriptedRunner(status_lines=(f"{ZERO} {ZERO} 1\n",) * 2)
            request = self.krun_request(root)
            RoutedService(PodmanClient(runner=runner)).start(
                request, output=io.StringIO()
            )
            policy = request.policy_path.read_text(encoding="utf-8")
            self.assertIn('iifname "tap0"', policy)
            self.assertIn("ip saddr 10.90.0.2", policy)
            self.assertIn("ip daddr 10.90.0.2 ct state established,related", policy)
            self.assertTrue(any("/dev/net/tun" in call for call in runner.calls))

    def test_initializer_that_remains_is_a_startup_failure(self) -> None:
        runner = ScriptedRunner(
            status_lines=(f"{ZERO} {ZERO} 1\n",) * 2,
            initializer_exists_status=0,
        )
        with self.assertRaisesRegex(RoutedGatewayError, "initializer remained"):
            RoutedService(PodmanClient(runner=runner)).start(
                self.request(), output=io.StringIO()
            )

    def test_initializer_exit_probe_infrastructure_failure_is_not_absence(self) -> None:
        runner = ScriptedRunner(
            status_lines=(f"{ZERO} {ZERO} 1\n",) * 2,
            initializer_exists_status=125,
        )
        with self.assertRaisesRegex(RoutedGatewayError, "verify routed initializer"):
            RoutedService(PodmanClient(runner=runner)).start(
                self.request(), output=io.StringIO()
            )

    def test_gateway_is_rechecked_after_initializer_exits(self) -> None:
        runner = ScriptedRunner(
            status_lines=(f"{ZERO} {ZERO} 1\n", f"{NET_ADMIN} {ZERO} 1\n")
        )
        with self.assertRaisesRegex(RoutedGatewayError, "changed after policy"):
            RoutedService(PodmanClient(runner=runner)).start(
                self.request(), output=io.StringIO()
            )

    def test_nonzero_status_read_is_rejected_even_with_plausible_output(self) -> None:
        runner = ScriptedRunner(
            status_lines=(f"{ZERO} {ZERO} 1\n",),
            status_codes=(1,),
        )
        with self.assertRaisesRegex(RoutedGatewayError, "capability-less"):
            RoutedService(PodmanClient(runner=runner)).start(
                self.request(), output=io.StringIO()
            )

    def test_nonzero_forwarding_read_is_rejected(self) -> None:
        for family, options in (
            (4, {"forwarding_v4_status": 1}),
            (6, {"forwarding_v6_status": 1}),
        ):
            with self.subTest(family=family):
                runner = ScriptedRunner(**options)
                with self.assertRaisesRegex(RoutedGatewayError, "capability-less"):
                    RoutedService(PodmanClient(runner=runner)).start(
                        self.request(), output=io.StringIO()
                    )

    def test_unsafe_holder_fails_without_explicit_fallback(self) -> None:
        runner = ScriptedRunner(status_lines=(f"{NET_ADMIN} {NET_ADMIN} 1\n",))
        with self.assertRaisesRegex(RoutedGatewayError, "capability-less"):
            RoutedService(PodmanClient(runner=runner)).start(
                self.request(), output=io.StringIO()
            )
        self.assertTrue(any(call[1:3] == ("rm", "-f") for call in runner.calls))

    def test_explicit_persistent_fallback_is_verified(self) -> None:
        runner = ScriptedRunner(
            status_lines=(
                f"{NET_ADMIN} {NET_ADMIN} 1\n",
                f"{NET_ADMIN} {NET_ADMIN} 1\n",
            )
        )
        RoutedService(PodmanClient(runner=runner)).start(
            self.request(allow_persistent=True), output=io.StringIO()
        )
        holder_runs = [
            call for call in runner.calls if call[1:3] == ("run", "-d")
        ]
        self.assertEqual(len(holder_runs), 2)
        self.assertNotIn("--cap-add=NET_ADMIN", holder_runs[0])
        self.assertIn("--cap-add=NET_ADMIN", holder_runs[1])
        self.assertFalse(
            any(call[1:3] == ("container", "exists") for call in runner.calls)
        )

    def test_persistent_fallback_without_net_admin_is_rejected(self) -> None:
        runner = ScriptedRunner(
            status_lines=(f"{NET_ADMIN} {NET_ADMIN} 1\n", f"{ZERO} {ZERO} 1\n")
        )
        with self.assertRaisesRegex(RoutedGatewayError, "failed verification"):
            RoutedService(PodmanClient(runner=runner)).start(
                self.request(allow_persistent=True), output=io.StringIO()
            )

    def test_host_requirements_fail_closed(self) -> None:
        service = RoutedService(PodmanClient(runner=ScriptedRunner()))
        with mock.patch("asf.routed.platform.system", return_value="Darwin"):
            with self.assertRaisesRegex(RoutedGatewayError, "Linux"):
                service.require_host()


class LoaderTests(RoutedFixture):
    def test_loader_removes_gateway_self_route_and_verifies_table(self) -> None:
        loader = routed_module._LOADER
        self.assertIn("ip route show", loader)
        self.assertIn("ip route del", loader)
        self.assertIn("$ASF_GW_SCAN_IP", loader)
        self.assertIn("nft -f -", loader)
        self.assertIn("nft list table inet asf_filter", loader)

    def test_targets_are_arguments_not_interpolated(self) -> None:
        commands = self.commands()
        argv = commands.initializer_argv()
        targets = tuple(str(item) for item in commands.request.destinations)
        self.assertEqual(argv[-len(targets):], targets)
        self.assertIn("-i", argv)

    def test_persistent_path_executes_inside_gateway(self) -> None:
        commands = self.commands()
        argv = commands.persistent_loader_argv()
        self.assertIn("exec", argv)
        self.assertNotIn("run", argv)
        self.assertIn(commands.request.gateway.name, argv)


if __name__ == "__main__":
    unittest.main()
