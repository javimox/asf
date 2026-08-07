#!/usr/bin/env python3
"""Compatibility and regression tests for routed subnet allocation."""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from ipaddress import IPv4Network
from pathlib import Path
from unittest.mock import patch

from asf import routed_allocation as alloc
from asf.errors import ValidationError
from asf.process import CommandResult

POOL = IPv4Network("10.203.0.0/16")


def result(argv, status=0, stdout="", stderr="") -> CommandResult:
    command = tuple(str(item) for item in argv)
    return CommandResult(command, status, stdout, stderr)


class SequenceRunner:
    def __init__(self, values):
        self.values = iter(values)
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, **_kwargs):
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        value = next(self.values)
        return result(command, *value)


class DeterminismTests(unittest.TestCase):
    def test_same_session_gets_the_same_non_overlapping_subnets(self) -> None:
        first = alloc.allocate("session-x", 3, POOL, 24, ())
        second = alloc.allocate("session-x", 3, POOL, 24, ())
        self.assertEqual(first, second)
        for index, left in enumerate(first):
            for right in first[index + 1:]:
                self.assertFalse(left.overlaps(right))

    def test_different_sessions_spread(self) -> None:
        picks = {alloc.allocate(f"s{i}", 1, POOL, 24, ())[0] for i in range(20)}
        self.assertGreater(len(picks), 15)

    def test_avoids_taken_and_declared_target_ranges(self) -> None:
        avoid = (IPv4Network("10.88.0.0/17"), IPv4Network("10.203.50.0/24"))
        for index in range(10):
            picked = alloc.allocate(f"session-{index}", 1, POOL, 24, avoid)[0]
            self.assertFalse(any(picked.overlaps(item) for item in avoid))

    def test_invalid_or_exhausted_pools_fail_closed(self) -> None:
        with self.assertRaises((alloc.RoutedAllocationError, ValidationError)):
            alloc.allocate(
                "x", 1, IPv4Network("10.99.0.0/24"), 24,
                (IPv4Network("10.99.0.0/24"),),
            )
        with self.assertRaises((alloc.RoutedAllocationError, ValidationError)):
            alloc.allocate("x", 5, IPv4Network("10.99.0.0/22"), 24, ())
        with self.assertRaises((alloc.RoutedAllocationError, ValidationError)):
            alloc.allocate("x", 1, IPv4Network("10.99.0.0/24"), 16, ())
        with self.assertRaises((alloc.RoutedAllocationError, ValidationError)):
            alloc.allocate("x", 1, IPv4Network("10.99.0.0/24"), 29, ())


class DiscoveryTests(unittest.TestCase):
    def test_host_route_parsing_ignores_default(self) -> None:
        runner = SequenceRunner([(0, "default via 192.0.2.1\nlocal 127.0.0.0/8 dev lo table local\n", "")])
        self.assertEqual(
            alloc.host_routes(runner=runner),
            [IPv4Network("127.0.0.0/8")],
        )

    def test_podman_discovery_lists_then_inspects(self) -> None:
        runner = SequenceRunner([
            (0, "net1\n", ""),
            (0, '[{"name":"net1","subnets":[{"subnet":"10.99.0.0/24"}]}]\n', ""),
        ])
        self.assertEqual(
            alloc.podman_subnets("podman", runner=runner),
            [IPv4Network("10.99.0.0/24")],
        )
        self.assertEqual(runner.calls[0], ("podman", "network", "ls", "-q"))
        self.assertEqual(
            runner.calls[1],
            ("podman", "network", "inspect", "net1"),
        )

    def test_discovery_failures_are_not_treated_as_empty(self) -> None:
        runner = SequenceRunner([(127, "", "missing")])
        with self.assertRaisesRegex(alloc.RoutedAllocationError, "missing"):
            alloc.podman_subnets("podman", runner=runner)

    def test_libvirt_discovery_includes_inactive_networks(self) -> None:
        runner = SequenceRunner([
            (0, "default\n", ""),
            (0, "<network><ip address='192.168.122.1' prefix='24'/></network>", ""),
        ])
        with patch.object(alloc.shutil, "which", return_value="/usr/bin/virsh"):
            self.assertEqual(
                alloc.libvirt_subnets(runner=runner),
                [IPv4Network("192.168.122.0/24")],
            )


class ReservationTests(unittest.TestCase):
    def test_other_live_session_reservations_are_avoided(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            alloc.write_reservation(
                directory,
                "one",
                POOL,
                24,
                (IPv4Network("10.203.4.0/24"),),
                owner_pid=os.getpid(),
            )
            self.assertEqual(
                alloc.reserved_subnets(directory, "two"),
                [IPv4Network("10.203.4.0/24")],
            )

    def test_malformed_and_symlinked_reservations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "bad.json").write_text("not-json", encoding="utf-8")
            with self.assertRaises(alloc.RoutedAllocationError):
                alloc.reserved_subnets(directory)
            (directory / "bad.json").unlink()
            target = directory / "target"
            target.write_text("{}", encoding="utf-8")
            (directory / "link.json").symlink_to(target)
            with self.assertRaises(alloc.RoutedAllocationError):
                alloc.reserved_subnets(directory)

    def test_dead_and_legacy_reservations_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            alloc.write_reservation(
                directory,
                "dead",
                POOL,
                24,
                (IPv4Network("10.203.4.0/24"),),
                owner_pid=os.getpid(),
            )
            legacy = directory / "legacy.json"
            legacy.write_text(
                json.dumps({"session": "old", "subnets": ["10.203.5.0/24"]}),
                encoding="utf-8",
            )
            with patch.object(alloc, "_pid_alive", return_value=False):
                self.assertEqual(alloc.reserved_subnets(directory, "other"), [])
            self.assertEqual(list(directory.glob("*.json")), [])

    def test_release_and_lock_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaises(RuntimeError):
                with alloc.allocation_lock(directory):
                    raise RuntimeError("boom")
            with alloc.allocation_lock(directory):
                pass
            alloc.release_reservation(directory, "missing")

    def test_reservation_uses_explicit_owner_and_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            alloc.write_reservation(
                directory,
                "owned",
                POOL,
                24,
                (IPv4Network("10.203.4.0/24"),),
                owner_pid=424242,
            )
            path = next(directory.glob("*.json"))
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["pid"], 424242)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class CliTests(unittest.TestCase):
    def test_cli_requires_owner_when_reserving(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, redirect_stderr(io.StringIO()):
            self.assertEqual(
                alloc.main([
                    "--session", "demo", "--count", "1", "--no-probe",
                    "--reservation-dir", temporary,
                ]),
                1,
            )

    def test_cli_emits_json_and_fixed_shell_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            common = [
                "--session", "demo", "--count", "1", "--no-probe",
                "--no-reserve", "--reservation-dir", temporary,
            ]
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(alloc.main([*common, "--emit", "json"]), 0)
            self.assertEqual(len(json.loads(stdout.getvalue())), 1)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(alloc.main(common), 0)
            text = stdout.getvalue()
            self.assertIn("ASF_SUBNET_0_GATEWAY_IP=", text)
            self.assertIn("ASF_SUBNET_0_ROUTER_IP=", text)
            self.assertIn("ASF_SUBNET_0_RUNTIME_IP=", text)

    def test_gateway_spike_uses_its_parsed_runtime_address(self) -> None:
        root = Path(__file__).resolve().parents[1]
        spike = (root / "tests" / "spike-gateway-caps.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "SCAN_A_SUBNET SCAN_A_GW GW_A SCAN_A_RUNTIME",
            spike,
        )
        self.assertIn('load_rules "$GW_A" "$SCAN_A_RUNTIME"', spike)
        self.assertNotIn('$ASF_SUBNET_0_RUNTIME_IP', spike)

    def test_standalone_tool_is_a_thin_wrapper(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "tools" / "allocate_subnets.py").read_text(encoding="utf-8")
        self.assertIn("from asf.routed_allocation import main", source)
        self.assertNotIn("def allocate", source)


if __name__ == "__main__":
    unittest.main()
