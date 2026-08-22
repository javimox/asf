"""Focused tests for routed TAP network observation."""

from __future__ import annotations

import io
import os
import socket
import struct
import unittest
from dataclasses import replace
from ipaddress import IPv4Network
from pathlib import Path

from asf.manifest import load_model, parse
from asf.models import RoutedRule
from asf.network_observer import NetworkObserverService
from asf.network_observer_runtime import MAX_LOG_BYTES, _bounded_write, parse_frame
from asf.observation_sessions import begin_observation_session
from asf.ownership import ResourceKind
from asf.process import CommandResult
from asf.paths import RepoPaths
from asf.runtime_plan import build_runtime_plan
from asf.session import SessionRole

ROOT = Path(__file__).resolve().parents[1]


def _frame(src: str, dst: str, proto: int, transport: bytes) -> bytes:
    ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = proto
    ip[12:16] = socket.inet_aton(src)
    ip[16:20] = socket.inet_aton(dst)
    return ethernet + bytes(ip) + transport


class NetworkObserverPlanTests(unittest.TestCase):
    def test_network_activity_requires_routed_krun(self) -> None:
        with self.assertRaisesRegex(Exception, "requires network.mode: routed"):
            parse(
                {
                    "name": "worker",
                    "runtime": {"isolation": "container"},
                    "observability": {"network_activity": True},
                    "network": {
                        "mode": "proxy",
                        "verify_domain": "example.com",
                        "allow_domains": ["example.com"],
                    },
                }
            )

    def test_observer_has_net_raw_only_and_shares_gateway_namespace(self) -> None:
        manifest = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        manifest = replace(
            manifest,
            observability=replace(manifest.observability, network_activity=True),
            network=replace(
                manifest.network,
                routed_rules=(RoutedRule(IPv4Network("192.0.2.10/32")),),
            ),
        )
        from asf.routed_allocation import RoutedSubnetAllocation
        plan = build_runtime_plan(
            manifest,
            paths=RepoPaths.for_root(ROOT),
            owner_pid=4242,
            broker_globally_enabled=False,
            routed_subnets=RoutedSubnetAllocation(
                IPv4Network("10.76.1.0/24"),
                IPv4Network("10.77.1.0/24"),
                IPv4Network("10.79.1.0/24"),
            ),
        )
        observer = plan.container(SessionRole.NETWORK_OBSERVER)
        gateway = plan.container(SessionRole.ROUTED_GATEWAY)
        assert observer is not None and gateway is not None
        self.assertEqual(observer.capabilities, frozenset({"net_raw"}))
        self.assertEqual(observer.network_namespace_of, gateway.name)
        self.assertEqual(observer.attachments, ())
        self.assertIn(
            ResourceKind.NETWORK_OBSERVER_CONTAINER,
            {resource.kind for resource in plan.ephemeral_resources},
        )


class _ObserverPodman:
    engine = "podman"

    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def observe(self, argv, **kwargs):
        command = tuple(str(item) for item in argv)
        self.commands.append(command)
        return CommandResult(command, 0, "", "")


class NetworkObserverServiceTests(unittest.TestCase):
    def test_observer_container_has_net_raw_only(self) -> None:
        import tempfile
        from asf.routed_allocation import RoutedSubnetAllocation

        manifest = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        manifest = replace(
            manifest,
            observability=replace(manifest.observability, network_activity=True),
            network=replace(
                manifest.network,
                routed_rules=(RoutedRule(IPv4Network("192.0.2.10/32")),),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "agents").mkdir()
            (root / ".devcontainer").mkdir()
            paths = RepoPaths.for_root(root)
            begin_observation_session(paths, manifest.name)
            plan = build_runtime_plan(
                manifest,
                paths=paths,
                owner_pid=4242,
                broker_globally_enabled=False,
                routed_subnets=RoutedSubnetAllocation(
                    IPv4Network("10.76.1.0/24"),
                    IPv4Network("10.77.1.0/24"),
                    IPv4Network("10.79.1.0/24"),
                ),
            )
            fake = _ObserverPodman()
            NetworkObserverService(fake).start(paths, plan, output=io.StringIO())
            run = next(command for command in fake.commands if "run" in command)
            self.assertIn("--cap-drop=ALL", run)
            self.assertIn("--cap-add=NET_RAW", run)
            self.assertNotIn("--cap-add=NET_ADMIN", run)
            self.assertIn("--security-opt=no-new-privileges", run)
            self.assertIn("--read-only", run)
            gateway = plan.container(SessionRole.ROUTED_GATEWAY)
            assert gateway is not None
            self.assertIn(f"container:{gateway.name}", run)
            log = paths.session_artifact(
                manifest.name,
                "observability",
                begin_id := (root / ".devcontainer" / "sessions" / manifest.name / "observability" / "current").read_text().strip(),
                "network-activity.jsonl",
            )
            self.assertEqual(os.stat(log).st_mode & 0o777, 0o600)


class PacketParserTests(unittest.TestCase):
    def test_records_tcp_syn_udp_and_icmp_echo_only_from_guest(self) -> None:
        guest = "10.203.1.2"
        target = "192.0.2.10"
        tcp = bytearray(20)
        tcp[:4] = struct.pack("!HH", 50123, 22)
        tcp[13] = 0x02
        self.assertEqual(
            parse_frame(_frame(guest, target, 6, bytes(tcp)), guest),
            {
                "source": guest,
                "destination": target,
                "protocol": "tcp",
                "source_port": 50123,
                "destination_port": 22,
            },
        )

        udp = struct.pack("!HHHH", 50124, 53, 8, 0)
        self.assertEqual(parse_frame(_frame(guest, target, 17, udp), guest)["protocol"], "udp")
        self.assertEqual(
            parse_frame(_frame(guest, target, 1, bytes([8, 0]) + b"\x00" * 6), guest)["protocol"],
            "icmp_echo",
        )

        tcp[13] = 0x12  # SYN/ACK reply-like traffic is not an attempt.
        self.assertIsNone(parse_frame(_frame(guest, target, 6, bytes(tcp)), guest))
        self.assertIsNone(parse_frame(_frame("10.203.1.1", guest, 17, udp), guest))
        self.assertIsNone(parse_frame(_frame(guest, target, 17, udp), guest, target))

    def test_non_initial_ipv4_fragments_are_ignored(self) -> None:
        frame = bytearray(_frame("10.203.1.2", "192.0.2.10", 17, b"\x00" * 8))
        frame[20:22] = struct.pack("!H", 1)  # fragment offset = 1
        self.assertIsNone(parse_frame(bytes(frame), "10.203.1.2"))

    def test_network_log_stops_at_fixed_per_session_limit(self) -> None:
        output = io.StringIO()
        line = '{"event":"network_attempt","padding":"' + ("x" * 128) + '"}\n'
        truncated = '{"event":"network_activity_truncated"}\n'
        written, reached = _bounded_write(
            output,
            line,
            truncated,
            MAX_LOG_BYTES - len(truncated.encode("utf-8")),
        )
        self.assertTrue(reached)
        self.assertEqual(output.getvalue(), truncated)
        self.assertEqual(written, MAX_LOG_BYTES)


if __name__ == "__main__":
    unittest.main()
