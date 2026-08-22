"""Focused tests for per-run observability directories."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from asf.observation_sessions import (
    begin_observation_session,
    current_observation_session,
    observation_artifact,
    read_observation_policy,
    write_observation_policy,
)
from asf.manifest import parse
from asf.paths import RepoPaths
from asf.routed_allocation import RoutedSubnetAllocation
from asf.runtime_plan import build_runtime_plan
from asf.session_events import record_session_event
from ipaddress import IPv4Network


def make_paths(root: Path) -> RepoPaths:
    (root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "agents").mkdir()
    (root / ".devcontainer").mkdir()
    return RepoPaths.for_root(root)


class ObservationSessionTests(unittest.TestCase):
    def test_each_open_gets_its_own_private_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            paths = make_paths(root)

            first = begin_observation_session(paths, "hermes")
            record_session_event(paths, "hermes", "session_start")
            first_events = observation_artifact(paths, "hermes", "events.jsonl")
            self.assertEqual(first_events.parent, first.directory)

            second = begin_observation_session(paths, "hermes")
            record_session_event(paths, "hermes", "session_start")
            second_events = observation_artifact(paths, "hermes", "events.jsonl")

            self.assertNotEqual(first.session_id, second.session_id)
            self.assertNotEqual(first.directory, second.directory)
            self.assertTrue(first_events.is_file())
            self.assertTrue(second_events.is_file())
            self.assertEqual(first.directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(second.directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                current_observation_session(paths, "hermes").session_id,
                second.session_id,
            )

    def test_policy_snapshot_is_private_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            paths = make_paths(root)
            manifest = parse(
                {
                    "name": "hermes",
                    "runtime": {"isolation": "microvm"},
                    "network": {
                        "mode": "routed",
                        "allow": [{"cidr": "192.0.2.10/32"}],
                    },
                    "capabilities": ["net_raw"],
                }
            )
            begin_observation_session(paths, "hermes")
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
            policy_path = write_observation_policy(paths, plan, manifest)
            policy = read_observation_policy(paths, "hermes")

            self.assertEqual(policy.isolation, "microvm")
            self.assertEqual(policy.network_mode, "routed")
            self.assertEqual(policy.capabilities, frozenset({"net_raw"}))
            self.assertEqual(str(policy.routed_rules[0].destination), "192.0.2.10/32")
            self.assertEqual(policy_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
