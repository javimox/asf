"""Focused tests for private per-run evidence directories."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.runs import (
    begin_run,
    current_run,
    run_artifact,
    runs_root,
    read_run_policy,
    write_run_policy,
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
    with mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(root.parent / "state")}):
        return RepoPaths.for_root(root)


class RunTests(unittest.TestCase):
    def test_each_open_gets_its_own_private_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            paths = make_paths(root)

            first = begin_run(paths, "hermes")
            record_session_event(paths, "hermes", "session_start")
            first_events = run_artifact(paths, "hermes", "events.jsonl")
            self.assertEqual(first_events.parent, first.directory)

            second = begin_run(paths, "hermes")
            record_session_event(paths, "hermes", "session_start")
            second_events = run_artifact(paths, "hermes", "events.jsonl")

            self.assertNotEqual(first.session_id, second.session_id)
            self.assertNotEqual(first.directory, second.directory)
            self.assertTrue(first_events.is_file())
            self.assertTrue(second_events.is_file())
            self.assertEqual(first.directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(second.directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(first.directory.parent, runs_root(paths, "hermes"))
            with self.assertRaises(ValueError):
                first.directory.relative_to(paths.root)
            self.assertEqual(
                current_run(paths, "hermes").session_id,
                second.session_id,
            )

    def test_checkout_local_legacy_runs_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            paths = make_paths(root)
            session_id = "20260827T220000Z-0badcafe"
            legacy = paths.session_artifact("hermes", "runs")
            (legacy / session_id).mkdir(parents=True)
            (legacy / "current").write_text(session_id + "\n", encoding="utf-8")

            self.assertIsNone(current_run(paths, "hermes"))

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
            begin_run(paths, "hermes")
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
            policy_path = write_run_policy(paths, plan, manifest)
            policy = read_run_policy(paths, "hermes")

            self.assertEqual(policy.isolation, "microvm")
            self.assertEqual(policy.network_mode, "routed")
            self.assertEqual(policy.capabilities, frozenset({"net_raw"}))
            self.assertEqual(str(policy.routed_rules[0].destination), "192.0.2.10/32")
            self.assertEqual(policy_path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
