#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
from ipaddress import IPv4Network
from pathlib import Path
from unittest import mock

from asf.podman import PodmanClient
from asf.process import CommandResult
from asf.routed_allocation import (
    RoutedAllocationError,
    RoutedAllocator,
    allocate,
)
from asf.subnets import reservation_path


class AllocationTests(unittest.TestCase):
    def test_allocation_is_deterministic_non_overlapping_and_avoids_targets(self) -> None:
        pool = IPv4Network("10.203.0.0/16")
        avoid = (IPv4Network("10.203.20.0/24"),)
        first = allocate("session", 3, pool, 24, avoid)
        second = allocate("session", 3, pool, 24, avoid)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 3)
        for index, left in enumerate(first):
            self.assertFalse(left.overlaps(avoid[0]))
            for right in first[index + 1:]:
                self.assertFalse(left.overlaps(right))

    def test_full_pool_fails_closed(self) -> None:
        with self.assertRaises(RoutedAllocationError):
            allocate(
                "session",
                1,
                IPv4Network("10.90.0.0/24"),
                24,
                (IPv4Network("10.90.0.0/24"),),
            )


class Runner:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, **_kwargs) -> CommandResult:
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        if self.fail:
            return CommandResult(command, 1, "", "broken")
        if command[1:4] == ("network", "ls", "-q"):
            return CommandResult(command, 0, "", "")
        if command[:4] == ("ip", "-4", "route", "show"):
            return CommandResult(command, 0, "default via 192.0.2.1\n", "")
        return CommandResult(command, 0, "", "")


class ReservationTests(unittest.TestCase):
    def test_reservation_is_owned_by_session_and_lock_covers_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = Runner()
            allocator = RoutedAllocator(
                PodmanClient(runner=runner),
                runner=runner,
                reservation_root=root,
                sleeper=lambda _seconds: None,
            )
            with mock.patch("asf.routed_allocation.shutil.which", return_value=None):
                with allocator.reserve(
                    session="demo-session",
                    owner_pid=os.getpid(),
                    pool=IPv4Network("10.203.0.0/16"),
                    prefix=24,
                    avoid=(IPv4Network("192.168.50.0/24"),),
                ) as allocation:
                    target = reservation_path("demo-session", root)
                    self.assertTrue(target.exists())
                    payload = json.loads(target.read_text(encoding="utf-8"))
                    self.assertEqual(payload["pid"], os.getpid())
                    self.assertEqual(payload["subnets"], [
                        str(allocation.internal),
                        str(allocation.scan),
                        str(allocation.egress),
                    ])

    def test_discovery_failure_does_not_allocate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = Runner(fail=True)
            allocator = RoutedAllocator(
                PodmanClient(runner=runner),
                runner=runner,
                reservation_root=Path(temporary),
                sleeper=lambda _seconds: None,
            )
            with self.assertRaisesRegex(RoutedAllocationError, "command failed"):
                with allocator.reserve(
                    session="demo",
                    owner_pid=os.getpid(),
                    pool=IPv4Network("10.203.0.0/16"),
                    prefix=24,
                    avoid=(),
                ):
                    self.fail("allocation must not continue")


if __name__ == "__main__":
    unittest.main()
