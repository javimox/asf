"""Tests for routed subnet reservation discovery."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from ipaddress import IPv4Network
from pathlib import Path

from asf.errors import ValidationError
from asf.subnets import read_reservation, reservation_path

ROOT = Path(__file__).resolve().parents[1]
DEAD_PID = 4_194_304


class ReservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write(self, session: str, payload: object) -> Path:
        path = reservation_path(session, self.directory)
        path.write_text(payload if isinstance(payload, str) else json.dumps(payload))
        return path

    def test_path_matches_the_production_allocator(self) -> None:
        from asf.routed_allocation import reservation_path as allocator_path

        for session in ("asf-abc-claude", "weird name-000000000000-a"):
            self.assertEqual(
                reservation_path(session, self.directory),
                allocator_path(session, self.directory),
            )

    def test_live_dead_legacy_and_absent_reservations(self) -> None:
        self.write(
            "live",
            {
                "session": "live",
                "pid": os.getpid(),
                "subnets": ["10.89.1.0/28"],
            },
        )
        live = read_reservation("live", self.directory)
        self.assertTrue(live.exists)
        self.assertFalse(live.is_stale)
        self.assertEqual(live.subnets, (IPv4Network("10.89.1.0/28"),))

        self.write("dead", {"session": "dead", "pid": DEAD_PID, "subnets": []})
        self.assertTrue(read_reservation("dead", self.directory).is_stale)

        self.write("legacy", {"session": "legacy", "subnets": []})
        self.assertTrue(read_reservation("legacy", self.directory).is_stale)

        absent = read_reservation("absent", self.directory)
        self.assertFalse(absent.exists)
        self.assertFalse(absent.is_stale)

    def test_corrupt_and_symlinked_records_are_unreadable_stale_residue(self) -> None:
        for payload in (
            "{not json",
            "[]",
            '{"pid": 1, "subnets": "nope"}',
            '{"pid": true, "subnets": []}',
            '{"pid": 1, "subnets": ["not-a-cidr"]}',
            '{"pid": 1, "subnets": ["2001:db8::/64"]}',
        ):
            with self.subTest(payload=payload):
                self.write("broken", payload)
                reservation = read_reservation("broken", self.directory)
                self.assertTrue(reservation.exists)
                self.assertTrue(reservation.unreadable)
                self.assertTrue(reservation.is_stale)

        target = self.directory / "external.json"
        target.write_text('{"pid": 1, "subnets": []}')
        link = reservation_path("link", self.directory)
        link.symlink_to(target)
        reservation = read_reservation("link", self.directory)
        self.assertTrue(reservation.exists)
        self.assertTrue(reservation.unreadable)

    def test_invalid_session_key_is_rejected(self) -> None:
        for value in ("", "bad\x00key"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                reservation_path(value, self.directory)


if __name__ == "__main__":
    unittest.main()
