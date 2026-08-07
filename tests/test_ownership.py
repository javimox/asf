"""Tests for session resource ownership and teardown ordering."""

from __future__ import annotations

import unittest

from asf.errors import ValidationError
from asf.ownership import (
    TEARDOWN_ORDER,
    Resource,
    ResourceKind,
    ResourceLedger,
    teardown_sequence,
)


class TeardownOrderTests(unittest.TestCase):
    def test_order_matches_current_bash_cleanup_sequence(self) -> None:
        self.assertEqual(
            TEARDOWN_ORDER,
            (
                ResourceKind.RUNTIME_CONTAINER,
                ResourceKind.BROKER_CONTAINER,
                ResourceKind.SECRET,
                ResourceKind.BROKER_STATE,
                ResourceKind.PROXY_CONTAINER,
                ResourceKind.GATEWAY_INIT_CONTAINER,
                ResourceKind.GATEWAY_CONTAINER,
                ResourceKind.NETWORK,
                ResourceKind.SUBNET_RESERVATION,
                ResourceKind.SESSION_LOCK,
            ),
        )

    def test_persistent_volumes_are_never_removed(self) -> None:
        self.assertNotIn(ResourceKind.VOLUME, TEARDOWN_ORDER)
        ledger = ResourceLedger(runtime="claude")
        ledger.record(ResourceKind.VOLUME, "state-volume")
        self.assertEqual(ledger.teardown(), ())
        self.assertEqual(len(ledger.preserved), 1)

    def test_stable_order_within_one_kind(self) -> None:
        resources = [
            Resource(ResourceKind.NETWORK, name, runtime="claude")
            for name in ("scan", "internal", "egress")
        ]
        self.assertEqual(
            [resource.name for resource in teardown_sequence(resources)],
            ["scan", "internal", "egress"],
        )


class LedgerTests(unittest.TestCase):
    def test_interrupted_startup_records_only_created_resources(self) -> None:
        ledger = ResourceLedger(runtime="claude")
        ledger.record(ResourceKind.SESSION_LOCK, "/lock", owner_pid=123)
        ledger.record(ResourceKind.NETWORK, "internal")
        self.assertEqual(
            [resource.kind for resource in ledger.teardown()],
            [ResourceKind.NETWORK, ResourceKind.SESSION_LOCK],
        )

    def test_duplicate_record_and_forget_are_idempotent(self) -> None:
        ledger = ResourceLedger(runtime="claude")
        resource = ledger.record(ResourceKind.NETWORK, "internal")
        ledger.record(ResourceKind.NETWORK, "internal")
        self.assertEqual(len(ledger.created), 1)
        ledger.forget(resource)
        ledger.forget(resource)
        self.assertEqual(ledger.created, ())

    def test_extend_validates_values(self) -> None:
        ledger = ResourceLedger(runtime="claude")
        ledger.extend((Resource(ResourceKind.NETWORK, "internal"),))
        with self.assertRaises(TypeError):
            ledger.extend(("bad",))  # type: ignore[arg-type]

    def test_invalid_resource_values_use_shared_validation_errors(self) -> None:
        for name in ("", "   ", "bad\x00name"):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                Resource(ResourceKind.NETWORK, name)
        with self.assertRaises(ValidationError):
            Resource(ResourceKind.NETWORK, "net", owner_pid=0)


if __name__ == "__main__":
    unittest.main()
