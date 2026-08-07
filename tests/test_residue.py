"""Tests for read-only stale-session residue discovery."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.identity import ResourceIdentity
from asf.ownership import ResourceKind
from asf.podman import ObjectKind, PodmanCommandError
from asf.residue import ResidueScanner
from asf.session import SessionDiscovery
from asf.subnets import reservation_path


class FakePodman:
    def __init__(self) -> None:
        self.runtime_ids: dict[str, tuple[str, ...]] = {}
        self.role_ids: dict[tuple[str, str], tuple[str, ...]] = {}
        self.networks: set[str] = set()
        self.secrets: tuple[str, ...] = ()
        self.failure: Exception | None = None

    def container_ids(self, *, labels, include_stopped=False):  # noqa: ANN001
        if self.failure is not None:
            raise self.failure
        if isinstance(labels, dict):
            runtime = labels.get("asf.agent", "")
            role = labels.get("asf.role", "")
            return self.role_ids.get((runtime, role), ())
        label = tuple(labels)[0]
        for runtime, identifiers in self.runtime_ids.items():
            if label.endswith(f"-{runtime}"):
                return identifiers
        return ()

    def exists(self, reference: str, kind: ObjectKind = ObjectKind.CONTAINER) -> bool:
        if self.failure is not None:
            raise self.failure
        return kind is ObjectKind.NETWORK and reference in self.networks

    def secret_names(self) -> tuple[str, ...]:
        if self.failure is not None:
            raise self.failure
        return self.secrets


class ResidueScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / ".devcontainer").mkdir()
        (self.root / "agents" / "claude").mkdir(parents=True)
        (self.root / "agents" / "claude" / "runtime.yml").write_text(
            "name: claude\n"
        )
        self.identity = ResourceIdentity.from_physical_path(self.root)
        self.podman = FakePodman()
        self.discovery = SessionDiscovery(
            identity=self.identity,
            runtimes=("claude",),
            podman=self.podman,  # type: ignore[arg-type]
        )
        self.scanner = ResidueScanner(self.discovery)
        self.runtime_dir = self.root / "runtime"
        self.runtime_dir.mkdir()
        self.environment = mock.patch.dict(
            os.environ, {"XDG_RUNTIME_DIR": str(self.runtime_dir)}
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_clean_checkout_has_no_residue(self) -> None:
        residue = self.scanner.scan("claude")
        self.assertTrue(residue.empty)
        self.assertFalse(residue.is_stale)
        self.assertEqual(residue.summary(), "nothing left")

    def test_every_resource_kind_is_discovered_in_cleanup_order(self) -> None:
        self.podman.runtime_ids["claude"] = ("runtime-cid",)
        self.podman.role_ids.update(
            {
                ("claude", "broker"): ("broker-cid",),
                ("claude", "proxy"): ("proxy-cid",),
                ("claude", "routed-init"): ("init-cid",),
                ("claude", "routed-gateway"): ("gateway-cid",),
            }
        )
        networks = self.identity.network_names("claude")
        self.podman.networks.update(
            {
                networks.internal,
                networks.egress,
                networks.provider,
                networks.scan,
                networks.routed_egress,
            }
        )
        own_secret = self.identity.broker_secret_prefix("claude") + "123"
        self.podman.secrets = (own_secret, "unrelated-secret")

        lock = self.identity.session_lock("claude")
        lock.mkdir()
        (lock / "pid").write_text("4194304\n")
        broker_state = self.identity.broker_state("claude")
        broker_state.write_text("127.0.0.1:4000\n")
        reservation = reservation_path(
            self.identity.subnet_reservation_session("claude")
        )
        reservation.parent.mkdir(parents=True, exist_ok=True)
        reservation.write_text(
            json.dumps(
                {
                    "session": self.identity.subnet_reservation_session("claude"),
                    "pid": 4_194_304,
                    "subnets": ["10.89.1.0/28"],
                }
            )
        )

        residue = self.scanner.scan("claude")
        kinds = [resource.kind for resource in residue.resources()]
        self.assertEqual(
            kinds,
            [
                ResourceKind.RUNTIME_CONTAINER,
                ResourceKind.BROKER_CONTAINER,
                ResourceKind.SECRET,
                ResourceKind.BROKER_STATE,
                ResourceKind.PROXY_CONTAINER,
                ResourceKind.GATEWAY_INIT_CONTAINER,
                ResourceKind.GATEWAY_CONTAINER,
                *([ResourceKind.NETWORK] * 5),
                ResourceKind.SUBNET_RESERVATION,
                ResourceKind.SESSION_LOCK,
            ],
        )
        self.assertIn(own_secret, [resource.name for resource in residue.secrets])
        self.assertNotIn(
            "unrelated-secret", [resource.name for resource in residue.secrets]
        )
        self.assertTrue(residue.running)
        self.assertFalse(residue.is_stale)

    def test_stopped_container_and_dangling_broker_state_are_stale_residue(self) -> None:
        self.podman.runtime_ids["claude"] = ("stopped-cid",)
        state = self.identity.broker_state("claude")
        state.symlink_to(self.root / "missing")
        # The fake cannot distinguish running/all. Make the running query empty
        # after the all-container scan to model a stopped container.
        calls = 0
        original = self.podman.container_ids

        def container_ids(*, labels, include_stopped=False):  # noqa: ANN001
            nonlocal calls
            calls += 1
            if not include_stopped and not isinstance(labels, dict):
                return ()
            return original(labels=labels, include_stopped=include_stopped)

        self.podman.container_ids = container_ids  # type: ignore[method-assign]
        residue = self.scanner.scan("claude")
        self.assertTrue(residue.is_stale)
        self.assertIsNotNone(residue.broker_state)
        self.assertFalse(residue.empty)

    def test_active_or_being_claimed_lock_is_not_stale(self) -> None:
        lock = self.identity.session_lock("claude")
        lock.mkdir()
        residue = self.scanner.scan("claude")
        self.assertTrue(residue.active_lock)
        self.assertFalse(residue.is_stale)

    def test_failed_discovery_is_inconclusive_not_stale(self) -> None:
        self.podman.failure = PodmanCommandError("podman unavailable")
        residue = self.scanner.scan("claude")
        self.assertTrue(residue.inconclusive)
        self.assertFalse(residue.empty)
        self.assertFalse(residue.is_stale)
        self.assertTrue(residue.unreadable)

    def test_scan_all_and_stale_are_runtime_scoped(self) -> None:
        self.assertEqual([item.runtime for item in self.scanner.scan_all()], ["claude"])
        self.assertEqual(self.scanner.stale(), ())


if __name__ == "__main__":
    unittest.main()
