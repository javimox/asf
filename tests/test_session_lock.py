"""Focused tests for atomic ASF session locks."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.errors import InfrastructureError, ValidationError
from asf.identity import ResourceIdentity
from asf.session_lock import (
    SessionAlreadyRunningError,
    SessionLockAcquireError,
    SessionLockManager,
    SessionLockOwnershipError,
)


class SessionLockManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / ".devcontainer").mkdir()
        self.identity = ResourceIdentity.from_physical_path(self.root)
        self.live: set[int] = set()
        self.manager = SessionLockManager(
            self.identity,
            process_alive=lambda pid: pid in self.live,
        )

    def test_snapshot_defaults_device_and_inode(self) -> None:
        from asf.session_lock import SessionLockSnapshot

        snapshot = SessionLockSnapshot(
            path=Path("/tmp/lock"), pid=1, owner_alive=True
        )
        self.assertEqual(snapshot.device, 0)
        self.assertEqual(snapshot.inode, 0)

    def test_acquire_writes_compatible_pid_and_release_removes_lock(self) -> None:
        lock = self.manager.acquire("claude", owner_pid=1234)

        self.assertEqual(lock.path, self.identity.session_lock("claude"))
        self.assertEqual((lock.path / "pid").read_text(), "1234\n")
        self.assertEqual(lock.path.stat().st_mode & 0o777, 0o700)
        self.assertEqual((lock.path / "pid").stat().st_mode & 0o777, 0o600)

        snapshot = self.manager.inspect("claude")
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(snapshot.pid, 1234)
        self.assertTrue(snapshot.is_stale)

        self.manager.release(lock)
        self.assertIsNone(self.manager.inspect("claude"))

    def test_live_owner_is_never_replaced(self) -> None:
        path = self.identity.session_lock("claude")
        path.mkdir()
        (path / "pid").write_text("4242\n")
        self.live.add(4242)

        with self.assertRaises(SessionAlreadyRunningError) as caught:
            self.manager.acquire("claude", owner_pid=1234)

        self.assertEqual(caught.exception.runtime, "claude")
        self.assertEqual(caught.exception.pid, 4242)
        self.assertEqual((path / "pid").read_text(), "4242\n")

    def test_dead_owner_lock_is_replaced(self) -> None:
        path = self.identity.session_lock("claude")
        path.mkdir()
        (path / "pid").write_text("4242\n")

        lock = self.manager.acquire("claude", owner_pid=1234)
        self.assertEqual((path / "pid").read_text(), "1234\n")
        self.assertFalse(tuple(path.parent.glob(f"{path.name}.stale-*")))
        self.manager.release(lock)

    def test_symlinked_devcontainer_directory_is_rejected(self) -> None:
        external = self.root / "external-devcontainer"
        external.mkdir()
        (self.root / ".devcontainer").rmdir()
        (self.root / ".devcontainer").symlink_to(
            external, target_is_directory=True
        )

        with self.assertRaises(SessionLockAcquireError):
            self.manager.acquire("claude", owner_pid=1234)
        self.assertFalse(tuple(external.iterdir()))

    def test_stale_symlink_is_removed_without_following_target(self) -> None:
        external = self.root / "external"
        external.mkdir()
        marker = external / "keep"
        marker.write_text("untouched")
        path = self.identity.session_lock("claude")
        path.symlink_to(external, target_is_directory=True)

        lock = self.manager.acquire("claude", owner_pid=1234)

        self.assertTrue(path.is_dir())
        self.assertFalse(path.is_symlink())
        self.assertEqual(marker.read_text(), "untouched")
        self.manager.release(lock)

    def test_release_refuses_to_delete_a_successor_lock(self) -> None:
        acquired = self.manager.acquire("claude", owner_pid=1234)
        old = acquired.path.with_name(acquired.path.name + ".old")
        os.replace(acquired.path, old)
        acquired.path.mkdir()
        (acquired.path / "pid").write_text("1234\n")

        with self.assertRaises(SessionLockOwnershipError):
            self.manager.release(acquired)

        self.assertTrue(acquired.path.is_dir())

    def test_remove_stale_refuses_live_lock_and_is_idempotent(self) -> None:
        path = self.identity.session_lock("claude")
        path.mkdir()
        (path / "pid").write_text("4242\n")
        self.live.add(4242)
        with self.assertRaises(SessionLockOwnershipError):
            self.manager.remove_stale("claude")
        self.assertTrue(path.exists())

        self.live.clear()
        self.assertTrue(self.manager.remove_stale("claude"))
        self.assertFalse(path.exists())
        self.assertFalse(self.manager.remove_stale("claude"))

    def test_remove_stale_does_not_delete_a_successor_lock(self) -> None:
        path = self.identity.session_lock("claude")
        path.mkdir()
        (path / "pid").write_text("4242\n")
        real_replace = os.replace

        def replace_with_successor(source, destination):  # noqa: ANN001
            real_replace(source, destination)
            if Path(source) == path and ".cleanup-" in Path(destination).name:
                path.mkdir()
                (path / "pid").write_text("9999\n")

        with mock.patch("asf.session_lock.os.replace", side_effect=replace_with_successor):
            self.assertTrue(self.manager.remove_stale("claude"))

        self.assertEqual((path / "pid").read_text(), "9999\n")

    def test_hold_releases_after_body_failure(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "boom"):
            with self.manager.hold("claude", owner_pid=1234):
                raise RuntimeError("boom")
        self.assertIsNone(self.manager.inspect("claude"))

    def test_different_runtimes_have_independent_locks(self) -> None:
        claude = self.manager.acquire("claude", owner_pid=1234)
        hermes = self.manager.acquire("hermes", owner_pid=1234)
        self.assertNotEqual(claude.path, hermes.path)
        self.manager.release(claude)
        self.manager.release(hermes)

    def test_owner_pid_and_liveness_failures_use_shared_errors(self) -> None:
        for invalid in (0, -1, True, 1.5, "1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValidationError):
                    self.manager.acquire("claude", owner_pid=invalid)  # type: ignore[arg-type]

        path = self.identity.session_lock("claude")
        path.mkdir()
        (path / "pid").write_text("1234\n")
        manager = SessionLockManager(
            self.identity,
            process_alive=lambda _pid: (_ for _ in ()).throw(OSError("boom")),
        )
        with self.assertRaises(SessionLockAcquireError):
            manager.inspect("claude")

    def test_stale_replacement_failure_restores_previous_lock(self) -> None:
        path = self.identity.session_lock("claude")
        path.mkdir()
        (path / "pid").write_text("4242\n")

        with mock.patch(
            "asf.session_lock._write_pid", side_effect=OSError("disk full")
        ):
            with self.assertRaises(SessionLockAcquireError):
                self.manager.acquire("claude", owner_pid=1234)

        self.assertEqual((path / "pid").read_text(), "4242\n")
        self.assertFalse(tuple(path.parent.glob(f"{path.name}.stale-*")))

    def test_pid_write_failure_does_not_leave_a_lock(self) -> None:
        path = self.identity.session_lock("claude")
        with mock.patch(
            "asf.session_lock._write_pid", side_effect=OSError("disk full")
        ):
            with self.assertRaises(SessionLockAcquireError):
                self.manager.acquire("claude", owner_pid=1234)
        self.assertFalse(path.exists())

    def test_errors_remain_under_the_shared_cli_boundary(self) -> None:
        for error in (
            SessionAlreadyRunningError("claude", 1),
            SessionLockAcquireError("x"),
            SessionLockOwnershipError("x"),
        ):
            self.assertIsInstance(error, InfrastructureError)


class ClaimGraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / ".devcontainer").mkdir()
        self.identity = ResourceIdentity.from_physical_path(self.root)
        self.manager = SessionLockManager(
            self.identity,
            process_alive=lambda _pid: False,
        )

    def _age_lock(self, seconds: float) -> Path:
        from asf.session_lock import CLAIM_GRACE_SECONDS

        path = self.identity.session_lock("claude")
        timestamp = __import__("time").time() - max(seconds, CLAIM_GRACE_SECONDS + 1)
        os.utime(path, (timestamp, timestamp))
        return path

    def test_fresh_pidless_lock_is_treated_as_being_claimed(self) -> None:
        path = self.identity.session_lock("claude")
        path.mkdir()
        snapshot = self.manager.inspect("claude")
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertTrue(snapshot.being_claimed)
        self.assertFalse(snapshot.is_stale)
        with self.assertRaises(SessionAlreadyRunningError):
            self.manager.acquire("claude", owner_pid=1234)
        self.assertTrue(path.is_dir())

    def test_aged_pidless_and_malformed_locks_are_replaced(self) -> None:
        from asf.session_lock import CLAIM_GRACE_SECONDS

        for payload in (None, "not-a-pid\n"):
            with self.subTest(payload=payload):
                path = self.identity.session_lock("claude")
                path.mkdir()
                if payload is not None:
                    (path / "pid").write_text(payload)
                timestamp = __import__("time").time() - CLAIM_GRACE_SECONDS - 1
                os.utime(path, (timestamp, timestamp))
                acquired = self.manager.acquire("claude", owner_pid=1234)
                self.assertEqual((path / "pid").read_text(), "1234\n")
                self.manager.release(acquired)

    def test_lock_symlink_is_never_treated_as_an_in_progress_claim(self) -> None:
        target = self.root / "target"
        target.mkdir()
        path = self.identity.session_lock("claude")
        path.symlink_to(target, target_is_directory=True)
        snapshot = self.manager.inspect("claude")
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertFalse(snapshot.being_claimed)
        self.assertTrue(snapshot.is_stale)

    def test_public_process_alive_handles_invalid_and_current_pids(self) -> None:
        from asf.session_lock import process_alive

        self.assertTrue(process_alive(os.getpid()))
        self.assertFalse(process_alive(None))
        self.assertFalse(process_alive(0))
        self.assertFalse(process_alive(-1))


if __name__ == "__main__":
    unittest.main()
