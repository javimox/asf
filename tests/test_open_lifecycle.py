"""Focused open cleanup and signal-supervision tests."""

from __future__ import annotations

import io
import os
import pty
import signal
import subprocess
import tempfile
import termios
import unittest
from pathlib import Path
from unittest import mock

from asf.cleanup import CleanupExecutor
from asf.errors import InfrastructureError
from asf.open_lifecycle import (
    OpenCleanupService,
    OpenLifecycleError,
    OpenSignal,
    SessionProcessResult,
    SessionProcessSupervisor,
    restore_terminal,
    run_open_session,
)
from asf.residue import ResidueScanner
from asf.session import SessionDiscovery
from asf.stop import StopService
from tests.test_stop import StatePodman, make_checkout


class FakeProcess:
    def __init__(self, returncode: int = 0, *, on_wait=None) -> None:  # noqa: ANN001
        self.returncode = returncode
        self.on_wait = on_wait
        self.signals: list[int] = []

    def wait(self, timeout=None) -> int:  # noqa: ANN001
        if self.on_wait is not None:
            callback, self.on_wait = self.on_wait, None
            callback()
        return self.returncode

    def send_signal(self, signum: int) -> None:
        self.signals.append(signum)

    def kill(self) -> None:
        self.returncode = -signal.SIGKILL


class StubbornProcess(FakeProcess):
    def __init__(self, *, on_wait=None) -> None:  # noqa: ANN001
        super().__init__(0, on_wait=on_wait)
        self.killed = False

    def wait(self, timeout=None) -> int:  # noqa: ANN001
        if self.on_wait is not None:
            callback, self.on_wait = self.on_wait, None
            callback()
        if not self.killed and timeout is not None:
            raise subprocess.TimeoutExpired(("child",), timeout)
        return -signal.SIGKILL if self.killed else self.returncode

    def kill(self) -> None:
        self.killed = True


class ProductionBoundaryTests(unittest.TestCase):
    def test_open_lock_supervision_and_cleanup_are_python_owned(self) -> None:
        root = Path(__file__).resolve().parents[1]
        sandbox = (root / "sandbox.sh").read_text()
        runtime = (root / "asf" / "runtime.py").read_text()
        self.assertIn("exec python3 -m asf", sandbox)
        self.assertNotIn("source ", sandbox)
        self.assertFalse((root / "lib").exists())
        self.assertIn("lock_manager.acquire", runtime)
        self.assertIn("run_open_session", runtime)


class TerminalRestorationTests(unittest.TestCase):
    def test_raw_terminal_gets_echo_canonical_input_and_cursor(self) -> None:
        controller, follower = pty.openpty()
        self.addCleanup(os.close, controller)
        stream = os.fdopen(follower, "w")
        self.addCleanup(stream.close)
        attributes = termios.tcgetattr(stream.fileno())
        attributes[3] &= ~(termios.ECHO | termios.ICANON)
        termios.tcsetattr(stream.fileno(), termios.TCSANOW, attributes)

        self.assertTrue(restore_terminal(stream))

        restored = termios.tcgetattr(stream.fileno())
        self.assertTrue(restored[3] & termios.ECHO)
        self.assertTrue(restored[3] & termios.ICANON)
        self.assertIn(b"\x1b[?25h", os.read(controller, 64))

    def test_redirected_closed_and_nonstream_targets_are_ignored(self) -> None:
        redirected = io.StringIO()
        self.assertFalse(restore_terminal(redirected))
        self.assertEqual(redirected.getvalue(), "")
        redirected.close()
        self.assertFalse(restore_terminal(redirected))

        class Odd:
            pass

        self.assertFalse(restore_terminal(Odd()))


class SessionProcessSupervisorTests(unittest.TestCase):
    def test_environment_overlay_is_passed_only_when_requested(self) -> None:
        calls = []

        def spawn(*args, **kwargs):  # noqa: ANN001
            calls.append((args, kwargs))
            return FakeProcess(0)

        supervisor = SessionProcessSupervisor(popen_factory=spawn)
        supervisor.run(("child",), env={"ASF_TEST_SECRET": "value"})

        self.assertEqual(calls[0][0], (["child"],))
        self.assertFalse(calls[0][1]["shell"])
        self.assertEqual(calls[0][1]["env"]["ASF_TEST_SECRET"], "value")
        self.assertNotIn("ASF_TEST_SECRET", os.environ)

    def test_normal_and_signal_exit_statuses_are_explicit(self) -> None:
        normal = SessionProcessSupervisor(
            popen_factory=lambda *_args, **_kwargs: FakeProcess(42)
        )
        self.assertEqual(normal.run(("child",)).returncode, 42)

        for expected in OpenSignal:
            with self.subTest(signal=expected):
                handlers = {}
                child = FakeProcess()

                def install(signum, handler):  # noqa: ANN001
                    handlers[signum] = handler

                child.on_wait = lambda item=expected: handlers[item.number](
                    item.number, None
                )
                supervisor = SessionProcessSupervisor(
                    popen_factory=lambda *_args, **_kwargs: child
                )
                with mock.patch(
                    "asf.open_lifecycle.signal.getsignal", return_value=None
                ), mock.patch(
                    "asf.open_lifecycle.signal.signal", side_effect=install
                ):
                    result = supervisor.run(("child",))

                self.assertEqual(
                    result, SessionProcessResult(expected.exit_code, expected)
                )
                self.assertEqual(child.signals, [expected.number])

    def test_signal_grace_forces_and_reaps_a_stubborn_child(self) -> None:
        handlers = {}

        def install(signum, handler):  # noqa: ANN001
            handlers[signum] = handler

        clock_values = iter((0.0, 0.0, 1.0))
        child = StubbornProcess(
            on_wait=lambda: handlers[signal.SIGTERM](signal.SIGTERM, None)
        )
        supervisor = SessionProcessSupervisor(
            popen_factory=lambda *_args, **_kwargs: child,
            signal_grace_seconds=0.5,
            poll_interval=0.01,
            clock=lambda: next(clock_values),
        )
        with mock.patch("asf.open_lifecycle.signal.getsignal", return_value=None), mock.patch(
            "asf.open_lifecycle.signal.signal", side_effect=install
        ):
            result = supervisor.run(("child",))

        self.assertEqual(result, SessionProcessResult(143, OpenSignal.TERM))
        self.assertTrue(child.killed)
        self.assertEqual(child.signals, [signal.SIGTERM])

    def test_supervisor_timing_is_validated(self) -> None:
        with self.assertRaisesRegex(Exception, "signal_grace_seconds"):
            SessionProcessSupervisor(signal_grace_seconds=-1)
        with self.assertRaisesRegex(Exception, "poll_interval"):
            SessionProcessSupervisor(poll_interval=0)

    def test_child_killed_by_signal_maps_to_shell_status(self) -> None:
        supervisor = SessionProcessSupervisor(
            popen_factory=lambda *_args, **_kwargs: FakeProcess(-signal.SIGINT)
        )
        result = supervisor.run(("child",))
        self.assertEqual(result.returncode, 130)
        self.assertEqual(result.signal, OpenSignal.INT)

    def test_empty_nul_and_missing_commands_fail_cleanly(self) -> None:
        supervisor = SessionProcessSupervisor(
            popen_factory=lambda *_args, **_kwargs: FakeProcess()
        )
        with self.assertRaisesRegex(Exception, "must not be empty"):
            supervisor.run(())
        with self.assertRaisesRegex(Exception, "NUL"):
            supervisor.run(("bad\x00arg",))

        missing = SessionProcessSupervisor(
            popen_factory=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                FileNotFoundError()
            )
        )
        with self.assertRaises(OpenLifecycleError):
            missing.run(("missing",))


class OpenLockCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "asf"
        self.paths = make_checkout(self.root)




class OpenCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "asf"
        self.paths = make_checkout(self.root)
        self.podman = StatePodman(self.paths.identity)
        self.discovery = SessionDiscovery.from_paths(self.paths, podman=self.podman)
        cleanup = CleanupExecutor(
            self.podman,
            self.discovery.lock_manager(),
            stop_timeout=0,
            network_retry_delay=0,
            sleeper=lambda _seconds: None,
        )
        stop = StopService(
            self.discovery,
            ResidueScanner(self.discovery),
            cleanup,
            verify_attempts=2,
            verify_delay=0,
            sleeper=lambda _seconds: None,
            clock=lambda: 0,
        )
        self.service = OpenCleanupService(stop)

    def _lock(self, runtime: str = "claude") -> Path:
        path = self.paths.identity.session_lock(runtime)
        path.mkdir(parents=True)
        (path / "pid").write_text(f"{os.getpid()}\n")
        return path

    def test_owned_cleanup_removes_live_resources_and_exact_lock(self) -> None:
        self.podman.add_runtime("claude")
        network = self.paths.identity.network_names("claude").internal
        self.podman.networks.add(network)
        lock = self._lock()

        result = self.service.cleanup("claude", os.getpid())

        self.assertEqual(result.returncode, 0)
        self.assertFalse(lock.exists())
        self.assertFalse(self.podman.containers)
        self.assertFalse(self.podman.networks)
        self.assertIn("ASF session cleanup complete", result.stdout)

    def test_startup_failure_with_only_owned_lock_is_cleaned(self) -> None:
        lock = self._lock()
        result = self.service.cleanup("claude", os.getpid())
        self.assertEqual(result.returncode, 0)
        self.assertFalse(lock.exists())

    def test_wrong_owner_never_removes_the_lock(self) -> None:
        lock = self._lock()
        with self.assertRaisesRegex(InfrastructureError, "belongs to PID"):
            self.service.cleanup("claude", os.getpid() + 100000)
        self.assertTrue(lock.exists())



class FakeCleanup:
    def __init__(
        self,
        *,
        returncode: int = 0,
        error: Exception | None = None,
        order: list[str] | None = None,
    ) -> None:
        self.returncode = returncode
        self.error = error
        self.order = order
        self.calls = 0
        self.release_calls = 0

    def release_lock(self, *_args, **_kwargs):  # noqa: ANN002, ANN003
        self.release_calls += 1

    def cleanup(self, *_args, **_kwargs):  # noqa: ANN002, ANN003
        self.calls += 1
        if self.order is not None:
            self.order.append("cleanup")
        if self.error is not None:
            raise self.error
        return mock.Mock(returncode=self.returncode)


class FakeSupervisor:
    def __init__(
        self,
        result: SessionProcessResult | None = None,
        error=None,  # noqa: ANN001
    ) -> None:
        self.result = result or SessionProcessResult(0)
        self.error = error

    def run(self, _argv):  # noqa: ANN001
        if self.error is not None:
            raise self.error
        return self.result


class RunOpenSessionTests(unittest.TestCase):
    def test_terminal_is_restored_before_cleanup(self) -> None:
        order: list[str] = []
        cleanup = FakeCleanup(order=order)
        with mock.patch(
            "asf.open_lifecycle.restore_terminal",
            side_effect=lambda _stream=None: order.append("terminal"),
        ):
            status = run_open_session(
                ("child",),
                cleanup=cleanup,  # type: ignore[arg-type]
                runtime="claude",
                owner_pid=os.getpid(),
                supervisor=FakeSupervisor(),  # type: ignore[arg-type]
                stderr=io.StringIO(),
            )
        self.assertEqual(status, 0)
        self.assertEqual(order, ["terminal", "cleanup"])

    def test_detach_preserves_live_runtime_and_releases_only_the_lock(self) -> None:
        cleanup = FakeCleanup()
        output = io.StringIO()
        status = run_open_session(
            ("child",),
            cleanup=cleanup,  # type: ignore[arg-type]
            runtime="hermes",
            owner_pid=os.getpid(),
            supervisor=FakeSupervisor(),  # type: ignore[arg-type]
            stdout=output,
            stderr=io.StringIO(),
            preserve_if_running=lambda: True,
        )
        self.assertEqual(status, 0)
        self.assertEqual(cleanup.calls, 0)
        self.assertEqual(cleanup.release_calls, 1)
        self.assertIn("Detached from hermes", output.getvalue())
        self.assertIn("./sandbox.sh shell hermes", output.getvalue())

    def test_normal_exit_returns_cleanup_status(self) -> None:
        cleanup = FakeCleanup(returncode=1)
        status = run_open_session(
            ("child",),
            cleanup=cleanup,  # type: ignore[arg-type]
            runtime="claude",
            owner_pid=os.getpid(),
            supervisor=FakeSupervisor(),  # type: ignore[arg-type]
            stderr=io.StringIO(),
        )
        self.assertEqual(status, 1)
        self.assertEqual(cleanup.calls, 1)

    def test_child_failure_is_preserved_after_cleanup(self) -> None:
        errors = io.StringIO()
        status = run_open_session(
            ("child",),
            cleanup=FakeCleanup(),  # type: ignore[arg-type]
            runtime="claude",
            owner_pid=os.getpid(),
            supervisor=FakeSupervisor(SessionProcessResult(42)),  # type: ignore[arg-type]
            stderr=errors,
        )
        self.assertEqual(status, 42)
        self.assertIn("Agent session exited with status 42", errors.getvalue())

    def test_signal_status_wins_without_false_session_error(self) -> None:
        errors = io.StringIO()
        status = run_open_session(
            ("child",),
            cleanup=FakeCleanup(
                error=InfrastructureError("cleanup failed")
            ),  # type: ignore[arg-type]
            runtime="claude",
            owner_pid=os.getpid(),
            supervisor=FakeSupervisor(
                SessionProcessResult(130, OpenSignal.INT)
            ),  # type: ignore[arg-type]
            stderr=errors,
        )
        self.assertEqual(status, 130)
        self.assertNotIn("Agent session exited", errors.getvalue())
        self.assertIn("cleanup failed", errors.getvalue())

    def test_child_start_failure_still_runs_cleanup(self) -> None:
        cleanup = FakeCleanup()
        status = run_open_session(
            ("missing",),
            cleanup=cleanup,  # type: ignore[arg-type]
            runtime="claude",
            owner_pid=os.getpid(),
            supervisor=FakeSupervisor(
                error=OpenLifecycleError("missing")
            ),  # type: ignore[arg-type]
            stderr=io.StringIO(),
        )
        self.assertEqual(status, 1)
        self.assertEqual(cleanup.calls, 1)


if __name__ == "__main__":
    unittest.main()
