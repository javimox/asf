"""Focused tests for on-demand routed TAP packet capture."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from asf.network_observer import (
    NetworkCaptureError,
    NetworkCaptureService,
    run_capture_command,
)
from asf.runs import begin_run
from asf.paths import RepoPaths
from asf.process import CommandResult
from asf.session import SessionRole, SessionStatus


class _ServicePodman:
    engine = "podman"
    timeout = 30.0

    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.running = True

    def observe(self, argv, **kwargs):
        del kwargs
        command = tuple(str(item) for item in argv)
        self.commands.append(command)
        return CommandResult(command, 0, "", "")

    def exists(self, reference, kind):
        del reference, kind
        return True

    def inspect_container(self, reference, **kwargs):
        del reference, kwargs
        return SimpleNamespace(running=self.running)

    def container_logs(self, reference, *, tail):
        del reference, tail
        return CommandResult(("podman", "logs"), 0, "", "")


class NetworkCaptureServiceTests(unittest.TestCase):
    @patch.object(NetworkCaptureService, "_wait_ready")
    def test_capture_uses_tcpdump_and_net_raw_only(self, wait_ready) -> None:
        fake = _ServicePodman()
        service = NetworkCaptureService(fake)
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "capture.pcap"
            capture.touch()
            service.start(
                "routed-scanner",
                "asf-gateway",
                "gateway:test",
                "asf-network-observer",
                capture,
                sandbox_label="asf.sandbox=/tmp/asf",
            )

        run = fake.commands[-1]
        self.assertIn("--network", run)
        self.assertIn("container:asf-gateway", run)
        self.assertIn("--cap-drop=ALL", run)
        self.assertIn("--cap-add=NET_RAW", run)
        self.assertNotIn("--cap-add=NET_ADMIN", run)
        self.assertIn("--security-opt=no-new-privileges", run)
        self.assertIn("--read-only", run)
        self.assertIn("--stop-signal=SIGINT", run)
        self.assertIn("tap0", run)
        snaplen_index = run.index("-s")
        self.assertEqual(run[snaplen_index + 1], "0")
        self.assertNotIn("-c", run)
        self.assertIn("/asf/network.pcap", run)
        self.assertIn("gateway:test", run)
        self.assertIn("tcpdump", run)
        self.assertNotIn("-Z", run)
        wait_ready.assert_called_once_with("asf-network-observer")

    def test_stop_is_graceful_before_removal(self) -> None:
        fake = _ServicePodman()
        NetworkCaptureService(fake).stop("observer")
        self.assertEqual(fake.commands[0][1:4], ("stop", "--ignore", "--time"))
        self.assertEqual(fake.commands[1], ("podman", "rm", "--ignore", "observer"))


class CaptureCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "asf"
        root.mkdir()
        (root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "containers").mkdir()
        (root / ".asf").mkdir()
        runtime = root / "agents" / "routed-scanner"
        runtime.mkdir(parents=True)
        (runtime / "runtime.yml").write_text("name: routed-scanner\n", encoding="utf-8")
        with patch.dict(
            os.environ, {"XDG_STATE_HOME": str(Path(self.temporary.name) / "state")}
        ):
            self.paths = RepoPaths.for_root(root)
        self.observation = begin_run(self.paths, "routed-scanner")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _session(self, *, observer=None):
        gateway = SimpleNamespace(
            name="gateway",
            is_running=True,
            inspect=SimpleNamespace(image="gateway:test"),
        )

        def role(requested):
            if requested is SessionRole.ROUTED_GATEWAY:
                return gateway
            if requested is SessionRole.NETWORK_OBSERVER:
                return observer
            return None

        return SimpleNamespace(
            status=SessionStatus.RUNNING,
            lock=SimpleNamespace(pid=4242),
            role=role,
        )

    def _discovery(self, session):
        discovery = Mock()
        discovery.resolve_runtime.return_value = "routed-scanner"
        discovery.session.return_value = session
        return discovery

    @patch.object(NetworkCaptureService, "start")
    @patch("asf.network_observer.read_run_policy")
    @patch("asf.network_observer.SessionDiscovery.from_paths")
    def test_start_creates_private_timestamped_capture(
        self, from_paths, read_policy, start
    ) -> None:
        from_paths.return_value = self._discovery(self._session())
        read_policy.return_value = SimpleNamespace(
            isolation="microvm", network_mode="routed"
        )

        result = run_capture_command(
            ("capture", "start", "routed-scanner"),
            self.paths,
            podman=Mock(),
            require_available=False,
        )

        captures = tuple(self.observation.directory.glob("network-*.pcap"))
        self.assertEqual(len(captures), 1)
        self.assertEqual(os.stat(captures[0]).st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            captures[0].relative_to(self.paths.root)
        self.assertIn(captures[0].name, result.stdout)
        args = start.call_args.args
        self.assertEqual(args[0], "routed-scanner")
        self.assertEqual(args[1], "gateway")
        self.assertEqual(args[2], "gateway:test")
        self.assertEqual(args[4], captures[0])

    @patch.object(NetworkCaptureService, "start", side_effect=NetworkCaptureError("boom"))
    @patch("asf.network_observer.read_run_policy")
    @patch("asf.network_observer.SessionDiscovery.from_paths")
    def test_failed_start_removes_unused_reserved_capture(
        self, from_paths, read_policy, start
    ) -> None:
        from_paths.return_value = self._discovery(self._session())
        read_policy.return_value = SimpleNamespace(
            isolation="microvm", network_mode="routed"
        )
        podman = Mock()
        podman.exists.return_value = False

        with self.assertRaisesRegex(NetworkCaptureError, "boom"):
            run_capture_command(
                ("capture", "start", "routed-scanner"),
                self.paths,
                podman=podman,
                require_available=False,
            )

        self.assertEqual(tuple(self.observation.directory.glob("network-*.pcap")), ())
        start.assert_called_once()

    @patch.object(NetworkCaptureService, "start")
    @patch("asf.network_observer.read_run_policy")
    @patch("asf.network_observer.SessionDiscovery.from_paths")
    def test_repeated_starts_use_distinct_files(self, from_paths, read_policy, start) -> None:
        from_paths.return_value = self._discovery(self._session())
        read_policy.return_value = SimpleNamespace(
            isolation="microvm", network_mode="routed"
        )
        with patch("asf.network_observer.datetime") as clock:
            clock.now.return_value = SimpleNamespace(
                strftime=lambda _: "20260825T220733Z"
            )
            run_capture_command(
                ("capture", "start", "routed-scanner"),
                self.paths,
                podman=Mock(),
                require_available=False,
            )
            run_capture_command(
                ("capture", "start", "routed-scanner"),
                self.paths,
                podman=Mock(),
                require_available=False,
            )
        names = sorted(path.name for path in self.observation.directory.glob("*.pcap"))
        self.assertEqual(
            names,
            ["network-20260825T220733Z-2.pcap", "network-20260825T220733Z.pcap"],
        )

    @patch.object(NetworkCaptureService, "stop")
    @patch("asf.network_observer.read_run_policy")
    @patch("asf.network_observer.SessionDiscovery.from_paths")
    def test_stop_is_idempotent(self, from_paths, read_policy, stop) -> None:
        read_policy.return_value = SimpleNamespace(
            isolation="microvm", network_mode="routed"
        )
        from_paths.return_value = self._discovery(self._session())
        result = run_capture_command(
            ("capture", "stop", "routed-scanner"),
            self.paths,
            podman=Mock(),
            require_available=False,
        )
        self.assertEqual(result.stdout, "Packet capture is not running.\n")
        stop.assert_not_called()

    @patch("asf.network_observer.read_run_policy")
    @patch("asf.network_observer.SessionDiscovery.from_paths")
    def test_capture_requires_routed_microvm(self, from_paths, read_policy) -> None:
        from_paths.return_value = self._discovery(self._session())
        read_policy.return_value = SimpleNamespace(
            isolation="container", network_mode="routed"
        )
        with self.assertRaisesRegex(NetworkCaptureError, "requires a routed microVM"):
            run_capture_command(
                ("capture", "start", "routed-scanner"),
                self.paths,
                podman=Mock(),
                require_available=False,
            )


if __name__ == "__main__":
    unittest.main()
