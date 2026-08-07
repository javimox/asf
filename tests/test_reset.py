#!/usr/bin/env python3
"""Focused Phase 3D reset orchestration tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.cleanup import CleanupExecutor, CleanupOutcome, CleanupReport
from asf.ownership import Resource, ResourceKind
from asf.paths import RepoPaths
from asf.podman import PodmanClient
from asf.process import CommandResult
from asf.manifest import load_model
from asf.reset import (
    ResetDisposition,
    ResetService,
    run_reset_command,
    state_volume_names,
)
from asf.residue import SessionResidue
from asf.session import SessionStatus
from asf.stop import StopDisposition, StopReport, StopService


class VolumeRunner:
    def __init__(self, volumes: set[str], *, fail_remove: bool = False) -> None:
        self.volumes = set(volumes)
        self.fail_remove = fail_remove
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, *, timeout, **kwargs):
        args = tuple(str(value) for value in argv)
        self.calls.append(args)
        if args[1:3] == ("volume", "inspect"):
            name = args[3]
            if name in self.volumes:
                return CommandResult(args, 0, "[]\n", "")
            return CommandResult(args, 1, "", f"no such volume {name}\n")
        if args[1:3] == ("volume", "rm"):
            names = args[3:]
            if self.fail_remove:
                return CommandResult(args, 1, "", "volume is in use\n")
            self.volumes.difference_update(names)
            return CommandResult(args, 0, "\n".join(names) + "\n", "")
        raise AssertionError(f"unexpected Podman call: {args}")


def make_checkout(root: Path) -> RepoPaths:
    root.mkdir(parents=True)
    (root / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
    (root / ".devcontainer").mkdir()
    runtime_dir = root / "agents" / "demo"
    runtime_dir.mkdir(parents=True)
    (runtime_dir / "runtime.yml").write_text(
        """name: demo
runtime:
  mode: interactive
filesystem:
  state:
    - key: config
      target: /home/node/.config/demo
    - key: cache
      target: /home/node/.cache/demo
network:
  mode: isolated
"""
    )
    return RepoPaths.for_root(root)


def successful_stop(runtime: str = "demo") -> StopReport:
    residue = SessionResidue(runtime)
    return StopReport(
        runtime,
        SessionStatus.ABSENT,
        residue,
        CleanupReport(()),
        residue,
        StopDisposition.ALREADY_STOPPED,
    )


def failed_stop(runtime: str = "demo") -> StopReport:
    residue = SessionResidue(runtime, unreadable=("Podman unavailable",))
    return StopReport(
        runtime,
        SessionStatus.UNREADABLE,
        residue,
        CleanupReport((), inconclusive=("Podman unavailable",)),
        residue,
        StopDisposition.INCONCLUSIVE,
    )


class ResetModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.paths = make_checkout(Path(self.temporary.name) / "asf")

    def test_state_volume_names_are_manifest_ordered_and_identity_scoped(self) -> None:
        manifest = load_model(self.paths.identity.runtime_manifest("demo"))
        self.assertEqual(
            state_volume_names(self.paths.identity, "demo", manifest),
            (
                self.paths.identity.state_volume("demo", "config"),
                self.paths.identity.state_volume("demo", "cache"),
                self.paths.identity.shell_history_volume("demo"),
            ),
        )

    def test_dispositions_distinguish_success_and_failure_classes(self) -> None:
        self.assertTrue(ResetDisposition.CLEARED.succeeded)
        self.assertTrue(ResetDisposition.NOTHING_TO_CLEAR.succeeded)
        self.assertFalse(ResetDisposition.SESSION_CLEANUP_FAILED.succeeded)
        self.assertFalse(ResetDisposition.VOLUME_CLEANUP_FAILED.succeeded)


class ResetServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.paths = make_checkout(Path(self.temporary.name) / "asf")

    def service(self, runner: VolumeRunner) -> ResetService:
        podman = PodmanClient(engine="podman", runner=runner)
        service = ResetService.from_paths(self.paths, podman=podman)
        self.assertIs(service.cleanup, service.stop_service.cleanup)
        return service

    def volume_names(self) -> tuple[str, ...]:
        identity = self.paths.identity
        return (
            identity.state_volume("demo", "config"),
            identity.state_volume("demo", "cache"),
            identity.shell_history_volume("demo"),
        )

    def test_reset_stops_first_then_removes_manifest_and_history_volumes(self) -> None:
        names = self.volume_names()
        runner = VolumeRunner(set(names))
        service = self.service(runner)
        with mock.patch.object(
            StopService, "stop_runtime", return_value=successful_stop()
        ) as stop:
            report = service.reset("demo")
        stop.assert_called_once_with("demo")
        self.assertTrue(report.succeeded)
        self.assertEqual(report.removed, names)
        self.assertEqual(runner.volumes, set())
        self.assertIn(("podman", "volume", "rm", *names), runner.calls)

    def test_failed_stop_prevents_every_volume_mutation(self) -> None:
        names = self.volume_names()
        runner = VolumeRunner(set(names))
        service = self.service(runner)
        with mock.patch.object(
            StopService, "stop_runtime", return_value=failed_stop()
        ):
            report = service.reset("demo")
        self.assertFalse(report.succeeded)
        self.assertEqual(runner.calls, [])
        self.assertEqual(runner.volumes, set(names))

    def test_absent_volumes_are_idempotent(self) -> None:
        runner = VolumeRunner(set())
        service = self.service(runner)
        with mock.patch.object(
            StopService, "stop_runtime", return_value=successful_stop()
        ):
            report = service.reset("demo")
        self.assertTrue(report.succeeded)
        self.assertEqual(report.removed, ())
        self.assertEqual(report.absent, self.volume_names())

    def test_failed_batch_removal_is_aggregated_and_verified(self) -> None:
        names = self.volume_names()
        runner = VolumeRunner(set(names), fail_remove=True)
        service = self.service(runner)
        with mock.patch.object(
            StopService, "stop_runtime", return_value=successful_stop()
        ):
            report = service.reset("demo")
        self.assertFalse(report.succeeded)
        self.assertEqual(len(report.cleanup.failures), 3)
        self.assertEqual(report.remaining, names)

    def test_cleanup_rejects_non_volume_and_cross_runtime_names(self) -> None:
        runner = VolumeRunner(set())
        service = self.service(runner)
        with self.assertRaisesRegex(Exception, "only volume"):
            service.cleanup.reset_volumes(
                (Resource(ResourceKind.NETWORK, "bad", runtime="demo"),)
            )
        with self.assertRaisesRegex(Exception, "outside runtime ownership"):
            service.cleanup.reset_volumes(
                (
                    Resource(
                        ResourceKind.VOLUME,
                        "other-runtime-cache",
                        runtime="demo",
                    ),
                )
            )


class ResetCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.paths = make_checkout(Path(self.temporary.name) / "asf")

    def service(self, volumes: set[str], *, stop: StopReport | None = None):
        runner = VolumeRunner(volumes)
        service = ResetService.from_paths(
            self.paths,
            podman=PodmanClient(engine="podman", runner=runner),
        )
        patcher = mock.patch.object(
            StopService,
            "stop_runtime",
            return_value=successful_stop() if stop is None else stop,
        )
        return service, runner, patcher

    def test_missing_and_unknown_runtime_preserve_bash_text(self) -> None:
        service, _, patcher = self.service(set())
        with patcher:
            missing = run_reset_command(
                ["reset"], self.paths, service=service, require_available=False
            )
            unknown = run_reset_command(
                ["reset", "unknown"],
                self.paths,
                service=service,
                require_available=False,
            )
        self.assertEqual(missing.returncode, 1)
        self.assertIn("An agent name is required", missing.stdout)
        self.assertIn("    demo\n", missing.stdout)
        self.assertEqual(unknown.returncode, 1)
        self.assertIn("Unknown agent: unknown", unknown.stdout)
        self.assertEqual(missing.stderr, unknown.stderr)

    def test_success_and_extra_arguments_preserve_output_contract(self) -> None:
        identity = self.paths.identity
        names = {
            identity.state_volume("demo", "config"),
            identity.state_volume("demo", "cache"),
            identity.shell_history_volume("demo"),
        }
        service, _, patcher = self.service(set(names))
        with patcher:
            result = run_reset_command(
                ["reset", "demo", "ignored"],
                self.paths,
                service=service,
                require_available=False,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn("✓ Cleared all demo state.", result.stdout)
        self.assertIn("./sandbox.sh open demo", result.stdout)

    def test_no_volumes_is_a_successful_noop(self) -> None:
        service, _, patcher = self.service(set())
        with patcher:
            result = run_reset_command(
                ["reset", "demo"],
                self.paths,
                service=service,
                require_available=False,
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn("No persistent volumes found for demo.", result.stdout)
        self.assertIn("Nothing to clear.", result.stdout)

    def test_stop_failure_is_nonzero_and_never_removes_state(self) -> None:
        service, runner, patcher = self.service(
            set(), stop=failed_stop()
        )
        with patcher:
            result = run_reset_command(
                ["reset", "demo"],
                self.paths,
                service=service,
                require_available=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("persistent state was not cleared", result.stderr)
        self.assertEqual(runner.calls, [])

    def test_volume_failure_is_nonzero_without_false_success(self) -> None:
        names = {
            self.paths.identity.state_volume("demo", key)
            for key in ("config", "cache")
        }
        names.add(self.paths.identity.shell_history_volume("demo"))
        runner = VolumeRunner(names, fail_remove=True)
        service = ResetService.from_paths(
            self.paths,
            podman=PodmanClient(engine="podman", runner=runner),
        )
        with mock.patch.object(
            StopService, "stop_runtime", return_value=successful_stop()
        ):
            result = run_reset_command(
                ["reset", "demo"],
                self.paths,
                service=service,
                require_available=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("✓ Cleared", result.stdout)
        self.assertIn("Could not clear all demo state", result.stderr)


if __name__ == "__main__":
    unittest.main()
