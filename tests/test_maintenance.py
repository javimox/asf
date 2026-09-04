#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.maintenance import run_maintenance_command
from asf.paths import RepoPaths
from asf.podman import PodmanClient
from asf.process import CommandResult

ROOT = Path(__file__).resolve().parents[1]


class AvailablePodman(PodmanClient):
    def is_available(self) -> bool:
        return True


class MaintenanceCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "asf"
        import shutil
        shutil.copytree(ROOT, self.root)
        self.paths = RepoPaths.for_root(self.root)
        self.output = io.StringIO()
        self.error = io.StringIO()

    @mock.patch("asf.maintenance.run")
    def test_build_builds_shared_base_then_selected_runtime_image(self, command) -> None:
        command.return_value = CommandResult(("podman",), 0, "", "")
        result = run_maintenance_command(
            ("build", "claude"), self.paths, podman=AvailablePodman(),
            output=self.output, error=self.error,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(command.call_count, 2)
        base = command.call_args_list[0].args[0]
        runtime = command.call_args_list[1].args[0]
        self.assertEqual(base[:2], ("podman", "build"))
        self.assertEqual(runtime[:2], ("podman", "build"))
        self.assertIn(str(self.paths.containers_dir / "base" / "Containerfile"), base)
        self.assertIn(str(self.paths.containers_dir / "claude" / "Containerfile"), runtime)
        self.assertIn("ASF_BASE_IMAGE=localhost/" + self.paths.identity.prefix.lower() + "-base:runtime", runtime)
        self.assertTrue(runtime[runtime.index("--tag") + 1].endswith("-claude:runtime"))
        self.assertIn("Done.", self.output.getvalue())

    @mock.patch("asf.maintenance.run")
    def test_build_microvm_uses_the_same_runtime_image_pipeline(self, command) -> None:
        manifest = self.root / "agents" / "hermes" / "runtime.yml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "  isolation: container  # container or microvm\n",
                "  isolation: microvm  # container or microvm\n",
                1,
            ),
            encoding="utf-8",
        )
        command.return_value = CommandResult(("podman",), 0, "", "")
        result = run_maintenance_command(
            ("build", "hermes"), self.paths, podman=AvailablePodman(),
            output=self.output, error=self.error,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(command.call_count, 2)
        runtime = command.call_args_list[1].args[0]
        self.assertIn(str(self.paths.containers_dir / "hermes" / "Containerfile"), runtime)
        self.assertTrue(runtime[runtime.index("--tag") + 1].endswith("-hermes:runtime"))

    @mock.patch("asf.maintenance.run")
    def test_build_routed_microvm_needs_no_subnet_allocation(self, command) -> None:
        manifest = self.root / "agents" / "routed-scanner" / "runtime.yml"
        self.assertIn("isolation: microvm", manifest.read_text(encoding="utf-8"))
        command.return_value = CommandResult(("podman",), 0, "", "")
        result = run_maintenance_command(
            ("build", "routed-scanner"), self.paths, podman=AvailablePodman(),
            output=self.output, error=self.error,
        )
        self.assertEqual(result.returncode, 0)
        runtime = command.call_args_list[1].args[0]
        self.assertIn(str(self.paths.containers_dir / "generic" / "Containerfile"), runtime)
        self.assertIn(
            self.paths.identity.session_key("routed-scanner").lower(),
            runtime[runtime.index("--tag") + 1],
        )

    def test_build_requires_exactly_one_runtime(self) -> None:
        result = run_maintenance_command(
            ("build",), self.paths, podman=AvailablePodman(),
            output=self.output, error=self.error,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Usage", result.stderr)

    @mock.patch("asf.maintenance.run")
    @mock.patch("asf.maintenance.SessionDiscovery")
    @mock.patch("asf.maintenance.load_runtime_plan")
    @mock.patch("asf.maintenance.validate_runtime_plan_context")
    def test_scan_uses_podman_exec_and_configured_repository(
        self, _validate, load_plan, discovery_class, command
    ) -> None:
        plan = mock.Mock(session_label="asf.session=test-claude", runtime="claude", runtime_isolation="container")
        load_plan.return_value = plan
        discovery = discovery_class.from_paths.return_value
        discovery.extract_runtime_argument.return_value = ("claude", ("repo",))
        discovery.resolve_runtime.return_value = "claude"
        discovery.unique_match.return_value = mock.Mock(container_id="runtime")
        (self.root / "agents" / "claude" / "repos.yml").write_text(
            "repos:\n" f"- path: {self.root.parent / 'repo'}\n" "  mode: rw\n",
            encoding="utf-8",
        )
        (self.root.parent / "repo").mkdir()
        command.return_value = CommandResult(("podman",), 0, "", "")
        result = run_maintenance_command(
            ("scan", "repo", "claude"), self.paths,
            podman=AvailablePodman(), output=self.output, error=self.error,
        )
        self.assertEqual(result.returncode, 0)
        argv = command.call_args.args[0]
        self.assertEqual(argv[:3], ("podman", "exec", "runtime"))
        self.assertEqual(
            argv[-5:],
            ("semgrep", "scan", "--config", "auto", "/workspace/repos/repo"),
        )
        self.assertNotIn("sh", argv)


if __name__ == "__main__":
    unittest.main()
