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

    @mock.patch("asf.maintenance.shutil.which", return_value="/usr/bin/devcontainer")
    @mock.patch("asf.maintenance.run")
    def test_build_uses_build_only_config_and_no_id_label(self, command, _which) -> None:
        command.return_value = CommandResult(("devcontainer",), 0, "", "")
        result = run_maintenance_command(
            ("build", "claude"),
            self.paths,
            podman=AvailablePodman(),
            output=self.output,
            error=self.error,
        )
        self.assertEqual(result.returncode, 0)
        argv = command.call_args.args[0]
        self.assertEqual(argv[:2], ("devcontainer", "build"))
        self.assertNotIn("--id-label", argv)
        config = self.paths.session_artifact("claude", "devcontainer.json")
        self.assertTrue(config.is_file())
        self.assertIn("Done.", self.output.getvalue())

    @mock.patch("asf.maintenance.shutil.which", return_value="/usr/bin/devcontainer")
    @mock.patch("asf.maintenance.run")
    def test_build_uses_only_the_selected_runtime_repositories(
        self,
        command,
        _which,
    ) -> None:
        claude_repo = self.root.parent / "claude-project"
        hermes_repo = self.root.parent / "hermes-project"
        claude_repo.mkdir()
        hermes_repo.mkdir()
        (self.root / "agents" / "claude" / "repos.yml").write_text(
            "repos:\n"
            f"  - path: {claude_repo}\n"
            "    mode: ro\n",
            encoding="utf-8",
        )
        (self.root / "agents" / "hermes" / "repos.yml").write_text(
            "repos:\n"
            f"  - path: {hermes_repo}\n"
            "    mode: rw\n",
            encoding="utf-8",
        )
        command.return_value = CommandResult(("devcontainer",), 0, "", "")

        result = run_maintenance_command(
            ("build", "claude"),
            self.paths,
            podman=AvailablePodman(),
            output=self.output,
            error=self.error,
        )

        self.assertEqual(result.returncode, 0)
        config_path = self.paths.session_artifact("claude", "devcontainer.json")
        lines = config_path.read_text(encoding="utf-8").splitlines()
        config = json.loads(
            "\n".join(line for line in lines if not line.startswith("//"))
        )
        mounts = config["mounts"]
        self.assertTrue(any(str(claude_repo) in mount for mount in mounts))
        self.assertTrue(
            any(
                str(claude_repo) in mount and ",readonly" in mount
                for mount in mounts
            )
        )
        self.assertFalse(any(str(hermes_repo) in mount for mount in mounts))

    @mock.patch("asf.maintenance.shutil.which", return_value="/usr/bin/devcontainer")
    def test_build_requires_exactly_one_runtime(self, _which) -> None:
        result = run_maintenance_command(
            ("build",), self.paths, podman=AvailablePodman(),
            output=self.output, error=self.error,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Usage", result.stderr)

    @mock.patch("asf.maintenance.shutil.which", return_value="/usr/bin/devcontainer")
    @mock.patch("asf.maintenance.run")
    @mock.patch("asf.maintenance.SessionDiscovery")
    @mock.patch("asf.maintenance.load_runtime_plan")
    @mock.patch("asf.maintenance.validate_runtime_plan_context")
    def test_scan_uses_fixed_command_and_configured_repository(
        self, _validate, load_plan, discovery_class, command, _which
    ) -> None:
        plan = mock.Mock(session_label="asf.session=test-claude", runtime="claude")
        load_plan.return_value = plan
        discovery = discovery_class.from_paths.return_value
        discovery.extract_runtime_argument.return_value = ("claude", ("repo",))
        discovery.resolve_runtime.return_value = "claude"
        discovery.unique_match.return_value = mock.Mock(container_id="runtime")
        (self.root / "agents" / "claude" / "repos.yml").write_text(
            "repos:\n"
            f"- path: {self.root.parent / 'repo'}\n"
            "  mode: rw\n",
            encoding="utf-8",
        )
        (self.root.parent / "repo").mkdir()
        command.return_value = CommandResult(("devcontainer",), 0, "", "")

        result = run_maintenance_command(
            ("scan", "repo", "claude"), self.paths,
            podman=AvailablePodman(), output=self.output, error=self.error,
        )
        self.assertEqual(result.returncode, 0)
        argv = command.call_args.args[0]
        self.assertEqual(argv[0:2], ("devcontainer", "exec"))
        self.assertIn("--id-label", argv)
        self.assertEqual(
            argv[-5:],
            ("semgrep", "scan", "--config", "auto", "/workspace/repos/repo"),
        )
        self.assertNotIn("sh", argv)


if __name__ == "__main__":
    unittest.main()
