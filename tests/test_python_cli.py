#!/usr/bin/env python3
"""Tests for the final Python CLI boundary."""
from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.cli import main
from asf.session import SessionStatus

ROOT = Path(__file__).resolve().parents[1]


def make_checkout(root: Path) -> None:
    (root / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
    (root / "agents" / "claude").mkdir(parents=True)
    (root / "agents" / "claude" / "runtime.yml").write_text(
        "name: claude\n", encoding="utf-8"
    )
    (root / ".devcontainer").mkdir()


class PythonCliTests(unittest.TestCase):
    def test_help_and_missing_command_show_help(self) -> None:
        for argv in ([], ["help"], ["--help"], ["-h"]):
            with self.subTest(argv=argv):
                stdout = io.StringIO()
                stderr = io.StringIO()
                status = main(argv, stdout=stdout, stderr=stderr)
                self.assertEqual(status, 0)
                self.assertIn("./sandbox.sh open <agent>", stdout.getvalue())
                self.assertEqual(stderr.getvalue(), "")

    def test_version_is_available_without_repository_discovery(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        status = main(["--version"], stdout=stdout, stderr=stderr)
        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), "ASF 1.0\n")
        self.assertEqual(stderr.getvalue(), "")

    def test_unknown_command_is_a_clean_usage_error(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        status = main(["unknown"], stdout=stdout, stderr=stderr)
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("{open|shell|ls|observe|repo|repository|build|scan", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_open_requires_a_runtime(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        status = main(["open"], stdout=stdout, stderr=stderr)
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "Usage: ./sandbox.sh open <agent>\n")

    def test_repo_commands_are_nested_and_agent_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            make_checkout(root)
            repository = Path(temporary) / "repo"
            repository.mkdir()
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.dict(os.environ, {"HOME": temporary}):
                status = main(
                    ["repo", "add", "claude", os.fspath(repository), "--mode", "ro"],
                    root=root,
                    stdout=stdout,
                    stderr=stderr,
                )
            self.assertEqual(status, 0)
            self.assertEqual(stderr.getvalue(), "")
            config = root / "agents" / "claude" / "repos.yml"
            self.assertIn(os.fspath(repository), config.read_text())
            self.assertIn("mode: ro", config.read_text())

    def test_repository_is_an_alias_for_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            make_checkout(root)
            repo_stdout = io.StringIO()
            repository_stdout = io.StringIO()
            repo_status = main(
                ["repo", "list", "claude"],
                root=root,
                stdout=repo_stdout,
                stderr=io.StringIO(),
            )
            repository_status = main(
                ["repository", "list", "claude"],
                root=root,
                stdout=repository_stdout,
                stderr=io.StringIO(),
            )
            self.assertEqual(repository_status, repo_status)
            self.assertEqual(repository_stdout.getvalue(), repo_stdout.getvalue())

    def test_plural_repos_command_is_rejected(self) -> None:
        stderr = io.StringIO()
        status = main(["repos"], stdout=io.StringIO(), stderr=stderr)
        self.assertEqual(status, 1)
        self.assertIn("{open|shell|ls|observe|repo|repository|build|scan", stderr.getvalue())

    def test_ls_renders_running_agent_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            make_checkout(root)
            session = mock.Mock()
            session.runtime = "claude"
            session.status = SessionStatus.RUNNING
            session.container = mock.Mock(name="container")
            session.container.name = "asf-test-claude"
            discovery = mock.Mock()
            discovery.sessions.return_value = (session,)
            podman = mock.Mock()
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch("asf.cli.SessionDiscovery.from_paths", return_value=discovery):
                status = main(
                    ["ls"], root=root, stdout=stdout, stderr=stderr, podman=podman
                )
            self.assertEqual(status, 0)
            podman.require_available.assert_called_once_with()
            self.assertIn("claude", stdout.getvalue())
            self.assertIn("running", stdout.getvalue())
            self.assertIn("asf-test-claude", stdout.getvalue())
            self.assertEqual(stderr.getvalue(), "")

    def test_advise_reads_local_evidence_without_requiring_podman(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            make_checkout(root)
            runtime = root / "agents" / "claude"
            runtime.mkdir(exist_ok=True)
            (runtime / "runtime.yml").write_text(
                (ROOT / "agents" / "claude" / "runtime.yml").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            status = main(
                ["advise", "claude"],
                root=root,
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(status, 0)
            self.assertIn("Egress policy advice for claude", stdout.getvalue())
            self.assertEqual(stderr.getvalue(), "")

    def test_launcher_is_one_thin_python_boundary(self) -> None:
        launcher = (ROOT / "sandbox.sh").read_text(encoding="utf-8")
        self.assertIn('exec python3 -m asf "$@"', launcher)
        self.assertIn('PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"', launcher)
        self.assertNotIn("source ", launcher)
        self.assertNotIn("case ", launcher)
        self.assertFalse((ROOT / "lib").exists())

    def test_cli_maps_configuration_failure_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            make_checkout(root)
            config = root / "agents" / "claude" / "repos.yml"
            config.mkdir()
            stdout = io.StringIO()
            stderr = io.StringIO()
            status = main(
                ["repo", "list", "claude"],
                root=root,
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(status, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Cannot read repository configuration", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
