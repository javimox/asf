#!/usr/bin/env python3
"""Command-boundary tests for per-runtime repository configuration."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class RepositoryCliBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.checkout = Path(self.temporary.name) / "asf"
        shutil.copytree(ROOT, self.checkout)
        self.repository = Path(self.temporary.name) / "project"
        self.repository.mkdir()

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ("./sandbox.sh", *arguments),
            cwd=self.checkout,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_add_list_remove_are_nested_and_agent_scoped(self) -> None:
        added = self.run_cli(
            "repo", "add", "claude", str(self.repository), "--mode", "ro"
        )
        self.assertEqual(added.returncode, 0, added.stderr)
        config = self.checkout / "agents" / "claude" / "repos.yml"
        self.assertTrue(config.is_file())
        self.assertFalse((self.checkout / "agents" / "hermes" / "repos.yml").exists())

        listed = self.run_cli("repo", "list", "claude")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("read-only", listed.stdout)
        self.assertIn(str(self.repository), listed.stdout)

        removed = self.run_cli("repo", "remove", "claude", "project")
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertNotIn(str(self.repository), self.run_cli("repo", "list", "claude").stdout)

    def test_repository_long_form_alias(self) -> None:
        result = self.run_cli("repository", "list", "claude")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Repositories for", result.stdout)

    def test_plural_repos_command_is_rejected(self) -> None:
        result = self.run_cli("repos", "list", "claude")
        self.assertEqual(result.returncode, 1)

    def test_old_top_level_commands_are_rejected(self) -> None:
        for command in ("add", "remove", "list"):
            with self.subTest(command=command):
                result = self.run_cli(command)
                self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
