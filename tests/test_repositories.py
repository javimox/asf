#!/usr/bin/env python3
"""Focused tests for per-runtime YAML repository configuration."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from asf.errors import ConfigurationError
from asf.repositories import (
    RepositoryConfigError,
    RepositoryStore,
    run_repository_command,
)


class RepositoryParserTests(unittest.TestCase):
    def test_yaml_parser_expands_tilde_and_defaults_to_rw(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "repos.yml"
            config.write_text(
                """repos:
  - ~/one
  - path: /absolute/two
    mode: ro
  - path: "/three#with-hash"  # YAML comment stays outside the scalar
""",
                encoding="utf-8",
            )
            store = RepositoryStore.for_file(
                config,
                runtime="claude",
                home="/home/tester",
                cwd=temporary,
            )
            entries = store.entries()
            self.assertEqual(
                tuple((entry.path, entry.mode) for entry in entries),
                (
                    ("/home/tester/one", "rw"),
                    ("/absolute/two", "ro"),
                    ("/three#with-hash", "rw"),
                ),
            )

    def test_missing_file_is_an_empty_repository_list(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RepositoryStore.for_file(
                Path(temporary) / "missing.yml",
                runtime="hermes",
            )
            self.assertEqual(store.entries(), ())

    def test_invalid_shapes_and_modes_fail_cleanly(self) -> None:
        invalid = (
            "repos: not-a-list\n",
            "repos:\n  - path: /repo\n    mode: execute\n",
            "repos:\n  - path: relative/repo\n",
            "repos:\n  - path: /one/same\n  - path: /two/same\n",
            "other: []\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "repos.yml"
            for payload in invalid:
                with self.subTest(payload=payload):
                    config.write_text(payload, encoding="utf-8")
                    store = RepositoryStore.for_file(
                        config,
                        runtime="claude",
                    )
                    with self.assertRaises(RepositoryConfigError):
                        store.entries()

    def test_read_failure_uses_shared_configuration_hierarchy(self) -> None:
        self.assertTrue(issubclass(RepositoryConfigError, ConfigurationError))


class RepositoryCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.config = self.root / "agents" / "claude" / "repos.yml"
        self.store = RepositoryStore.for_file(
            self.config,
            runtime="claude",
            home=os.fspath(self.home),
            cwd=self.root,
        )

    def test_add_creates_yaml_native_file_with_rw_default(self) -> None:
        repository = self.root / "project with spaces"
        repository.mkdir()
        result = self.store.add(os.fspath(repository))
        self.assertEqual(result.returncode, 0)
        self.assertIn("read-write", result.stdout)
        self.assertEqual(
            tuple((entry.path, entry.mode) for entry in self.store.entries()),
            ((os.fspath(repository), "rw"),),
        )
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o600)

    def test_add_read_only_and_update_mode(self) -> None:
        repository = self.root / "reference"
        repository.mkdir()
        added = self.store.add(os.fspath(repository), "ro")
        self.assertEqual(added.returncode, 0)
        self.assertEqual(self.store.entries()[0].mode, "ro")

        updated = self.store.add(os.fspath(repository), "rw")
        self.assertEqual(updated.returncode, 0)
        self.assertIn("Updated", updated.stdout)
        self.assertEqual(self.store.entries()[0].mode, "rw")

    def test_add_preserves_logical_symlink_path(self) -> None:
        target = self.root / "target"
        target.mkdir()
        link = self.root / "logical-link"
        link.symlink_to(target, target_is_directory=True)
        self.store.add(os.fspath(link), "ro")
        entry = self.store.entries()[0]
        self.assertEqual(entry.path, os.fspath(link))
        self.assertEqual(entry.mode, "ro")

    def test_duplicate_basename_is_rejected(self) -> None:
        first = self.root / "first" / "same"
        second = self.root / "second" / "same"
        first.mkdir(parents=True)
        second.mkdir(parents=True)
        self.assertEqual(self.store.add(os.fspath(first)).returncode, 0)
        result = self.store.add(os.fspath(second))
        self.assertEqual(result.returncode, 1)
        self.assertIn("Basename collision", result.stdout)

    def test_add_rejects_missing_path_and_invalid_mode(self) -> None:
        self.assertEqual(self.store.add("").returncode, 1)
        repository = self.root / "repo"
        repository.mkdir()
        invalid = self.store.add(os.fspath(repository), "invalid")
        self.assertEqual(invalid.returncode, 1)
        self.assertIn("ro", invalid.stderr)

    def test_remove_and_list_are_scoped_to_runtime_file(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        self.store.add(os.fspath(repository), "ro")
        listing = self.store.list()
        self.assertIn("Repositories for", listing.stdout)
        self.assertIn("claude", listing.stdout)
        self.assertIn("read-only", listing.stdout)

        removed = self.store.remove("repo")
        self.assertEqual(removed.returncode, 0)
        self.assertEqual(self.store.entries(), ())

    def test_remove_missing_file_is_not_found_success(self) -> None:
        result = self.store.remove("anything")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Not found", result.stdout)
        self.assertFalse(self.config.exists())

    def test_add_to_unterminated_empty_yaml_stays_parseable(self) -> None:
        repository = self.root / "newline-safe"
        repository.mkdir()
        self.config.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text("repos:", encoding="utf-8")

        result = self.store.add(os.fspath(repository), "ro")

        self.assertEqual(result.returncode, 0)
        entries = self.store.entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].path, os.fspath(repository))
        self.assertEqual(entries[0].mode, "ro")

    def test_remove_not_found_does_not_rewrite_yaml(self) -> None:
        self.config.parent.mkdir(parents=True, exist_ok=True)
        original = "repos:\n  - path: /one/keep  # preserve this comment\n"
        self.config.write_text(original, encoding="utf-8")

        result = self.store.remove("missing")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.config.read_text(encoding="utf-8"), original)

    def test_updates_preserve_existing_file_mode(self) -> None:
        repository = self.root / "mode-preserved"
        repository.mkdir()
        self.config.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text("repos: []\n", encoding="utf-8")
        os.chmod(self.config, 0o640)

        result = self.store.add(os.fspath(repository))

        self.assertEqual(result.returncode, 0)
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o640)

    def test_dispatch_rejects_unknown_command(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported repository command"):
            run_repository_command("open", "", self.store)


if __name__ == "__main__":
    unittest.main()
