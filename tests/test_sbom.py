#!/usr/bin/env python3
"""Focused tests for deterministic source/deployment inventory generation."""
from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "generate_sbom.py"
spec = importlib.util.spec_from_file_location("generate_sbom", MODULE_PATH)
assert spec and spec.loader
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)


class SbomTests(unittest.TestCase):
    def test_git_checkout_ignores_untracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "VERSION").write_text("2.0\n", encoding="utf-8")
            (root / "CITATION.cff").write_text(
                "date-released: 2026-08-26\n", encoding="utf-8"
            )
            tracked = root / "tracked.txt"
            tracked.write_text("tracked\n", encoding="utf-8")
            subprocess.run(("git", "init", "-q", str(root)), check=True)
            subprocess.run(
                (
                    "git",
                    "-C",
                    str(root),
                    "add",
                    "tracked.txt",
                    "VERSION",
                    "CITATION.cff",
                ),
                check=True,
            )
            (root / "untracked.txt").write_text("local only\n", encoding="utf-8")

            with mock.patch.object(sbom, "ROOT", root):
                files = sbom._inventory_files()

            relatives = {path.relative_to(root) for path in files}
            self.assertIn(Path("tracked.txt"), relatives)
            self.assertNotIn(Path("untracked.txt"), relatives)

    def test_archive_fallback_ignores_generated_session_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kept = root / "tracked.txt"
            kept.write_text("source\n", encoding="utf-8")
            generated = root / ".devcontainer" / "sessions" / "hermes" / "runtime-plan.json"
            generated.parent.mkdir(parents=True)
            generated.write_text("{}\n", encoding="utf-8")

            with (
                mock.patch.object(sbom, "ROOT", root),
                mock.patch.object(sbom, "_git_tracked_files", return_value=None),
            ):
                files = sbom._inventory_files()

            relatives = {path.relative_to(root) for path in files}
            self.assertIn(Path("tracked.txt"), relatives)
            self.assertNotIn(
                Path(".devcontainer/sessions/hermes/runtime-plan.json"),
                relatives,
            )

    def test_release_date_is_the_stable_default_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "CITATION.cff").write_text(
                "date-released: 2026-08-26\n", encoding="utf-8"
            )
            with mock.patch.object(sbom, "ROOT", root):
                self.assertEqual(sbom._created_timestamp(), "2026-08-26T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
