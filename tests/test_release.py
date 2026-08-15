"""Release-candidate consolidation checks."""

from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path

from asf import __version__

ROOT = Path(__file__).resolve().parents[1]


class ReleaseMetadataTests(unittest.TestCase):
    def test_version_is_consistent(self) -> None:
        display = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        project_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"$', project_text, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(display, "1.0")
        self.assertEqual(__version__, "1.0")
        self.assertEqual(match.group(1), __version__)

    def test_source_sbom_describes_the_release(self) -> None:
        path = ROOT / "docs" / "sbom" / "asf-v1.0.spdx.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["spdxVersion"], "SPDX-2.3")
        self.assertIn("SPDXRef-Package-ASF", data["documentDescribes"])
        package = next(
            item for item in data["packages"]
            if item["SPDXID"] == "SPDXRef-Package-ASF"
        )
        self.assertEqual(package["versionInfo"], "1.0")
        self.assertFalse(package["filesAnalyzed"])


class ConsolidationTests(unittest.TestCase):
    def test_one_python_production_boundary_remains(self) -> None:
        launcher = (ROOT / "sandbox.sh").read_text(encoding="utf-8")
        self.assertIn('exec python3 -m asf "$@"', launcher)
        self.assertNotIn("source ", launcher)
        self.assertFalse((ROOT / "lib").exists())

    def test_obsolete_migration_wrappers_are_removed(self) -> None:
        for relative in (
            "tools/build_runtime_plan.py",
            "tools/generate_devcontainer.py",
            "tools/load_runtime.py",
            "asf/repos.py",
            "asf/locks.py",
        ):
            with self.subTest(relative=relative):
                self.assertFalse((ROOT / relative).exists())

    def test_local_and_generated_state_are_ignored(self) -> None:
        self.assertFalse((ROOT / ".claude/settings.local.json").exists())
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".claude/", ignore)
        self.assertIn(".devcontainer/sessions/", ignore)
        self.assertIn("__pycache__/", ignore)
        self.assertIn("build/", ignore)
        self.assertIn("dist/", ignore)

    def test_production_sources_do_not_execute_shell_command_strings(self) -> None:
        offenders: list[str] = []
        for path in (ROOT / "asf").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name) and node.func.id == "eval":
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}: eval")
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr == "system"
                ):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}: os.system")
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}: shell=True")
        self.assertEqual(offenders, [])



if __name__ == "__main__":
    unittest.main()
