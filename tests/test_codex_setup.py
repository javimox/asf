from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "agents" / "codex" / "setup.sh"


class CodexSetupTests(unittest.TestCase):
    def run_setup(
        self,
        *,
        login_ok: bool,
        existing_files: dict[str, str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], Path]:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        bin_dir = root / "bin"
        codex_home = root / "codex-home"
        bin_dir.mkdir()

        if existing_files:
            codex_home.mkdir(mode=0o700)
            for name, content in existing_files.items():
                (codex_home / name).write_text(content, encoding="utf-8")

        fake = bin_dir / "codex"
        fake.write_text(
            textwrap.dedent(
                f"""\
                #!/bin/sh
                case "${{1:-}} ${{2:-}}" in
                    "--version ") echo "codex-cli 0.test" ;;
                    "login status") exit {0 if login_ok else 1} ;;
                    *) exit 64 ;;
                esac
                """
            ),
            encoding="utf-8",
        )
        fake.chmod(0o755)

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
        env["CODEX_HOME"] = str(codex_home)
        result = subprocess.run(
            ["bash", str(SETUP)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        return result, codex_home

    def test_unauthenticated_setup_creates_private_state_and_prints_login_hint(self) -> None:
        result, codex_home = self.run_setup(login_ok=False)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Codex CLI: codex-cli 0.test", result.stdout)
        self.assertIn("Codex authentication: not logged in", result.stdout)
        self.assertIn("codex login --device-auth", result.stdout)
        self.assertTrue(codex_home.is_dir())
        self.assertEqual(stat.S_IMODE(codex_home.stat().st_mode), 0o700)
        self.assertEqual(list(codex_home.iterdir()), [])

    def test_authenticated_setup_reports_cached_login(self) -> None:
        result, _ = self.run_setup(login_ok=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Codex authentication: cached login available", result.stdout)
        self.assertNotIn("codex login --device-auth", result.stdout)

    def test_setup_preserves_existing_codex_state(self) -> None:
        files = {
            "config.toml": 'model = "gpt-5.6-sol"\nmodel_reasoning_effort = "high"\n',
            "auth.json": '{"access_token":"do-not-touch"}\n',
        }
        result, codex_home = self.run_setup(login_ok=True, existing_files=files)

        self.assertEqual(result.returncode, 0, result.stderr)
        for name, content in files.items():
            with self.subTest(name=name):
                self.assertEqual(
                    (codex_home / name).read_text(encoding="utf-8"),
                    content,
                )


if __name__ == "__main__":
    unittest.main()
