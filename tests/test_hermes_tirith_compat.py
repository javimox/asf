from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "containers" / "hermes" / "apply_tirith_fail_closed.py"

spec = importlib.util.spec_from_file_location("apply_tirith_fail_closed", HELPER)
assert spec is not None and spec.loader is not None
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)


class HermesTirithCompatibilityTests(unittest.TestCase):
    def test_applies_exact_fail_closed_rewrite(self) -> None:
        source = (
            "def check_command_security(command: str) -> dict:\n"
            "    cfg = _load_security_config()\n"
            + compat.UNSAFE_BLOCK
            + "    return {\"action\": \"allow\"}\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tirith_security.py"
            path.write_text(source, encoding="utf-8")
            compat.apply(path)
            updated = path.read_text(encoding="utf-8")

        self.assertNotIn(compat.UNSAFE_BLOCK, updated)
        self.assertIn('if cfg["tirith_fail_open"]:', updated)
        self.assertIn('"action": "block"', updated)
        self.assertIn("circuit breaker open (fail-closed)", updated)

    def test_rejects_upstream_drift_or_duplicate_match(self) -> None:
        cases = {
            "missing": "def check_command_security(command: str) -> dict:\n    pass\n",
            "duplicate": compat.UNSAFE_BLOCK + compat.UNSAFE_BLOCK,
        }

        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "tirith_security.py"
                path.write_text(source, encoding="utf-8")
                with self.assertRaises(ValueError):
                    compat.apply(path)


if __name__ == "__main__":
    unittest.main()
