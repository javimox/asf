from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.atomic import write_text_atomic


class AtomicWriteTests(unittest.TestCase):
    def test_creates_parent_and_replaces_existing_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "report.json"
            destination.parent.mkdir()
            destination.write_text("old\n", encoding="utf-8")

            write_text_atomic(destination, "new\n")

            self.assertEqual(destination.read_text(encoding="utf-8"), "new\n")
            self.assertEqual(list(destination.parent.glob(".report.json.*")), [])

    def test_removes_temporary_file_when_replace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            with mock.patch("asf.atomic.os.replace", side_effect=OSError("boom")):
                with self.assertRaisesRegex(OSError, "boom"):
                    write_text_atomic(destination, "payload\n")

            self.assertFalse(destination.exists())
            self.assertEqual(list(destination.parent.glob(".report.json.*")), [])


if __name__ == "__main__":
    unittest.main()
