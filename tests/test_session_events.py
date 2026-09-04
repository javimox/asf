"""Focused tests for the host-owned session lifecycle log."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.runs import begin_run, run_artifact
from asf.paths import RepoPaths
from asf.session_events import read_session_events, record_session_event


class SessionEventTests(unittest.TestCase):
    def test_append_and_tail_are_small_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            (root / "sandbox.sh").write_text("#!/bin/sh\n")
            (root / "agents").mkdir()
            (root / "containers").mkdir()
            (root / ".asf").mkdir()
            with mock.patch.dict(
                os.environ, {"XDG_STATE_HOME": str(Path(temporary) / "state")}
            ):
                paths = RepoPaths.for_root(root)
            session = begin_run(paths, "hermes")

            record_session_event(paths, "hermes", "session_start")
            record_session_event(paths, "hermes", "broker_ready")
            record_session_event(
                paths,
                "hermes",
                "cleanup_complete",
                disposition="stopped",
            )

            path = run_artifact(paths, "hermes", "events.jsonl")
            self.assertEqual(path.parent.name, session.session_id)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            records = read_session_events(paths, "hermes", limit=2)
            self.assertEqual(
                [record["event"] for record in records],
                ["broker_ready", "cleanup_complete"],
            )
            self.assertEqual(records[-1]["disposition"], "stopped")
            self.assertTrue(all(record["runtime"] == "hermes" for record in records))
            self.assertTrue(all(record["session_id"] == session.session_id for record in records))
            self.assertTrue(all(record.get("ts") for record in records))

    def test_missing_log_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            (root / "sandbox.sh").write_text("#!/bin/sh\n")
            (root / "agents").mkdir()
            (root / "containers").mkdir()
            (root / ".asf").mkdir()
            paths = RepoPaths.for_root(root)
            self.assertEqual(read_session_events(paths, "hermes"), ())


if __name__ == "__main__":
    unittest.main()
