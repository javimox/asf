#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asf.broker_metadata import (
    prepare_broker_prompt_log,
    prepare_broker_request_log,
    read_broker_requests,
)
from asf.runs import begin_run
from asf.paths import RepoPaths


def make_paths(root: Path) -> RepoPaths:
    (root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "agents").mkdir()
    (root / ".devcontainer").mkdir()
    return RepoPaths.for_root(root)


class BrokerMetadataTests(unittest.TestCase):
    def test_prepare_is_private_and_reader_returns_recent_valid_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            paths = make_paths(root)
            begin_run(paths, "hermes")
            path = prepare_broker_request_log(paths, "hermes")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            rows = [
                {"event": "llm_request_complete", "model": "gpt-5.5"},
                {"event": "llm_request_failed", "model": "gpt-5-nano"},
                {"event": "llm_request_complete", "model": "gpt-5.5"},
            ]
            path.write_text(
                "bad json\n" + "\n".join(json.dumps(row) for row in rows) + "\n",
                encoding="utf-8",
            )
            records = read_broker_requests(paths, "hermes", limit=2)
            self.assertEqual([row["event"] for row in records], ["llm_request_failed", "llm_request_complete"])

    def test_prompt_log_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            paths = make_paths(root)
            begin_run(paths, "hermes")
            path = prepare_broker_prompt_log(paths, "hermes")
            self.assertEqual(path.name, "llm-prompts.jsonl")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_missing_log_is_empty_and_limit_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            root.mkdir()
            paths = make_paths(root)
            self.assertEqual(read_broker_requests(paths, "hermes"), ())
            for value in (0, -1, True):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    read_broker_requests(paths, "hermes", limit=value)


if __name__ == "__main__":
    unittest.main()
