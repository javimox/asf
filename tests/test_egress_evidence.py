#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.runs import begin_run, prune_runs, runs_root
from asf.egress_evidence import (
    ADVICE_WINDOW,
    EgressEvidenceError,
    begin_egress_session,
    finalize_egress_session,
    load_evidence_history,
    mark_egress_session_active,
    run_advise_command,
)
from asf.paths import RepoPaths

ROOT = Path(__file__).resolve().parents[1]


class EgressEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "asf"
        (self.root / "agents" / "claude").mkdir(parents=True)
        (self.root / "containers").mkdir()
        (self.root / ".asf").mkdir()
        (self.root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (self.root / "agents" / "claude" / "runtime.yml").write_text(
            (ROOT / "agents" / "claude" / "runtime.yml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        with mock.patch.dict(
            os.environ, {"XDG_STATE_HOME": str(Path(self.temporary.name) / "state")}
        ):
            self.paths = RepoPaths.for_root(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def entry(
        host: str,
        status: int,
        *,
        method: str = "CONNECT",
        probe: bool = False,
    ) -> str:
        headers = {"X-Asf-Probe": ["verification"]} if probe else {}
        return json.dumps(
            {
                "request": {
                    "method": method,
                    "host": host,
                    "headers": headers,
                },
                "status": status,
            }
        )

    def record(self, lines: list[str], *, allowlisted=("sentry.io", "statsig.com")):
        begin_run(self.paths, "claude")
        context = begin_egress_session(self.paths, "claude", allowlisted)
        mark_egress_session_active(self.paths, "claude")
        context.access_log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return context, finalize_egress_session(self.paths, "claude")

    def test_teardown_parses_connects_and_excludes_startup_probes(self) -> None:
        begin_run(self.paths, "claude")
        context = begin_egress_session(
            self.paths, "claude", ("sentry.io", "statsig.com")
        )
        mark_egress_session_active(self.paths, "claude")
        context.access_log_path.write_text(
            "\n".join(
                [
                    self.entry("statsig.com:443", 200, probe=True),
                    self.entry("sentry.io:443", 200),
                    self.entry("registry.npmjs.org:443", 403),
                    self.entry("example.com:80", 403, method="GET"),
                    "not-json",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (context.directory / "caddy-access-2026-08-03T00-00-00-size.log").write_text(
            self.entry("registry.npmjs.org:443", 403) + "\n",
            encoding="utf-8",
        )
        evidence = finalize_egress_session(self.paths, "claude")
        assert evidence is not None
        self.assertEqual(evidence.connect_attempts, 3)
        self.assertEqual(evidence.allowlisted_connects, {"sentry.io": 1})
        self.assertEqual(evidence.denied_connects, {"registry.npmjs.org": 2})
        self.assertEqual(evidence.ignored_probe_connects, 1)
        self.assertEqual(evidence.malformed_lines, 1)
        self.assertTrue((context.metadata_path.parent / "egress-summary.json").is_file())
        self.assertTrue(context.access_log_path.is_file())
        self.assertEqual(len(load_evidence_history(self.paths, "claude")), 1)

    def test_aborted_start_is_not_counted_and_finalize_is_idempotent(self) -> None:
        begin_run(self.paths, "claude")
        context = begin_egress_session(
            self.paths, "claude", ("sentry.io", "statsig.com")
        )
        context.access_log_path.write_text("", encoding="utf-8")
        self.assertIsNone(finalize_egress_session(self.paths, "claude"))
        self.assertIsNone(finalize_egress_session(self.paths, "claude"))
        self.assertEqual(load_evidence_history(self.paths, "claude"), ())
        self.assertFalse(context.directory.exists())

    def test_evidence_requires_a_run_and_is_unique_per_run(self) -> None:
        with self.assertRaisesRegex(EgressEvidenceError, "no session run"):
            begin_egress_session(self.paths, "claude", ("sentry.io",))
        begin_run(self.paths, "claude")
        begin_egress_session(self.paths, "claude", ("sentry.io",))
        with self.assertRaisesRegex(EgressEvidenceError, "already exists"):
            begin_egress_session(self.paths, "claude", ("sentry.io",))

    def test_history_outlives_pruned_run_directories(self) -> None:
        with mock.patch("asf.egress_evidence._MAX_HISTORY", 3):
            first, _ = self.record([self.entry("sentry.io:443", 200)])
            second, _ = self.record([self.entry("sentry.io:443", 200)])
            third, _ = self.record([self.entry("sentry.io:443", 200)])
        prune_runs(self.paths, "claude", keep=2)

        history = load_evidence_history(self.paths, "claude")
        self.assertEqual(
            [item.session_id for item in history],
            [first.session_id, second.session_id, third.session_id],
        )
        self.assertFalse((runs_root(self.paths, "claude") / first.session_id).exists())
        self.assertTrue(second.directory.is_dir())
        self.assertTrue(third.directory.is_dir())

    def test_advise_uses_twelve_sessions_and_repeated_denials(self) -> None:
        for index in range(ADVICE_WINDOW):
            denied = 3 if index == ADVICE_WINDOW - 1 else 4
            lines = [self.entry("statsig.com:443", 200)]
            lines.extend(
                self.entry("registry.npmjs.org:443", 403) for _ in range(denied)
            )
            self.record(lines)

        result = run_advise_command(("advise", "claude"), self.paths)
        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "sentry.io was allowlisted but unused in your last 12 sessions",
            result.stdout,
        )
        self.assertIn(
            "attempted 47 denied CONNECTs to registry.npmjs.org across 12 sessions",
            result.stdout,
        )
        # The provider domain is configured but removed from the effective
        # brokered policy, so it must not be called an unused active rule.
        self.assertNotIn(
            "api.anthropic.com was allowlisted but unused", result.stdout
        )

    def test_advise_never_recommends_an_ip_address(self) -> None:
        for _ in range(3):
            self.record(
                [
                    self.entry("statsig.com:443", 200),
                    self.entry("203.0.113.50:443", 403),
                ]
            )
        result = run_advise_command(("advise", "claude"), self.paths)
        self.assertNotIn("203.0.113.50", result.stdout)

    def test_advise_refuses_early_removal_and_ignores_one_off_denials(self) -> None:
        self.record(
            [
                self.entry("statsig.com:443", 200),
                self.entry("typo.invalid:443", 403),
            ]
        )
        result = run_advise_command(("advise", "claude"), self.paths)
        self.assertIn("Removal advice needs 12 completed proxy sessions", result.stdout)
        self.assertNotIn("consider removing", result.stdout)
        self.assertNotIn("consider adding", result.stdout)

    def test_checkout_local_legacy_history_is_ignored(self) -> None:
        legacy = self.paths.session_artifact("claude", "egress-history.json")
        legacy.parent.mkdir(parents=True)
        legacy.write_text("{}\n", encoding="utf-8")

        self.assertEqual(load_evidence_history(self.paths, "claude"), ())

    def test_malformed_history_fails_closed(self) -> None:
        history = self.paths.state_artifact("claude", "egress-history.json")
        history.parent.mkdir(parents=True)
        history.write_text("{}\n", encoding="utf-8")
        with self.assertRaises(EgressEvidenceError):
            load_evidence_history(self.paths, "claude")

    def test_usage_requires_agent(self) -> None:
        result = run_advise_command(("advise",), self.paths)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "Usage: ./sandbox.sh advise <agent>\n")


if __name__ == "__main__":
    unittest.main()
