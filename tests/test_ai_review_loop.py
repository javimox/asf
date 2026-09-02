#!/usr/bin/env python3
"""Small contract tests for the experimental host review loop."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "ai-review-loop.sh"
STREAM = ROOT / "tools" / "ai-review-stream.py"


class AiReviewLoopTests(unittest.TestCase):
    def test_script_has_valid_shell_syntax_and_help(self) -> None:
        syntax = subprocess.run(
            ["bash", "-n", str(SCRIPT)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        help_result = subprocess.run(
            [str(SCRIPT), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Codex / GPT-5.6 Sol", help_result.stdout)
        self.assertIn("Claude / Opus", help_result.stdout)
        self.assertIn("ASF_REVIEW_GATE", help_result.stdout)
        self.assertIn("ASF_REVIEW_BASELINE", help_result.stdout)
        self.assertIn("ASF_REVIEW_REFRESH", help_result.stdout)
        self.assertIn("ASF_REVIEW_CLAUDE_MAX_TURNS", help_result.stdout)
        self.assertIn("regressions belong in CI", help_result.stdout)
        self.assertIn("model as Git", help_result.stdout)

        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("--json", script)
        self.assertIn("--output-format stream-json", script)
        self.assertIn("--verbose", script)
        self.assertIn('--max-turns "$claude_max_turns"', script)
        self.assertIn("ASF_REVIEW_TIMEOUT", script)
        self.assertIn("run_preflight_gate", script)
        self.assertIn("no model rounds were started", script)
        self.assertIn("refresh_derived", script)
        self.assertIn("refresh_command=${ASF_REVIEW_REFRESH-python3 tools/generate_sbom.py}", script)
        self.assertIn('claude_max_turns=${ASF_REVIEW_CLAUDE_MAX_TURNS:-40}', script)
        self.assertIn("proportional to the diff", script)
        self.assertIn("not a general audit of ASF", script)
        self.assertIn("base-gate.txt records the gate the host already ran", script)
        self.assertIn("write_base_gate_evidence", script)
        self.assertIn("already failing before this branch", script)
        self.assertIn("Do not run repository-wide test discovery", script)
        self.assertIn("belong to the host and CI", script)
        self.assertIn("do not weaken or\ndelete an existing test assertion", script)
        self.assertIn("abort_round 2 \"claude review\"", script)
        self.assertIn("(round $round failed)", script)
        self.assertIn("no task-tree changes to commit from the failed round", script)
        self.assertIn("partial changes committed for inspection", script)
        self.assertIn("main ASF checkout must be clean", script)
        self.assertIn("clean -fdX --quiet", script)
        self.assertIn('check_gate_clean "final gate" || return 1', script)
        self.assertIn('--reason "ai-review loop in progress"', script)
        self.assertIn("gate_failures", script)
        self.assertIn("Review worktree:", script)
        self.assertIn("If you accept the result, from the branch you want to update:", script)
        self.assertIn("git merge --no-ff", script)
        self.assertIn("If you reject the result:", script)
        self.assertIn("Review state retained after failure:", script)
        self.assertIn("To remove this failed review:", script)
        self.assertIn("print_cleanup_commands", script)
        self.assertIn("branch -D", script)
        self.assertIn('"Codex via ASF" "codex@localhost"', script)
        self.assertIn('"Claude via ASF" "claude@localhost"', script)
        self.assertIn('"ASF Review Loop" "ai-review@localhost"', script)
        self.assertIn('--author="$author_name <$author_email>"', script)
        self.assertNotIn("unittest discover", script)
        self.assertNotIn("tests/test_cli.sh", script)

    def test_baseline_override_is_explicit_opt_in(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as prompt:
            prompt.write("test task\n")
            prompt.flush()
            result = subprocess.run(
                [str(SCRIPT), "baseline-contract", prompt.name],
                cwd=ROOT,
                env={**os.environ, "ASF_REVIEW_BASELINE": "yes"},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ASF_REVIEW_BASELINE must be unset or 1", result.stderr)

    def test_claude_turn_limit_override_is_validated(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as prompt:
            prompt.write("test task\n")
            prompt.flush()
            result = subprocess.run(
                [str(SCRIPT), "turn-limit-contract", prompt.name],
                cwd=ROOT,
                env={**os.environ, "ASF_REVIEW_CLAUDE_MAX_TURNS": "0"},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "ASF_REVIEW_CLAUDE_MAX_TURNS must be a positive integer",
            result.stderr,
        )

    def test_stream_helper_separates_codex_events_answer_and_usage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            events = directory / "codex.jsonl"
            runtime = directory / "runtime.log"
            answer = directory / "answer.md"
            usage = directory / "usage.jsonl"
            source = "\n".join(
                [
                    '{"outcome":"success","containerId":"abc"}',
                    '{"type":"thread.started","thread_id":"t1"}',
                    json.dumps({"type": "item.started", "item": {"id": "i1", "type": "command_execution", "command": "/bin/bash -lc 'python3 -m unittest tests.test_dependencies'", "aggregated_output": "", "status": "in_progress"}}),
                    '{"type":"item.completed","item":{"id":"i2","type":"agent_message","text":"Implemented the focused regression test."}}',
                    '{"type":"turn.completed","usage":{"input_tokens":1000,"cached_input_tokens":800,"output_tokens":120,"reasoning_output_tokens":20}}',
                    "",
                ]
            )
            result = subprocess.run(
                [
                    str(STREAM),
                    "stream",
                    "--agent",
                    "codex",
                    "--round",
                    "1",
                    "--jsonl",
                    str(events),
                    "--runtime-log",
                    str(runtime),
                    "--answer",
                    str(answer),
                    "--usage",
                    str(usage),
                ],
                input=source,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("agent started", result.stdout)
            self.assertIn("Bash: python3 -m unittest tests.test_dependencies", result.stdout)
            self.assertNotIn("/bin/bash -lc", result.stdout)
            self.assertEqual(
                answer.read_text(encoding="utf-8"),
                "Implemented the focused regression test.\n",
            )
            self.assertIn('"outcome":"success"', runtime.read_text(encoding="utf-8"))
            self.assertNotIn("outcome", events.read_text(encoding="utf-8"))
            record = json.loads(usage.read_text(encoding="utf-8"))
            self.assertEqual(record["input_tokens"], 1000)
            self.assertEqual(record["cached_input_tokens"], 800)
            self.assertEqual(record["output_tokens"], 120)

            summary = subprocess.run(
                [str(STREAM), "summarize", "--usage", str(usage)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(summary.returncode, 0, summary.stderr)
            self.assertIn("input 200 new + 800 cached", summary.stdout)

    def test_stream_helper_drains_bursty_input_without_false_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            events = directory / "codex.jsonl"
            process = subprocess.Popen(
                [
                    str(STREAM),
                    "stream",
                    "--agent",
                    "codex",
                    "--round",
                    "1",
                    "--jsonl",
                    str(events),
                    "--runtime-log",
                    str(directory / "runtime.log"),
                    "--answer",
                    str(directory / "answer.md"),
                    "--usage",
                    str(directory / "usage.jsonl"),
                    "--heartbeat",
                    "1",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert process.stdin is not None
            source = "\n".join(
                [
                    '{"type":"thread.started","thread_id":"t1"}',
                    '{"type":"item.started","item":{"type":"command_execution","command":"echo hi"}}',
                    '{"type":"item.completed","item":{"type":"agent_message","text":"done"}}',
                    '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":2}}',
                    "",
                ]
            )
            process.stdin.write(source)
            process.stdin.flush()

            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                if events.exists() and len(events.read_text(encoding="utf-8").splitlines()) == 4:
                    break
                time.sleep(0.02)
            self.assertTrue(events.exists())
            self.assertEqual(len(events.read_text(encoding="utf-8").splitlines()), 4)

            process.stdin.close()
            returncode = process.wait(timeout=5)
            stderr = ""
            if process.stderr is not None:
                stderr = process.stderr.read()
                process.stderr.close()
            self.assertEqual(returncode, 0, stderr)

    def test_stream_helper_handles_claude_usage_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            usage = directory / "usage.jsonl"
            source = "\n".join(
                [
                    '{"type":"system","subtype":"init","session_id":"s1"}',
                    '{"type":"assistant","message":{"id":"m-tool","content":[{"type":"tool_use","name":"Read","input":{"file_path":"README.md"}},{"type":"tool_use","name":"Bash","input":{"command":"python3 -m unittest tests.test_ai_review_loop"}},{"type":"tool_use","name":"Grep","input":{"pattern":"ASF_REVIEW_GATE","path":"tools"}}]}}',
                    '{"type":"assistant","message":{"id":"m-final","content":[{"type":"text","text":"Review passed; "}]}}',
                    '{"type":"assistant","message":{"id":"m-final","content":[{"type":"text","text":"no fixes needed."}]}}',
                    '{"type":"result","subtype":"success","is_error":false,"duration_ms":2500,"num_turns":3,"result":"","total_cost_usd":0.125,"usage":{"input_tokens":20,"cache_read_input_tokens":900,"cache_creation_input_tokens":50,"output_tokens":80}}',
                    "",
                ]
            )
            result = subprocess.run(
                [
                    str(STREAM),
                    "stream",
                    "--agent",
                    "claude",
                    "--round",
                    "2",
                    "--jsonl",
                    str(directory / "claude.jsonl"),
                    "--runtime-log",
                    str(directory / "runtime.log"),
                    "--answer",
                    str(directory / "answer.md"),
                    "--usage",
                    str(usage),
                ],
                input=source,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Read: README.md", result.stdout)
            self.assertIn("Bash: python3 -m unittest tests.test_ai_review_loop", result.stdout)
            self.assertIn("Grep: 'ASF_REVIEW_GATE' in tools", result.stdout)
            self.assertEqual(
                (directory / "answer.md").read_text(encoding="utf-8"),
                "Review passed; no fixes needed.\n",
            )

            summary = subprocess.run(
                [str(STREAM), "summarize", "--usage", str(usage)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(summary.returncode, 0, summary.stderr)
            self.assertIn("round 2 · claude · 2s", summary.stdout)
            self.assertIn("input 70 new + 900 cached", summary.stdout)
            self.assertIn("provider-reported $0.1250", summary.stdout)
            self.assertIn("claude total", summary.stdout)
            self.assertIn("provider-reported $0.1250", summary.stdout.splitlines()[-1])

    def test_stream_helper_reports_a_truncated_claude_round_as_failed(self) -> None:
        # error_max_turns can arrive with is_error false; a truncated review
        # must still fail the round and name its cause.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            usage = directory / "usage.jsonl"
            source = (
                '{"type":"result","subtype":"error_max_turns","is_error":false,'
                '"duration_ms":1000,"num_turns":40,"usage":{"output_tokens":1}}\n'
            )
            result = subprocess.run(
                [
                    str(STREAM),
                    "stream",
                    "--agent",
                    "claude",
                    "--round",
                    "2",
                    "--jsonl",
                    str(directory / "claude.jsonl"),
                    "--runtime-log",
                    str(directory / "runtime.log"),
                    "--answer",
                    str(directory / "answer.md"),
                    "--usage",
                    str(usage),
                ],
                input=source,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn("hit the turn cap after 40 turns", result.stdout)
            self.assertEqual(
                json.loads(usage.read_text(encoding="utf-8"))["outcome"],
                "error_max_turns",
            )

            summary = subprocess.run(
                [str(STREAM), "summarize", "--usage", str(usage)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(summary.returncode, 0, summary.stderr)
            self.assertIn("error_max_turns", summary.stdout)


if __name__ == "__main__":
    unittest.main()
