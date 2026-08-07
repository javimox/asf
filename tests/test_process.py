#!/usr/bin/env python3
"""Focused tests for ASF's subprocess execution boundary."""

from __future__ import annotations

import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.errors import AsfError, InfrastructureError
from asf.process import (
    CommandError,
    CommandFailedError,
    CommandNotFoundError,
    CommandResult,
    CommandStartError,
    CommandTimeoutError,
    SensitiveArgument,
    probe,
    replace,
    run,
    run_streaming,
    sensitive,
)
from asf.secrets import SecretValue


PYTHON = Path(sys.executable)


def python_command(source: str, *arguments: object) -> list[object]:
    return [PYTHON, "-c", source, *arguments]


class ExecutionTests(unittest.TestCase):
    def test_success_keeps_stdout_and_stderr_separate(self) -> None:
        result = run(
            python_command(
                "import sys; print('out'); print('err', file=sys.stderr)"
            ),
            timeout=5,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "out\n")
        self.assertEqual(result.stderr, "err\n")
        self.assertTrue(result.succeeded)

    def test_run_raises_for_nonzero_status(self) -> None:
        with self.assertRaises(CommandFailedError) as caught:
            run(
                python_command(
                    "import sys; print('out'); print('err', file=sys.stderr); "
                    "raise SystemExit(7)"
                ),
                timeout=5,
            )

        error = caught.exception
        self.assertIsInstance(error, InfrastructureError)
        self.assertEqual(error.returncode, 7)
        self.assertEqual(error.result.returncode, 7)
        self.assertEqual(error.stdout, "out\n")
        self.assertEqual(error.stderr, "err\n")
        self.assertIn("status 7", str(error))

    def test_probe_returns_nonzero_as_an_observation(self) -> None:
        result = probe(
            python_command("raise SystemExit(23)"),
            timeout=5,
        )

        self.assertEqual(result.returncode, 23)
        self.assertFalse(result.succeeded)

    def test_missing_executable_is_distinct(self) -> None:
        executable = "/asf-test/command-that-does-not-exist"
        with self.assertRaises(CommandNotFoundError) as caught:
            probe([executable], timeout=5)

        self.assertEqual(caught.exception.argv, (executable,))
        self.assertIsNone(caught.exception.returncode)
        self.assertIn("command not found", str(caught.exception))

    def test_missing_working_directory_is_not_command_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaises(CommandStartError) as caught:
                probe([PYTHON, "-c", "pass"], timeout=5, cwd=missing)

        self.assertNotIsInstance(caught.exception, CommandNotFoundError)
        self.assertIn(str(missing), str(caught.exception))

    def test_general_start_failure_is_wrapped(self) -> None:
        failure = PermissionError(13, "permission denied")
        with mock.patch("asf.process.subprocess.run", side_effect=failure):
            with self.assertRaises(CommandStartError) as caught:
                probe(["blocked-command"], timeout=5)

        self.assertIn("permission denied", str(caught.exception))
        self.assertEqual(caught.exception.argv, ("blocked-command",))

    def test_timeout_is_an_infrastructure_error(self) -> None:
        with self.assertRaises(CommandTimeoutError) as caught:
            probe(
                python_command("import time; time.sleep(10)"),
                timeout=0.05,
            )

        self.assertIsInstance(caught.exception, InfrastructureError)
        self.assertEqual(caught.exception.timeout, 0.05)
        self.assertIsNone(caught.exception.returncode)
        self.assertIn("0.05s", str(caught.exception))

    def test_timeout_preserves_partial_output(self) -> None:
        source = (
            "import sys, time; "
            "print('partial-out', flush=True); "
            "print('partial-err', file=sys.stderr, flush=True); "
            "time.sleep(10)"
        )
        with self.assertRaises(CommandTimeoutError) as caught:
            probe(python_command(source), timeout=1.0)

        self.assertEqual(caught.exception.stdout, "partial-out\n")
        self.assertEqual(caught.exception.stderr, "partial-err\n")

    def test_invalid_utf8_is_replaced_deterministically(self) -> None:
        source = (
            "import sys; "
            "sys.stdout.buffer.write(b'out\\xff\\n'); "
            "sys.stderr.buffer.write(b'err\\xfe\\n')"
        )
        result = run(python_command(source), timeout=5)

        self.assertEqual(result.stdout, "out\ufffd\n")
        self.assertEqual(result.stderr, "err\ufffd\n")

    def test_environment_is_inherited_and_overridden(self) -> None:
        source = (
            "import os; "
            "print(os.environ['ASF_INHERITED']); "
            "print(os.environ['ASF_OVERRIDE']); "
            "print(os.environ['ASF_ADDED'])"
        )
        with mock.patch.dict(
            os.environ,
            {"ASF_INHERITED": "parent", "ASF_OVERRIDE": "old"},
            clear=False,
        ):
            result = run(
                python_command(source),
                timeout=5,
                env={"ASF_OVERRIDE": "new", "ASF_ADDED": "child"},
            )

        self.assertEqual(result.stdout, "parent\nnew\nchild\n")

    def test_standard_input_is_text(self) -> None:
        result = run(
            python_command("import sys; print(sys.stdin.read().upper(), end='')"),
            timeout=5,
            input_text="hello\n",
        )
        self.assertEqual(result.stdout, "HELLO\n")

    def test_capture_false_uses_parent_streams(self) -> None:
        completed = subprocess.CompletedProcess(["command"], 0, None, None)
        with mock.patch(
            "asf.process.subprocess.run", return_value=completed
        ) as mocked_run:
            result = probe(["command"], timeout=5, capture=False)

        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        kwargs = mocked_run.call_args.kwargs
        self.assertIsNone(kwargs["stdout"])
        self.assertIsNone(kwargs["stderr"])

    def test_pathlike_arguments_and_working_directory_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = run(
                [
                    PYTHON,
                    "-c",
                    "import os, sys; print(os.getcwd()); print(sys.argv[1])",
                    directory,
                ],
                timeout=5,
                cwd=directory,
            )

        self.assertEqual(result.stdout, f"{directory}\n{directory}\n")


class ValidationTests(unittest.TestCase):
    def test_argv_must_be_a_nonempty_sequence(self) -> None:
        for bad in ("echo hello", b"echo hello"):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                probe(bad, timeout=5)  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            probe([], timeout=5)
        with self.assertRaisesRegex(ValueError, "executable"):
            probe([""], timeout=5)

    def test_arguments_and_cwd_reject_nul_bytes(self) -> None:
        with self.assertRaisesRegex(ValueError, r"argv\[1\]"):
            probe(["echo", "bad\x00value"], timeout=5)
        with self.assertRaisesRegex(ValueError, "cwd"):
            probe(["echo"], timeout=5, cwd="bad\x00path")
        with self.assertRaisesRegex(ValueError, "NUL"):
            sensitive("bad\x00secret")

    def test_timeout_must_be_a_finite_positive_number(self) -> None:
        invalid = (0, -1, math.inf, -math.inf, math.nan)
        for timeout in invalid:
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                probe(["echo"], timeout=timeout)

        for timeout in (True, False, "5", None):
            with self.subTest(timeout=timeout), self.assertRaises(TypeError):
                probe(["echo"], timeout=timeout)  # type: ignore[arg-type]

    def test_input_text_must_be_text_or_none(self) -> None:
        with self.assertRaises(TypeError):
            probe(["echo"], timeout=5, input_text=b"bytes")  # type: ignore[arg-type]

    def test_environment_keys_and_values_must_be_safe_text(self) -> None:
        invalid = (
            [("NAME", "value")],
            {1: "value"},
            {"": "value"},
            {"NAME": 1},
            {"BAD=NAME": "value"},
            {"BAD\x00NAME": "value"},
            {"NAME": "bad\x00value"},
        )
        for environment in invalid:
            with self.subTest(environment=environment), self.assertRaises(
                (TypeError, ValueError)
            ):
                probe(["echo"], timeout=5, env=environment)  # type: ignore[arg-type]


class RedactionAndDiagnosticsTests(unittest.TestCase):
    def test_sensitive_argument_reaches_child_but_is_redacted_everywhere(self) -> None:
        secret = "token with spaces"
        result = run(
            python_command("import sys; print(sys.argv[1])", sensitive(secret)),
            timeout=5,
        )

        self.assertEqual(result.argv[-1], "***")
        self.assertEqual(result.stdout, "***\n")
        self.assertNotIn(secret, result.command)
        self.assertNotIn(secret, repr(result))

    def test_sensitive_values_echoed_to_both_streams_are_redacted(self) -> None:
        secret = "provider-secret"
        source = (
            "import sys; "
            "print(sys.argv[1]); "
            "print('error=' + sys.argv[1], file=sys.stderr)"
        )
        result = run(
            python_command(source, SensitiveArgument(secret)),
            timeout=5,
        )

        self.assertEqual(result.stdout, "***\n")
        self.assertEqual(result.stderr, "error=***\n")

    def test_overlapping_secrets_are_redacted_longest_first(self) -> None:
        source = "print('abcd abc')"
        result = run(
            python_command(source, sensitive("abc"), sensitive("abcd")),
            timeout=5,
        )
        self.assertEqual(result.stdout, "*** ***\n")

    def test_failure_diagnostics_do_not_expose_secret_or_captured_output(self) -> None:
        secret = "top-secret"
        output = "ordinary-output"
        source = (
            "import os, sys; "
            "print(os.environ['ASF_OUTPUT_MARKER']); "
            "print(sys.argv[1], file=sys.stderr); "
            "raise SystemExit(9)"
        )
        with self.assertRaises(CommandFailedError) as caught:
            run(
                python_command(source, sensitive(secret)),
                timeout=5,
                env={"ASF_OUTPUT_MARKER": output},
            )

        error = caught.exception
        self.assertEqual(error.stdout, f"{output}\n")
        self.assertEqual(error.stderr, "***\n")
        for displayed in (str(error), repr(error), error.command, repr(error.result)):
            self.assertNotIn(secret, displayed)
            self.assertNotIn(output, displayed)

    def test_timeout_output_is_redacted(self) -> None:
        secret = "timeout-secret"
        source = (
            "import sys, time; "
            "print(sys.argv[1], flush=True); "
            "print(sys.argv[1], file=sys.stderr, flush=True); "
            "time.sleep(10)"
        )
        with self.assertRaises(CommandTimeoutError) as caught:
            probe(
                python_command(source, sensitive(secret)),
                timeout=1.0,
            )

        self.assertEqual(caught.exception.stdout, "***\n")
        self.assertEqual(caught.exception.stderr, "***\n")
        self.assertNotIn(secret, str(caught.exception))

    def test_command_formatting_quotes_and_escapes_safely(self) -> None:
        result = CommandResult(
            argv=(
                "tool",
                "space value",
                "quote'value",
                "line\nnext",
                "tab\tvalue",
                "slash\\value",
            ),
            returncode=0,
            stdout="hidden",
            stderr="also-hidden",
        )

        self.assertIn("'space value'", result.command)
        self.assertIn("line\\nnext", result.command)
        self.assertIn("tab\\tvalue", result.command)
        self.assertIn("slash\\\\value", result.command)
        self.assertNotIn("\n", result.command)
        self.assertNotIn("\t", result.command)
        self.assertNotIn("hidden", repr(result))
        self.assertNotIn("also-hidden", repr(result))


    def test_opaque_secret_can_cross_the_process_boundary_directly(self) -> None:
        secret = SecretValue("direct-secret")
        result = run(
            python_command("import sys; print(sys.argv[1])", secret),
            timeout=5,
        )
        self.assertEqual(result.argv[-1], "***")
        self.assertEqual(result.stdout, "***\n")
        self.assertNotIn("direct-secret", repr(result))

    def test_sensitive_argument_representation_is_opaque(self) -> None:
        value = SensitiveArgument("secret")
        self.assertEqual(str(value), "***")
        self.assertEqual(repr(value), "SensitiveArgument(***)")
        self.assertEqual(value.reveal(), "secret")
        with self.assertRaises(TypeError):
            SensitiveArgument(123)  # type: ignore[arg-type]


class ReplaceProcessTests(unittest.TestCase):
    class Replaced(BaseException):
        pass

    def test_replace_uses_execvpe_with_validated_arguments(self) -> None:
        captured: list[tuple[str, list[str], dict[str, str]]] = []

        def fake_exec(executable: str, argv: list[str], env: dict[str, str]) -> None:
            captured.append((executable, argv, env))
            raise self.Replaced()

        with mock.patch("os.execvpe", side_effect=fake_exec):
            with self.assertRaises(self.Replaced):
                replace(["podman", "logs", "-f", "container"])
        self.assertEqual(captured[0][0], "podman")
        self.assertEqual(
            captured[0][1], ["podman", "logs", "-f", "container"]
        )
        self.assertIn("PATH", captured[0][2])

    def test_replace_maps_start_failures_without_a_shell(self) -> None:
        with mock.patch("os.execvpe", side_effect=FileNotFoundError()):
            with self.assertRaises(CommandNotFoundError):
                replace(["missing-command"])
        with mock.patch("os.execvpe", side_effect=PermissionError("denied")):
            with self.assertRaises(CommandStartError):
                replace(["podman", "logs", "-f", "container"])

class AdditionalContractTests(unittest.TestCase):
    def test_timeout_is_required_by_run_and_probe(self) -> None:
        with self.assertRaises(TypeError):
            run(["true"])  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            probe(["true"])  # type: ignore[call-arg]

    def test_timeout_is_not_a_command_status_failure(self) -> None:
        with self.assertRaises(CommandTimeoutError) as caught:
            probe(python_command("import time; time.sleep(10)"), timeout=0.05)
        self.assertIsInstance(caught.exception, CommandError)
        self.assertNotIsInstance(caught.exception, CommandFailedError)

    def test_sensitive_value_reaches_the_child_unchanged(self) -> None:
        result = probe(
            python_command(
                "import sys; "
                "raise SystemExit(0 if sys.argv[1] == 'exact token' else 4)",
                sensitive("exact token"),
            ),
            timeout=5,
        )
        self.assertTrue(result.succeeded)

    def test_result_is_immutable_and_repr_omits_output_fields(self) -> None:
        result = run(python_command("print('captured' + str(42))"), timeout=5)
        with self.assertRaises(Exception):
            result.returncode = 1  # type: ignore[misc]
        rendered = repr(result)
        self.assertEqual(result.stdout, "captured42\n")
        self.assertNotIn("captured42", rendered)
        self.assertNotIn("stdout=", rendered)
        self.assertNotIn("stderr=", rendered)

    def test_errors_carry_redacted_argv_and_rendered_command(self) -> None:
        with self.assertRaises(CommandFailedError) as caught:
            run(
                python_command("raise SystemExit(3)", sensitive("hidden-token")),
                timeout=5,
            )
        self.assertEqual(caught.exception.argv[-1], "***")
        self.assertIn(str(PYTHON), caught.exception.command)
        self.assertNotIn("hidden-token", caught.exception.command)

    def test_one_cli_boundary_catches_process_failures(self) -> None:
        raisers = (
            lambda: run(python_command("raise SystemExit(1)"), timeout=5),
            lambda: probe(["/asf-test/missing-command"], timeout=5),
            lambda: probe(
                python_command("import time; time.sleep(10)"), timeout=0.05
            ),
        )
        for index, raiser in enumerate(raisers):
            with self.subTest(index=index), self.assertRaises(AsfError) as caught:
                raiser()
            self.assertIsInstance(caught.exception, InfrastructureError)
            self.assertEqual(caught.exception.exit_code, 1)


    def test_streaming_redacts_selected_environment_values(self) -> None:
        output = __import__("io").StringIO()
        error = __import__("io").StringIO()
        token = "ephemeral-broker-token"
        result = run_streaming(
            python_command(
                "import os, sys; "
                "value=os.environ['TOKEN']; "
                "print('stdout=' + value); "
                "print('stderr=' + value, file=sys.stderr)"
            ),
            timeout=5,
            output=output,
            error=error,
            env={"TOKEN": token},
            redact_values=(SecretValue(token),),
        )
        self.assertTrue(result.succeeded)
        for text in (output.getvalue(), error.getvalue(), result.stdout, result.stderr):
            self.assertNotIn(token, text)
            self.assertIn("***", text)

    def test_streaming_failure_retains_only_redacted_diagnostics(self) -> None:
        output = __import__("io").StringIO()
        error = __import__("io").StringIO()
        token = "ephemeral-broker-token"
        with self.assertRaises(CommandFailedError) as caught:
            run_streaming(
                python_command(
                    "import os, sys; "
                    "print(os.environ['TOKEN'], file=sys.stderr); "
                    "raise SystemExit(7)"
                ),
                timeout=5,
                output=output,
                error=error,
                env={"TOKEN": token},
                redact_values=(token,),
            )
        self.assertEqual(caught.exception.returncode, 7)
        self.assertNotIn(token, caught.exception.stderr)
        self.assertEqual(caught.exception.stderr, "***\n")

    def test_succeeded_property_reflects_return_code(self) -> None:
        self.assertTrue(CommandResult(("x",), 0, "", "").succeeded)
        self.assertFalse(CommandResult(("x",), 1, "", "").succeeded)


if __name__ == "__main__":
    unittest.main()
