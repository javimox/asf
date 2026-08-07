"""Tests for the typed Podman client boundary."""

from __future__ import annotations

import json
import math
import os
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from asf.errors import AsfError, InfrastructureError, ValidationError
from asf.podman import (
    ContainerInspection,
    ContainerState,
    HealthStatus,
    ObjectKind,
    ObjectNotFoundError,
    PodmanClient,
    PodmanUnavailableError,
    PodmanCommandError,
    PodmanError,
    PodmanOutputError,
    PodmanValidationError,
)
from asf.process import CommandNotFoundError, CommandResult


class FakeRunner:
    def __init__(
        self,
        *,
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
        error: Exception | None = None,
    ) -> None:
        self.result = CommandResult(
            argv=("podman",),
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )
        self.error = error
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def __call__(
        self,
        argv: Sequence[str | Path],
        *,
        timeout: float,
        **_: Any,
    ) -> CommandResult:
        self.calls.append((tuple(str(value) for value in argv), timeout))
        if self.error is not None:
            raise self.error
        return self.result


def inspect_document(
    *,
    container_id: str = "0123456789ab",
    name: str = "asf-demo",
    image: str = "localhost/asf:latest",
    status: str = "running",
    running: bool = True,
    health: str | None = "healthy",
    labels: dict[str, str] | None = None,
) -> dict[str, object]:
    state: dict[str, object] = {"Status": status, "Running": running}
    if health is not None:
        state["Health"] = {"Status": health}
    return {
        "Id": container_id,
        "Name": name,
        "Config": {"Image": image, "Labels": labels or {}},
        "State": state,
    }


class ErrorHierarchyTests(unittest.TestCase):
    def test_errors_reach_shared_cli_boundary(self) -> None:
        for error in (
            PodmanError("x"),
            PodmanCommandError("x"),
            PodmanOutputError("x"),
            PodmanValidationError("x"),
        ):
            self.assertIsInstance(error, AsfError)

        self.assertTrue(issubclass(PodmanError, InfrastructureError))
        self.assertTrue(issubclass(PodmanValidationError, ValidationError))


class ClientValidationTests(unittest.TestCase):
    def test_engine_and_timeout_are_validated(self) -> None:
        for engine in ("", "podman\x00x"):
            with self.subTest(engine=engine):
                with self.assertRaises(PodmanValidationError):
                    PodmanClient(engine=engine)

        for timeout in (0, -1, math.inf, math.nan):
            with self.subTest(timeout=timeout):
                with self.assertRaises(PodmanValidationError):
                    PodmanClient(timeout=timeout)

        with self.assertRaises(TypeError):
            PodmanClient(timeout=True)

    def test_labels_and_references_are_validated(self) -> None:
        client = PodmanClient(runner=FakeRunner())
        with self.assertRaises(TypeError):
            client.container_ids(labels="asf.session=x")
        for label in ("", "x\ny", "x\x00y"):
            with self.subTest(label=label):
                with self.assertRaises(PodmanValidationError):
                    client.container_ids(labels=(label,))

        with self.assertRaises(TypeError):
            client.inspect_containers("container")
        with self.assertRaises(PodmanValidationError):
            client.inspect_containers(())
        for reference in ("", " x", "x y", "x\ny"):
            with self.subTest(reference=reference):
                with self.assertRaises(PodmanValidationError):
                    client.inspect_container(reference)


class ContainerListingTests(unittest.TestCase):
    def test_running_lookup_matches_the_bash_command_shape(self) -> None:
        runner = FakeRunner(stdout="abc123\n\ndef456\nabc123\n")
        client = PodmanClient(timeout=9, runner=runner)

        actual = client.container_ids(
            labels=("asf.session=checkout-hermes", "asf.owner=yes")
        )

        self.assertEqual(actual, ("abc123", "def456"))
        self.assertEqual(
            runner.calls,
            [
                (
                    (
                        "podman",
                        "ps",
                        "-q",
                        "--filter",
                        "label=asf.session=checkout-hermes",
                        "--filter",
                        "label=asf.owner=yes",
                    ),
                    9.0,
                )
            ],
        )

    def test_stopped_lookup_adds_all_without_changing_filters(self) -> None:
        runner = FakeRunner()
        client = PodmanClient(runner=runner)
        self.assertEqual(
            client.container_ids(
                labels=("asf.session=x",), include_stopped=True
            ),
            (),
        )
        self.assertEqual(
            runner.calls[0][0],
            (
                "podman",
                "ps",
                "--all",
                "-q",
                "--filter",
                "label=asf.session=x",
            ),
        )

    def test_invalid_output_is_not_treated_as_a_container(self) -> None:
        client = PodmanClient(runner=FakeRunner(stdout="id with spaces\n"))
        with self.assertRaises(PodmanOutputError):
            client.container_ids(labels=("asf.session=x",))


    def test_nonzero_custom_runner_result_is_still_a_command_failure(self) -> None:
        client = PodmanClient(
            runner=FakeRunner(returncode=125, stderr="engine failure")
        )
        with self.assertRaises(PodmanCommandError) as caught:
            client.container_ids(labels=("asf.session=x",))
        self.assertIn("status 125", str(caught.exception))
        self.assertNotIn("engine failure", str(caught.exception))

    def test_command_failure_is_not_collapsed_to_no_match(self) -> None:
        process_error = CommandNotFoundError(
            "command not found: podman", argv=("podman",)
        )
        client = PodmanClient(runner=FakeRunner(error=process_error))
        with self.assertRaises(PodmanUnavailableError) as caught:
            client.container_ids(labels=("asf.session=x",))
        self.assertIs(caught.exception.__cause__, process_error)


class ContainerInspectionTests(unittest.TestCase):
    def test_parses_a_stable_immutable_inspection_subset(self) -> None:
        document = inspect_document(labels={"asf.agent": "hermes"})
        runner = FakeRunner(stdout=json.dumps([document]))
        client = PodmanClient(runner=runner)

        inspected = client.inspect_container("abc123")

        self.assertEqual(
            inspected,
            ContainerInspection(
                container_id="0123456789ab",
                name="asf-demo",
                image="localhost/asf:latest",
                status="running",
                running=True,
                health="healthy",
                labels={"asf.agent": "hermes"},
            ),
        )
        self.assertEqual(inspected.label("asf.agent"), "hermes")
        copy = inspected.labels_dict()
        copy["asf.agent"] = "changed"
        self.assertEqual(inspected.label("asf.agent"), "hermes")
        with self.assertRaises(TypeError):
            inspected.labels["new"] = "value"  # type: ignore[index]
        self.assertEqual(
            runner.calls[0][0],
            ("podman", "inspect", "--type", "container", "abc123"),
        )

    def test_health_and_labels_are_optional(self) -> None:
        document = inspect_document(health=None)
        document["Config"] = {"Image": "image", "Labels": None}
        inspected = PodmanClient(
            runner=FakeRunner(stdout=json.dumps([document]))
        ).inspect_container("abc")
        self.assertIsNone(inspected.health)
        self.assertEqual(inspected.labels_dict(), {})

    def test_multiple_containers_are_parsed_in_order(self) -> None:
        documents = [
            inspect_document(container_id="aaa", name="one"),
            inspect_document(
                container_id="bbb",
                name="two",
                status="exited",
                running=False,
            ),
        ]
        client = PodmanClient(
            runner=FakeRunner(stdout=json.dumps(documents))
        )
        actual = client.inspect_containers(("one", "two"))
        self.assertEqual(
            tuple(container.container_id for container in actual),
            ("aaa", "bbb"),
        )

    def test_malformed_or_incomplete_documents_fail_closed(self) -> None:
        invalid_documents: tuple[str, ...] = (
            "not-json",
            "{}",
            "[]",
            json.dumps([{}]),
            json.dumps([inspect_document() | {"State": {}}]),
            json.dumps(
                [inspect_document() | {"Config": {"Image": "x", "Labels": {"x": 1}}}]
            ),
        )
        for output in invalid_documents:
            with self.subTest(output=output):
                client = PodmanClient(runner=FakeRunner(stdout=output))
                with self.assertRaises(PodmanOutputError):
                    client.inspect_container("abc")


class ObservationTests(unittest.TestCase):
    def test_observe_preserves_nonzero_status_and_timeout_override(self) -> None:
        runner = FakeRunner(returncode=125, stderr="engine failure")
        client = PodmanClient(timeout=20, runner=runner)

        result = client.observe(("podman", "run", "image"), timeout=3)

        self.assertEqual(result.returncode, 125)
        self.assertEqual(runner.calls[0][1], 3.0)

    def test_observe_requires_the_configured_engine(self) -> None:
        client = PodmanClient(runner=FakeRunner())
        with self.assertRaises(PodmanValidationError):
            client.observe(("docker", "ps"))
        with self.assertRaises(PodmanValidationError):
            client.observe(())
        with self.assertRaises(TypeError):
            client.observe("podman ps")  # type: ignore[arg-type]

        with self.assertRaises(TypeError):
            client.observe(
                ("podman", "ps"),
                missing_kind="container",  # type: ignore[arg-type]
            )
        with self.assertRaises(TypeError):
            client.observe(
                ("podman", "ps"),
                input_text=b"bytes",  # type: ignore[arg-type]
            )

    def test_inspect_and_exec_accept_per_probe_timeouts(self) -> None:
        inspect_runner = FakeRunner(
            stdout=json.dumps([inspect_document()])
        )
        PodmanClient(runner=inspect_runner).inspect_container(
            "runtime", timeout=2
        )
        self.assertEqual(inspect_runner.calls[0][1], 2.0)

        exec_runner = FakeRunner(returncode=1)
        result = PodmanClient(runner=exec_runner).exec_container(
            "runtime", ("nc", "-z", "host", "443"),
            check=False,
            timeout=4,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(exec_runner.calls[0][1], 4.0)

    def test_normal_calls_do_not_require_input_text_runner_keyword(self) -> None:
        calls: list[tuple[tuple[str, ...], float]] = []

        def runner(argv, *, timeout):
            calls.append((tuple(str(value) for value in argv), timeout))
            return CommandResult(
                argv=("podman",),
                returncode=0,
                stdout="",
                stderr="",
            )

        PodmanClient(runner=runner).container_ids(("asf.session=x",))
        self.assertEqual(calls[0][0][:2], ("podman", "ps"))

    def test_exec_with_input_enables_interactive_stdin(self) -> None:
        runner = FakeRunner(returncode=0)
        client = PodmanClient(runner=runner)
        client.exec_container(
            "runtime",
            ("nc", "proxy", "3128"),
            check=False,
            input_text="GET / HTTP/1.0\r\n\r\n",
        )
        self.assertEqual(
            runner.calls[0][0],
            ("podman", "exec", "-i", "runtime", "nc", "proxy", "3128"),
        )

        with self.assertRaises(TypeError):
            client.exec_container(
                "runtime",
                ("nc", "proxy", "3128"),
                input_text=b"bytes",  # type: ignore[arg-type]
            )

    def test_timeout_override_is_validated(self) -> None:
        client = PodmanClient(runner=FakeRunner())
        for timeout in (0, -1, math.inf, math.nan):
            with self.subTest(timeout=timeout):
                with self.assertRaises(PodmanValidationError):
                    client.observe(("podman", "ps"), timeout=timeout)
        with self.assertRaises(TypeError):
            client.observe(("podman", "ps"), timeout=True)


class SecretDiscoveryTests(unittest.TestCase):
    def test_secret_names_use_the_unfiltered_compatible_command(self) -> None:
        runner = FakeRunner(stdout="asf-a-provider-1\n\nother\n")
        client = PodmanClient(runner=runner)
        self.assertEqual(
            client.secret_names(), ("asf-a-provider-1", "other")
        )
        self.assertEqual(
            runner.calls[-1][0],
            ("podman", "secret", "ls", "--format", "{{.Name}}"),
        )

    def test_malformed_secret_names_fail_closed(self) -> None:
        client = PodmanClient(runner=FakeRunner(stdout="bad name\n"))
        with self.assertRaises(PodmanOutputError):
            client.secret_names()


class ScriptedRunner:
    def __init__(self, *results: CommandResult) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, ...]] = []

    def __call__(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        timeout: float,
        **_: Any,
    ) -> CommandResult:
        del timeout
        self.calls.append(tuple(os.fspath(value) for value in argv))
        if not self.results:
            raise AssertionError("unexpected Podman call")
        return self.results.pop(0)


def result(
    *, stdout: str = "", stderr: str = "", returncode: int = 0
) -> CommandResult:
    return CommandResult(
        argv=("podman",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def payload(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "Id": "0123456789abcdef",
        "Name": "/asf-runtime",
        "Config": {
            "Image": "localhost/asf:test",
            "Labels": {"asf.agent": "hermes"},
            "Env": ["TOKEN=must-not-be-captured"],
        },
        "State": {
            "Status": "running",
            "Running": True,
            "ExitCode": 0,
            "Healthcheck": {"Status": "healthy"},
        },
        "NetworkSettings": {
            "Networks": {"z-network": {}, "a-network": {}}
        },
    }
    document.update(overrides)
    return document


class TypedModelTests(unittest.TestCase):
    def test_state_and_health_are_forward_compatible(self) -> None:
        self.assertIs(ContainerState.parse("running"), ContainerState.RUNNING)
        self.assertIs(ContainerState.parse("future-state"), ContainerState.UNKNOWN)
        self.assertIs(HealthStatus.parse(None), HealthStatus.NONE)
        self.assertIs(HealthStatus.parse("future"), HealthStatus.UNKNOWN)

    def test_full_inspect_payload_exposes_typed_views_without_environment(self) -> None:
        client = PodmanClient(
            runner=ScriptedRunner(result(stdout=json.dumps([payload()])))
        )
        inspected = client.inspect_container("0123456789ab")
        self.assertEqual(inspected.name, "asf-runtime")
        self.assertIs(inspected.state, ContainerState.RUNNING)
        self.assertIs(inspected.health_status, HealthStatus.HEALTHY)
        self.assertEqual(inspected.networks, ("a-network", "z-network"))
        self.assertEqual(inspected.exit_code, 0)
        self.assertNotIn("environment", dir(inspected))
        self.assertNotIn("TOKEN", repr(inspected))

    def test_unknown_nonempty_state_is_not_mistaken_for_stopped(self) -> None:
        document = payload()
        document["State"] = {"Status": "future-state", "Running": False}
        inspected = PodmanClient(
            runner=ScriptedRunner(result(stdout=json.dumps([document])))
        ).inspect_container("id")
        self.assertIs(inspected.state, ContainerState.UNKNOWN)
        self.assertFalse(inspected.running)

    def test_incomplete_identity_or_state_fails_closed(self) -> None:
        invalid = (
            {},
            {"Id": "id", "Config": {}, "State": {}},
            payload(Id=""),
            payload(State={"Status": "running", "Running": "yes"}),
            payload(Config={"Image": "image", "Labels": {"x": 1}}),
        )
        for document in invalid:
            with self.subTest(document=document):
                client = PodmanClient(
                    runner=ScriptedRunner(
                        result(stdout=json.dumps([document]))
                    )
                )
                with self.assertRaises(PodmanOutputError):
                    client.inspect_container("id")


class ObjectOutcomeTests(unittest.TestCase):
    def test_missing_object_is_distinct_from_engine_failure(self) -> None:
        missing = PodmanClient(
            runner=ScriptedRunner(
                result(
                    returncode=125,
                    stderr="Error: no such container: demo\n",
                )
            )
        )
        with self.assertRaises(ObjectNotFoundError):
            missing.inspect_container("demo")

        failed = PodmanClient(
            runner=ScriptedRunner(
                result(
                    returncode=125,
                    stderr="network plugin not found in search path\n",
                )
            )
        )
        with self.assertRaises(PodmanCommandError):
            failed.inspect_container("demo")

    def test_exists_uses_object_specific_commands(self) -> None:
        runner = ScriptedRunner(
            result(stdout="[]"),
            result(),
            result(stdout="{}"),
            result(stdout="{}"),
        )
        client = PodmanClient(runner=runner)
        self.assertTrue(client.exists("c", ObjectKind.CONTAINER))
        self.assertTrue(client.exists("n", ObjectKind.NETWORK))
        self.assertTrue(client.exists("v", ObjectKind.VOLUME))
        self.assertTrue(client.exists("s", ObjectKind.SECRET))
        self.assertEqual(
            runner.calls,
            [
                ("podman", "inspect", "--type", "container", "c"),
                ("podman", "network", "exists", "n"),
                ("podman", "volume", "inspect", "v"),
                ("podman", "secret", "inspect", "s"),
            ],
        )

    def test_network_exists_uses_return_code_one_for_absence(self) -> None:
        client = PodmanClient(runner=ScriptedRunner(result(returncode=1)))
        self.assertFalse(client.exists("missing", ObjectKind.NETWORK))

    def test_network_exists_keeps_status_125_as_infrastructure_failure(self) -> None:
        client = PodmanClient(
            runner=ScriptedRunner(
                result(returncode=125, stderr="network backend failed")
            )
        )
        with self.assertRaisesRegex(PodmanCommandError, "status 125"):
            client.exists("missing", ObjectKind.NETWORK)

    def test_inspect_present_skips_only_confirmed_absence(self) -> None:
        missing = result(
            returncode=125, stderr="Error: no such container: gone\n"
        )
        present = result(stdout=json.dumps([payload(Id="present")]))
        client = PodmanClient(runner=ScriptedRunner(missing, present))
        inspected = client.inspect_present(("gone", "present"))
        self.assertEqual(tuple(item.container_id for item in inspected), ("present",))

    def test_all_errors_reach_the_shared_cli_boundary(self) -> None:
        for error in (
            ObjectNotFoundError("x"),
            PodmanCommandError("x"),
            PodmanOutputError("x"),
        ):
            self.assertIsInstance(error, AsfError)


class DiagnosticCommandTests(unittest.TestCase):
    def test_exec_can_return_a_nonzero_observation(self) -> None:
        runner = ScriptedRunner(result(returncode=7, stderr="query failed"))
        client = PodmanClient(runner=runner)
        observed = client.exec_container(
            "container-id", ("python", "-c", "print('x')"), check=False
        )
        self.assertEqual(observed.returncode, 7)
        self.assertEqual(
            runner.calls[0],
            (
                "podman",
                "exec",
                "container-id",
                "python",
                "-c",
                "print('x')",
            ),
        )

    def test_exec_failure_is_strict_by_default(self) -> None:
        client = PodmanClient(
            runner=ScriptedRunner(result(returncode=9, stderr="failed"))
        )
        with self.assertRaises(PodmanCommandError):
            client.exec_container("container-id", ("cat", "/file"))

    def test_log_arguments_are_validated_and_deterministic(self) -> None:
        client = PodmanClient(engine="/usr/bin/podman", runner=ScriptedRunner())
        self.assertEqual(
            client.logs_argv("container-id", tail=100),
            ("/usr/bin/podman", "logs", "--tail", "100", "container-id"),
        )
        self.assertEqual(
            client.logs_argv("container-id", tail=200, follow=True),
            (
                "/usr/bin/podman",
                "logs",
                "--tail",
                "200",
                "-f",
                "container-id",
            ),
        )
        for tail in (-1, True, 1.5):
            with self.subTest(tail=tail), self.assertRaises(
                (TypeError, PodmanValidationError)
            ):
                client.logs_argv("container-id", tail=tail)  # type: ignore[arg-type]

    def test_finite_log_tail_uses_the_shared_timeout_runner(self) -> None:
        runner = ScriptedRunner(result(stdout="line\n"))
        result_value = PodmanClient(runner=runner).container_logs(
            "container-id", tail=25
        )
        self.assertEqual(result_value.stdout, "line\n")
        self.assertEqual(
            runner.calls[0],
            ("podman", "logs", "--tail", "25", "container-id"),
        )


class AvailabilityTests(unittest.TestCase):
    def test_absolute_executable_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "podman"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            self.assertTrue(PodmanClient(engine=executable).is_available())


if __name__ == "__main__":
    unittest.main()
