"""Focused Phase 2B tests for proxy and broker diagnostics."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from asf.cli import main
from asf.diagnostics import DiagnosticsError, run_diagnostic_command
from asf.egress_evidence import begin_egress_session
from asf.paths import RepoPaths
from asf.session import AmbiguousSessionError
from asf.podman import PodmanClient
from asf.process import CommandResult


def make_checkout(root: Path) -> RepoPaths:
    (root / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
    (root / ".devcontainer").mkdir()
    agents = root / "agents"
    for runtime in ("claude", "hermes"):
        directory = agents / runtime
        directory.mkdir(parents=True)
        (directory / "runtime.yml").write_text(f"name: {runtime}\n")
    return RepoPaths.for_root(root)


def inspection(
    container_id: str,
    name: str,
    *,
    image: str,
    labels: dict[str, str],
    networks: tuple[str, ...] = (),
) -> str:
    return json.dumps(
        [
            {
                "Id": container_id,
                "Name": name,
                "Config": {"Image": image, "Labels": labels},
                "State": {"Status": "running", "Running": True},
                "NetworkSettings": {
                    "Networks": {network: {} for network in networks}
                },
            }
        ]
    )


class DiagnosticRunner:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls: list[tuple[str, ...]] = []
        self.running_runtime = "claude"
        self.proxy = True
        self.broker = True
        self.access_logs = "true"
        self.duplicate_proxy = False
        self.live_models = "gpt-5.5, gpt-5.6\n"

    def __call__(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        timeout: float,
        **_: Any,
    ) -> CommandResult:
        del timeout
        call = tuple(os.fspath(value) for value in argv)
        self.calls.append(call)
        command = call[1:]
        stdout = ""
        stderr = ""
        returncode = 0

        if command[:1] == ("ps",):
            joined = " ".join(command)
            if "asf.session=" in joined:
                if self.running_runtime and joined.endswith(self.running_runtime):
                    stdout = "runtime-id\n"
            elif "asf.role=proxy" in joined and self.proxy:
                stdout = "proxy-id\nproxy-id-2\n" if self.duplicate_proxy else "proxy-id\n"
            elif "asf.role=broker" in joined and self.broker:
                stdout = "broker-id\n"
        elif command[:3] == ("inspect", "--type", "container"):
            reference = command[3]
            if reference == "proxy-id":
                stdout = inspection(
                    "proxy-id",
                    "proxy-name",
                    image="caddy:test",
                    labels={
                        "asf.access-logs": self.access_logs,
                        "asf.role": "proxy",
                    },
                    networks=("internal", "egress"),
                )
            elif reference == "broker-id":
                stdout = inspection(
                    "broker-id",
                    "/broker-name",
                    image="litellm:test",
                    labels={
                        "asf.provider": "openai",
                        "asf.model-route": "openai/* (all models)",
                        "asf.agent": "claude",
                        "asf.default-model": "gpt-5.5",
                    },
                )
            else:
                returncode = 125
                stderr = "Error: no such container\n"
        elif command[:2] == ("exec", "proxy-id"):
            stdout = (
                ":3128 {\n"
                "  forward_proxy {\n"
                "    ports 443\n"
                "    acl {\n"
                "      allow github.com\n"
                "      allow api.openai.com\n"
                "      deny all\n"
                "    }\n"
                "  }\n"
                "}\n"
            )
        elif command[:2] == ("exec", "broker-id"):
            stdout = self.live_models
        elif command[:1] == ("logs",):
            stdout = "diagnostic log\n"
        else:
            raise AssertionError(f"unexpected command: {call}")

        return CommandResult(
            argv=call,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )


class ProxyDiagnosticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "asf"
        root.mkdir()
        self.paths = make_checkout(root)
        self.runner = DiagnosticRunner(root)
        self.podman = PodmanClient(engine="/bin/true", runner=self.runner)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_status_and_config_use_typed_inspection(self) -> None:
        status = run_diagnostic_command(
            ("proxy", "status", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(status.returncode, 0)
        self.assertEqual(status.stderr, "")
        self.assertIn("Caddy proxy for claude", status.stdout)
        self.assertIn("  container: proxy-name", status.stdout)
        self.assertIn("  access logs: true", status.stdout)
        self.assertIn("    egress", status.stdout)
        self.assertIn("  permitted port: 443", status.stdout)
        self.assertIn("    github.com", status.stdout)

        config = run_diagnostic_command(
            ("proxy", "config", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertTrue(config.stdout.startswith(":3128"))

    def test_logs_read_session_file_and_follow_without_spawning_a_shell(self) -> None:
        context = begin_egress_session(self.paths, "claude", ("github.com",))
        context.access_log_path.write_text(
            '{"request":{"method":"CONNECT","host":"github.com:443"}}\n',
            encoding="utf-8",
        )
        finite = run_diagnostic_command(
            ("proxy", "logs", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertIn("CONNECT", finite.stdout)
        self.assertEqual(finite.stderr, "")

        following = run_diagnostic_command(
            ("proxy", "logs", "-f", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(
            following.replace_argv,
            ("tail", "-n", "100", "-f", "--", str(context.access_log_path)),
        )
        accepted_legacy_quirk = run_diagnostic_command(
            ("proxy", "logs", "--follow", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertIsNone(accepted_legacy_quirk.replace_argv)
        self.assertIn("CONNECT", accepted_legacy_quirk.stdout)

        self.runner.access_logs = "false"
        disabled = run_diagnostic_command(
            ("proxy", "logs", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(disabled.stdout, "diagnostic log\n")
        self.assertIn("access logs are unavailable", disabled.stderr)

    def test_absence_usage_and_duplicate_ownership(self) -> None:
        self.runner.proxy = False
        absent = run_diagnostic_command(
            ("proxy", "status", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(absent.returncode, 1)
        self.assertIn("No running Caddy proxy", absent.stderr)

        usage = run_diagnostic_command(
            ("proxy", "status", "unexpected"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(usage.returncode, 1)
        self.assertIn("Usage: ./sandbox.sh proxy", usage.stderr)

        self.runner.proxy = True
        self.runner.duplicate_proxy = True
        with self.assertRaises(AmbiguousSessionError):
            run_diagnostic_command(
                ("proxy", "status", "claude"),
                self.paths,
                podman=self.podman,
                require_available=False,
            )


class BrokerDiagnosticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "asf"
        root.mkdir()
        self.paths = make_checkout(root)
        self.runner = DiagnosticRunner(root)
        self.podman = PodmanClient(engine="/bin/true", runner=self.runner)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_status_prefers_live_models_and_keeps_default(self) -> None:
        result = run_diagnostic_command(
            ("broker", "status", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("LiteLLM broker", result.stdout)
        self.assertIn("  container: broker-name", result.stdout)
        self.assertIn("  image:     litellm:test", result.stdout)
        self.assertIn("  models:    gpt-5.5, gpt-5.6", result.stdout)
        self.assertIn("  default:   gpt-5.5", result.stdout)

    def test_status_falls_back_to_declared_route(self) -> None:
        self.runner.live_models = ""
        result = run_diagnostic_command(
            ("broker", "status", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertIn("  models:    openai/* (all models)", result.stdout)

    def test_logs_and_absence_preserve_bash_streams(self) -> None:
        logs = run_diagnostic_command(
            ("broker", "logs", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(logs.stdout, "diagnostic log\n")
        follow = run_diagnostic_command(
            ("broker", "logs", "--follow", "claude", "ignored"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(
            follow.replace_argv,
            ("/bin/true", "logs", "--tail", "200", "-f", "broker-id"),
        )

        self.runner.broker = False
        absent = run_diagnostic_command(
            ("broker", "status", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(absent.returncode, 1)
        self.assertEqual(absent.stderr, "")
        self.assertIn("No LiteLLM broker", absent.stdout)


class CliBoundaryTests(unittest.TestCase):
    def test_missing_podman_preserves_the_bash_help_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "asf"
            root.mkdir()
            make_checkout(root)
            stdout = io.StringIO()
            stderr = io.StringIO()
            status = main(
                ["proxy", "status", "claude"],
                root=root,
                stdout=stdout,
                stderr=stderr,
                podman=PodmanClient(engine=root / "missing-podman"),
            )
            self.assertEqual(status, 1)
            self.assertEqual(stderr.getvalue(), "")
            self.assertIn("Podman not found", stdout.getvalue())
            self.assertIn("rootless Podman", stdout.getvalue())
            self.assertNotIn("Traceback", stdout.getvalue())

    def test_follow_mode_flushes_then_replaces_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "asf"
            root.mkdir()
            make_checkout(root)
            runner = DiagnosticRunner(root)
            podman = PodmanClient(engine="/bin/true", runner=runner)
            stdout = io.StringIO()
            stderr = io.StringIO()
            replaced: list[tuple[str, ...]] = []

            def fake_replace(argv: Sequence[str]) -> None:
                replaced.append(tuple(argv))
                raise RuntimeError("replaced")

            with self.assertRaisesRegex(RuntimeError, "replaced"):
                main(
                    ["proxy", "logs", "-f", "claude"],
                    root=root,
                    stdout=stdout,
                    stderr=stderr,
                    podman=podman,
                    replace_process=fake_replace,
                )
            self.assertEqual(
                replaced,
                [("/bin/true", "logs", "--tail", "100", "-f", "proxy-id")],
            )


if __name__ == "__main__":
    unittest.main()
