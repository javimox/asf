#!/usr/bin/env python3
"""Permanent behavioural vectors for ``./sandbox.sh test``.

The expected output was captured from the accepted Bash implementation before
its production body was removed.  The command is invoked through the real
Python CLI with an in-memory Podman runner, keeping all 17 scenarios fast enough
to run in the default suite.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS_FILE = Path(__file__).with_name("security_test_vectors.json")


def _proxy_script_exit(status_line: str) -> int:
    """Mirror the frozen probe script's status-line-to-exit-code mapping."""

    parts = status_line.split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        return 61
    code = parts[1]
    if code == "403":
        return 40
    if code == "407":
        return 41
    if len(code) != 3 or not code.isdigit():
        return 61
    if code.startswith("2"):
        return 20
    if code.startswith("5"):
        return 50
    return 30


def _script_equivalent(command: str, rc: int, stdout: str) -> tuple[int, str]:
    """Translate a vector's Bash-era wire observation into the evidence the
    fixed probe scripts now produce.

    The vectors stay frozen as wire truth (netcat/ip status plus raw output);
    the scripts read that truth in-container and report it in the exit code,
    echoing at most the first status line for diagnostics.
    """

    if "asf-probe-response" in command:
        status = stdout.splitlines()[0].rstrip("\r") if stdout else ""
        return _proxy_script_exit(status), f"{status}\n" if status else ""
    if "route show default" in command:
        if rc != 0:
            return 2, stdout
        if stdout.strip():
            return 21, stdout
        return 22, stdout
    return rc, stdout
sys.path.insert(0, str(ROOT))

from asf.cli import main as cli_main  # noqa: E402
from asf.identity import ResourceIdentity  # noqa: E402
from asf.podman import PodmanClient  # noqa: E402
from asf.process import CommandResult  # noqa: E402


def _labels(container: dict) -> dict[str, str]:
    labels = dict(container.get("labels", {}))
    for source, target in (
        ("role", "asf.role"),
        ("agent", "asf.agent"),
        ("session", "asf.session"),
        ("sandbox", "asf.sandbox"),
    ):
        if container.get(source):
            labels.setdefault(target, container[source])
    return labels


def _document(container: dict) -> dict:
    state = container.get("state", "running")
    return {
        "Id": container["id"],
        "Name": container.get("name", container["id"]),
        "Config": {
            "Image": container.get("image", "asf-test:latest"),
            "Labels": _labels(container),
            "User": container.get("user", "10001:10001"),
        },
        "State": {
            "Status": state,
            "Running": state == "running",
            "ExitCode": int(container.get("exit_code", 0)),
        },
        "NetworkSettings": {
            "Networks": {name: {} for name in container.get("networks", [])}
        },
        "HostConfig": {
            "ReadonlyRootfs": bool(container.get("read_only_root", True)),
            "PortBindings": (
                {"8080/tcp": [{"HostPort": "18080"}]}
                if container.get("published_ports")
                else {}
            ),
        },
    }


class ScriptedPodmanRunner:
    def __init__(self, state: dict) -> None:
        self.state = state

    def __call__(
        self,
        argv,
        *,
        timeout: float,
        input_text: str | None = None,
        **_kwargs,
    ) -> CommandResult:
        args = [os.fspath(item) for item in argv]
        command = args[1:]
        if not command:
            return self._result(args, 125, stderr="fake podman: no subcommand\n")
        if command[0] == "ps":
            return self._ps(args, command[1:])
        if command[0] == "inspect":
            return self._inspect(args, command[1:])
        if command[0] == "exec":
            return self._exec(args, command[1:], input_text or "")
        if command[0] == "version":
            return self._result(args, 0, stdout="5.0.0-fake\n")
        return self._result(
            args,
            125,
            stderr=f"fake podman: unsupported command: {' '.join(command)}\n",
        )

    @staticmethod
    def _result(
        argv: list[str],
        returncode: int,
        *,
        stdout: str = "",
        stderr: str = "",
    ) -> CommandResult:
        return CommandResult(tuple(argv), returncode, stdout, stderr)

    def _find(self, reference: str) -> dict | None:
        for container in self.state.get("containers", []):
            if reference in (
                container["id"],
                container["id"][:12],
                container.get("name"),
            ):
                return container
        return None

    def _ps(self, argv: list[str], args: list[str]) -> CommandResult:
        filters: dict[str, str] = {}
        for index, argument in enumerate(args):
            if argument == "--filter" and index + 1 < len(args):
                value = args[index + 1]
                if value.startswith("label="):
                    key, _, wanted = value[len("label=") :].partition("=")
                    filters[key] = wanted
        include_stopped = "--all" in args or "-a" in args or "-aq" in args
        lines: list[str] = []
        for container in self.state.get("containers", []):
            labels = _labels(container)
            if not all(labels.get(key) == value for key, value in filters.items()):
                continue
            if not include_stopped and container.get("state", "running") != "running":
                continue
            lines.append(container["id"][:12])
        return self._result(argv, 0, stdout="".join(line + "\n" for line in lines))

    def _inspect(self, argv: list[str], args: list[str]) -> CommandResult:
        references: list[str] = []
        index = 0
        while index < len(args):
            argument = args[index]
            if argument == "--type":
                index += 2
                continue
            if argument.startswith("-"):
                index += 1
                continue
            references.append(argument)
            index += 1

        documents: list[dict] = []
        failing = self.state.get("inspect_fail", [])
        for reference in references:
            container = self._find(reference)
            unreachable = container is not None and any(
                marker
                in (
                    container["id"],
                    container["id"][:12],
                    container.get("name"),
                )
                for marker in failing
            )
            if container is None or reference in failing or unreachable:
                return self._result(
                    argv,
                    125,
                    stderr=f'Error: no such object: "{reference}"\n',
                )
            documents.append(_document(container))
        return self._result(argv, 0, stdout=json.dumps(documents) + "\n")

    def _exec(
        self,
        argv: list[str],
        args: list[str],
        input_text: str,
    ) -> CommandResult:
        index = 0
        while index < len(args):
            argument = args[index]
            if argument in ("-e", "--env"):
                index += 2
                continue
            if argument in ("-i", "-t", "-it") or argument.startswith("-"):
                index += 1
                continue
            break
        reference = args[index] if index < len(args) else ""
        command = " ".join(args[index + 1 :])
        if self._find(reference) is None:
            return self._result(
                argv,
                125,
                stderr=f'Error: no such container: "{reference}"\n',
            )
        evidence = command + "\n" + input_text
        for entry in self.state.get("exec", []):
            marker = entry["match"]
            matched = marker in evidence
            # The vectors preserve the Bash command markers. Typed proxy
            # probes send requests through stdin instead of a shell pipeline;
            # treat those equivalent fixed invocations as the same evidence.
            if marker in {"asf-proxy-request", "| nc -w 8"} and (
                input_text.startswith("CONNECT ")
                or input_text.startswith("GET http://")
            ):
                matched = True
            if (
                marker.endswith("route show default")
                and "route show default" in command
                and command.rstrip().endswith(marker.split()[1])
            ):
                matched = True
            if matched:
                rc = int(entry.get("rc", 0))
                stdout = entry.get("stdout", "")
                rc, stdout = _script_equivalent(command, rc, stdout)
                return self._result(
                    argv,
                    rc,
                    stdout=stdout,
                    stderr=entry.get("stderr", ""),
                )
        default = self.state.get("exec_default", {"rc": 0})
        return self._result(
            argv,
            int(default.get("rc", 0)),
            stdout=default.get("stdout", ""),
            stderr=default.get("stderr", ""),
        )


class SecurityTestContractTests(unittest.TestCase):
    """Permanent command contract; requires neither Bash nor Podman."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.checkout = self.base / "checkout"
        self.checkout.mkdir()
        (self.checkout / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
        (self.checkout / "containers").mkdir()
        (self.checkout / "agents").mkdir()
        (self.checkout / "secrets").mkdir()
        shutil.copy2(ROOT / "asf.conf", self.checkout / "asf.conf")
        (self.checkout / "secrets" / "proxy-agent.env").write_text(
            "ANTHROPIC_API_KEY=sk-host-secret\n"
        )
        for name, text in self.doc["manifests"].items():
            directory = self.checkout / "agents" / name
            directory.mkdir()
            (directory / "runtime.yml").write_text(text)
        identity = ResourceIdentity.from_checkout(self.checkout)
        self.prefix = identity.prefix
        self.sandbox = str(identity.script_dir)

    def render(self, value):
        if isinstance(value, str):
            return value.replace("{PREFIX}", self.prefix).replace(
                "{SANDBOX}", self.sandbox
            )
        if isinstance(value, list):
            return [self.render(item) for item in value]
        if isinstance(value, dict):
            return {key: self.render(item) for key, item in value.items()}
        return value

    def set_broker_enabled(self, value: str) -> None:
        path = self.checkout / "asf.conf"
        lines, replaced = [], False
        for line in path.read_text().splitlines():
            if line.strip().startswith("BROKER_ENABLED="):
                lines.append(f"BROKER_ENABLED={value}")
                replaced = True
            else:
                lines.append(line)
        if not replaced:
            lines.append(f"BROKER_ENABLED={value}")
        path.write_text("\n".join(lines) + "\n")

    def run_case(self, vector: dict) -> tuple[int, str, str]:
        self.set_broker_enabled(vector["broker_enabled"])
        state = {
            "containers": self.render(vector["containers"]),
            "exec": self.render(vector["exec"]),
            "inspect_fail": self.render(vector["inspect_fail"]),
        }
        client = PodmanClient(
            engine=sys.executable,
            runner=ScriptedPodmanRunner(state),
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        status = cli_main(
            ["test", vector["agent"]],
            root=self.checkout,
            stdout=stdout,
            stderr=stderr,
            podman=client,
        )
        return status, stdout.getvalue(), stderr.getvalue()

    def test_every_vector(self) -> None:
        self.assertTrue(self.doc["vectors"])
        for vector in self.doc["vectors"]:
            with self.subTest(vector["id"]):
                status, stdout, stderr = self.run_case(vector)
                self.assertEqual(stdout, self.render(vector["stdout"]), "stdout")
                self.assertEqual(stderr, self.render(vector["stderr"]), "stderr")
                self.assertEqual(status, vector["returncode"], "exit status")

    def test_all_three_modes_are_covered(self) -> None:
        identifiers = {vector["id"] for vector in self.doc["vectors"]}
        for required in (
            "proxy-all-pass",
            "isolated-all-pass",
            "routed-all-pass",
            "broker-enabled",
            "broker-disabled",
            "empty-allowlist-and-no-positive-control",
            "stale-session-no-container",
        ):
            with self.subTest(required):
                self.assertIn(required, identifiers)

    def test_infrastructure_failures_are_covered_by_cause(self) -> None:
        identifiers = {vector["id"] for vector in self.doc["vectors"]}
        for required in (
            "infra-probe-not-found",
            "infra-podman-125",
            "infra-dns-failure-on-tcp-probe",
            "infra-proxy-unreachable",
            "infra-caddyfile-unreadable",
            "infra-inspect-fails",
        ):
            with self.subTest(required):
                self.assertIn(required, identifiers)

    def test_success_and_failure_stream_contract(self) -> None:
        for vector in self.doc["vectors"]:
            with self.subTest(vector["id"]):
                if vector["returncode"] == 0:
                    self.assertEqual(vector["stderr"], "")
                    self.assertIn("Security test passed", vector["stdout"])
                elif not vector["id"].startswith("stale-session"):
                    self.assertIn("Security test failed", vector["stderr"])

    def test_stale_session_stops_before_checks(self) -> None:
        vector = next(
            item
            for item in self.doc["vectors"]
            if item["id"] == "stale-session-no-container"
        )
        self.assertEqual(vector["returncode"], 1)
        self.assertEqual(vector["stdout"], "")
        self.assertIn("No running proxy-agent container.", vector["stderr"])
        self.assertNotIn("Testing", vector["stderr"])

    def test_only_documented_infrastructure_cases_diverge_from_bash(self) -> None:
        diverging = [
            vector for vector in self.doc["vectors"] if "divergence" in vector
        ]
        self.assertEqual(len(diverging), 4)
        for vector in diverging:
            with self.subTest(vector["id"]):
                self.assertTrue(vector["id"].startswith("infra-"))
                self.assertTrue(vector["divergence"].strip())
                self.assertEqual(
                    vector["returncode"] == 0,
                    vector["bash_returncode"] == 0,
                )

    def test_vectors_never_freeze_a_traceback(self) -> None:
        for vector in self.doc["vectors"]:
            with self.subTest(vector["id"]):
                combined = vector["stdout"] + vector["stderr"]
                self.assertNotIn("Traceback (most recent call last)", combined)
                self.assertNotIn("executor raised", combined)


if __name__ == "__main__":
    unittest.main()
