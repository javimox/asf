#!/usr/bin/env python3
"""Permanent behavioural contract for ``sandbox.sh stop``.

The expected values in ``stop_command_vectors.json`` were captured from the
removed Bash command.  The permanent vectors execute the real Python stop
service in-process with a typed, mutating Podman fake.  This keeps all output,
exit-status and residue assertions while avoiding hundreds of fake executable
startups.  A separate smoke test retains the real ``sandbox.sh`` dispatch
boundary, and the host suite exercises real Podman.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.cleanup import CleanupExecutor
from asf.paths import RepoPaths
from asf.podman import (
    ContainerInspection,
    ObjectKind,
    ObjectNotFoundError,
    PodmanClient,
)
from asf.process import CommandResult
from asf.residue import ResidueScanner
from asf.session import SessionDiscovery
from asf.stop import StopService, run_stop_command
from asf.subnets import reservation_path

ROOT = Path(__file__).resolve().parents[2]
VECTORS_FILE = Path(__file__).with_name("stop_command_vectors.json")
FAKE_ENGINE = Path(__file__).with_name("fake_podman_stop.py")

ELAPSED = re.compile(r"\(\d+s")


def _labels(container: dict) -> dict[str, str]:
    labels = dict(container.get("labels", {}))
    for key, label in (
        ("role", "asf.role"),
        ("agent", "asf.agent"),
        ("session", "asf.session"),
        ("sandbox", "asf.sandbox"),
    ):
        if container.get(key):
            labels.setdefault(label, container[key])
    return labels


def _label_filters(labels) -> dict[str, str]:  # noqa: ANN001
    if isinstance(labels, dict):
        return dict(labels)
    result: dict[str, str] = {}
    for item in labels:
        key, value = item.split("=", 1)
        result[key] = value
    return result


class VectorPodman(PodmanClient):
    """Small stateful Podman model for the permanent stop vectors."""

    def __init__(self, state: dict) -> None:
        super().__init__(engine="podman", timeout=2, runner=self._unused)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "calls", [])

    @staticmethod
    def _unused(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("the vector fake must not invoke a process runner")

    def require_available(self) -> None:
        return None

    def _find(self, reference: str) -> dict | None:
        for container in self.state["containers"]:
            if reference in (
                container["id"],
                container["id"][:12],
                container.get("name"),
            ):
                return container
        return None

    def container_ids(self, labels=(), *, include_stopped=False):  # noqa: ANN001
        wanted = _label_filters(labels)
        found: list[str] = []
        for container in self.state["containers"]:
            if not include_stopped and container.get("state", "running") != "running":
                continue
            have = _labels(container)
            if all(have.get(key) == value for key, value in wanted.items()):
                found.append(container["id"][:12])
        return tuple(found)

    def inspect_container(self, reference: str, *, timeout=None):  # noqa: ANN001
        container = self._find(reference)
        if container is None:
            raise ObjectNotFoundError(f"no such container: {reference}")
        state = container.get("state", "running")
        return ContainerInspection(
            container_id=container["id"],
            name=container.get("name", container["id"]),
            image="localhost/asf:test",
            status=state,
            running=state == "running",
            health=None,
            labels=_labels(container),
            networks=tuple(container.get("networks", ())),
        )

    def exists(self, reference: str, kind=ObjectKind.CONTAINER):  # noqa: ANN001
        if kind is ObjectKind.CONTAINER:
            return self._find(reference) is not None
        if kind is ObjectKind.NETWORK:
            return reference in self.state["networks"]
        if kind is ObjectKind.SECRET:
            return reference in self.state["secrets"]
        return False

    def secret_names(self) -> tuple[str, ...]:
        return tuple(self.state["secrets"])

    def _forced(self, key: str, argv: tuple[str, ...]) -> CommandResult | None:
        entry = self.state.get("fail", {}).get(key)
        if not entry:
            return None
        return CommandResult(argv, int(entry[0]), "", str(entry[1]))

    def observe(self, argv, **_kwargs):  # noqa: ANN001
        args = tuple(str(value) for value in argv)
        self.calls.append(args)
        command = args[1:]

        if command[:1] == ("stop",):
            forced = self._forced("stop", args)
            if forced is not None:
                return forced
            reference = command[-1]
            container = self._find(reference)
            if container is not None:
                container["state"] = "exited"
            return CommandResult(args, 0, "", "")

        if command[:1] == ("rm",):
            forced = self._forced("rm", args)
            if forced is not None:
                return forced
            references = _operands(command[1:], options_with_values={"--time", "-t"})
            for reference in references:
                container = self._find(reference)
                if container is not None:
                    self.state["containers"].remove(container)
            return CommandResult(args, 0, "", "")

        if command[:2] == ("network", "rm"):
            forced = self._forced("network rm", args)
            if forced is not None:
                return forced
            for name in _operands(command[2:]):
                if name in self.state["networks"]:
                    self.state["networks"].remove(name)
            return CommandResult(args, 0, "", "")

        if command[:2] == ("secret", "rm"):
            forced = self._forced("secret rm", args)
            if forced is not None:
                return forced
            for name in _operands(command[2:]):
                if name in self.state["secrets"]:
                    self.state["secrets"].remove(name)
            return CommandResult(args, 0, "", "")

        return CommandResult(args, 125, "", f"unsupported fake command: {command}\n")

    def exported_state(self) -> dict:
        return {
            "containers": self.state["containers"],
            "networks": self.state["networks"],
            "secrets": self.state["secrets"],
            "fail": self.state.get("fail", {}),
        }


def _operands(
    values: tuple[str, ...],
    *,
    options_with_values: set[str] | None = None,
) -> list[str]:
    consume = options_with_values or set()
    found: list[str] = []
    skip = False
    for value in values:
        if skip:
            skip = False
            continue
        if value in consume:
            skip = True
            continue
        if value.startswith("-"):
            continue
        found.append(value)
    return found


class StopCommandVectorTests(unittest.TestCase):
    """Permanent stop contract; all vectors are executed exactly once."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.checkout = cls.base / "checkout"
        cls.checkout.mkdir()
        (cls.checkout / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
        (cls.checkout / "containers").mkdir()
        (cls.checkout / ".asf").mkdir()
        (cls.checkout / "agents").mkdir()
        for name, text in cls.doc["manifests"].items():
            directory = cls.checkout / "agents" / name
            directory.mkdir()
            (directory / "runtime.yml").write_text(text)

        cls.paths = RepoPaths.for_root(cls.checkout)
        cls.identity = cls.paths.identity
        cls.prefix = cls.identity.prefix
        cls.sandbox = str(cls.identity.script_dir)
        cls.runtime_dir = cls.base / "runtime"
        cls.runtime_dir.mkdir()
        cls.reservations = cls.runtime_dir / "asf-subnets"
        cls.results: dict[str, tuple[object, dict]] = {}

        environment = {
            "XDG_RUNTIME_DIR": str(cls.runtime_dir),
            "ASF_STOP_VERIFY_ATTEMPTS": "1",
            "ASF_STOP_VERIFY_DELAY": "0",
            "ASF_SHUTDOWN_TIMEOUT": "2",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            for vector in cls.doc["vectors"]:
                cls.results[vector["id"]] = cls._execute_vector(vector)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def render(cls, value):  # noqa: ANN001
        if isinstance(value, str):
            return value.replace("{PREFIX}", cls.prefix).replace(
                "{SANDBOX}", cls.sandbox
            )
        if isinstance(value, list):
            return [cls.render(item) for item in value]
        if isinstance(value, dict):
            return {key: cls.render(item) for key, item in value.items()}
        return value

    @classmethod
    def _prepare_files(cls, vector: dict) -> None:
        shutil.rmtree(cls.reservations, ignore_errors=True)
        cls.reservations.mkdir(parents=True)
        runtime_state = cls.checkout / ".asf"
        for entry in tuple(runtime_state.iterdir()):
            if entry.name.startswith((".open-lock-", ".broker-host-")):
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry)
                else:
                    entry.unlink()

        files = vector["files"]
        if "lock" in files:
            lock = cls.identity.session_lock(files["lock"])
            lock.mkdir(parents=True, exist_ok=True)
            (lock / "pid").write_text("4194304\n")
        if "broker_state" in files:
            cls.identity.broker_state(files["broker_state"]).write_text("host\n")
        if "reservation" in files:
            path = reservation_path(
                cls.identity.subnet_reservation_session(files["reservation"]),
                cls.reservations,
            )
            path.write_text(
                json.dumps(
                    {
                        "session": "x",
                        "pid": 4194304,
                        "subnets": ["10.89.1.0/28"],
                    }
                )
            )

    @classmethod
    def _execute_vector(cls, vector: dict):  # noqa: ANN206
        cls._prepare_files(vector)
        state = {
            "containers": cls.render(vector["containers"]),
            "networks": cls.render(vector["networks"]),
            "secrets": cls.render(vector["secrets"]),
            "fail": vector["fail"],
        }
        podman = VectorPodman(state)
        discovery = SessionDiscovery.from_paths(cls.paths, podman=podman)
        cleanup = CleanupExecutor(
            podman,
            discovery.lock_manager(),
            stop_timeout=2,
            network_retry_delay=0,
            sleeper=lambda _seconds: None,
        )
        service = StopService(
            discovery,
            ResidueScanner(discovery),
            cleanup,
            verify_attempts=1,
            verify_delay=0,
            sleeper=lambda _seconds: None,
            clock=lambda: 0.0,
        )
        result = run_stop_command(
            tuple(vector["argv"]),
            cls.paths,
            podman=podman,
            require_available=False,
            service=service,
        )
        return result, podman.exported_state()

    @staticmethod
    def normalise(text: str) -> str:
        return ELAPSED.sub("({T}s", text)

    def test_every_vector(self) -> None:
        self.assertTrue(self.doc["vectors"])
        for vector in self.doc["vectors"]:
            with self.subTest(vector["id"]):
                result, _state = self.results[vector["id"]]
                self.assertEqual(
                    self.normalise(result.stdout),
                    self.render(vector["stdout"]),
                    "stdout",
                )
                self.assertEqual(
                    self.normalise(result.stderr),
                    self.render(vector["stderr"]),
                    "stderr",
                )
                self.assertEqual(
                    result.returncode, vector["returncode"], "exit status"
                )

    def test_what_remains_matches_the_contract(self) -> None:
        """The removed Bash command never checked; Python must."""
        for vector in self.doc["vectors"]:
            with self.subTest(vector["id"]):
                _result, after = self.results[vector["id"]]
                expected = self.render(vector["remaining"])
                for key in ("containers", "networks", "secrets"):
                    self.assertEqual(
                        sorted(map(str, after[key])),
                        sorted(map(str, expected[key])),
                        key,
                    )

    def test_a_successful_stop_leaves_nothing(self) -> None:
        for vector in self.doc["vectors"]:
            if vector["returncode"] != 0:
                continue
            with self.subTest(vector["id"]):
                remaining = vector["remaining"]
                self.assertEqual(remaining["containers"], [])
                self.assertEqual(remaining["networks"], [])
                self.assertEqual(remaining["secrets"], [])

    def test_repeated_stop_is_idempotent(self) -> None:
        vector = next(
            value for value in self.doc["vectors"]
            if value["id"] == "explicit-live-proxy"
        )
        _first, after = self.results[vector["id"]]
        podman = VectorPodman(json.loads(json.dumps(after)))
        discovery = SessionDiscovery.from_paths(self.paths, podman=podman)
        service = StopService(
            discovery,
            ResidueScanner(discovery),
            CleanupExecutor(
                podman,
                discovery.lock_manager(),
                network_retry_delay=0,
                sleeper=lambda _seconds: None,
            ),
            verify_attempts=1,
            verify_delay=0,
            sleeper=lambda _seconds: None,
            clock=lambda: 0.0,
        )
        result = run_stop_command(
            tuple(vector["argv"]),
            self.paths,
            podman=podman,
            require_available=False,
            service=service,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("already absent", result.stdout)

    def test_every_divergence_is_documented_and_stricter(self) -> None:
        diverging = [v for v in self.doc["vectors"] if "divergence" in v]
        self.assertEqual(len(diverging), 3)
        for vector in diverging:
            with self.subTest(vector["id"]):
                self.assertTrue(vector["divergence"].strip())
                for key in ("bash_stdout", "bash_stderr", "bash_returncode"):
                    self.assertIn(key, vector)
                if vector["returncode"] != vector["bash_returncode"]:
                    self.assertEqual(vector["bash_returncode"], 0)
                    self.assertEqual(vector["returncode"], 1)

    def test_bash_left_resources_that_python_removes(self) -> None:
        vector = next(
            value for value in self.doc["vectors"]
            if value["id"] == "stale-lock-with-resources"
        )
        self.assertEqual(vector["remaining"]["containers"], [])
        self.assertTrue(vector["bash_remaining"]["containers"])

    def test_no_traceback_reaches_the_user(self) -> None:
        for vector in self.doc["vectors"]:
            with self.subTest(vector["id"]):
                combined = vector["stdout"] + vector["stderr"]
                self.assertNotIn("Traceback (most recent call last)", combined)
                self.assertNotIn("executor raised", combined)

    def test_real_sandbox_dispatches_stop_to_python(self) -> None:
        """Keep one real launcher boundary in the permanent contract."""
        checkout = self.base / "launcher-checkout"
        checkout.mkdir()
        shutil.copy2(ROOT / "sandbox.sh", checkout / "sandbox.sh")
        (checkout / "asf").symlink_to(ROOT / "asf", target_is_directory=True)
        (checkout / "containers").mkdir()
        (checkout / ".asf").mkdir()
        (checkout / "agents").mkdir()
        for name, text in self.doc["manifests"].items():
            directory = checkout / "agents" / name
            directory.mkdir()
            (directory / "runtime.yml").write_text(text)
        fake_bin = self.base / "launcher-bin"
        fake_bin.mkdir()
        shutil.copy2(FAKE_ENGINE, fake_bin / "podman")
        (fake_bin / "podman").chmod(0o755)
        state = self.base / "launcher-state.json"
        state.write_text(
            json.dumps({"containers": [], "networks": [], "secrets": [], "fail": {}})
        )
        completed = subprocess.run(
            ["./sandbox.sh", "stop", "not-an-agent"],
            cwd=checkout,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "PATH": f"{fake_bin}{os.pathsep}/usr/bin:/bin",
                "ASF_FAKE_PODMAN_STATE": str(state),
                "XDG_RUNTIME_DIR": str(self.runtime_dir),
                "HOME": str(self.base),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("Unknown agent: not-an-agent", completed.stdout)
        self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
