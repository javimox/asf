#!/usr/bin/env python3
"""Fast permanent reset contract using the real Python services in-process."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

_SUPPORT_SPEC = importlib.util.spec_from_file_location(
    "_asf_reset_vector_support",
    ROOT / "tests" / "test_stop.py",
)
if _SUPPORT_SPEC is None or _SUPPORT_SPEC.loader is None:
    raise RuntimeError("cannot load reset vector support")
_SUPPORT = importlib.util.module_from_spec(_SUPPORT_SPEC)
sys.modules[_SUPPORT_SPEC.name] = _SUPPORT
_SUPPORT_SPEC.loader.exec_module(_SUPPORT)
StatePodman = _SUPPORT.StatePodman
make_checkout = _SUPPORT.make_checkout

from asf.cleanup import CleanupExecutor  # noqa: E402
from asf.podman import ObjectKind  # noqa: E402
from asf.process import CommandResult  # noqa: E402
from asf.reset import ResetService, run_reset_command  # noqa: E402
from asf.residue import ResidueScanner  # noqa: E402
from asf.session import SessionDiscovery  # noqa: E402
from asf.stop import StopService  # noqa: E402

VECTORS = Path(__file__).with_name("reset_command_vectors.json")


class ResetStatePodman(StatePodman):
    def __init__(self, identity) -> None:  # noqa: ANN001
        super().__init__(identity)
        object.__setattr__(self, "volumes", set())
        object.__setattr__(self, "fail_container_rm", set())
        object.__setattr__(self, "fail_volume_rm", False)

    def exists(self, reference, kind=ObjectKind.CONTAINER):  # noqa: ANN001
        if kind is ObjectKind.VOLUME:
            return reference in self.volumes
        return super().exists(reference, kind)

    def observe(self, argv, **kwargs):  # noqa: ANN001
        args = tuple(str(value) for value in argv)
        if len(args) > 1 and args[1] == "rm" and args[-1] in self.fail_container_rm:
            self.calls.append(args)
            return CommandResult(args, 125, "", "Error: cannot remove container\n")
        if len(args) > 2 and args[1:3] == ("volume", "rm"):
            self.calls.append(args)
            if self.fail_volume_rm:
                return CommandResult(args, 125, "", "Error: volume is in use\n")
            self.volumes.difference_update(args[3:])
            return CommandResult(args, 0, "\n".join(args[3:]) + "\n", "")
        return super().observe(args, **kwargs)


class ResetCommandVectorTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "checkout"
        self.paths = make_checkout(
            self.root,
            tuple(self.document["manifests"]),
        )
        for runtime, text in self.document["manifests"].items():
            self.paths.identity.runtime_manifest(runtime).write_text(text)
        self.runtime_dir = Path(self.temporary.name) / "runtime"
        self.runtime_dir.mkdir()
        self.environment = mock.patch.dict(
            os.environ,
            {"XDG_RUNTIME_DIR": str(self.runtime_dir)},
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def render(self, value):  # noqa: ANN001
        if isinstance(value, str):
            return value.replace("{PREFIX}", self.paths.identity.prefix)
        if isinstance(value, dict):
            return {key: self.render(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.render(item) for item in value]
        return value

    def build(self):  # noqa: ANN201
        podman = ResetStatePodman(self.paths.identity)
        discovery = SessionDiscovery.from_paths(self.paths, podman=podman)
        scanner = ResidueScanner(discovery)
        cleanup = CleanupExecutor(
            podman,
            discovery.lock_manager(),
            stop_timeout=0,
            network_retry_delay=0,
            sleeper=lambda _seconds: None,
        )
        stop = StopService(
            discovery,
            scanner,
            cleanup,
            verify_attempts=1,
            verify_delay=0,
            sleeper=lambda _seconds: None,
            clock=lambda: 0.0,
        )
        return podman, ResetService(self.paths, stop, cleanup)

    def volume_name(self, runtime: str, key: str) -> str:
        if key == "shell":
            return self.paths.identity.shell_history_volume(runtime)
        return self.paths.identity.state_volume(runtime, key)

    def prepare(self, vector: dict, podman: ResetStatePodman) -> str:
        setup = vector["setup"]
        runtime = vector["argv"][1] if len(vector["argv"]) > 1 else "proxy-agent"
        if runtime not in self.document["manifests"]:
            runtime = "proxy-agent"

        session = setup.get("session")
        runtime_reference = ""
        if session:
            runtime_reference = podman.add_runtime(runtime, running=session == "live")
        for role in setup.get("support", ()):
            podman.add_support(runtime, role, running=session != "stale")
        names = self.paths.identity.network_names(runtime)
        for name in setup.get("networks", ()):
            podman.networks.add(getattr(names, name))
        for key in setup.get("volumes", ()):
            podman.volumes.add(self.volume_name(runtime, key))
        if setup.get("other_volume"):
            podman.volumes.add(
                self.paths.identity.shell_history_volume("other-agent")
            )
        if setup.get("broker_state"):
            self.paths.identity.broker_state(runtime).write_text("host\n")
        lock_kind = setup.get("lock")
        if lock_kind:
            lock = self.paths.identity.session_lock(runtime)
            lock.mkdir(parents=True)
            pid = os.getpid() if lock_kind == "live" else 99999999
            (lock / "pid").write_text(f"{pid}\n")
            if lock_kind == "live":
                object.__setattr__(podman, "release_lock_runtime", runtime)
            else:
                os.utime(lock, (0, 0))
                os.utime(lock / "pid", (0, 0))
        if setup.get("fail_runtime_remove"):
            podman.fail_container_rm.add(runtime_reference)
        if setup.get("fail_volume_remove"):
            object.__setattr__(podman, "fail_volume_rm", True)
        if setup.get("fail_secret_list"):
            object.__setattr__(podman, "fail_secret_list", True)
        return runtime

    def run_vector(self, vector: dict):  # noqa: ANN201
        podman, service = self.build()
        runtime = self.prepare(vector, podman)
        result = run_reset_command(
            vector["argv"],
            self.paths,
            podman=podman,
            require_available=False,
            service=service,
        )
        target = {
            name
            for name in podman.volumes
            if f"-{runtime}-" in name
        }
        other = podman.volumes - target
        state = {
            "containers": len(podman.containers),
            "networks": len(podman.networks),
            "target_volumes": len(target),
            "other_volumes": len(other),
            "lock": self.paths.identity.session_lock(runtime).exists(),
            "broker_state": self.paths.identity.broker_state(runtime).exists(),
        }
        return result, state

    def test_every_vector(self) -> None:
        for vector in self.document["vectors"]:
            with self.subTest(vector["id"]):
                result, state = self.run_vector(vector)
                self.assertEqual(result.returncode, vector["returncode"])
                self.assertEqual(result.stdout, self.render(vector["stdout"]))
                self.assertEqual(result.stderr, self.render(vector["stderr"]))
                expected_disposition = vector["disposition"]
                actual = result.report.disposition.value if result.report else None
                self.assertEqual(actual, expected_disposition)
                self.assertEqual(state, vector["remaining"])

    def test_every_divergence_is_explicitly_documented(self) -> None:
        divergences = [
            vector for vector in self.document["vectors"] if "divergence" in vector
        ]
        self.assertEqual(len(divergences), 5)
        for vector in divergences:
            with self.subTest(vector["id"]):
                self.assertTrue(vector["divergence"].strip())

    def test_success_never_leaves_target_session_residue(self) -> None:
        for vector in self.document["vectors"]:
            if vector["returncode"] != 0 or len(vector["argv"]) < 2:
                continue
            with self.subTest(vector["id"]):
                remaining = vector["remaining"]
                self.assertEqual(remaining["containers"], 0)
                self.assertEqual(remaining["networks"], 0)
                self.assertEqual(remaining["target_volumes"], 0)
                self.assertFalse(remaining["lock"])
                self.assertFalse(remaining["broker_state"])

    def test_no_traceback_is_part_of_the_contract(self) -> None:
        for vector in self.document["vectors"]:
            combined = vector["stdout"] + vector["stderr"]
            self.assertNotIn("Traceback (most recent call last)", combined)


if __name__ == "__main__":
    unittest.main()
