"""Focused stop orchestration tests."""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from asf.cleanup import CleanupExecutor
from asf.cli import main
from asf.egress_evidence import begin_egress_session, mark_egress_session_active
from asf.runs import begin_run
from asf.identity import ResourceIdentity
from asf.paths import RepoPaths
from asf.podman import (
    ContainerInspection,
    ObjectKind,
    ObjectNotFoundError,
    PodmanClient,
    PodmanCommandError,
)
from asf.process import CommandResult
from asf.residue import ResidueScanner
from asf.session import SessionDiscovery, SessionStatus
from asf.stop import StopDisposition, StopService, run_stop_command
from asf.subnets import reservation_path


def make_checkout(root: Path, runtimes: tuple[str, ...] = ("claude",)) -> RepoPaths:
    root.mkdir(parents=True, exist_ok=True)
    (root / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
    (root / ".devcontainer").mkdir()
    (root / "agents").mkdir()
    for runtime in runtimes:
        directory = root / "agents" / runtime
        directory.mkdir()
        (directory / "runtime.yml").write_text(
            f"name: {runtime}\nadapter: generic\nnetwork:\n  mode: isolated\n"
        )
    return RepoPaths.for_root(root)


class StatePodman(PodmanClient):
    def __init__(self, identity: ResourceIdentity) -> None:
        super().__init__(engine="podman", timeout=2, runner=self._unused)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "containers", {})
        object.__setattr__(self, "networks", set())
        object.__setattr__(self, "secrets", set())
        object.__setattr__(self, "calls", [])
        object.__setattr__(self, "fail_secret_list", False)
        object.__setattr__(self, "release_lock_runtime", "")
        object.__setattr__(self, "spawn_network_after_rm", "")

    @staticmethod
    def _unused(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("direct runner should not be used")

    def require_available(self) -> None:
        return None

    def add_runtime(self, runtime: str, *, running: bool = True) -> str:
        reference = f"runtime-{runtime}"
        self.containers[reference] = ContainerInspection(
            container_id=reference,
            name=reference,
            image="runtime-image",
            status="running" if running else "exited",
            running=running,
            health=None,
            labels={"asf.session": self.identity.session_key(runtime)},
        )
        return reference

    def add_support(self, runtime: str, role: str, *, running: bool = True) -> str:
        reference = f"{role}-{runtime}"
        self.containers[reference] = ContainerInspection(
            container_id=reference,
            name=reference,
            image="support-image",
            status="running" if running else "exited",
            running=running,
            health=None,
            labels={
                "asf.sandbox": str(self.identity.script_dir),
                "asf.role": role,
                "asf.agent": runtime,
            },
        )
        return reference

    def container_ids(self, labels=(), *, include_stopped=False):  # noqa: ANN001
        required = _labels_dict(labels)
        found = []
        for reference, inspection in self.containers.items():
            if not include_stopped and not inspection.running:
                continue
            if all(inspection.labels.get(key) == value for key, value in required.items()):
                found.append(reference)
        return tuple(found)

    def inspect_container(self, reference: str, *, timeout=None):  # noqa: ANN001
        try:
            return self.containers[reference]
        except KeyError as exc:
            raise ObjectNotFoundError(f"no such container: {reference}") from exc

    def exists(self, reference: str, kind=ObjectKind.CONTAINER):  # noqa: ANN001
        if kind is ObjectKind.CONTAINER:
            return reference in self.containers
        if kind is ObjectKind.NETWORK:
            return reference in self.networks
        if kind is ObjectKind.SECRET:
            return reference in self.secrets
        return False

    def secret_names(self) -> tuple[str, ...]:
        if self.fail_secret_list:
            raise PodmanCommandError("secret discovery failed")
        return tuple(sorted(self.secrets))

    def observe(self, argv, **_kwargs):  # noqa: ANN001
        args = tuple(str(value) for value in argv)
        self.calls.append(args)
        if len(args) > 1 and args[1] == "stop":
            reference = args[-1]
            inspection = self.containers.get(reference)
            if inspection is not None:
                self.containers[reference] = _with_running(inspection, False)
        elif len(args) > 1 and args[1] == "rm":
            reference = args[-1]
            removed = self.containers.pop(reference, None)
            if removed is not None and self.release_lock_runtime:
                lock = self.identity.session_lock(self.release_lock_runtime)
                shutil.rmtree(lock, ignore_errors=True)
            if self.spawn_network_after_rm:
                self.networks.add(self.spawn_network_after_rm)
                object.__setattr__(self, "spawn_network_after_rm", "")
        elif len(args) > 2 and args[1:3] == ("network", "rm"):
            self.networks.discard(args[-1])
        elif len(args) > 2 and args[1:3] == ("secret", "rm"):
            self.secrets.discard(args[-1])
        return CommandResult(args, 0, "", "")


def _labels_dict(labels) -> dict[str, str]:  # noqa: ANN001
    if isinstance(labels, dict):
        return dict(labels)
    result: dict[str, str] = {}
    for item in labels:
        key, value = item.split("=", 1)
        result[key] = value
    return result


def _with_running(inspection: ContainerInspection, running: bool) -> ContainerInspection:
    return ContainerInspection(
        container_id=inspection.container_id,
        name=inspection.name,
        image=inspection.image,
        status="running" if running else "exited",
        running=running,
        health=inspection.health,
        labels=inspection.labels,
        networks=inspection.networks,
    )


class StopCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "asf"
        self.paths = make_checkout(self.root, ("claude", "hermes"))
        self.identity = self.paths.identity
        self.podman = StatePodman(self.identity)
        self.discovery = SessionDiscovery.from_paths(self.paths, podman=self.podman)
        self.scanner = ResidueScanner(self.discovery)
        self.cleanup = CleanupExecutor(
            self.podman,
            self.discovery.lock_manager(),
            stop_timeout=2,
            network_retry_delay=0,
            sleeper=lambda _seconds: None,
        )
        self.service = StopService(
            self.discovery,
            self.scanner,
            self.cleanup,
            verify_attempts=3,
            verify_delay=0,
            sleeper=lambda _seconds: None,
            clock=lambda: 0.0,
        )
        self.runtime_dir = Path(self.temporary.name) / "runtime"
        self.runtime_dir.mkdir()
        self.environment = mock.patch.dict(
            os.environ, {"XDG_RUNTIME_DIR": str(self.runtime_dir)}
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def _run(self, *arguments: str):
        return run_stop_command(
            ("stop", *arguments),
            self.paths,
            podman=self.podman,
            require_available=False,
            service=self.service,
        )

    def _lock(self, runtime: str, payload: str | None) -> Path:
        lock = self.identity.session_lock(runtime)
        lock.mkdir(parents=True)
        if payload is not None:
            (lock / "pid").write_text(payload)
        return lock

    def test_successful_live_stop_waits_for_owner_lock_release(self) -> None:
        self.podman.add_runtime("claude")
        lock = self._lock("claude", f"{os.getpid()}\n")
        object.__setattr__(self.podman, "release_lock_runtime", "claude")

        result = self._run("claude")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.reports[0].disposition, StopDisposition.STOPPED)
        self.assertFalse(lock.exists())
        self.assertNotIn("runtime-claude", self.podman.containers)
        self.assertIn("ASF session cleanup complete", result.stdout)

    def test_stop_report_is_persisted_without_temporary_residue(self) -> None:
        service = StopService(
            self.discovery,
            self.scanner,
            self.cleanup,
            verify_attempts=1,
            verify_delay=0,
            sleeper=lambda _seconds: None,
            clock=lambda: 0.0,
            paths=self.paths,
        )

        service.stop_runtime("claude")

        destination = self.paths.session_artifact(
            "claude", "cleanup-report.json"
        )
        payload = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(payload["runtime"], "claude")
        self.assertEqual(
            list(destination.parent.glob(".cleanup-report.json.*")), []
        )

    def test_successful_stop_records_current_egress_evidence(self) -> None:
        begin_run(self.paths, "claude")
        context = begin_egress_session(self.paths, "claude", ("sentry.io",))
        mark_egress_session_active(self.paths, "claude")
        context.access_log_path.write_text(
            json.dumps(
                {
                    "request": {
                        "method": "CONNECT",
                        "host": "registry.npmjs.org:443",
                        "headers": {},
                    },
                    "status": 403,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        service = StopService(
            self.discovery,
            self.scanner,
            self.cleanup,
            verify_attempts=1,
            verify_delay=0,
            sleeper=lambda _seconds: None,
            clock=lambda: 0.0,
            paths=self.paths,
        )

        result = run_stop_command(
            ("stop", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
            service=service,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Egress evidence recorded", result.stdout)
        self.assertIn("(1 agent CONNECT; 1 denied)", result.stdout)
        summary = context.metadata_path.parent / "egress-summary.json"
        self.assertTrue(summary.is_file())
        self.assertEqual(
            json.loads(summary.read_text(encoding="utf-8"))["denied_connects"],
            {"registry.npmjs.org": 1},
        )

    def test_repeated_stop_is_idempotent(self) -> None:
        first = self._run("claude")
        second = self._run("claude")
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(
            second.reports[0].disposition,
            StopDisposition.ALREADY_STOPPED,
        )
        self.assertIn("claude container: already absent", second.stdout)
        self.assertIn("LiteLLM broker: already absent", second.stdout)

    def test_stale_session_recovers_every_owned_resource(self) -> None:
        self.podman.add_runtime("claude", running=False)
        self.podman.add_support("claude", "broker", running=False)
        networks = self.identity.network_names("claude")
        self.podman.networks.update({networks.internal, networks.provider})
        secret = self.identity.broker_secret_prefix("claude") + "999999"
        self.podman.secrets.add(secret)
        state = self.identity.broker_state("claude")
        state.write_text("broker")
        self._lock("claude", "99999999\n")
        reservation = reservation_path(
            self.identity.subnet_reservation_session("claude")
        )
        reservation.parent.mkdir(parents=True, exist_ok=True)
        reservation.write_text(
            json.dumps(
                {
                    "session": self.identity.subnet_reservation_session("claude"),
                    "pid": 99999999,
                    "subnets": ["10.90.0.0/28"],
                }
            )
        )

        result = self._run("claude")

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            result.reports[0].disposition,
            StopDisposition.STALE_RECOVERED,
        )
        self.assertFalse(self.podman.containers)
        self.assertFalse(self.podman.networks)
        self.assertFalse(self.podman.secrets)
        self.assertFalse(os.path.lexists(state))
        self.assertFalse(os.path.lexists(reservation))
        self.assertFalse(os.path.lexists(self.identity.session_lock("claude")))

    def test_fresh_incomplete_lock_is_not_stolen(self) -> None:
        lock = self._lock("claude", None)

        result = self._run("claude")

        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.reports[0].previous_status,
            SessionStatus.STARTING,
        )
        self.assertEqual(
            result.reports[0].disposition,
            StopDisposition.INCONCLUSIVE,
        )
        self.assertTrue(lock.exists())
        self.assertEqual(self.podman.calls, [])
        self.assertIn("session is still starting", result.stderr)

    def test_live_inconclusive_discovery_refuses_mutation(self) -> None:
        self.podman.add_runtime("claude")
        object.__setattr__(self.podman, "fail_secret_list", True)

        result = self._run("claude")

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.reports[0].disposition, StopDisposition.INCONCLUSIVE)
        self.assertIn("runtime-claude", self.podman.containers)
        self.assertFalse(any("rm" in call for call in self.podman.calls))

    def test_stale_inconclusive_discovery_cleans_known_subset_but_fails(self) -> None:
        self.podman.add_runtime("claude", running=False)
        object.__setattr__(self.podman, "fail_secret_list", True)

        result = self._run("claude")

        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.reports[0].disposition,
            StopDisposition.PARTIALLY_CLEANED,
        )
        self.assertNotIn("runtime-claude", self.podman.containers)
        self.assertTrue(result.reports[0].cleanup.inconclusive)

    def test_post_cleanup_residue_forces_nonzero_status(self) -> None:
        self.podman.add_runtime("claude", running=False)
        network = self.identity.network_names("claude").internal
        object.__setattr__(self.podman, "spawn_network_after_rm", network)

        result = self._run("claude")

        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.reports[0].disposition,
            StopDisposition.PARTIALLY_CLEANED,
        )
        self.assertTrue(result.reports[0].remaining.resources())
        self.assertIn("resource(s) still present", result.stderr)

    def test_no_operand_stops_every_running_runtime(self) -> None:
        self.podman.add_runtime("claude")
        self.podman.add_runtime("hermes")

        result = self._run()

        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            [report.runtime for report in result.reports],
            ["claude", "hermes"],
        )
        self.assertFalse(self.podman.containers)

    def test_no_running_runtime_sweeps_every_known_runtime(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            [report.runtime for report in result.reports],
            ["claude", "hermes"],
        )

    def test_unknown_runtime_and_extra_arguments_match_legacy_contract(
        self,
    ) -> None:
        unknown = self._run("missing")
        self.assertEqual(unknown.returncode, 1)
        self.assertEqual(unknown.stderr, "")
        self.assertIn("Unknown agent: missing", unknown.stdout)
        self.assertIn("    claude", unknown.stdout)

        extra = self._run("claude", "ignored")
        self.assertEqual(extra.returncode, 0)
        self.assertEqual(extra.reports[0].runtime, "claude")


    def test_explicit_stop_does_not_touch_another_runtime(self) -> None:
        self.podman.add_runtime("claude")
        self.podman.add_runtime("hermes")

        result = self._run("claude")

        self.assertEqual(result.returncode, 0)
        self.assertNotIn("runtime-claude", self.podman.containers)
        self.assertIn("runtime-hermes", self.podman.containers)

    def test_top_level_cli_uses_stop_result_without_traceback(self) -> None:
        self.podman.add_runtime("claude", running=False)
        stdout = io.StringIO()
        stderr = io.StringIO()

        status = main(
            ["stop", "claude"],
            root=self.root,
            stdout=stdout,
            stderr=stderr,
            podman=self.podman,
        )

        self.assertEqual(status, 0)
        self.assertIn("Stopping claude session", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn("Traceback", stdout.getvalue())

    def test_shutdown_timeout_zero_and_invalid_text(
        self,
    ) -> None:
        with mock.patch.dict(os.environ, {"ASF_SHUTDOWN_TIMEOUT": "0"}):
            accepted = run_stop_command(
                ("stop", "claude"),
                self.paths,
                podman=self.podman,
                require_available=False,
            )
        self.assertEqual(accepted.returncode, 0)

        with mock.patch.dict(os.environ, {"ASF_SHUTDOWN_TIMEOUT": "nope"}):
            rejected = run_stop_command(
                ("stop", "claude"),
                self.paths,
                podman=self.podman,
                require_available=False,
            )
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(
            rejected.stderr,
            "ASF_SHUTDOWN_TIMEOUT must be a non-negative integer.\n",
        )


    def test_stop_events_stream_once_and_match_buffered_result(self) -> None:
        self.podman.add_runtime("claude", running=False)
        events = []

        result = run_stop_command(
            ("stop", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
            service=self.service,
            event_sink=events.append,
        )

        self.assertEqual(tuple(events), result.events)
        self.assertEqual(
            "".join(event.text for event in events if event.stream.value == "stdout"),
            result.stdout,
        )
        self.assertEqual(
            "".join(event.text for event in events if event.stream.value == "stderr"),
            result.stderr,
        )

    def test_cli_streams_stop_output_without_duplication(self) -> None:
        self.podman.add_runtime("claude", running=False)
        stdout = io.StringIO()
        stderr = io.StringIO()

        status = main(
            ["stop", "claude"],
            root=self.root,
            stdout=stdout,
            stderr=stderr,
            podman=self.podman,
        )

        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue().count("Stopping claude session"), 1)
        self.assertEqual(stderr.getvalue(), "")

    def test_verification_tuning_environment_is_validated(self) -> None:
        cases = (
            (
                {"ASF_STOP_VERIFY_ATTEMPTS": "0"},
                "ASF_STOP_VERIFY_ATTEMPTS must be a positive integer.\n",
            ),
            (
                {"ASF_STOP_VERIFY_DELAY": "nan"},
                "ASF_STOP_VERIFY_DELAY must be a finite non-negative number.\n",
            ),
        )
        for environment, expected in cases:
            with self.subTest(environment=environment):
                with mock.patch.dict(os.environ, environment, clear=False):
                    result = run_stop_command(
                        ("stop", "claude"),
                        self.paths,
                        podman=self.podman,
                        require_available=False,
                    )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr, expected)


    def test_broken_output_pipe_does_not_interrupt_cleanup(self) -> None:
        self.podman.add_runtime("claude", running=False)
        calls = 0

        def broken_sink(_event) -> None:
            nonlocal calls
            calls += 1
            raise BrokenPipeError

        result = run_stop_command(
            ("stop", "claude"),
            self.paths,
            podman=self.podman,
            require_available=False,
            service=self.service,
            event_sink=broken_sink,
        )

        self.assertEqual(calls, 1)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("runtime-claude", self.podman.containers)

    def test_report_exposes_compact_compatibility_properties(self) -> None:
        self.podman.add_runtime("claude", running=False)
        report = self._run("claude").reports[0]
        self.assertFalse(report.was_running)
        self.assertTrue(report.had_residue)
        self.assertIn("claude: stale-recovered", report.summary())


class TranscriptGroupingTests(unittest.TestCase):
    """Freeze the grouped transcript inherited from Bash cleanup."""

    def test_networks_are_reported_as_one_group(self) -> None:
        from asf.stop import _GROUPS

        groups = {key: (kinds, label, success) for key, kinds, label, success in _GROUPS}
        kinds, label, success = groups["networks"]
        from asf.ownership import ResourceKind

        self.assertEqual(kinds, (ResourceKind.NETWORK,))
        self.assertEqual(label, "Removing session networks")
        self.assertEqual(success, "Session networks removed")

    def test_container_labels_include_the_stop_grace(self) -> None:
        from asf.stop import _GROUPS

        labels = {key: label for key, _kinds, label, _success in _GROUPS}
        self.assertIn("grace: {grace}s", labels["runtime"])
        self.assertIn("grace: {grace}s", labels["broker"])

    def test_reservation_and_lock_cleanup_remain_silent(self) -> None:
        from asf.stop import _GROUPS

        labels = {
            key: (label, success)
            for key, _kinds, label, success in _GROUPS
        }
        self.assertEqual(labels["reservation"], ("", ""))
        self.assertEqual(labels["lock"], ("", ""))

    def test_only_runtime_and_broker_announce_absence(self) -> None:
        from asf.stop import _ANNOUNCE_ABSENT

        self.assertEqual(set(_ANNOUNCE_ABSENT), {"runtime", "broker"})

    def test_groups_follow_the_canonical_teardown_order(self) -> None:
        from asf.ownership import TEARDOWN_ORDER
        from asf.stop import _GROUPS

        flattened = [kind for _key, kinds, _label, _success in _GROUPS for kind in kinds]
        positions = [TEARDOWN_ORDER.index(kind) for kind in flattened]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(set(flattened), set(TEARDOWN_ORDER))

    def test_every_group_has_one_unique_key(self) -> None:
        from asf.stop import _GROUPS

        keys = [key for key, _kinds, _label, _success in _GROUPS]
        self.assertEqual(len(keys), len(set(keys)))


if __name__ == "__main__":
    unittest.main()
