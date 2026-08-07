"""Tests for ASF session discovery, support roles, and stale-state handling."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from collections.abc import Mapping, Sequence

from asf.errors import (
    AsfError,
    ConfigurationError,
    InfrastructureError,
    UsageError,
    ValidationError,
)
from asf.identity import ResourceIdentity
from asf.paths import RepoPaths
from asf.podman import ContainerInspection, HealthStatus, ObjectNotFoundError
from asf.session import (
    AmbiguousSessionError,
    InspectedSession,
    MultipleRunningSessionsError,
    NoRunningSessionError,
    RuntimeCatalogError,
    RuntimeSession,
    SessionContainer,
    SessionLockSnapshot,
    SessionOwnership,
    SessionRole,
    SessionStatus,
    SessionDiscoveryError,
    SessionError,
    SessionInfrastructureError,
    SessionDiscovery,
    SessionMatch,
    UnknownRuntimeError,
)


class FakePodman:
    def __init__(self, matches: dict[tuple[str, bool], tuple[str, ...]]) -> None:
        self.matches = matches
        self.calls: list[tuple[str, bool]] = []
        self.inspections: dict[str, ContainerInspection] = {}

    def container_ids(
        self,
        labels: Mapping[str, str] | Sequence[str] = (),
        *,
        include_stopped: bool = False,
    ) -> tuple[str, ...]:
        if isinstance(labels, Mapping):
            normalised = tuple(
                f"{key}={value}" for key, value in labels.items()
            )
        else:
            normalised = tuple(labels)
        label_key = normalised[0] if len(normalised) == 1 else "&".join(normalised)
        self.calls.append((label_key, include_stopped))
        return self.matches.get((label_key, include_stopped), ())

    def all_container_ids(
        self, labels: Mapping[str, str] | Sequence[str]
    ) -> tuple[str, ...]:
        return self.container_ids(labels, include_stopped=True)

    def inspect_container(self, reference: str) -> ContainerInspection:
        return self.inspections[reference]


def identity() -> ResourceIdentity:
    return ResourceIdentity.from_physical_path("/tmp/asf-session-tests")


def discovery(
    matches: dict[tuple[str, bool], tuple[str, ...]] | None = None,
) -> tuple[SessionDiscovery, FakePodman]:
    resource = identity()
    fake = FakePodman(matches or {})
    return (
        SessionDiscovery(
            identity=resource,
            runtimes=("hermes", "claude"),
            podman=fake,  # type: ignore[arg-type]
        ),
        fake,
    )


class ErrorHierarchyTests(unittest.TestCase):
    def test_all_session_failures_reach_one_cli_boundary(self) -> None:
        for error in (
            NoRunningSessionError("x"),
            MultipleRunningSessionsError(("claude", "hermes")),
            AmbiguousSessionError("hermes", ("a", "b")),
            UnknownRuntimeError("other", ("claude", "hermes")),
            RuntimeCatalogError("x"),
        ):
            self.assertIsInstance(error, AsfError)

        self.assertIsInstance(NoRunningSessionError("x"), InfrastructureError)
        self.assertIsInstance(RuntimeCatalogError("x"), ConfigurationError)

    def test_compatibility_umbrella_catches_every_discovery_failure(self) -> None:
        for error_type in (
            SessionError,
            SessionInfrastructureError,
            NoRunningSessionError,
            MultipleRunningSessionsError,
            AmbiguousSessionError,
            UnknownRuntimeError,
            RuntimeCatalogError,
        ):
            with self.subTest(error_type=error_type.__name__):
                self.assertTrue(
                    issubclass(error_type, SessionDiscoveryError)
                )


class HostHarnessRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tests = Path(__file__).resolve().parent
        self.fixture = (self.tests / "lib" / "host-fixture.sh").read_text()
        self.discovery = (self.tests / "test_session_discovery_host.sh").read_text()
        self.stop = (self.tests / "test_stop_host.sh").read_text()

    def test_shared_host_fixture_owns_checkout_setup(self) -> None:
        for expected in (
            "WORK_ROOT=$(mktemp -d",
            'ROOT="$WORK_ROOT/asf"',
            "DUMMY_KEY=",
            'cp -a "$SOURCE_ROOT/." "$ROOT"',
            'python3 - "$ROOT/asf.conf" "$MODEL_SETTING"',
            'chmod 600 "$ROOT/secrets/$AGENT.env"',
            'mode: service',
            "host_fixture_stop_open_process()",
            "host_fixture_stop_runtime_quietly()",
            "host_fixture_remove_work_root()",
        ):
            self.assertIn(expected, self.fixture)

    def test_both_host_harnesses_source_the_shared_fixture(self) -> None:
        source = 'source "$SOURCE_ROOT/tests/lib/host-fixture.sh"'
        self.assertIn(source, self.discovery)
        self.assertIn(source, self.stop)
        self.assertNotIn('cp -a "$SOURCE_ROOT/." "$ROOT"', self.discovery)
        self.assertNotIn('cp -a "$SOURCE_ROOT/." "$ROOT"', self.stop)
        self.assertNotIn("sandbox_in_fixture()", self.discovery)
        self.assertNotIn("sandbox_in_fixture()", self.stop)

    def test_session_harness_preserves_discovery_checks_and_messages(self) -> None:
        script = self.discovery
        self.assertIn("from asf.session import SessionDiscovery", script)
        self.assertIn("ASF_HOST_OPEN_TIMEOUT", script)
        self.assertIn("OPEN_LOG", script)
        self.assertIn('kill -0 "$OPEN_PID"', script)
        self.assertIn("PYTHONUNBUFFERED=1", script)
        self.assertIn("host-session-hold.sh", script)
        self.assertIn("required_stable_polls=3", script)
        self.assertIn(
            "Starting ${AGENT} session-discovery test containers", script
        )
        self.assertIn(
            "Stopping and removing ${AGENT} session-discovery test containers", script
        )
        self.assertIn(
            "session-discovery test containers stopped and cleanup verified", script
        )
        self.assertIn('[[ "$(query root)" == "$ROOT" ]]', script)
        self.assertNotIn('open "$AGENT" >/dev/null 2>&1 &', script)
        self.assertNotIn("legacy_diagnostics", script)

    def test_stop_harness_preserves_lifecycle_checks_and_messages(self) -> None:
        script = self.stop
        for expected in (
            "host-stop-hold.sh",
            "required_stable_polls=3",
            '[[ "$fixture_root" == "$ROOT" ]]',
            'label=asf.sandbox=$ROOT',
            "Live stop and idempotent cleanup",
            "Signal-triggered cleanup",
            "SIGKILL stale-session recovery",
            "Partial-resource recovery",
            "Starting ${AGENT} test containers",
            "Stopping and removing ${AGENT} test containers",
        ):
            self.assertIn(expected, script)
        self.assertIn(
            "expected a support proxy container for partial-resource recovery",
            script,
        )
        self.assertNotIn(
            "No support container present; continuing partial-cleanup check",
            script,
        )
        self.assertNotIn('open "$AGENT" >/dev/null 2>&1 &', script)


class RecordingPodman:
    def __init__(self) -> None:
        self.matches: dict[tuple[tuple[str, ...], bool], tuple[str, ...]] = {}
        self.inspections: dict[str, ContainerInspection | Exception] = {}
        self.calls: list[tuple[tuple[str, ...], bool]] = []

    @staticmethod
    def normalise(
        labels: Mapping[str, str] | Sequence[str],
    ) -> tuple[str, ...]:
        if isinstance(labels, Mapping):
            return tuple(f"{key}={value}" for key, value in labels.items())
        return tuple(labels)

    def container_ids(
        self,
        labels: Mapping[str, str] | Sequence[str] = (),
        *,
        include_stopped: bool = False,
    ) -> tuple[str, ...]:
        key = (self.normalise(labels), include_stopped)
        self.calls.append(key)
        return self.matches.get(key, ())

    def all_container_ids(
        self, labels: Mapping[str, str] | Sequence[str]
    ) -> tuple[str, ...]:
        return self.container_ids(labels, include_stopped=True)

    def inspect_container(self, reference: str) -> ContainerInspection:
        value = self.inspections[reference]
        if isinstance(value, Exception):
            raise value
        return value


def inspection(
    container_id: str,
    *,
    status: str = "running",
    running: bool = True,
    health: str | None = None,
) -> ContainerInspection:
    return ContainerInspection(
        container_id=container_id,
        name=f"name-{container_id}",
        image="localhost/asf:test",
        status=status,
        running=running,
        health=health,
        labels={},
    )


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "checkout"
        root.mkdir()
        (root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / ".devcontainer").mkdir()
        for runtime in ("claude", "hermes"):
            directory = root / "agents" / runtime
            directory.mkdir(parents=True)
            (directory / "runtime.yml").write_text(
                f"name: {runtime}\n", encoding="utf-8"
            )
        self.paths = RepoPaths.for_root(root)
        self.podman = RecordingPodman()
        self.discovery = SessionDiscovery.from_paths(
            self.paths, podman=self.podman  # type: ignore[arg-type]
        )

    def key(
        self,
        labels: Mapping[str, str] | Sequence[str],
        stopped: bool,
    ) -> tuple[tuple[str, ...], bool]:
        return (RecordingPodman.normalise(labels), stopped)

    def set_runtime(
        self,
        runtime: str,
        identifiers: tuple[str, ...],
        *,
        stopped: bool = False,
    ) -> None:
        labels = (self.paths.identity.session_label(runtime),)
        self.podman.matches[self.key(labels, stopped)] = identifiers

    def set_role(
        self,
        runtime: str,
        role: SessionRole,
        identifiers: tuple[str, ...],
        *,
        stopped: bool = True,
    ) -> None:
        labels = {
            "asf.sandbox": str(self.paths.root),
            "asf.role": role.value,
            "asf.agent": runtime,
        }
        self.podman.matches[self.key(labels, stopped)] = identifiers


class DiscoveryTests(Fixture):
    def test_discovery_from_paths_uses_the_manifest_catalogue(self) -> None:
        inspector = SessionDiscovery.from_paths(
            self.paths, podman=self.podman  # type: ignore[arg-type]
        )
        self.assertEqual(inspector.known_runtimes(), ("claude", "hermes"))

    def test_support_lookup_uses_exact_checkout_role_and_runtime_labels(self) -> None:
        self.set_role("hermes", SessionRole.PROXY, ("proxy",), stopped=False)
        self.assertEqual(
            self.discovery.role_container_ids("hermes", SessionRole.PROXY),
            ("proxy",),
        )
        labels, include_stopped = self.podman.calls[-1]
        self.assertEqual(
            labels,
            (
                f"asf.sandbox={self.paths.root}",
                "asf.role=proxy",
                "asf.agent=hermes",
            ),
        )
        self.assertFalse(include_stopped)

    def test_duplicate_runtime_ownership_fails_closed(self) -> None:
        self.set_runtime("hermes", ("one", "two"))
        with self.assertRaises(AmbiguousSessionError):
            self.discovery.running_runtimes()

    def test_extract_runtime_argument_matches_legacy_flexible_position(self) -> None:
        self.assertEqual(
            self.discovery.extract_runtime_argument(("-f", "hermes", "tail")),
            ("hermes", ("-f", "tail")),
        )
        self.assertEqual(
            self.discovery.extract_runtime_argument(("hermes", "claude")),
            ("hermes", ("claude",)),
        )

    def test_unknown_runtime_is_both_usage_and_validation(self) -> None:
        error = UnknownRuntimeError("other", self.discovery.runtimes)
        self.assertIsInstance(error, UsageError)
        self.assertIsInstance(error, ValidationError)


class DetailedSessionTests(Fixture):
    def test_runtime_and_support_containers_form_one_session(self) -> None:
        self.set_runtime("hermes", ("runtime",), stopped=True)
        self.set_role("hermes", SessionRole.PROXY, ("proxy",))
        self.podman.inspections["runtime"] = inspection(
            "runtime", health="healthy"
        )
        self.podman.inspections["proxy"] = inspection("proxy")

        session = self.discovery.session("hermes")
        self.assertTrue(session.is_running)
        self.assertFalse(session.is_stale)
        self.assertIsNotNone(session.container)
        assert session.container is not None
        self.assertEqual(session.container.container_id, "runtime")
        self.assertIs(session.container.health, HealthStatus.HEALTHY)
        self.assertEqual(
            session.role(SessionRole.PROXY).container_id,  # type: ignore[union-attr]
            "proxy",
        )

    def test_duplicate_support_role_is_not_silently_selected(self) -> None:
        containers = (
            SessionContainer("hermes", SessionRole.PROXY, inspection("one")),
            SessionContainer("hermes", SessionRole.PROXY, inspection("two")),
        )
        session = RuntimeSession(runtime="hermes", containers=containers)
        with self.assertRaises(AmbiguousSessionError):
            session.role(SessionRole.PROXY)

    def test_container_removed_between_list_and_inspect_is_recorded(self) -> None:
        self.set_runtime("hermes", ("vanished",), stopped=True)
        self.podman.inspections["vanished"] = ObjectNotFoundError("gone")
        session = self.discovery.session("hermes")
        self.assertEqual(session.unreadable, ("vanished",))
        self.assertFalse(session.is_running)

    def test_non_absence_inspect_failure_propagates(self) -> None:
        self.set_runtime("hermes", ("broken",), stopped=True)
        self.podman.inspections["broken"] = InfrastructureError("engine failed")
        with self.assertRaises(InfrastructureError):
            self.discovery.session("hermes")


class StaleStateTests(Fixture):
    def test_stopped_runtime_or_support_container_is_stale(self) -> None:
        self.set_runtime("hermes", ("runtime",), stopped=True)
        self.podman.inspections["runtime"] = inspection(
            "runtime", status="exited", running=False
        )
        self.assertTrue(self.discovery.session("hermes").is_stale)

    def test_live_lock_without_container_is_starting_not_stale(self) -> None:
        lock = self.paths.identity.session_lock("hermes")
        lock.mkdir()
        (lock / "pid").write_text(str(os.getpid()), encoding="utf-8")
        session = self.discovery.session("hermes")
        self.assertTrue(session.is_starting)
        self.assertFalse(session.is_stale)

    def test_fresh_invalid_lock_is_starting_until_grace_expires(self) -> None:
        lock = self.paths.identity.session_lock("hermes")
        lock.mkdir()
        (lock / "pid").write_text("not-a-pid", encoding="utf-8")
        session = self.discovery.session("hermes")
        self.assertTrue(session.is_starting)
        self.assertFalse(session.is_stale)

    def test_aged_invalid_lock_is_stale(self) -> None:
        from asf.session_lock import CLAIM_GRACE_SECONDS
        import time

        lock = self.paths.identity.session_lock("hermes")
        lock.mkdir()
        (lock / "pid").write_text("not-a-pid", encoding="utf-8")
        timestamp = time.time() - CLAIM_GRACE_SECONDS - 1
        os.utime(lock, (timestamp, timestamp))
        session = self.discovery.session("hermes")
        self.assertTrue(session.lock.is_stale)  # type: ignore[union-attr]
        self.assertTrue(session.is_stale)

    def test_broker_state_alone_is_stale(self) -> None:
        self.paths.identity.broker_state("hermes").write_text(
            "state", encoding="utf-8"
        )
        self.assertTrue(self.discovery.session("hermes").is_stale)


if __name__ == "__main__":
    unittest.main()
