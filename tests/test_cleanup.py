"""Focused tests for ordered Phase 3B cleanup execution."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from asf.cleanup import (
    NETWORK_ATTEMPTS,
    CleanupError,
    CleanupExecutor,
    CleanupFailedError,
    CleanupOutcome,
    CleanupReport,
)
from asf.errors import InfrastructureError, ValidationError
from asf.identity import ResourceIdentity
from asf.ownership import Resource, ResourceKind, ResourceLedger, teardown_sequence
from asf.podman import (
    ContainerInspection,
    ObjectKind,
    PodmanClient,
)
from asf.paths import RepoPaths
from asf.process import CommandResult
from asf.residue import ResidueScanner, SessionResidue
from asf.session import SessionDiscovery, SessionRole
from asf.session_lock import SessionLockManager
from asf.subnets import reservation_path


class FakePodman(PodmanClient):
    def __init__(self) -> None:
        super().__init__(engine="podman", timeout=3, runner=self._unused)
        object.__setattr__(self, "present", {kind: set() for kind in ObjectKind})
        object.__setattr__(self, "running", set())
        object.__setattr__(self, "fail", {})
        object.__setattr__(self, "responses", {})
        object.__setattr__(self, "calls", [])

    @staticmethod
    def _unused(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("direct runner should not be used")

    def exists(self, reference: str, kind: ObjectKind = ObjectKind.CONTAINER) -> bool:
        self.calls.append(("exists", kind.value, reference))
        return reference in self.present[kind]

    def inspect_container(self, reference: str, *, timeout=None):  # noqa: ANN001
        self.calls.append(("inspect", reference))
        if reference not in self.present[ObjectKind.CONTAINER]:
            from asf.podman import ObjectNotFoundError

            raise ObjectNotFoundError("no such container")
        return ContainerInspection(
            container_id=reference,
            name=reference,
            image="image",
            status="running" if reference in self.running else "exited",
            running=reference in self.running,
            health=None,
        )

    def observe(self, argv, **_kwargs):  # noqa: ANN001
        args = tuple(str(value) for value in argv)
        self.calls.append(args)
        action = _action(args)
        queue = self.responses.get((action, args[-1]), [])
        if queue:
            returncode, stderr = queue.pop(0)
        else:
            returncode = self.fail.get((action, args[-1]), 0)
            stderr = "simulated failure" if returncode else ""
        if returncode == 0:
            reference = args[-1]
            if action in {"rm", "stop"}:
                if action == "stop":
                    self.running.discard(reference)
                else:
                    self.present[ObjectKind.CONTAINER].discard(reference)
                    self.running.discard(reference)
            elif action == "network-rm":
                self.present[ObjectKind.NETWORK].discard(reference)
            elif action == "secret-rm":
                self.present[ObjectKind.SECRET].discard(reference)
        return CommandResult(args, returncode, "", stderr)


def _action(args: tuple[str, ...]) -> str:
    if len(args) > 1 and args[1] == "stop":
        return "stop"
    if len(args) > 1 and args[1] == "rm":
        return "rm"
    if len(args) > 2 and args[1:3] == ("network", "rm"):
        return "network-rm"
    if len(args) > 2 and args[1:3] == ("secret", "rm"):
        return "secret-rm"
    return "other"


class CleanupExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / ".devcontainer").mkdir()
        self.identity = ResourceIdentity.from_physical_path(self.root)
        self.live: set[int] = set()
        self.lock_manager = SessionLockManager(
            self.identity,
            process_alive=lambda pid: pid in self.live,
        )
        self.podman = FakePodman()
        self.executor = CleanupExecutor(
            self.podman,
            self.lock_manager,
            stop_timeout=2,
            sleeper=lambda _seconds: None,
        )

    def _resource(self, kind: ResourceKind, name: str) -> Resource:
        return Resource(kind, name, runtime="claude")

    def test_cleanup_uses_dependency_order_and_aggregates_failures(self) -> None:
        networks = self.identity.network_names("claude")
        runtime = self._resource(ResourceKind.RUNTIME_CONTAINER, "runtime")
        broker = self._resource(ResourceKind.BROKER_CONTAINER, "broker")
        secret_name = self.identity.broker_secret_prefix("claude") + "123"
        secret = self._resource(ResourceKind.SECRET, secret_name)
        network = self._resource(ResourceKind.NETWORK, networks.internal)
        self.podman.present[ObjectKind.CONTAINER].update({"runtime", "broker"})
        self.podman.present[ObjectKind.SECRET].add(secret_name)
        self.podman.present[ObjectKind.NETWORK].add(networks.internal)
        self.podman.fail[("rm", "broker")] = 7

        report = self.executor.cleanup((network, broker, secret, runtime))

        self.assertEqual(
            [result.resource.kind for result in report.results],
            [
                ResourceKind.RUNTIME_CONTAINER,
                ResourceKind.BROKER_CONTAINER,
                ResourceKind.SECRET,
                ResourceKind.NETWORK,
            ],
        )
        self.assertFalse(report.succeeded)
        self.assertEqual(report.exit_code, 1)
        self.assertEqual([item.resource.name for item in report.failures], ["broker"])
        self.assertNotIn(secret_name, self.podman.present[ObjectKind.SECRET])
        self.assertNotIn(networks.internal, self.podman.present[ObjectKind.NETWORK])

    def test_cleanup_or_raise_raises_only_after_later_actions_run(self) -> None:
        networks = self.identity.network_names("claude")
        failed = self._resource(ResourceKind.RUNTIME_CONTAINER, "runtime")
        network = self._resource(ResourceKind.NETWORK, networks.internal)
        self.podman.present[ObjectKind.CONTAINER].add("runtime")
        self.podman.present[ObjectKind.NETWORK].add(networks.internal)
        self.podman.fail[("rm", "runtime")] = 1

        with self.assertRaises(CleanupFailedError) as caught:
            self.executor.cleanup_or_raise((failed, network))

        self.assertEqual(len(caught.exception.report.failures), 1)
        self.assertNotIn(networks.internal, self.podman.present[ObjectKind.NETWORK])

    def test_duplicate_resources_are_attempted_once(self) -> None:
        resource = self._resource(ResourceKind.RUNTIME_CONTAINER, "runtime")
        self.podman.present[ObjectKind.CONTAINER].add("runtime")
        report = self.executor.cleanup((resource, resource))
        self.assertEqual(len(report.results), 1)
        self.assertEqual(report.results[0].outcome, CleanupOutcome.REMOVED)

    def test_residue_and_ledger_are_merged_without_duplicates(self) -> None:
        networks = self.identity.network_names("claude")
        residue_resource = self._resource(
            ResourceKind.RUNTIME_CONTAINER,
            "runtime",
        )
        network = self._resource(ResourceKind.NETWORK, networks.internal)
        residue = SessionResidue(
            runtime="claude",
            containers=(residue_resource,),
        )
        ledger = ResourceLedger(runtime="claude")
        ledger.extend((residue_resource, network))
        self.podman.present[ObjectKind.CONTAINER].add("runtime")
        self.podman.present[ObjectKind.NETWORK].add(networks.internal)

        report = self.executor.cleanup(residue, ledger=ledger)

        self.assertEqual(
            [result.resource.name for result in report.results],
            ["runtime", networks.internal],
        )
        self.assertEqual(len(ledger), 0)

    def test_failed_resource_remains_in_ledger(self) -> None:
        ledger = ResourceLedger(runtime="claude")
        resource = ledger.record(ResourceKind.RUNTIME_CONTAINER, "runtime")
        self.podman.present[ObjectKind.CONTAINER].add("runtime")
        self.podman.fail[("rm", "runtime")] = 1

        report = self.executor.cleanup(ledger)

        self.assertEqual(report.results[0].outcome, CleanupOutcome.FAILED)
        self.assertIn(resource, ledger)

    def test_ledger_runtime_must_match_residue_runtime(self) -> None:
        residue = SessionResidue(runtime="claude")
        ledger = ResourceLedger(runtime="hermes")
        with self.assertRaises(ValidationError):
            self.executor.cleanup(residue, ledger=ledger)

    def test_absent_resources_are_idempotent(self) -> None:
        report = self.executor.cleanup(
            (self._resource(ResourceKind.RUNTIME_CONTAINER, "missing"),)
        )
        self.assertTrue(report.succeeded)
        self.assertEqual(report.results[0].outcome, CleanupOutcome.ABSENT)

    def test_persistent_volumes_are_preserved_without_podman_calls(self) -> None:
        ledger = ResourceLedger(runtime="claude")
        ledger.record(ResourceKind.VOLUME, "state")
        report = self.executor.cleanup(ledger)
        self.assertEqual(report.preserved[0].resource.name, "state")
        self.assertEqual(self.podman.calls, [])
        self.assertEqual(len(ledger), 1)

    def test_broker_state_symlink_is_unlinked_without_following_target(self) -> None:
        external = self.root / "external"
        external.write_text("keep")
        state = self.identity.broker_state("claude")
        state.symlink_to(external)
        resource = self._resource(ResourceKind.BROKER_STATE, str(state))

        report = self.executor.cleanup((resource,))

        self.assertEqual(report.results[0].outcome, CleanupOutcome.REMOVED)
        self.assertFalse(os.path.lexists(state))
        self.assertEqual(external.read_text(), "keep")

    def test_unexpected_file_paths_fail_closed(self) -> None:
        outside = self.root / "outside"
        outside.write_text("keep")
        resource = self._resource(ResourceKind.BROKER_STATE, str(outside))
        report = self.executor.cleanup((resource,))
        self.assertEqual(report.failures[0].outcome, CleanupOutcome.FAILED)
        self.assertEqual(outside.read_text(), "keep")

    def test_reservation_is_removed_without_following_symlink(self) -> None:
        runtime_dir = self.root / "runtime"
        runtime_dir.mkdir()
        previous = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = str(runtime_dir)
        self.addCleanup(_restore_env, "XDG_RUNTIME_DIR", previous)
        target = self.root / "target"
        target.write_text("keep")
        path = reservation_path(
            self.identity.subnet_reservation_session("claude")
        )
        path.parent.mkdir(parents=True)
        path.symlink_to(target)
        resource = self._resource(ResourceKind.SUBNET_RESERVATION, str(path))

        report = self.executor.cleanup((resource,))

        self.assertEqual(report.results[0].outcome, CleanupOutcome.REMOVED)
        self.assertFalse(os.path.lexists(path))
        self.assertEqual(target.read_text(), "keep")

    def test_owned_lock_is_released_with_exact_token(self) -> None:
        acquired = self.lock_manager.acquire("claude", owner_pid=1234)
        resource = Resource(
            ResourceKind.SESSION_LOCK,
            str(acquired.path),
            runtime="claude",
            owner_pid=1234,
        )
        report = self.executor.cleanup((resource,), acquired_lock=acquired)
        self.assertEqual(report.results[0].outcome, CleanupOutcome.REMOVED)
        self.assertIsNone(self.lock_manager.inspect("claude"))

    def test_stale_lock_is_removed_but_live_lock_is_preserved_as_failure(self) -> None:
        stale = self.identity.session_lock("claude")
        stale.mkdir()
        (stale / "pid").write_text("2222\n")
        resource = Resource(
            ResourceKind.SESSION_LOCK,
            str(stale),
            runtime="claude",
            owner_pid=2222,
        )
        removed = self.executor.cleanup((resource,))
        self.assertEqual(removed.results[0].outcome, CleanupOutcome.REMOVED)

        live = self.identity.session_lock("claude")
        live.mkdir()
        (live / "pid").write_text("3333\n")
        self.live.add(3333)
        failed = self.executor.cleanup(
            (
                Resource(
                    ResourceKind.SESSION_LOCK,
                    str(live),
                    runtime="claude",
                    owner_pid=3333,
                ),
            )
        )
        self.assertEqual(failed.results[0].outcome, CleanupOutcome.FAILED)
        self.assertTrue(live.exists())

    def test_routed_krun_teardown_orders_vmm_before_gateway_before_network(self) -> None:
        resources = (
            self._resource(ResourceKind.NETWORK, "scan-network"),
            self._resource(ResourceKind.GATEWAY_CONTAINER, "gateway"),
            self._resource(ResourceKind.GATEWAY_INIT_CONTAINER, "gateway-init"),
            self._resource(ResourceKind.RUNTIME_CONTAINER, "microvm"),
        )

        ordered = teardown_sequence(resources)

        self.assertEqual(
            [resource.kind for resource in ordered],
            [
                ResourceKind.RUNTIME_CONTAINER,
                ResourceKind.GATEWAY_INIT_CONTAINER,
                ResourceKind.GATEWAY_CONTAINER,
                ResourceKind.NETWORK,
            ],
        )

    def test_routed_container_uses_stop_then_remove(self) -> None:
        resource = self._resource(ResourceKind.GATEWAY_CONTAINER, "gateway")
        self.podman.present[ObjectKind.CONTAINER].add("gateway")
        self.podman.running.add("gateway")
        report = self.executor.cleanup((resource,))
        actions = [
            call[1]
            for call in self.podman.calls
            if isinstance(call, tuple) and call and call[0] == "podman"
        ]
        self.assertEqual(actions, ["stop", "rm"])
        self.assertEqual(report.results[0].outcome, CleanupOutcome.REMOVED)

    def test_failed_routed_stop_is_safe_when_container_already_exited(self) -> None:
        resource = self._resource(ResourceKind.GATEWAY_INIT_CONTAINER, "init")
        self.podman.present[ObjectKind.CONTAINER].add("init")
        self.podman.fail[("stop", "init")] = 125
        report = self.executor.cleanup((resource,))
        self.assertEqual(report.results[0].outcome, CleanupOutcome.REMOVED)

    def test_failed_routed_stop_does_not_remove_a_running_container(self) -> None:
        resource = self._resource(ResourceKind.GATEWAY_CONTAINER, "gateway")
        self.podman.present[ObjectKind.CONTAINER].add("gateway")
        self.podman.running.add("gateway")
        self.podman.fail[("stop", "gateway")] = 1
        report = self.executor.cleanup((resource,))
        self.assertEqual(report.results[0].outcome, CleanupOutcome.FAILED)
        self.assertIn("gateway", self.podman.present[ObjectKind.CONTAINER])
        self.assertFalse(
            any(
                _action(call) == "rm"
                for call in self.podman.calls
                if isinstance(call, tuple) and call and call[0] == "podman"
            )
        )

    def test_runtime_owned_network_and_secret_names_are_enforced(self) -> None:
        bad_network = self._resource(ResourceKind.NETWORK, "unrelated-network")
        bad_secret = self._resource(ResourceKind.SECRET, "unrelated-secret")
        self.podman.present[ObjectKind.NETWORK].add(bad_network.name)
        self.podman.present[ObjectKind.SECRET].add(bad_secret.name)
        report = self.executor.cleanup((bad_secret, bad_network))
        self.assertEqual(len(report.failures), 2)
        self.assertIn(bad_network.name, self.podman.present[ObjectKind.NETWORK])
        self.assertIn(bad_secret.name, self.podman.present[ObjectKind.SECRET])

    def test_network_in_use_is_retried_and_then_removed(self) -> None:
        network = self.identity.network_names("claude").internal
        resource = self._resource(ResourceKind.NETWORK, network)
        self.podman.present[ObjectKind.NETWORK].add(network)
        self.podman.responses[("network-rm", network)] = [
            (125, "network is being used by container abc"),
            (125, "network has active endpoints"),
            (0, ""),
        ]

        report = self.executor.cleanup((resource,))

        self.assertEqual(report.results[0].outcome, CleanupOutcome.REMOVED)
        calls = [
            call
            for call in self.podman.calls
            if isinstance(call, tuple) and _action(call) == "network-rm"
        ]
        self.assertEqual(len(calls), 3)

    def test_network_retry_is_bounded(self) -> None:
        network = self.identity.network_names("claude").internal
        resource = self._resource(ResourceKind.NETWORK, network)
        self.podman.present[ObjectKind.NETWORK].add(network)
        self.podman.responses[("network-rm", network)] = [
            (125, "network is being used")
            for _ in range(NETWORK_ATTEMPTS)
        ]

        report = self.executor.cleanup((resource,))

        self.assertEqual(report.results[0].outcome, CleanupOutcome.FAILED)
        calls = [
            call
            for call in self.podman.calls
            if isinstance(call, tuple) and _action(call) == "network-rm"
        ]
        self.assertEqual(len(calls), NETWORK_ATTEMPTS)

    def test_non_race_network_failure_is_not_retried(self) -> None:
        network = self.identity.network_names("claude").internal
        resource = self._resource(ResourceKind.NETWORK, network)
        self.podman.present[ObjectKind.NETWORK].add(network)
        self.podman.responses[("network-rm", network)] = [
            (125, "permission denied"),
        ]

        report = self.executor.cleanup((resource,))

        self.assertEqual(report.results[0].outcome, CleanupOutcome.FAILED)
        calls = [
            call
            for call in self.podman.calls
            if isinstance(call, tuple) and _action(call) == "network-rm"
        ]
        self.assertEqual(len(calls), 1)

    def test_inconclusive_residue_is_never_cleaned(self) -> None:
        residue = SessionResidue(
            runtime="claude",
            containers=(
                self._resource(ResourceKind.RUNTIME_CONTAINER, "runtime"),
            ),
            unreadable=("Podman unavailable",),
        )
        self.podman.present[ObjectKind.CONTAINER].add("runtime")
        with self.assertRaises(CleanupError):
            self.executor.cleanup(residue)
        self.assertIn("runtime", self.podman.present[ObjectKind.CONTAINER])
        self.assertEqual(self.podman.calls, [])

    def test_conclusive_residue_can_feed_the_cleanup_engine(self) -> None:
        resource = self._resource(ResourceKind.RUNTIME_CONTAINER, "runtime")
        residue = SessionResidue(runtime="claude", containers=(resource,))
        self.podman.present[ObjectKind.CONTAINER].add("runtime")
        report = self.executor.cleanup(residue)
        self.assertEqual(report.results[0].outcome, CleanupOutcome.REMOVED)

    def test_report_is_immutable_and_errors_use_shared_hierarchy(self) -> None:
        report = CleanupReport(())
        self.assertTrue(report.succeeded)
        self.assertTrue(report.complete)
        self.assertEqual(report.summary(), "0 removed")
        with self.assertRaises((AttributeError, TypeError)):
            report.results += ()  # type: ignore[misc]
        self.assertTrue(issubclass(CleanupError, InfrastructureError))
        zero_timeout = CleanupExecutor(
            self.podman, self.lock_manager, stop_timeout=0
        )
        self.assertEqual(zero_timeout.stop_timeout, 0.0)
        with self.assertRaises(ValidationError):
            CleanupExecutor(
                self.podman,
                self.lock_manager,
                network_attempts=0,
            )
        with self.assertRaises(ValidationError):
            CleanupExecutor(
                self.podman,
                self.lock_manager,
                network_retry_delay=-1,
            )

    def test_progress_callback_receives_results_in_order(self) -> None:
        seen = []
        executor = CleanupExecutor(
            self.podman,
            self.lock_manager,
            stop_timeout=2,
            sleeper=lambda _seconds: None,
            on_result=seen.append,
        )
        first = self._resource(ResourceKind.RUNTIME_CONTAINER, "runtime")
        volume = self._resource(ResourceKind.VOLUME, "state")
        self.podman.present[ObjectKind.CONTAINER].add("runtime")

        report = executor.cleanup((volume, first))

        self.assertEqual(seen, list(report.results))


    def test_inconclusive_residue_can_clean_known_resources_only_when_explicit(
        self,
    ) -> None:
        network = self._resource(
            ResourceKind.NETWORK,
            self.identity.network_names("claude").internal,
        )
        residue = SessionResidue(
            runtime="claude",
            networks=(network,),
            unreadable=("secrets: podman unavailable",),
        )
        self.podman.present[ObjectKind.NETWORK].add(network.name)

        with self.assertRaisesRegex(
            CleanupError,
            "refusing cleanup from an inconclusive residue scan",
        ):
            self.executor.cleanup(residue)
        self.assertIn(network.name, self.podman.present[ObjectKind.NETWORK])

        report = self.executor.cleanup(residue, allow_inconclusive=True)

        self.assertEqual(report.removed[0].resource, network)
        self.assertEqual(
            report.inconclusive,
            ("secrets: podman unavailable",),
        )
        self.assertFalse(report.succeeded)
        self.assertFalse(report.complete)
        self.assertEqual(report.exit_code, 1)
        self.assertIn("1 not checked", report.summary())

    def test_partial_recovery_forgets_only_proved_resources(self) -> None:
        network = self._resource(
            ResourceKind.NETWORK,
            self.identity.network_names("claude").internal,
        )
        volume = self._resource(ResourceKind.VOLUME, "state")
        ledger = ResourceLedger(runtime="claude")
        ledger.record(network.kind, network.name)
        ledger.record(volume.kind, volume.name)
        residue = SessionResidue(
            runtime="claude",
            unreadable=("secrets: list failed",),
        )
        self.podman.present[ObjectKind.NETWORK].add(network.name)

        report = self.executor.cleanup(
            residue,
            ledger=ledger,
            allow_inconclusive=True,
        )

        self.assertFalse(report.succeeded)
        self.assertEqual(
            {(resource.kind, resource.name) for resource in ledger.created},
            {(ResourceKind.VOLUME, "state")},
        )
        self.assertEqual(report.preserved[0].resource, volume)

    def test_inconclusive_cleanup_or_raise_raises_after_known_cleanup(
        self,
    ) -> None:
        network = self._resource(
            ResourceKind.NETWORK,
            self.identity.network_names("claude").internal,
        )
        residue = SessionResidue(
            runtime="claude",
            networks=(network,),
            unreadable=("runtime containers: inspect failed",),
        )
        self.podman.present[ObjectKind.NETWORK].add(network.name)

        with self.assertRaises(CleanupFailedError) as caught:
            self.executor.cleanup_or_raise(
                residue,
                allow_inconclusive=True,
            )

        self.assertNotIn(network.name, self.podman.present[ObjectKind.NETWORK])
        self.assertEqual(
            caught.exception.report.inconclusive,
            ("runtime containers: inspect failed",),
        )
        self.assertIn("1 unchecked lookup", str(caught.exception))

    def test_allow_inconclusive_must_be_boolean(self) -> None:
        with self.assertRaisesRegex(
            TypeError,
            "allow_inconclusive must be a Boolean",
        ):
            self.executor.cleanup((), allow_inconclusive=1)  # type: ignore[arg-type]

    def test_inconclusive_report_rejects_non_text_reasons(self) -> None:
        with self.assertRaisesRegex(
            TypeError,
            "inconclusive reasons must be text",
        ):
            CleanupReport((), inconclusive=(1,))  # type: ignore[arg-type]


class EndToEndCleanupTests(unittest.TestCase):
    class Engine(PodmanClient):
        def __init__(self, containers, networks, secrets):  # noqa: ANN001
            super().__init__(engine="podman", timeout=3, runner=self._unused)
            object.__setattr__(self, "containers", dict(containers))
            object.__setattr__(self, "networks", set(networks))
            object.__setattr__(self, "secrets", list(secrets))

        @staticmethod
        def _unused(*_args, **_kwargs):  # noqa: ANN002, ANN003
            raise AssertionError("direct runner should not be used")

        @staticmethod
        def _wanted(labels):  # noqa: ANN001
            from asf.podman import _normalise_labels

            wanted = {}
            for entry in _normalise_labels(labels):
                key, _, value = entry.partition("=")
                wanted[key] = value
            return wanted

        def container_ids(self, labels=(), **kwargs):  # noqa: ANN001, ANN003
            return self.all_container_ids(labels, **kwargs)

        def all_container_ids(self, labels=(), **_kwargs):  # noqa: ANN001
            wanted = self._wanted(labels)
            return tuple(
                name
                for name, present_labels in self.containers.items()
                if all(
                    present_labels.get(key) == value
                    for key, value in wanted.items()
                )
            )

        def exists(self, reference, kind=ObjectKind.CONTAINER):  # noqa: ANN001
            if kind is ObjectKind.NETWORK:
                return reference in self.networks
            if kind is ObjectKind.SECRET:
                return reference in self.secrets
            return reference in self.containers

        def secret_names(self):
            return tuple(self.secrets)

        def inspect_container(self, reference, *, timeout=None):  # noqa: ANN001
            if reference not in self.containers:
                from asf.podman import ObjectNotFoundError

                raise ObjectNotFoundError("no such container")
            return ContainerInspection(
                container_id=reference,
                name=reference,
                image="image",
                status="exited",
                running=False,
                health=None,
                labels=self.containers[reference],
            )

        def observe(self, argv, **_kwargs):  # noqa: ANN001
            args = tuple(str(value) for value in argv)
            action = _action(args)
            reference = args[-1]
            if action == "stop":
                return CommandResult(args, 0, "", "")
            if action == "rm":
                self.containers.pop(reference, None)
            elif action == "network-rm":
                self.networks.discard(reference)
            elif action == "secret-rm" and reference in self.secrets:
                self.secrets.remove(reference)
            return CommandResult(args, 0, "", "")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / ".devcontainer").mkdir()
        (self.root / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
        for runtime in ("claude", "hermes"):
            agent = self.root / "agents" / runtime
            agent.mkdir(parents=True)
            (agent / "runtime.yml").write_text(f"name: {runtime}\n")
        self.paths = RepoPaths.for_root(self.root)

    def test_killed_session_is_fully_removed_and_cleanup_is_idempotent(self) -> None:
        identity = self.paths.identity
        networks = identity.network_names("hermes")
        engine = self.Engine(
            containers={
                "runtime-id": {
                    "asf.session": identity.session_key("hermes"),
                    "asf.sandbox": str(identity.script_dir),
                },
                "proxy-id": {
                    "asf.sandbox": str(identity.script_dir),
                    "asf.role": SessionRole.PROXY.value,
                    "asf.agent": "hermes",
                },
            },
            networks={networks.internal, networks.egress},
            secrets=[f"{identity.broker_secret_prefix('hermes')}4242"],
        )
        lock = identity.session_lock("hermes")
        lock.mkdir()
        (lock / "pid").write_text("4194304\n")
        identity.broker_state("hermes").write_text("host\n")
        scanner = ResidueScanner(
            SessionDiscovery.from_paths(self.paths, podman=engine)
        )
        lock_manager = SessionLockManager(identity, process_alive=lambda _pid: False)
        executor = CleanupExecutor(
            engine,
            lock_manager,
            sleeper=lambda _seconds: None,
        )

        first = executor.cleanup(scanner.scan("hermes"))
        second = executor.cleanup(scanner.scan("hermes"))

        self.assertTrue(first.complete, first.summary())
        self.assertTrue(second.complete, second.summary())
        self.assertEqual(second.results, ())
        self.assertEqual(engine.containers, {})
        self.assertEqual(engine.networks, set())
        self.assertEqual(engine.secrets, [])
        self.assertFalse(lock.exists())
        self.assertFalse(identity.broker_state("hermes").exists())

    def test_cleanup_does_not_touch_another_runtime(self) -> None:
        identity = self.paths.identity
        claude_networks = identity.network_names("claude")
        secret = f"{identity.broker_secret_prefix('claude')}1"
        engine = self.Engine(
            containers={
                "claude-id": {
                    "asf.session": identity.session_key("claude"),
                    "asf.sandbox": str(identity.script_dir),
                },
            },
            networks={claude_networks.internal},
            secrets=[secret],
        )
        scanner = ResidueScanner(
            SessionDiscovery.from_paths(self.paths, podman=engine)
        )
        executor = CleanupExecutor(
            engine,
            SessionLockManager(identity),
            sleeper=lambda _seconds: None,
        )

        report = executor.cleanup(scanner.scan("hermes"))

        self.assertTrue(report.complete)
        self.assertIn("claude-id", engine.containers)
        self.assertEqual(engine.networks, {claude_networks.internal})
        self.assertEqual(engine.secrets, [secret])


def _restore_env(name: str, value: str | None) -> None:
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value


if __name__ == "__main__":
    unittest.main()
