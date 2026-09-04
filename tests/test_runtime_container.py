#!/usr/bin/env python3
"""Security-critical direct Podman container argv tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from asf.config import AsfConfig
from asf.errors import ConfigurationError, ValidationError
from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.repositories import RepositoryEntry
from asf.runtime_container import (
    ContainerRequest,
    build_container_environment,
    build_container_exec_argv,
    build_container_run_argv,
)
from asf.runtime_plan import RoutedSubnetAllocation, build_runtime_plan

ROOT = Path(__file__).resolve().parents[1]


class RuntimeContainerTests(unittest.TestCase):
    def _request(
        self,
        runtime: str = "claude",
        *,
        broker: bool = False,
        repositories: tuple[RepositoryEntry, ...] = (),
    ) -> ContainerRequest:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(ROOT / "agents" / runtime / "runtime.yml")
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=broker,
        )
        config = AsfConfig.load(paths.config_file)
        return ContainerRequest(
            paths,
            plan,
            manifest,
            repositories=repositories,
            run_arguments=config.hardening_arguments(manifest),
        )

    def test_run_vector_contains_fixed_container_boundary(self) -> None:
        request = self._request()
        argv = build_container_run_argv(request, env_file=Path("/tmp/runtime.env"))
        self.assertEqual(argv[:3], ("podman", "run", "--detach"))
        self.assertIn("--userns=keep-id:uid=1000,gid=1000", argv)
        self.assertIn("--user=1000:1000", argv)
        self.assertIn("--workdir=/workspace", argv)
        self.assertIn("--http-proxy=false", argv)
        self.assertIn("--init", argv)
        self.assertIn("--env-file", argv)
        self.assertEqual(argv[-2:], ("sleep", "infinity"))

    def test_run_vector_passes_every_hardening_argument(self) -> None:
        request = self._request()
        argv = build_container_run_argv(request, env_file=Path("/tmp/runtime.env"))
        for argument in request.run_arguments:
            self.assertIn(argument, argv)

    def test_run_vector_uses_only_planned_network_attachments(self) -> None:
        request = self._request()
        argv = build_container_run_argv(request, env_file=Path("/tmp/runtime.env"))
        observed = tuple(item for item in argv if item.startswith("--network="))
        expected = tuple(
            "--network=" + attachment.network
            + ("" if attachment.address is None else f":ip={attachment.address}")
            for attachment in request.plan.runtime_container.attachments
        )
        self.assertEqual(observed, expected)

    def test_run_vector_mounts_framework_readonly_and_respects_repo_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rw = root / "rw-repo"
            ro = root / "ro-repo"
            rw.mkdir()
            ro.mkdir()
            request = self._request(
                repositories=(
                    RepositoryEntry(str(rw), "rw"),
                    RepositoryEntry(str(ro), "ro"),
                )
            )
            argv = build_container_run_argv(
                request, env_file=Path("/tmp/runtime.env")
            )
        mounts = tuple(argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--mount")
        self.assertIn(
            f"type=bind,source={ROOT},target=/workspace/sandbox,readonly",
            mounts,
        )
        rw_mount = next(item for item in mounts if "target=/workspace/repos/rw-repo" in item)
        ro_mount = next(item for item in mounts if "target=/workspace/repos/ro-repo" in item)
        self.assertNotIn("readonly", rw_mount)
        self.assertIn("readonly", ro_mount)

    def test_run_vector_references_environment_file_without_embedding_values(self) -> None:
        request = self._request()
        env_file = Path("/tmp/asf secret.env")
        argv = build_container_run_argv(request, env_file=env_file)
        index = argv.index("--env-file")
        self.assertEqual(argv[index + 1], str(env_file))
        self.assertNotIn("=secret", " ".join(argv))

    def test_exec_validates_environment_names(self) -> None:
        request = self._request()
        with self.assertRaises(ValidationError):
            build_container_exec_argv(
                request, environment_names=("GOOD", "BAD-NAME")
            )

    def test_exec_deduplicates_environment_names_without_values(self) -> None:
        request = self._request()
        argv = build_container_exec_argv(
            request,
            environment_names=("SECRET", "SECRET", "OTHER"),
        )
        pairs = tuple(zip(argv, argv[1:]))
        self.assertEqual(pairs.count(("--env", "SECRET")), 1)
        self.assertEqual(pairs.count(("--env", "OTHER")), 1)
        self.assertNotIn("SECRET=value", argv)

    def test_microvm_manifest_cannot_construct_container_request(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=False,
            routed_subnets=RoutedSubnetAllocation.parse(
                ("10.90.0.0/24", "10.91.0.0/24", "10.92.0.0/24")
            ),
        )
        config = AsfConfig.load(paths.config_file)
        with self.assertRaisesRegex(ConfigurationError, "runtime.isolation: container"):
            ContainerRequest(
                paths,
                plan,
                manifest,
                run_arguments=config.hardening_arguments(manifest),
            )

    def test_broker_session_token_persistence_is_explicit_and_session_scoped(self) -> None:
        request = self._request(broker=True)
        environment = build_container_environment(
            request,
            broker_token="session-token",
        )
        self.assertEqual(environment["ANTHROPIC_AUTH_TOKEN"], "session-token")
        self.assertEqual(environment["ANTHROPIC_API_KEY"], "")


if __name__ == "__main__":
    unittest.main()
