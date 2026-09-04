#!/usr/bin/env python3
"""Focused proxy and isolated runtime orchestration tests."""

from __future__ import annotations

import io
import tempfile
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from asf.config import AsfConfig
from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.podman import PodmanClient
from asf.process import CommandFailedError, CommandResult
from asf.runtime import (
    RuntimeOpenError,
    RuntimeService,
    load_runtime_environment,
    run_runtime_command,
)
from asf.runtime_container import (
    ContainerRequest,
    build_container_exec_argv,
)
from asf.runtime_plan import (
    RoutedSubnetAllocation,
    SecretFilePlan,
    build_runtime_plan,
    load_runtime_plan,
    runtime_plan_path,
    write_runtime_plan,
)

ROOT = Path(__file__).resolve().parents[1]


class RecordingRunner:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.calls: list[tuple[str, ...]] = []
        self.inputs: list[str | None] = []

    def __call__(self, argv, **kwargs) -> CommandResult:
        command = tuple(str(item) for item in argv)
        self.calls.append(command)
        self.inputs.append(kwargs.get("input_text"))
        return CommandResult(command, self.returncode, "", "")


def create_checkout(root: Path, manifest_source: Path, runtime: str) -> RepoPaths:
    (root / "agents" / runtime).mkdir(parents=True)
    (root / "containers").mkdir()
    (root / ".asf").mkdir()
    (root / "secrets").mkdir()
    (root / "sandbox.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (root / "asf.conf").write_text((ROOT / "asf.conf").read_text(encoding="utf-8"), encoding="utf-8")
    (root / "agents" / runtime / "runtime.yml").write_text(
        manifest_source.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return RepoPaths.for_root(root)


class RuntimeEnvironmentTests(unittest.TestCase):
    def plan_with_files(self, files: tuple[Path, ...]):
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(ROOT / "agents" / "claude" / "runtime.yml")
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=True,
        )
        return replace(
            plan,
            secret_files=tuple(
                SecretFilePlan(path.name, path) for path in files
            ),
        )

    def test_later_secret_file_wins_and_provider_key_is_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = root / "common.env"
            runtime = root / "claude.env"
            common.write_text(
                "ANTHROPIC_API_KEY=provider\nSHARED=common\nFIRST=one\n",
                encoding="utf-8",
            )
            runtime.write_text("SHARED=runtime\nSECOND=two\n", encoding="utf-8")
            common.chmod(0o600)
            runtime.chmod(0o600)
            output = io.StringIO()
            error = io.StringIO()
            values = load_runtime_environment(
                self.plan_with_files((common, runtime)),
                excluded_key="ANTHROPIC_API_KEY",
                output=output,
                error=error,
            )
            self.assertEqual(
                dict(values),
                {"SHARED": "runtime", "SECOND": "two", "FIRST": "one"},
            )
            self.assertNotIn("provider", repr(values))
            self.assertIn("injected 3 key(s)", output.getvalue())
            self.assertIn("broker is active", error.getvalue())

    def test_secret_symlinks_and_invalid_names_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "real.env"
            target.write_text("SAFE=value\n", encoding="utf-8")
            target.chmod(0o600)
            link = root / "linked.env"
            link.symlink_to(target)
            with self.assertRaisesRegex(Exception, "must not be a symlink"):
                load_runtime_environment(self.plan_with_files((link,)))
            target.write_text("INVALID-NAME=value\n", encoding="utf-8")
            with self.assertRaisesRegex(Exception, "Invalid environment variable"):
                load_runtime_environment(self.plan_with_files((target,)))


class RuntimeCommandTests(unittest.TestCase):
    def test_routed_open_uses_the_python_runtime_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            paths = create_checkout(
                root,
                ROOT / "agents" / "routed-scanner" / "example-runtime-ci-tested.yml",
                "routed-scanner",
            )
            with mock.patch.object(RuntimeService, "open", return_value=23) as opened:
                result = run_runtime_command(("open", "routed-scanner"), paths)
            self.assertEqual(result, 23)
            opened.assert_called_once_with("routed-scanner")

    def test_run_passes_one_shot_command_as_an_argv_vector(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            paths = create_checkout(
                root, ROOT / "agents" / "claude" / "runtime.yml", "claude"
            )
            command = ("python3", "-c", "print('two words')")
            with mock.patch.object(RuntimeService, "open", return_value=17) as opened:
                result = run_runtime_command(("run", "claude", "--", *command), paths)
            self.assertEqual(result, 17)
            opened.assert_called_once_with("claude", command=command)


    def test_routed_allocation_lock_covers_plan_persistence_and_network_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            paths = create_checkout(
                root,
                ROOT / "agents" / "routed-scanner" / "example-runtime-ci-tested.yml",
                "routed-scanner",
            )
            manifest = load_model(paths.identity.runtime_manifest("routed-scanner"))
            allocation = RoutedSubnetAllocation.parse(
                ("10.90.0.0/24", "10.91.0.0/24", "10.92.0.0/24")
            )

            class Allocator:
                active = False

                @contextmanager
                def reserve(self, **_kwargs):
                    self.active = True
                    try:
                        yield allocation
                    finally:
                        self.active = False

            allocator = Allocator()

            class Networks:
                def create(self, plan, *, output):
                    self.plan = plan
                    self.output = output
                    if not allocator.active:
                        raise AssertionError("allocation lock was released too early")
                    persisted = load_runtime_plan(
                        runtime_plan_path(paths, "routed-scanner")
                    )
                    self.persisted = persisted
                    self.assertion = persisted == plan

            networks = Networks()
            service = RuntimeService(
                paths,
                PodmanClient(runner=RecordingRunner()),
                io.StringIO(),
                io.StringIO(),
                network_service=networks,
                routed_allocator=allocator,
            )
            plan = service._build_and_create_plan(
                manifest,
                AsfConfig(
                    paths.config_file,
                    {
                        "ASF_SUBNET_POOL": "10.90.0.0/16",
                        "ASF_SUBNET_PREFIX": "24",
                    },
                ),
                4242,
                False,
            )
            self.assertFalse(allocator.active)
            self.assertTrue(networks.assertion)
            self.assertIs(networks.plan, plan)
            by_role = {item.role.value: item for item in plan.networks}
            self.assertTrue(by_role["internal"].no_default_route)
            self.assertTrue(by_role["scan"].no_default_route)
            self.assertFalse(by_role["routed-egress"].no_default_route)

    def _container_request(self, runtime: str, *, broker: bool = False) -> ContainerRequest:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(ROOT / "agents" / runtime / "runtime.yml")
        plan = build_runtime_plan(
            manifest, paths=paths, owner_pid=4242, broker_globally_enabled=broker
        )
        config = AsfConfig.load(paths.config_file)
        return ContainerRequest(
            paths, plan, manifest, run_arguments=config.hardening_arguments(manifest)
        )

    def test_container_exec_is_a_fixed_podman_vector(self) -> None:
        request = self._container_request("claude")
        argv = build_container_exec_argv(request, interactive=True)
        self.assertEqual(argv[:4], ("podman", "exec", "--interactive", "--tty"))
        self.assertEqual(argv[-2:], (request.plan.runtime_container.name, "zsh"))
        self.assertNotIn("sh", argv)

    def test_container_exec_preserves_one_shot_command_boundaries(self) -> None:
        request = self._container_request("codex")
        command = ("python3", "-c", "print('two words')")
        argv = build_container_exec_argv(request, command=command)
        self.assertEqual(argv[-4:], (request.plan.runtime_container.name, *command))
        self.assertNotIn("sh", argv[-4:])

    def test_container_exec_inherits_named_secrets_without_values_in_argv(self) -> None:
        request = self._container_request("claude")
        argv = build_container_exec_argv(
            request,
            environment_names=("ANTHROPIC_API_KEY", "EXTRA_SECRET"),
        )
        self.assertIn(("--env", "ANTHROPIC_API_KEY"), tuple(zip(argv, argv[1:])))
        self.assertIn(("--env", "EXTRA_SECRET"), tuple(zip(argv, argv[1:])))
        self.assertNotIn("secret-value", argv)

    def test_prepare_container_keeps_runtime_secrets_at_exec_boundary(self) -> None:
        request = self._container_request("claude")
        service = RuntimeService(request.paths, PodmanClient(runner=RecordingRunner()))
        config = AsfConfig.load(request.paths.config_file)
        captured: dict[str, str] = {}

        def start_container(_request, environment):
            captured.update(environment)

        runtime_environment = {
            "ANTHROPIC_API_KEY": "provider-secret",
            "EXTRA_SECRET": "two words",
        }
        support = SimpleNamespace(broker=None, token=None)
        with mock.patch.object(
            RuntimeService, "_build_runtime_image", return_value=None
        ), mock.patch.object(
            RuntimeService, "_load_repositories", return_value=()
        ), mock.patch.object(
            RuntimeService, "_runtime_environment", return_value=runtime_environment
        ), mock.patch.object(
            RuntimeService, "_start_container", side_effect=start_container
        ):
            argv, process_environment = service._prepare_container(
                request.manifest,
                config,
                request.plan,
                support,
            )

        self.assertNotIn("ANTHROPIC_API_KEY", captured)
        self.assertNotIn("EXTRA_SECRET", captured)
        self.assertEqual(process_environment, runtime_environment)
        self.assertNotIn("provider-secret", argv)
        self.assertNotIn("two words", argv)
        self.assertIn(("--env", "ANTHROPIC_API_KEY"), tuple(zip(argv, argv[1:])))
        self.assertIn(("--env", "EXTRA_SECRET"), tuple(zip(argv, argv[1:])))

    def test_container_start_failure_keeps_the_open_contract(self) -> None:
        request = self._container_request("claude")
        service = RuntimeService(request.paths, PodmanClient(runner=RecordingRunner()))
        result = CommandResult(("podman", "run"), 1, "", "")
        with mock.patch(
            "asf.runtime.run_streaming", side_effect=CommandFailedError(result)
        ):
            with self.assertRaisesRegex(RuntimeOpenError, "Container failed to start"):
                service._start_container(request, {"SAFE": "value"})

    def test_container_start_keeps_environment_values_out_of_argv(self) -> None:
        request = self._container_request("claude", broker=True)
        service = RuntimeService(request.paths, PodmanClient(runner=RecordingRunner()))
        calls: list[tuple[tuple[str, ...], str | None]] = []

        def streamed(argv, **_kwargs):
            vector = tuple(argv)
            env_text = None
            if "--env-file" in vector:
                env_path = Path(vector[vector.index("--env-file") + 1])
                env_text = env_path.read_text(encoding="utf-8")
            calls.append((vector, env_text))
            return CommandResult(vector, 0, "", "")

        with mock.patch("asf.runtime.run_streaming", side_effect=streamed):
            service._start_container(
                request, {"ASF_BROKER_TOKEN": "secret-token", "SAFE": "two words"}
            )
        self.assertEqual(len(calls), 2)
        run_argv, env_text = calls[0]
        self.assertEqual(run_argv[:2], ("podman", "run"))
        self.assertNotIn("secret-token", " ".join(run_argv))
        self.assertNotIn("two words", " ".join(run_argv))
        self.assertIn("ASF_BROKER_TOKEN=secret-token", env_text or "")
        env_path = Path(run_argv[run_argv.index("--env-file") + 1])
        self.assertFalse(env_path.exists())
        bootstrap = calls[1][0]
        self.assertEqual(
            bootstrap[-3:],
            (request.plan.runtime_container.name, "bash", "/workspace/sandbox/containers/on-start.sh"),
        )

    def test_shell_consumes_the_persisted_plan_and_omits_provider_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            paths = create_checkout(
                root,
                ROOT / "agents" / "claude" / "runtime.yml",
                "claude",
            )
            manifest = load_model(paths.identity.runtime_manifest("claude"))
            plan = build_runtime_plan(
                manifest,
                paths=paths,
                owner_pid=4242,
                broker_globally_enabled=True,
            )
            write_runtime_plan(plan, runtime_plan_path(paths, "claude"))
            class Discovery:
                def resolve_runtime(self, requested):
                    self.requested = requested
                    return "claude"

                def unique_match(self, runtime):
                    return object()

            command: list[tuple[str, ...]] = []

            def replace_process(argv, **_kwargs):
                command.append(tuple(argv))
                raise SystemExit(0)

            service = RuntimeService(
                paths,
                PodmanClient(runner=RecordingRunner()),
                io.StringIO(),
                io.StringIO(),
            )
            with mock.patch.object(
                RuntimeService, "_require_tools", return_value=None
            ), mock.patch(
                "asf.runtime.SessionDiscovery.from_paths",
                return_value=Discovery(),
            ):
                with self.assertRaises(SystemExit):
                    service.shell("claude", replace_process=replace_process)
            self.assertEqual(len(command), 1)
            self.assertEqual(
                command[0],
                (
                    "podman", "exec", "--interactive", "--tty",
                    plan.runtime_container.name, "zsh",
                ),
            )

    def test_direct_shell_loads_provider_key_only_into_podman_exec_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            paths = create_checkout(
                root,
                ROOT / "agents" / "claude" / "runtime.yml",
                "claude",
            )
            manifest = load_model(paths.identity.runtime_manifest("claude"))
            plan = build_runtime_plan(
                manifest,
                paths=paths,
                owner_pid=4242,
                broker_globally_enabled=False,
            )
            secret = plan.secret_files[-1].source
            secret.write_text("ANTHROPIC_API_KEY=provider-secret\n", encoding="utf-8")
            secret.chmod(0o600)
            write_runtime_plan(plan, runtime_plan_path(paths, "claude"))

            class Discovery:
                def resolve_runtime(self, requested):
                    return requested or "claude"

                def unique_match(self, _runtime):
                    return object()

            observed: dict[str, object] = {}

            def replace_process(argv, **kwargs):
                observed["argv"] = tuple(argv)
                observed["env"] = dict(kwargs.get("env", {}))
                raise SystemExit(0)

            service = RuntimeService(
                paths,
                PodmanClient(runner=RecordingRunner()),
                io.StringIO(),
                io.StringIO(),
            )
            with mock.patch.object(
                RuntimeService, "_require_tools", return_value=None
            ), mock.patch(
                "asf.runtime.SessionDiscovery.from_paths",
                return_value=Discovery(),
            ):
                with self.assertRaises(SystemExit):
                    service.shell("claude", replace_process=replace_process)

            argv = observed["argv"]
            self.assertIsInstance(argv, tuple)
            self.assertIn(("--env", "ANTHROPIC_API_KEY"), tuple(zip(argv, argv[1:])))
            self.assertNotIn("provider-secret", argv)
            self.assertEqual(
                observed["env"], {"ANTHROPIC_API_KEY": "provider-secret"}
            )


if __name__ == "__main__":
    unittest.main()
