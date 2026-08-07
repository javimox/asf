#!/usr/bin/env python3
"""Focused proxy and isolated runtime orchestration tests."""

from __future__ import annotations

import io
import tempfile
from contextlib import contextmanager
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
    _persist_verification_report,
    load_runtime_environment,
    run_runtime_command,
)
from asf.verification.engine import VerificationReport
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
    (root / ".devcontainer").mkdir()
    (root / "secrets").mkdir()
    (root / "sandbox.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    (root / "agents" / runtime / "runtime.yml").write_text(
        manifest_source.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return RepoPaths.for_root(root)


class VerificationReportPersistenceTests(unittest.TestCase):
    def test_report_is_persisted_without_temporary_residue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "session" / "verification-report.json"
            output = io.StringIO()

            _persist_verification_report(
                VerificationReport(()), destination, output
            )

            self.assertTrue(destination.exists())
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(
                list(destination.parent.glob(".verification-report.json.*")),
                [],
            )


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
                ROOT / "examples" / "routed-runtime.yml",
                "routed-scanner",
            )
            with mock.patch.object(RuntimeService, "open", return_value=23) as opened:
                result = run_runtime_command(("open", "routed-scanner"), paths)
            self.assertEqual(result, 23)
            opened.assert_called_once_with("routed-scanner")


    def test_routed_allocation_lock_covers_plan_persistence_and_network_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            paths = create_checkout(
                root,
                ROOT / "examples" / "routed-runtime.yml",
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

    def test_devcontainer_exec_is_a_fixed_vector_with_remote_environment(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(ROOT / "agents" / "claude" / "runtime.yml")
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=False,
        )
        service = RuntimeService(paths, PodmanClient(runner=RecordingRunner()))
        argv = service._devcontainer_exec_argv(
            plan,
            (("FIRST", "one"), ("SECOND", "two words")),
        )
        self.assertEqual(argv[0:2], ("devcontainer", "exec"))
        self.assertNotIn("sh", argv)
        self.assertIn("FIRST=one", argv)
        self.assertIn("SECOND=two words", argv)
        self.assertEqual(argv[-2:], ("--", "zsh"))

    def test_devcontainer_start_failure_keeps_the_open_contract(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(ROOT / "agents" / "claude" / "runtime.yml")
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=False,
        )
        service = RuntimeService(paths, PodmanClient(runner=RecordingRunner()))
        result = CommandResult(("devcontainer", "up"), 1, "", "")
        with mock.patch(
            "asf.runtime.run_streaming", side_effect=CommandFailedError(result)
        ):
            with self.assertRaisesRegex(
                RuntimeOpenError, "Container failed to start"
            ):
                service._start_devcontainer(plan, {})

    def test_devcontainer_start_redacts_environment_values(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        manifest = load_model(ROOT / "agents" / "claude" / "runtime.yml")
        plan = build_runtime_plan(
            manifest,
            paths=paths,
            owner_pid=4242,
            broker_globally_enabled=True,
        )
        service = RuntimeService(paths, PodmanClient(runner=RecordingRunner()))
        with mock.patch("asf.runtime.run_streaming") as streamed:
            service._start_devcontainer(plan, {"ASF_BROKER_TOKEN": "secret-token"})
        kwargs = streamed.call_args.kwargs
        self.assertEqual(kwargs["redact_values"], ("secret-token",))
        self.assertIs(kwargs["output"], service.output)
        self.assertIs(kwargs["error"], service.error)

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
            for secret in plan.secret_files:
                secret.source.write_text(
                    "ANTHROPIC_API_KEY=provider-secret\nSAFE_SETTING=enabled\n",
                    encoding="utf-8",
                )
                secret.source.chmod(0o600)

            class Discovery:
                def resolve_runtime(self, requested):
                    self.requested = requested
                    return "claude"

                def unique_match(self, runtime):
                    return object()

            command: list[tuple[str, ...]] = []

            def replace_process(argv):
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
            joined = " ".join(command[0])
            self.assertIn("SAFE_SETTING=enabled", joined)
            self.assertNotIn("provider-secret", joined)
            self.assertNotIn("ANTHROPIC_API_KEY=", joined)
            self.assertTrue(joined.endswith("-- zsh"))


if __name__ == "__main__":
    unittest.main()
