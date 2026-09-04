#!/usr/bin/env python3
"""Unit tests for the opt-in krun runtime backend."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asf.config import AsfConfig  # noqa: E402
from asf.krun import (  # noqa: E402
    KrunRequest,
    build_krun_build_argv,
    build_krun_environment,
    build_krun_run_argv,
    krun_runtime_name,
    require_krun_host,
    validate_krun_beta,
)
from asf.manifest import ManifestError, load_model, parse  # noqa: E402
from asf.paths import RepoPaths  # noqa: E402
from asf.podman import PodmanClient  # noqa: E402
from asf.process import CommandResult  # noqa: E402
from asf.runtime import RuntimeService  # noqa: E402
from asf.runtime_plan import (  # noqa: E402
    RoutedSubnetAllocation,
    RuntimePlanError,
    build_runtime_plan,
    validate_runtime_plan_context,
)
from asf.session import SessionRole  # noqa: E402


class KrunManifestTests(unittest.TestCase):
    def test_isolation_defaults_to_container_and_accepts_microvm(self) -> None:
        self.assertEqual(parse({"name": "demo"}).runtime.isolation, "container")
        model = parse({"name": "demo", "runtime": {"isolation": "microvm"}})
        self.assertEqual(model.runtime.isolation, "microvm")

    def test_unknown_isolation_is_rejected(self) -> None:
        for value in ("vm", "krun"):
            with self.subTest(value=value), self.assertRaises(ManifestError):
                parse({"name": "demo", "runtime": {"isolation": value}})


class KrunBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.paths = RepoPaths.for_root(ROOT)
        base = load_model(ROOT / "agents" / "claude" / "runtime.yml")
        self.manifest = replace(
            base,
            runtime=replace(base.runtime, isolation="microvm"),
        )
        self.plan = build_runtime_plan(
            self.manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=True,
        )
        self.request = KrunRequest(
            self.paths,
            self.plan,
            self.manifest,
            run_arguments=(
                "--mount=type=tmpfs,target=/workspace/sandbox/secrets,ro=true,notmpcopyup",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--ulimit=nofile=4096:65536",
                "--ulimit=core=0:0",
            ),
            build_arguments=("CLAUDE_CODE_VERSION=9.9.9",),
        )

    def test_routed_microvm_uses_local_tap_runtime_unless_overridden(self) -> None:
        routed = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        expected = ROOT / "tools" / "krun-runtime" / "bin" / "crun"

        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(krun_runtime_name(self.paths, routed), str(expected))

        with mock.patch.dict(
            "os.environ", {"CRUN_TAP_RUNTIME": "/tmp/custom-crun"}, clear=True
        ):
            self.assertEqual(
                krun_runtime_name(self.paths, routed), "/tmp/custom-crun"
            )

        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(krun_runtime_name(self.paths, self.manifest), "krun")

    def test_routed_host_check_fails_closed_on_stale_local_runtime(self) -> None:
        routed = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
            (root / "agents").mkdir()
            (root / "containers").mkdir()
            (root / ".asf").mkdir()
            runtime_dir = root / "tools" / "krun-runtime"
            install = runtime_dir / "bin"
            install.mkdir(parents=True)
            (runtime_dir / "VERSION").write_text("1.29.1\n")
            (runtime_dir / "COMMIT").write_text("a" * 40 + "\n")
            crun = install / "crun"
            crun.write_text("#!/bin/sh\n")
            crun.chmod(0o755)
            paths = replace(self.paths, root=root)

            with mock.patch.dict("os.environ", {}, clear=True):
                with self.assertRaisesRegex(Exception, "provenance"):
                    require_krun_host(paths, routed)

                (install / "VERSION").write_text("1.28\n")
                (install / "COMMIT").write_text("b" * 40 + "\n")
                with self.assertRaisesRegex(Exception, "does not match"):
                    require_krun_host(paths, routed)

            # The explicit development override deliberately skips pin checks.
            (install / "VERSION").unlink()
            (install / "COMMIT").unlink()
            with mock.patch.dict(
                "os.environ", {"CRUN_TAP_RUNTIME": os.fspath(crun)}, clear=True
            ):
                try:
                    require_krun_host(paths, routed)
                except Exception as exc:
                    self.assertNotIn("provenance", str(exc))
                    self.assertNotIn("does not match", str(exc))

    def test_runtime_plan_persists_isolation_and_rejects_backend_drift(self) -> None:
        self.assertEqual(self.plan.runtime_isolation, "microvm")
        self.assertEqual(self.plan.to_dict()["runtime_isolation"], "microvm")
        changed = replace(
            self.manifest,
            runtime=replace(self.manifest.runtime, isolation="container"),
        )
        with self.assertRaisesRegex(RuntimePlanError, "does not match"):
            validate_runtime_plan_context(self.plan, changed, self.paths)

    def test_beta_allows_routed_tap_protocols_and_net_raw(self) -> None:
        routed = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        routed = replace(
            routed,
            runtime=replace(routed.runtime, isolation="microvm"),
            capabilities=frozenset({"net_raw"}),
        )
        validate_krun_beta(routed)

        udp_rule = replace(routed.network.routed_rules[0], protocol="udp")
        routed_udp = replace(
            routed,
            network=replace(routed.network, routed_rules=(udp_rule,)),
        )
        validate_krun_beta(routed_udp)

        validate_krun_beta(routed, broker_enabled=True)

        capable = replace(self.manifest, capabilities=frozenset({"net_raw"}))
        with self.assertRaisesRegex(Exception, "routed TAP"):
            validate_krun_beta(capable)

        with self.assertRaisesRegex(Exception, "SSH-agent"):
            validate_krun_beta(self.manifest, ssh_agent=True)

    def test_request_requires_krun_hardening_invariants(self) -> None:
        with self.assertRaisesRegex(Exception, "cap-drop"):
            replace(
                self.request,
                run_arguments=(
                    "--mount=type=tmpfs,target=/workspace/sandbox/secrets,ro=true",
                    "--ulimit=core=0:0",
                ),
            )
        with self.assertRaisesRegex(Exception, "core dumps disabled"):
            replace(
                self.request,
                run_arguments=(
                    "--mount=type=tmpfs,target=/workspace/sandbox/secrets,ro=true",
                    "--cap-drop=ALL",
                ),
            )
        with self.assertRaisesRegex(Exception, "secrets tmpfs mask"):
            replace(
                self.request,
                run_arguments=(
                    "--cap-drop=ALL",
                    "--ulimit=core=0:0",
                ),
            )
        with self.assertRaisesRegex(Exception, "secrets tmpfs mask"):
            replace(
                self.request,
                run_arguments=(
                    "--cap-drop=ALL",
                    "--ulimit=core=0:0",
                    "--mount=type=tmpfs,target=/workspace/sandbox/secretsX,ro=true",
                ),
            )

    def test_host_process_environment_names_are_rejected(self) -> None:
        # krun exports session values through the host Podman/VMM process
        # environment; names that reconfigure that host process must fail
        # closed whether they arrive from a manifest or a secret env file.
        for name in (
            "LD_PRELOAD",
            "LD_DEBUG",
            "PATH",
            "CONTAINERS_CONF",
            "PODMAN_CONNECTIONS_CONF",
            "STORAGE_DRIVER",
            "XDG_RUNTIME_DIR",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(Exception, "reserved"):
                build_krun_environment(
                    self.request,
                    broker_token="token",
                    runtime_environment=((name, "/tmp/injected"),),
                )

        # Keep the same guard at the final argv sink so a future caller cannot
        # bypass build_krun_environment() by supplying a mapping directly.
        with self.assertRaisesRegex(Exception, "reserved"):
            build_krun_run_argv(
                self.request,
                {"PODMAN_CONNECTIONS_CONF": "/tmp/injected"},
            )

    def test_build_argv_uses_the_thin_agent_containerfile(self) -> None:
        argv = build_krun_build_argv(self.request)
        self.assertEqual(argv[:2], ("podman", "build"))
        self.assertIn(str(ROOT / "containers" / "claude" / "Containerfile"), argv)
        self.assertIn("ASF_BASE_IMAGE=localhost/" + self.paths.identity.prefix.lower() + "-base:runtime", argv)
        self.assertIn("CLAUDE_CODE_VERSION=9.9.9", argv)
        self.assertEqual(argv[-1], str(ROOT))

    def test_krun_uses_the_shared_runtime_image_builder(self) -> None:
        service = RuntimeService(
            self.paths, PodmanClient(engine="podman"), io.StringIO(), io.StringIO(), verifier=mock.Mock()
        )
        config = mock.Mock(spec=AsfConfig)
        with (
            mock.patch("asf.runtime.AsfConfig.load", return_value=config),
            mock.patch.object(RuntimeService, "_build_runtime_image") as build,
        ):
            service._ensure_krun_image(self.request)
        build.assert_called_once_with(self.request.manifest, config)

    def test_environment_keeps_broker_and_runtime_secrets_out_of_argv(self) -> None:
        environment = build_krun_environment(
            self.request,
            broker_token="broker-secret",
            runtime_environment=(("SAFE_SETTING", "runtime-secret"),),
        )
        self.assertEqual(environment["ASF_ISOLATION"], "microvm")
        self.assertEqual(environment["ANTHROPIC_AUTH_TOKEN"], "broker-secret")
        self.assertEqual(environment["ANTHROPIC_API_KEY"], "")
        self.assertEqual(environment["SAFE_SETTING"], "runtime-secret")
        self.assertEqual(environment["HTTPS_PROXY"], "http://asf-proxy:3128")
        self.assertIn("asf-broker", environment["NO_PROXY"])

        argv = build_krun_run_argv(self.request, environment)
        joined = " ".join(argv)
        self.assertNotIn("broker-secret", joined)
        self.assertNotIn("runtime-secret", joined)
        self.assertIn("--env ANTHROPIC_AUTH_TOKEN", joined)
        self.assertIn("--env SAFE_SETTING", joined)

    def test_framework_identity_cannot_be_overridden(self) -> None:
        environment = build_krun_environment(
            self.request,
            broker_token="token",
            runtime_environment=(
                ("ASF_AGENT", "wrong"),
                ("ASF_ISOLATION", "container"),
            ),
        )
        self.assertEqual(environment["ASF_AGENT"], self.plan.runtime)
        self.assertEqual(environment["ASF_ISOLATION"], "microvm")

    def test_service_run_has_no_tty_and_only_one_user_mapping(self) -> None:
        service_manifest = replace(
            self.manifest,
            runtime=replace(
                self.manifest.runtime,
                mode="service",
                command=("python3", "serve.py"),
            ),
        )
        service_plan = build_runtime_plan(
            service_manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=True,
        )
        request = replace(self.request, plan=service_plan, manifest=service_manifest)
        environment = build_krun_environment(request, broker_token="token")
        argv = build_krun_run_argv(request, environment)
        self.assertNotIn("--interactive", argv)
        self.assertNotIn("--tty", argv)
        self.assertEqual(argv.count("--user=1000:1000"), 1)
        self.assertEqual(
            argv[-4:],
            (
                "bash",
                "/workspace/sandbox/containers/on-start.sh",
                "python3",
                "serve.py",
            ),
        )

    def test_one_shot_run_uses_initial_guest_process_without_tty(self) -> None:
        environment = build_krun_environment(self.request, broker_token="token")
        command = ("python3", "-c", "print('two words')")

        argv = build_krun_run_argv(self.request, environment, command=command)

        self.assertNotIn("--interactive", argv)
        self.assertNotIn("--tty", argv)
        self.assertNotIn("--detach-keys=ctrl-p,ctrl-q", argv)
        self.assertEqual(
            argv[-5:],
            (
                "bash",
                "/workspace/sandbox/containers/on-start.sh",
                *command,
            ),
        )

    def test_routed_krun_broker_uses_fixed_ip_and_explicit_guest_route(self) -> None:
        hermes = load_model(ROOT / "agents" / "hermes" / "runtime.yml")
        routed = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        manifest = replace(
            hermes,
            runtime=replace(hermes.runtime, isolation="microvm"),
            network=routed.network,
            capabilities=frozenset({"net_raw"}),
        )
        allocation = RoutedSubnetAllocation.parse(
            ("10.76.40.0/24", "10.77.40.0/24", "10.79.40.0/24")
        )
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=True,
            routed_subnets=allocation,
        )
        request = replace(self.request, plan=plan, manifest=manifest)
        environment = build_krun_environment(
            request, broker_token="a" * 64,
        )
        self.assertEqual(
            environment["OPENAI_BASE_URL"],
            "http://10.77.40.3:4000/v1",
        )
        self.assertIn("10.77.40.3/32", environment["ASF_KRUN_TAP_ROUTES"])
        self.assertNotIn("asf-broker", environment["OPENAI_BASE_URL"])

    def test_routed_krun_uses_gateway_namespace_and_tap(self) -> None:
        routed = load_model(ROOT / "agents" / "routed-scanner" / "runtime.yml")
        routed = replace(
            routed,
            runtime=replace(routed.runtime, isolation="microvm"),
            capabilities=frozenset({"net_raw"}),
        )
        allocation = RoutedSubnetAllocation.parse(
            ("10.76.40.0/24", "10.77.40.0/24", "10.79.40.0/24")
        )
        plan = build_runtime_plan(
            routed,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=False,
            routed_subnets=allocation,
        )
        request = replace(
            self.request,
            plan=plan,
            manifest=routed,
            run_arguments=self.request.run_arguments
            + (
                "--cap-add=NET_RAW",
                "--sysctl=net.ipv4.ip_forward=0",
                "--sysctl=net.ipv6.conf.all.forwarding=0",
            ),
        )
        environment = build_krun_environment(request)
        argv = build_krun_run_argv(request, environment)

        attachments = [item for item in argv if item.startswith("--network=")]
        gateway = plan.container(SessionRole.ROUTED_GATEWAY)
        self.assertIsNotNone(gateway)
        assert gateway is not None
        self.assertEqual(attachments, [f"--network=container:{gateway.name}"])
        self.assertIn("krun.tap_name=tap0", argv)
        self.assertIn("/dev/net/tun", argv)
        self.assertNotIn("--cap-add=NET_RAW", argv)
        self.assertNotIn("--sysctl=net.ipv4.ip_forward=0", argv)
        self.assertNotIn("--sysctl=net.ipv6.conf.all.forwarding=0", argv)
        self.assertIn("ASF_KRUN_TAP_ADDRESS", environment)
        self.assertIn("ASF_KRUN_TAP_GATEWAY", environment)
        self.assertIn("192.0.2.10/32", environment["ASF_KRUN_TAP_ROUTES"])
        self.assertEqual(environment["ASF_KRUN_CAPABILITIES"], "net_raw")

    def test_run_argv_is_foreground_krun_with_uid_mapping_and_startup_checks(self) -> None:
        environment = build_krun_environment(
            self.request,
            broker_token="token",
        )
        argv = build_krun_run_argv(self.request, environment)
        joined = " ".join(argv)
        self.assertEqual(argv[:3], ("podman", "run", "--runtime=krun"))
        self.assertIn("--interactive", argv)
        self.assertIn("--tty", argv)
        self.assertIn("--detach-keys=ctrl-p,ctrl-q", argv)
        self.assertIn("--userns=keep-id:uid=1000,gid=1000", argv)
        self.assertIn("--user=1000:1000", argv)
        self.assertIn("--http-proxy=false", argv)
        self.assertIn(f"--network={self.plan.runtime_container.attachments[0].network}", argv)
        self.assertIn("target=/workspace/sandbox,readonly", joined)
        self.assertIn("target=/workspace/sandbox/secrets", joined)
        self.assertNotIn("--ulimit=nofile=4096:65536", argv)
        self.assertIn("--ulimit=core=0:0", argv)
        self.assertEqual(
            argv[-3:],
            ("bash", "/workspace/sandbox/containers/on-start.sh", "zsh"),
        )
        self.assertTrue(joined.endswith("bash /workspace/sandbox/containers/on-start.sh zsh"))

    def test_routed_microvm_bootstrap_rejects_default_routes(self) -> None:
        source = (ROOT / "containers" / "on-start.sh").read_text(encoding="utf-8")
        self.assertIn("ip -4 route show default | grep -q .", source)
        self.assertIn("ip -6 route show default | grep -q .", source)
        self.assertIn("unexpected IPv4 default route", source)
        self.assertIn("unexpected IPv6 default route", source)




class KrunLifecycleTests(unittest.TestCase):
    def test_open_selects_microvm_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "asf"
            (root / "agents" / "krun-test").mkdir(parents=True)
            (root / "containers").mkdir()
            (root / ".asf").mkdir()
            (root / "sandbox.sh").write_text("#!/bin/sh\n")
            (root / "asf.conf").write_text("BROKER_ENABLED=false\n")
            (root / "agents" / "krun-test" / "runtime.yml").write_text(
                "name: krun-test\n"
                "runtime:\n"
                "  mode: service\n"
                "  isolation: microvm\n"
                "  command: [echo, ok]\n"
                "network:\n"
                "  mode: isolated\n"
                "llm:\n"
                "  broker: false\n"
            )
            paths = RepoPaths.for_root(root)
            manifest = load_model(paths.identity.runtime_manifest("krun-test"))

            config = mock.Mock(spec=AsfConfig)
            config.broker_enabled = False
            config.hardening_arguments.return_value = (
                "--mount=type=tmpfs,target=/workspace/sandbox/secrets,ro=true,notmpcopyup",
                "--cap-drop=ALL",
            )
            config.build_arguments.return_value = ()
            plan = SimpleNamespace(
                runtime="krun-test",
                runtime_mode="service",
                runtime_isolation="microvm",
                network_mode="isolated",
                command=("echo", "ok"),
                broker_enabled=False,
            )
            lock_manager = mock.Mock()
            lock_manager.inspect.return_value = None
            stop_service = mock.Mock()
            stop_service.discovery.inspect.return_value = None
            stop_service.discovery.lock_manager.return_value = lock_manager
            stop_service.cleanup.stop_timeout = 2.0
            service = RuntimeService(
                paths,
                PodmanClient(engine="podman"),
                io.StringIO(),
                io.StringIO(),
                verifier=mock.Mock(),
            )
            krun_request = object()
            session_environment = {"ASF_ISOLATION": "microvm"}
            child = ("podman", "run", "--runtime=krun", "image")

            with (
                mock.patch("asf.runtime.load_model", return_value=manifest),
                mock.patch("asf.runtime.AsfConfig.load", return_value=config),
                mock.patch.object(RuntimeService, "_require_tools"),
                mock.patch(
                    "asf.runtime.stop_service_from_environment",
                    return_value=stop_service,
                ),
                mock.patch.object(RuntimeService, "_clear_previous_resources"),
                mock.patch.object(
                    RuntimeService, "_build_and_create_plan", return_value=plan
                ),
                mock.patch.object(
                    RuntimeService, "_load_repositories", return_value=()
                ),
                mock.patch("asf.runtime.KrunRequest", return_value=krun_request),
                mock.patch.object(RuntimeService, "_ensure_krun_image") as ensure_image,
                mock.patch(
                    "asf.runtime.load_runtime_environment", return_value=()
                ),
                mock.patch(
                    "asf.runtime.build_krun_environment",
                    return_value=session_environment,
                ),
                mock.patch(
                    "asf.runtime.build_krun_run_argv", return_value=child
                ),
                mock.patch("asf.runtime.run_open_session", return_value=0) as run_session,
            ):
                self.assertEqual(service.open("krun-test"), 0)

            ensure_image.assert_called_once_with(krun_request)
            run_session.assert_called_once()
            self.assertEqual(run_session.call_args.args[0], child)
            self.assertEqual(
                run_session.call_args.kwargs["environment"], session_environment
            )


class KrunAttachTests(unittest.TestCase):
    def test_attach_uses_podman_attach_and_detach_preserves_session(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        output = io.StringIO()
        service = RuntimeService(
            paths, PodmanClient(engine="podman"), output, io.StringIO()
        )
        manager = mock.Mock()
        attach_lock = object()
        manager.acquire.return_value = attach_lock
        discovery = mock.Mock()
        discovery.lock_manager.return_value = manager

        with (
            mock.patch(
                "asf.runtime.SessionDiscovery.from_paths", return_value=discovery
            ),
            mock.patch(
                "asf.runtime.SessionProcessSupervisor.run",
                return_value=SimpleNamespace(returncode=0, signal=None),
            ) as attached,
            mock.patch.object(
                RuntimeService, "_runtime_container_running", return_value=True
            ),
        ):
            self.assertEqual(service._attach_krun("hermes", "container-id"), 0)

        command = attached.call_args.args[0]
        self.assertEqual(command[:2], ("podman", "attach"))
        self.assertIn("--detach-keys=ctrl-p,ctrl-q", command)
        self.assertIn("--sig-proxy=false", command)
        self.assertEqual(command[-1], "container-id")
        manager.release.assert_called_once_with(attach_lock)
        self.assertIn("Detach without stopping: Ctrl-P, Ctrl-Q", output.getvalue())


class SharedEgressEnvironmentTests(unittest.TestCase):
    """Container and krun paths must wire proxy/broker env identically."""

    class _StubPlan:
        def __init__(self, roles):
            self._roles = roles

        def container(self, role):
            return object() if role in self._roles else None

    def test_both_isolation_paths_share_one_egress_wiring(self) -> None:
        from asf.runtime_container import apply_egress_environment
        from asf.manifest import load_model
        from asf.session import SessionRole
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "runtime.yml"
            manifest_path.write_text(
                "name: t\nllm:\n  provider: anthropic\n  protocol: anthropic\n  broker: true\n  api_key_env: ANTHROPIC_API_KEY\n"
            )
            manifest = load_model(manifest_path)
        plan = self._StubPlan({SessionRole.PROXY, SessionRole.BROKER})

        container_env: dict[str, str] = {}
        apply_egress_environment(
            container_env,
            plan=plan,
            manifest=manifest,
            proxy_port=3128,
            broker_default_model="",
            broker_token="tok-container",
        )
        krun_env: dict[str, str] = {}
        apply_egress_environment(
            krun_env,
            plan=plan,
            manifest=manifest,
            proxy_port=3128,
            broker_default_model="",
            broker_token="tok-123",
        )
        self.assertEqual(
            container_env.pop("ANTHROPIC_AUTH_TOKEN"),
            "tok-container",
        )
        self.assertEqual(krun_env.pop("ANTHROPIC_AUTH_TOKEN"), "tok-123")
        # Everything except the token transport is byte-identical.
        self.assertEqual(container_env, krun_env)
        self.assertEqual(
            krun_env["NO_PROXY"], "localhost,127.0.0.1,asf-broker"
        )


if __name__ == "__main__":
    unittest.main()
