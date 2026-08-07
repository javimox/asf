#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from ipaddress import IPv4Network
from pathlib import Path

from asf.devcontainer import (
    BuildDevcontainerRequest,
    DevcontainerError,
    DevcontainerRequest,
    build_build_config,
    build_devcontainer_config,
    load_build_request,
    load_request,
    write_atomic,
)
from asf.manifest import load_model
from asf.models import (
    EnvironmentVariable,
    LlmSettings,
    NetworkPolicy,
    RoutedRule,
    RuntimeManifest,
    StateVolume,
)
from asf.paths import RepoPaths
from asf.repositories import RepositoryEntry
from asf.runtime_plan import (
    BROKER_INTERNAL_ALIAS,
    PROXY_INTERNAL_ALIAS,
    RoutedSubnetAllocation,
    build_runtime_plan,
    runtime_plan_path,
    write_runtime_plan,
)
from asf.session import SessionRole

ROOT = Path(__file__).resolve().parents[1]
BROKER_TEST = ROOT / "tools" / "test_broker.py"


def import_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json_with_comments(path: Path) -> dict:
    lines = path.read_text(encoding="utf-8").splitlines()
    return json.loads("\n".join(line for line in lines if not line.startswith("//")))


class GenerateDevcontainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "checkout"
        (self.root / "agents").mkdir(parents=True)
        (self.root / ".devcontainer").mkdir()
        (self.root / "secrets").mkdir()
        (self.root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (self.root / ".devcontainer" / "devcontainer.base.json").write_text(
            json.dumps(
                {
                    "build": {"context": "..", "dockerfile": "Dockerfile", "args": {}},
                    "runArgs": ["--user=1000:1000"],
                    "containerEnv": {"BASE": "1"},
                }
            ),
            encoding="utf-8",
        )
        for runtime in ("claude", "hermes"):
            target = self.root / "agents" / runtime
            target.mkdir()
            target.joinpath("runtime.yml").write_text(
                (ROOT / "agents" / runtime / "runtime.yml").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        self.paths = RepoPaths.for_root(self.root)
        self.repo = Path(self.tempdir.name) / "project"
        self.repo.mkdir()
        self.ssh_socket = Path(self.tempdir.name) / "ssh-agent.sock"
        self._ssh_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._ssh_server.bind(str(self.ssh_socket))

    def tearDown(self) -> None:
        self._ssh_server.close()
        self.tempdir.cleanup()

    @staticmethod
    def hardening_args(*capabilities: str) -> tuple[str, ...]:
        return (
            "--mount=type=tmpfs,target=/workspace/sandbox/secrets,ro=true,"
            "tmpfs-size=1048576,tmpfs-mode=0755,notmpcopyup",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--sysctl=net.ipv4.ip_forward=0",
            "--sysctl=net.ipv6.conf.all.forwarding=0",
            *(f"--cap-add={item.upper()}" for item in capabilities),
        )

    def request(
        self,
        runtime: str,
        *,
        broker: bool,
        manifest: RuntimeManifest | None = None,
        routed: RoutedSubnetAllocation | None = None,
        ssh: bool = False,
        model: str = "",
    ) -> DevcontainerRequest:
        model_manifest = manifest or load_model(
            self.paths.identity.runtime_manifest(runtime)
        )
        plan = build_runtime_plan(
            model_manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=broker,
            routed_subnets=routed,
        )
        return DevcontainerRequest(
            paths=self.paths,
            plan=plan,
            manifest=model_manifest,
            repositories=(self.repo,),
            run_arguments=self.hardening_args(*model_manifest.capabilities),
            build_arguments=("SEMGREP_VERSION=1.171.0",),
            ssh_agent_socket=self.ssh_socket if ssh else None,
            broker_default_model=model,
        )

    def test_direct_claude_configuration_uses_plan_identity_and_volumes(self) -> None:
        request = self.request("claude", broker=False)
        config = build_devcontainer_config(request)

        self.assertEqual(config["build"]["args"]["AGENT"], "claude")
        self.assertEqual(config["build"]["args"]["SEMGREP_VERSION"], "1.171.0")
        self.assertEqual(config["containerEnv"]["ASF_AGENT"], "claude")
        self.assertNotIn("ASF_BROKER_ENABLED", config["containerEnv"])
        self.assertNotIn("ANTHROPIC_BASE_URL", config["containerEnv"])
        self.assertIn(f"--label={request.plan.session_label}", config["runArgs"])
        self.assertIn(
            f"--name={request.plan.runtime_container.name}", config["runArgs"]
        )
        self.assertEqual(
            [item for item in config["mounts"] if "type=volume" in item],
            [
                f"source={item.name},target={item.target},type=volume"
                for item in request.plan.persistent_volumes
            ],
        )
        self.assertTrue(
            any("target=/workspace/repos/project" in item for item in config["mounts"])
        )

    def test_read_only_repository_renders_readonly_bind_mount(self) -> None:
        request = self.request("claude", broker=False)
        request = DevcontainerRequest(
            paths=request.paths,
            plan=request.plan,
            manifest=request.manifest,
            repositories=(RepositoryEntry(str(self.repo), "ro"),),
            run_arguments=request.run_arguments,
            build_arguments=request.build_arguments,
        )
        config = build_devcontainer_config(request)
        mount = next(
            item for item in config["mounts"]
            if "target=/workspace/repos/project" in item
        )
        self.assertIn("readonly", mount)

    def test_image_adapter_comes_from_plan_not_runtime_name(self) -> None:
        manifest = RuntimeManifest(
            name="python-agent",
            adapter="generic",
            network=NetworkPolicy(mode="proxy"),
        )
        request = self.request(
            "python-agent",
            broker=False,
            manifest=manifest,
        )
        config = build_devcontainer_config(request)

        self.assertEqual(request.plan.adapter, "generic")
        self.assertEqual(config["build"]["args"]["AGENT"], "generic")
        self.assertEqual(config["containerEnv"]["ASF_AGENT"], "python-agent")

    def test_brokered_hermes_configuration_uses_short_internal_alias(self) -> None:
        request = self.request("hermes", broker=True, model="gpt-5.5")
        config = build_devcontainer_config(request)
        environment = config["containerEnv"]
        self.assertEqual(environment["ASF_BROKER_ENABLED"], "true")
        self.assertEqual(
            environment["OPENAI_BASE_URL"], f"http://{BROKER_INTERNAL_ALIAS}:4000/v1"
        )
        self.assertEqual(environment["OPENAI_API_KEY"], "${localEnv:ASF_BROKER_TOKEN}")
        self.assertEqual(environment["ASF_DEFAULT_MODEL"], "gpt-5.5")
        self.assertEqual(environment["HERMES_YOLO_MODE"], "0")

    def test_manifest_env_cannot_override_plan_generated_security_values(self) -> None:
        manifest = RuntimeManifest(
            name="hermes",
            adapter="hermes",
            llm=LlmSettings(True, "openai", "openai"),
            network=NetworkPolicy(mode="proxy"),
            environment=(
                EnvironmentVariable("ASF_AGENT", "wrong"),
                EnvironmentVariable("HTTP_PROXY", "http://wrong:9999"),
                EnvironmentVariable("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            ),
        )
        request = self.request("hermes", broker=True, manifest=manifest)
        config = build_devcontainer_config(request)
        environment = config["containerEnv"]
        self.assertEqual(environment["ASF_AGENT"], "hermes")
        self.assertEqual(environment["HTTP_PROXY"], f"http://{PROXY_INTERNAL_ALIAS}:3128")
        self.assertEqual(environment["OPENAI_BASE_URL"], f"http://{BROKER_INTERNAL_ALIAS}:4000/v1")

    def test_routed_runtime_uses_planned_networks_and_fixed_address(self) -> None:
        manifest = RuntimeManifest(
            name="scanner",
            network=NetworkPolicy(
                mode="routed",
                routed_rules=(
                    RoutedRule(IPv4Network("192.0.2.10/32"), "tcp", (443,)),
                ),
            ),
        )
        routed = RoutedSubnetAllocation.parse(
            ("10.203.10.0/24", "10.203.11.0/24", "10.203.12.0/24")
        )
        request = self.request(
            "scanner", broker=False, manifest=manifest, routed=routed
        )
        config = build_devcontainer_config(request)
        networks = [item for item in config["runArgs"] if item.startswith("--network=")]
        self.assertEqual(
            networks,
            [
                f"--network={request.plan.runtime_container.attachments[0].network}",
                "--network="
                f"{request.plan.runtime_container.attachments[1].network}:"
                f"ip={request.plan.runtime_container.attachments[1].address}",
            ],
        )

    def test_capability_arguments_must_match_the_plan(self) -> None:
        manifest = RuntimeManifest(name="scanner", capabilities=frozenset({"net_raw"}))
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=False,
        )
        with self.assertRaisesRegex(DevcontainerError, "capability arguments"):
            build_devcontainer_config(
                DevcontainerRequest(
                    paths=self.paths,
                    plan=plan,
                    manifest=manifest,
                    run_arguments=self.hardening_args(),
                )
            )

    def test_ssh_agent_is_only_forwarded_when_explicit(self) -> None:
        direct = build_devcontainer_config(self.request("claude", broker=False))
        forwarded = build_devcontainer_config(
            self.request("claude", broker=False, ssh=True)
        )
        self.assertNotIn("SSH_AUTH_SOCK", direct["containerEnv"])
        self.assertFalse(any("/ssh-agent" in item for item in direct["mounts"]))
        self.assertEqual(forwarded["containerEnv"]["SSH_AUTH_SOCK"], "/ssh-agent")
        self.assertTrue(any("/ssh-agent" in item for item in forwarded["mounts"]))

    def test_missing_ssh_socket_is_rejected(self) -> None:
        request = self.request("claude", broker=False)
        with self.assertRaisesRegex(DevcontainerError, "SSH agent socket not found"):
            DevcontainerRequest(
                paths=request.paths,
                plan=request.plan,
                manifest=request.manifest,
                run_arguments=request.run_arguments,
                ssh_agent_socket=Path(self.tempdir.name) / "missing.sock",
            )

    def test_state_target_with_spaces_is_preserved_and_comma_is_rejected(self) -> None:
        with_spaces = RuntimeManifest(
            name="worker",
            state_volumes=(StateVolume("data", "/var/lib/my app"),),
        )
        config = build_devcontainer_config(
            self.request("worker", broker=False, manifest=with_spaces)
        )
        self.assertTrue(
            any(
                "target=/var/lib/my app,type=volume" in item
                for item in config["mounts"]
            )
        )

        with_comma = RuntimeManifest(
            name="worker",
            state_volumes=(StateVolume("data", "/var/lib/app,ro=true"),),
        )
        with self.assertRaisesRegex(DevcontainerError, "commas are not allowed"):
            build_devcontainer_config(
                self.request("worker", broker=False, manifest=with_comma)
            )

    def test_output_is_atomic_and_deterministic(self) -> None:
        request = self.request("claude", broker=False)
        config = build_devcontainer_config(request)
        output = request.output_path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("old", encoding="utf-8")
        write_atomic(output, config)
        first = output.read_bytes()
        write_atomic(output, config)
        self.assertEqual(output.read_bytes(), first)
        self.assertTrue(first.startswith(b"// GENERATED"))

    def test_build_only_configuration_needs_no_runtime_plan(self) -> None:
        manifest = load_model(self.paths.identity.runtime_manifest("hermes"))
        request = BuildDevcontainerRequest(
            paths=self.paths,
            manifest=manifest,
            repositories=(self.repo,),
            run_arguments=self.hardening_args(*manifest.capabilities),
            build_arguments=("SEMGREP_VERSION=1.171.0",),
        )
        config = build_build_config(request)
        identity = self.paths.identity

        self.assertFalse(runtime_plan_path(self.paths, "hermes").exists())
        self.assertEqual(config["build"]["args"]["AGENT"], manifest.adapter)
        self.assertEqual(config["containerEnv"]["ASF_AGENT"], "hermes")
        self.assertNotIn("ASF_BROKER_ENABLED", config["containerEnv"])
        self.assertNotIn("HTTP_PROXY", config["containerEnv"])
        self.assertIn(
            f"--network={identity.network_names('hermes').internal}",
            config["runArgs"],
        )
        self.assertTrue(
            any(
                item.startswith(
                    f"source={identity.shell_history_volume('hermes')},"
                )
                for item in config["mounts"]
            )
        )

    def test_build_only_cli_succeeds_without_a_persisted_plan(self) -> None:
        command = [
            sys.executable,
            "-m",
            "asf.devcontainer",
            "--root",
            str(self.root),
            "--runtime",
            "hermes",
            "--build-only",
            "--run-arg=--cap-drop=ALL",
            "--run-arg=--security-opt=no-new-privileges",
            "--run-arg=--sysctl=net.ipv4.ip_forward=0",
            "--run-arg=--sysctl=net.ipv6.conf.all.forwarding=0",
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        loaded = load_build_request(root=self.root, runtime="hermes")
        self.assertEqual(loaded.manifest.name, "hermes")
        self.assertTrue(loaded.output_path.is_file())
        self.assertFalse(runtime_plan_path(self.paths, "hermes").exists())

    def test_cli_loads_the_persisted_plan(self) -> None:
        manifest = load_model(self.paths.identity.runtime_manifest("claude"))
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=False,
        )
        write_runtime_plan(plan)
        command = [
            sys.executable,
            "-m",
            "asf.devcontainer",
            "--root",
            str(self.root),
            "--runtime",
            "claude",
            f"--run-arg={self.hardening_args()[0]}",
            "--run-arg=--cap-drop=ALL",
            "--run-arg=--security-opt=no-new-privileges",
            "--run-arg=--sysctl=net.ipv4.ip_forward=0",
            "--run-arg=--sysctl=net.ipv6.conf.all.forwarding=0",
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        self.assertEqual(
            load_request(
                root=self.root,
                runtime="claude",
                run_arguments=self.hardening_args(),
            ).plan,
            plan,
        )
        self.assertTrue(self.paths.identity.config_json("claude").is_file())

    def test_cli_rejects_a_tampered_persisted_plan(self) -> None:
        manifest = load_model(self.paths.identity.runtime_manifest("claude"))
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=False,
        )
        path = write_runtime_plan(plan)
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["runtime_container"]["name"] = "foreign-container"
        path.write_text(json.dumps(payload), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
            "asf.devcontainer",
                "--root",
                str(self.root),
                "--runtime",
                "claude",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match the current manifest", result.stderr)
        self.assertFalse(self.paths.identity.config_json("claude").exists())

    def test_session_symlink_cannot_redirect_generated_output(self) -> None:
        manifest = load_model(self.paths.identity.runtime_manifest("claude"))
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=False,
        )
        write_runtime_plan(plan)
        session = self.paths.identity.session_dir("claude")
        outside = Path(self.tempdir.name) / "outside"
        outside.mkdir()
        for child in session.iterdir():
            child.unlink()
        session.rmdir()
        session.symlink_to(outside, target_is_directory=True)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
            "asf.devcontainer",
                "--root",
                str(self.root),
                "--runtime",
                "claude",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse((outside / "devcontainer.json").exists())


class ProductionBoundaryTests(unittest.TestCase):
    def test_build_and_open_use_typed_render_requests(self) -> None:
        maintenance = (ROOT / "asf" / "maintenance.py").read_text(encoding="utf-8")
        runtime = (ROOT / "asf" / "runtime.py").read_text(encoding="utf-8")
        self.assertIn("BuildDevcontainerRequest(", maintenance)
        self.assertIn("DevcontainerRequest(", runtime)
        self.assertNotIn("--resource-prefix", maintenance)
        self.assertNotIn("--container-name", maintenance)
        self.assertFalse((ROOT / "lib").exists())


class BrokerDiagnosticTests(unittest.TestCase):
    def test_hermes_payload(self) -> None:
        module = import_module(BROKER_TEST, "broker_test_tool")
        endpoint, payload = module.request_payload("hermes", "gpt-5.5")
        self.assertEqual(endpoint, "/v1/chat/completions")
        self.assertEqual(payload["max_completion_tokens"], 128)
        self.assertNotIn("temperature", payload)


if __name__ == "__main__":
    unittest.main()
