#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from asf.broker import (
    BROKER_PORT,
    PROVIDER_DEFAULTS,
    BrokerError,
    BrokerLifecycleError,
    BrokerRequest,
    BrokerService,
    BrokerSettings,
    build_model_policy,
    describe_lines,
    generate_session_token,
    load_request,
    prepare_models,
    provider_api_key_name,
    provider_direct_domain,
    read_declared_secret,
    resolve_provider_settings,
)
from asf.errors import ConfigurationError, InfrastructureError, ValidationError
from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.podman import PodmanClient
from asf.process import CommandResult, SensitiveArgument
from asf.runtime_plan import (
    BROKER_INTERNAL_ALIAS,
    build_runtime_plan,
    runtime_plan_path,
    write_runtime_plan,
)
from asf.secrets import SecretValue
from asf.session import SessionRole

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "ghcr.io/berriai/litellm:v1.93.0"
TOKEN = "a" * 64


class RecordingRunner:
    def __init__(
        self,
        *,
        image_exists: int = 0,
        readiness_failures: int = 0,
        container_status: str = "running",
        fail_contains: str = "",
        readiness_status: int = 1,
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.actual_calls: list[tuple[str, ...]] = []
        self.inputs: list[str | None] = []
        self.image_exists = image_exists
        self.readiness_failures = readiness_failures
        self.container_status = container_status
        self.fail_contains = fail_contains
        self.readiness_status = readiness_status

    def __call__(self, argv, **kwargs) -> CommandResult:
        display: list[str] = []
        actual: list[str] = []
        for item in argv:
            if isinstance(item, SensitiveArgument):
                actual.append(item.reveal())
                display.append("***")
            else:
                actual.append(str(item))
                display.append(str(item))
        shown = tuple(display)
        real = tuple(actual)
        self.calls.append(shown)
        self.actual_calls.append(real)
        self.inputs.append(kwargs.get("input_text"))
        joined = " ".join(real)
        if self.fail_contains and self.fail_contains in joined:
            return CommandResult(shown, 1, "", "forced failure")
        if " image exists " in f" {joined} ":
            return CommandResult(shown, self.image_exists, "", "")
        if " exec " in f" {joined} " and "/health/liveliness" in joined:
            if self.readiness_failures > 0:
                self.readiness_failures -= 1
                return CommandResult(shown, self.readiness_status, "", "")
            return CommandResult(shown, 0, "", "")
        if " inspect --type container " in f" {joined} ":
            ref = real[-1]
            running = self.container_status == "running"
            payload = [
                {
                    "Id": "broker-id",
                    "Name": f"/{ref}",
                    "Config": {"Image": IMAGE, "Labels": {}},
                    "State": {"Status": self.container_status, "Running": running},
                    "NetworkSettings": {"Networks": {}},
                    "HostConfig": {"ReadonlyRootfs": True},
                }
            ]
            return CommandResult(shown, 0, json.dumps(payload), "")
        if " logs " in f" {joined} ":
            return CommandResult(shown, 0, "broker log", "")
        return CommandResult(shown, 0, "", "")


class BrokerTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "checkout"
        (self.root / "agents" / "claude").mkdir(parents=True)
        (self.root / ".devcontainer").mkdir()
        (self.root / "secrets").mkdir()
        (self.root / "tools").mkdir()
        (self.root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (self.root / ".devcontainer" / "devcontainer.base.json").write_text(
            "{}\n", encoding="utf-8"
        )
        (self.root / "agents" / "claude" / "runtime.yml").write_text(
            (ROOT / "agents" / "claude" / "runtime.yml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (self.root / "tools" / "litellm_entrypoint.py").write_text(
            "print('entrypoint')\n", encoding="utf-8"
        )
        self.paths = RepoPaths.for_root(self.root)
        self.manifest = load_model(self.paths.identity.runtime_manifest("claude"))

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def request(
        self,
        *,
        broker: bool = True,
        settings: BrokerSettings | None = None,
    ) -> BrokerRequest:
        plan = build_runtime_plan(
            self.manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=broker,
        )
        return BrokerRequest(
            self.paths,
            self.manifest,
            plan,
            settings or BrokerSettings(IMAGE, startup_timeout=2),
        )

    def persist(self) -> BrokerRequest:
        request = self.request()
        write_runtime_plan(request.plan, runtime_plan_path(self.paths, "claude"))
        return request

    def write_secret(self, filename: str, text: str, mode: int = 0o600) -> Path:
        path = self.root / "secrets" / filename
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path


class BrokerConfigurationTests(BrokerTestBase):
    def test_every_shipped_broker_runtime_uses_planned_identity_and_topology(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        for manifest_path in sorted((ROOT / "agents").glob("*/runtime.yml")):
            manifest = load_model(manifest_path)
            if manifest.llm is None or not manifest.llm.broker:
                continue
            with self.subTest(runtime=manifest.name):
                plan = build_runtime_plan(
                    manifest,
                    paths=paths,
                    owner_pid=4242,
                    broker_globally_enabled=True,
                )
                request = BrokerRequest(paths, manifest, plan, BrokerSettings(IMAGE))
                self.assertEqual(
                    request.container.networks,
                    (request.internal_network, request.provider_network),
                )
                self.assertEqual(request.container.capabilities, frozenset())
                self.assertEqual(
                    request.secret_name,
                    paths.identity.broker_secret(manifest.name, 4242),
                )
                self.assertEqual(request.state_path, paths.identity.broker_state(manifest.name))
                self.assertEqual(request.models.mode, "wildcard")

    def test_provider_defaults_and_description_are_plan_driven(self) -> None:
        request = self.request()
        self.assertEqual(request.provider, "anthropic")
        self.assertEqual(request.protocol, "anthropic")
        self.assertEqual(provider_api_key_name(self.manifest), "ANTHROPIC_API_KEY")
        self.assertEqual(provider_direct_domain(self.manifest), "api.anthropic.com")
        fields = describe_lines(request)
        self.assertEqual(fields[0], request.container.name)
        self.assertEqual(fields[1], request.secret_name)
        self.assertEqual(fields[4], "ANTHROPIC_API_KEY")
        self.assertEqual(fields[-1], "anthropic/* (all models)")
        self.assertTrue(all("\n" not in value for value in fields))

    def test_provider_policy_defaults_are_pure_and_fail_closed(self) -> None:
        for provider, domain in PROVIDER_DEFAULTS.items():
            with self.subTest(provider=provider):
                manifest = replace(
                    self.manifest,
                    llm=replace(
                        self.manifest.llm,
                        provider=provider,
                        direct_domain=None,
                        api_key_env=None,
                    ),
                )
                settings = resolve_provider_settings(manifest)
                self.assertEqual(settings.direct_domain, domain)
                self.assertEqual(
                    settings.api_key_name,
                    provider.upper().replace("-", "_") + "_API_KEY",
                )

        custom = replace(
            self.manifest,
            llm=replace(
                self.manifest.llm,
                provider="open-router",
                direct_domain="openrouter.example",
                api_key_env=None,
            ),
        )
        self.assertEqual(
            resolve_provider_settings(custom).api_key_name,
            "OPEN_ROUTER_API_KEY",
        )
        unknown = replace(
            self.manifest,
            llm=replace(
                self.manifest.llm,
                provider="unknown-provider",
                direct_domain=None,
            ),
        )
        with self.assertRaises(BrokerError):
            resolve_provider_settings(unknown)

    def test_restricted_models_strip_provider_prefix_and_deduplicate(self) -> None:
        llm = replace(
            self.manifest.llm,
            models=("anthropic/claude-opus", "claude-sonnet", "claude-opus"),
        )
        manifest = replace(self.manifest, llm=llm)
        models = prepare_models(self.paths, manifest)
        self.assertEqual(models.mode, "restricted")
        self.assertTrue(models.restricted)
        self.assertEqual(models.models, ("claude-opus", "claude-sonnet"))
        self.assertEqual(models.route, "claude-opus claude-sonnet")

    def test_model_policy_is_pure_and_validates_direct_callers(self) -> None:
        manifest = replace(
            self.manifest,
            llm=replace(
                self.manifest.llm,
                provider="openai",
                protocol="openai",
                models=("openai/gpt-5.5", "gpt-5.4", "gpt-5.5"),
            ),
        )
        models = build_model_policy(
            manifest, "openai", default_model="openai/gpt-5.5"
        )
        self.assertEqual(models.models, ("gpt-5.5", "gpt-5.4"))
        self.assertEqual(models.default_model, "gpt-5.5")

        malformed = replace(
            manifest, llm=replace(manifest.llm, models=("bad model",))
        )
        with self.assertRaises(BrokerError):
            build_model_policy(malformed, "openai")
        with self.assertRaises(BrokerError):
            build_model_policy(manifest, "openai", default_model="other-model")

    def test_hermes_default_model_comes_from_adapter_config(self) -> None:
        (self.root / "agents" / "hermes").mkdir()
        (self.root / "agents" / "hermes" / "config.yaml").write_text(
            "model:\n  default: openai/gpt-5.5\n", encoding="utf-8"
        )
        manifest = replace(
            self.manifest,
            name="hermes",
            adapter="hermes",
            llm=replace(
                self.manifest.llm,
                provider="openai",
                protocol="openai",
                models=("gpt-5.5",),
            ),
        )
        self.assertEqual(prepare_models(self.paths, manifest).default_model, "gpt-5.5")
        bad = replace(manifest, llm=replace(manifest.llm, models=("gpt-5.6",)))
        with self.assertRaises(BrokerError):
            prepare_models(self.paths, bad)

    def test_nonbroker_and_tampered_plans_fail_closed(self) -> None:
        plan = build_runtime_plan(
            self.manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=False,
        )
        with self.assertRaises(BrokerError):
            BrokerRequest(self.paths, self.manifest, plan, BrokerSettings(IMAGE))
        request = self.request()
        broker = request.plan.container(SessionRole.BROKER)
        assert broker is not None
        bad = replace(broker, capabilities=frozenset({"net_raw"}))
        support = tuple(
            bad if item.role is SessionRole.BROKER else item
            for item in request.plan.support_containers
        )
        with self.assertRaises(ConfigurationError):
            BrokerRequest(
                self.paths,
                self.manifest,
                replace(request.plan, support_containers=support),
                BrokerSettings(IMAGE),
            )

    def test_load_request_consumes_and_revalidates_persisted_plan(self) -> None:
        expected = self.persist()
        loaded = load_request(self.root, "claude", image=IMAGE)
        self.assertEqual(loaded.plan, expected.plan)
        payload = json.loads(runtime_plan_path(self.paths, "claude").read_text())
        payload["support_containers"][0]["name"] = "tampered-broker"
        runtime_plan_path(self.paths, "claude").write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(ConfigurationError):
            load_request(self.root, "claude", image=IMAGE)

    def test_entrypoint_and_hermes_config_symlinks_are_rejected(self) -> None:
        entrypoint = self.root / "tools" / "litellm_entrypoint.py"
        target = self.root / "tools" / "other.py"
        target.write_text("print('other')\n", encoding="utf-8")
        entrypoint.unlink()
        entrypoint.symlink_to(target)
        with self.assertRaises(BrokerError):
            self.request()

        entrypoint.unlink()
        entrypoint.write_text("print('entrypoint')\n", encoding="utf-8")
        (self.root / "agents" / "hermes").mkdir()
        hermes_target = self.root / "agents" / "hermes" / "real.yaml"
        hermes_target.write_text(
            "model:\n  default: openai/gpt-5.5\n", encoding="utf-8"
        )
        (self.root / "agents" / "hermes" / "config.yaml").symlink_to(
            hermes_target
        )
        manifest = replace(
            self.manifest,
            name="hermes",
            adapter="hermes",
            llm=replace(
                self.manifest.llm,
                provider="openai",
                protocol="openai",
            ),
        )
        with self.assertRaises(BrokerError):
            prepare_models(self.paths, manifest)

    def test_settings_validation_is_small_and_strict(self) -> None:
        for image in ("", "bad image", "bad\x00image"):
            with self.subTest(image=image), self.assertRaises(ValidationError):
                BrokerSettings(image)
        for timeout in (0, -1, True):
            with self.subTest(timeout=timeout), self.assertRaises((ValidationError, TypeError)):
                BrokerSettings(IMAGE, startup_timeout=timeout)


class BrokerSecretTests(BrokerTestBase):
    def test_declared_files_use_later_override_and_never_log_value(self) -> None:
        self.write_secret("common.env", "ANTHROPIC_API_KEY=first\n")
        self.write_secret("claude.env", "ANTHROPIC_API_KEY=second\n")
        warning = io.StringIO()
        secret = read_declared_secret(self.request(), "ANTHROPIC_API_KEY", error=warning)
        self.assertEqual(secret.reveal(), "second")
        self.assertNotIn("second", warning.getvalue())

    def test_invalid_env_name_and_symlinked_secret_are_rejected(self) -> None:
        self.write_secret("common.env", "BAD-NAME=value\n")
        with self.assertRaises(BrokerError):
            read_declared_secret(self.request(), "ANTHROPIC_API_KEY")
        (self.root / "secrets" / "common.env").unlink()
        outside = Path(self.tempdir.name) / "outside.env"
        outside.write_text("ANTHROPIC_API_KEY=value\n", encoding="utf-8")
        (self.root / "secrets" / "common.env").symlink_to(outside)
        with self.assertRaises(BrokerError):
            read_declared_secret(self.request(), "ANTHROPIC_API_KEY")

    def test_permissions_warning_names_file_but_not_secret(self) -> None:
        self.write_secret("claude.env", "ANTHROPIC_API_KEY=private-value\n", 0o644)
        warning = io.StringIO()
        secret = read_declared_secret(self.request(), "ANTHROPIC_API_KEY", error=warning)
        self.assertEqual(secret.reveal(), "private-value")
        self.assertIn("mode 644", warning.getvalue())
        self.assertNotIn("private-value", warning.getvalue())


class BrokerTokenTests(unittest.TestCase):
    def test_generated_tokens_are_opaque_random_and_compatible(self) -> None:
        first = generate_session_token()
        second = generate_session_token()
        self.assertIsInstance(first, SecretValue)
        self.assertNotEqual(first.reveal(), second.reveal())
        self.assertRegex(first.reveal(), r"^[0-9a-f]{64}$")
        self.assertNotIn(first.reveal(), repr(first))


class BrokerLifecycleTests(BrokerTestBase):
    def service(self, runner: RecordingRunner, **kwargs) -> BrokerService:
        return BrokerService(
            PodmanClient(engine=sys.executable, runner=runner),
            readiness_delay=0,
            sleep=lambda _seconds: None,
            **kwargs,
        )

    def test_public_command_builders_preserve_the_broker_boundary(self) -> None:
        request = self.request()
        service = self.service(RecordingRunner())
        secret_argv = service.secret_create_argv(request)
        self.assertEqual(secret_argv[-1], "-")
        self.assertEqual(secret_argv[-2], request.secret_name)

        run_argv = service.run_argv(request, SecretValue(TOKEN))
        actual = tuple(
            item.reveal() if isinstance(item, SensitiveArgument) else str(item)
            for item in run_argv
        )
        networks = [
            actual[index + 1]
            for index, item in enumerate(actual)
            if item == "--network"
        ]
        self.assertEqual(
            networks,
            [
                f"{request.internal_network}:alias={BROKER_INTERNAL_ALIAS}",
                request.provider_network,
            ],
        )
        self.assertNotIn("-p", actual)
        self.assertNotIn("--publish", actual)
        self.assertFalse(any(item.startswith("--cap-add") for item in actual))
        self.assertIn("--cap-drop=ALL", actual)
        self.assertIn(
            f"{request.secret_name},type=mount,target=provider_api_key",
            actual,
        )

        readiness = service.readiness_command()
        self.assertEqual(readiness[0], "python")
        self.assertIn(f"127.0.0.1:{BROKER_PORT}", readiness[-1])
        self.assertIn("health/liveliness", readiness[-1])

    def test_start_uses_planned_names_networks_labels_and_hardening(self) -> None:
        self.write_secret("claude.env", "ANTHROPIC_API_KEY=provider-key\n")
        request = self.request()
        runner = RecordingRunner(image_exists=0)
        output = io.StringIO()
        self.service(runner).start(
            request,
            SecretValue(TOKEN),
            output=output,
            error=io.StringIO(),
        )
        secret_call = next(
            call
            for call in runner.actual_calls
            if "secret" in call and "create" in call
        )
        secret_index = runner.actual_calls.index(secret_call)
        self.assertEqual(runner.inputs[secret_index], "provider-key")
        self.assertNotIn("provider-key", " ".join(secret_call))

        start = next(call for call in runner.actual_calls if "run" in call and "-d" in call)
        shown = runner.calls[runner.actual_calls.index(start)]
        self.assertIn(request.container.name, start)
        self.assertIn(
            f"{request.internal_network}:alias={BROKER_INTERNAL_ALIAS}", start
        )
        self.assertIn(request.provider_network, start)
        self.assertIn(request.plan.sandbox_label, start)
        self.assertIn("asf.role=broker", start)
        self.assertIn("--cap-drop=ALL", start)
        self.assertIn("--read-only", start)
        self.assertIn(f"LITELLM_MASTER_KEY={TOKEN}", start)
        self.assertNotIn(TOKEN, " ".join(shown))
        self.assertEqual(
            request.state_path.read_text(encoding="utf-8"),
            f"{request.container.name}\napi.anthropic.com\n",
        )
        self.assertEqual(request.state_path.stat().st_mode & 0o777, 0o600)
        self.assertIn("Broker container started", output.getvalue())

    def test_missing_key_fails_before_any_podman_mutation(self) -> None:
        request = self.request()
        runner = RecordingRunner()
        with self.assertRaises(BrokerError):
            self.service(runner).start(
                request,
                SecretValue(TOKEN),
                output=io.StringIO(),
                error=io.StringIO(),
            )
        self.assertEqual(runner.calls, [])

    def test_image_pull_and_command_failures_are_explicit(self) -> None:
        self.write_secret("claude.env", "ANTHROPIC_API_KEY=value\n")
        request = self.request()
        pull = RecordingRunner(image_exists=1)
        self.service(pull).start(
            request,
            SecretValue(TOKEN),
            output=io.StringIO(),
            error=io.StringIO(),
        )
        self.assertTrue(any("pull" in call for call in pull.actual_calls))

        failed = RecordingRunner(fail_contains="secret create")
        with self.assertRaises(BrokerLifecycleError):
            self.service(failed).start(
                request,
                SecretValue(TOKEN),
                output=io.StringIO(),
                error=io.StringIO(),
            )

    def test_readiness_retries_without_shell_and_reports_success(self) -> None:
        request = self.request()
        runner = RecordingRunner(readiness_failures=2)
        output = io.StringIO()
        self.service(runner).wait_ready(request, output=output, error=io.StringIO())
        health = [call for call in runner.actual_calls if "/health/liveliness" in " ".join(call)]
        self.assertEqual(len(health), 3)
        self.assertTrue(all("sh" not in call for call in health))
        self.assertIn("LiteLLM broker ready", output.getvalue())

    def test_exited_and_timeout_readiness_include_diagnostics(self) -> None:
        request = self.request(settings=BrokerSettings(IMAGE, startup_timeout=1))
        exited = RecordingRunner(readiness_failures=10, container_status="exited")
        with self.assertRaisesRegex(BrokerLifecycleError, "exited during startup"):
            self.service(exited).wait_ready(request, output=io.StringIO(), error=io.StringIO())

        timeout = RecordingRunner(readiness_failures=10, container_status="running")
        errors = io.StringIO()
        with self.assertRaisesRegex(BrokerLifecycleError, "failed to become ready"):
            self.service(timeout).wait_ready(request, output=io.StringIO(), error=errors)
        self.assertIn("broker log", errors.getvalue())

    def test_invalid_session_token_fails_before_podman(self) -> None:
        self.write_secret("claude.env", "ANTHROPIC_API_KEY=value\n")
        runner = RecordingRunner()
        with self.assertRaises(BrokerError):
            self.service(runner).start(
                self.request(),
                SecretValue("not-a-session-token"),
                output=io.StringIO(),
                error=io.StringIO(),
            )
        self.assertEqual(runner.calls, [])

    def test_readiness_infrastructure_status_fails_immediately(self) -> None:
        request = self.request()
        runner = RecordingRunner(
            readiness_failures=10,
            readiness_status=125,
        )
        with self.assertRaisesRegex(BrokerLifecycleError, "could not execute"):
            self.service(runner).wait_ready(
                request, output=io.StringIO(), error=io.StringIO()
            )
        health = [
            call
            for call in runner.actual_calls
            if "/health/liveliness" in " ".join(call)
        ]
        self.assertEqual(len(health), 1)

    def test_devcontainer_directory_symlink_is_rejected(self) -> None:
        request = self.request()
        outside = Path(self.tempdir.name) / "outside-devcontainer"
        outside.mkdir()
        (self.root / ".devcontainer" / "devcontainer.base.json").unlink()
        (self.root / ".devcontainer").rmdir()
        (self.root / ".devcontainer").symlink_to(outside, target_is_directory=True)
        (outside / "devcontainer.base.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaises(BrokerError):
            _ = request.state_path

    def test_state_symlink_is_rejected_before_replacement(self) -> None:
        self.write_secret("claude.env", "ANTHROPIC_API_KEY=value\n")
        request = self.request()
        outside = Path(self.tempdir.name) / "outside"
        outside.write_text("keep", encoding="utf-8")
        request.state_path.symlink_to(outside)
        with self.assertRaises(BrokerError):
            self.service(RecordingRunner()).start(
                request,
                SecretValue(TOKEN),
                output=io.StringIO(),
                error=io.StringIO(),
            )
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep")


class BrokerErrorHierarchyTests(unittest.TestCase):
    def test_broker_errors_use_shared_categories(self) -> None:
        self.assertTrue(issubclass(BrokerError, ConfigurationError))
        self.assertTrue(issubclass(BrokerLifecycleError, InfrastructureError))


if __name__ == "__main__":
    unittest.main()
