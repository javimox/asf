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
from unittest import mock

from asf.errors import ConfigurationError, ValidationError
from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.runs import begin_run
from asf.podman import PodmanClient
from asf.process import CommandResult
from asf.proxy import (
    CADDY_BUILDER_IMAGE,
    CADDY_FORWARDPROXY,
    CADDY_RUNTIME_IMAGE,
    CADDY_VERSION,
    ALLOWED_PORT,
    PRIVATE_DENY_RULES,
    PROXY_PORT,
    ProxyError,
    ProxyLifecycleError,
    ProxyRequest,
    ProxyService,
    caddy_image_tag,
    load_request,
    render_caddyfile,
    render_containerfile,
)
from asf.runtime_plan import (
    PROXY_INTERNAL_ALIAS,
    build_runtime_plan,
    runtime_plan_path,
    write_runtime_plan,
)
from asf.session import SessionRole

ROOT = Path(__file__).resolve().parents[1]


class RecordingRunner:
    def __init__(self, *, readiness_failures: int = 0, fail_contains: str = "") -> None:
        self.calls: list[tuple[str, ...]] = []
        self.readiness_failures = readiness_failures
        self.fail_contains = fail_contains

    def __call__(self, argv, **_kwargs) -> CommandResult:
        args = tuple(str(item) for item in argv)
        self.calls.append(args)
        joined = " ".join(args)
        if self.fail_contains and self.fail_contains in joined:
            return CommandResult(args, 1, "", "forced failure")
        if " exec " in f" {joined} " and "nc -z 127.0.0.1" in joined:
            if self.readiness_failures > 0:
                self.readiness_failures -= 1
                return CommandResult(args, 1, "", "")
        return CommandResult(args, 0, "", "")


class ProxyTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "checkout"
        (self.root / "agents" / "claude").mkdir(parents=True)
        (self.root / "containers").mkdir()
        (self.root / ".asf").mkdir()
        (self.root / "secrets").mkdir()
        (self.root / "sandbox.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (self.root / "agents" / "claude" / "runtime.yml").write_text(
            (ROOT / "agents" / "claude" / "runtime.yml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        with mock.patch.dict(
            os.environ, {"XDG_STATE_HOME": str(Path(self.tempdir.name) / "state")}
        ):
            self.paths = RepoPaths.for_root(self.root)
        begin_run(self.paths, "claude")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def request(self, *, broker: bool = True, access_logs: bool = True) -> ProxyRequest:
        manifest = load_model(self.paths.identity.runtime_manifest("claude"))
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=broker,
        )
        return ProxyRequest(self.paths, manifest, plan, access_logs=access_logs)

    def persist(self, *, broker: bool = True) -> ProxyRequest:
        request = self.request(broker=broker)
        write_runtime_plan(request.plan, runtime_plan_path(self.paths, "claude"))
        return request


class ProxyRenderingTests(ProxyTestBase):
    def test_every_shipped_proxy_runtime_renders_from_its_plan(self) -> None:
        paths = RepoPaths.for_root(ROOT)
        for manifest_path in sorted((ROOT / "agents").glob("*/runtime.yml")):
            manifest = load_model(manifest_path)
            if manifest.network.mode != "proxy":
                continue
            with self.subTest(runtime=manifest.name):
                plan = build_runtime_plan(
                    manifest,
                    paths=paths,
                    owner_pid=4242,
                    broker_globally_enabled=True,
                )
                request = ProxyRequest(paths, manifest, plan)
                policy = render_caddyfile(request.domains)
                self.assertIn("ports 443", policy)
                self.assertIn("deny all", policy)
                if plan.broker_enabled:
                    self.assertNotIn(
                        f"allow {request.removed_domain}",
                        policy,
                    )

    def test_effective_policy_removes_broker_provider_and_is_sorted(self) -> None:
        request = self.request(broker=True)
        self.assertNotIn("api.anthropic.com", request.domains)
        self.assertEqual(request.domains, tuple(sorted(set(request.domains))))
        direct = self.request(broker=False)
        self.assertIn("api.anthropic.com", direct.domains)

    def test_caddyfile_preserves_private_denials_before_allows_and_port(self) -> None:
        policy = render_caddyfile(("pypi.org", "files.pythonhosted.org"))
        self.assertIn(f":{PROXY_PORT} {{", policy)
        self.assertIn("            ports 443", policy)
        self.assertLess(policy.index("deny 10.0.0.0/8"), policy.index("allow pypi.org"))
        self.assertLess(policy.index("allow pypi.org"), policy.index("deny all"))
        self.assertIn("deny ::/96", policy)

    def test_access_logs_can_be_disabled_without_changing_policy(self) -> None:
        enabled = render_caddyfile(("example.com",), access_logs=True)
        disabled = render_caddyfile(("example.com",), access_logs=False)
        self.assertIn("output file /var/log/asf/caddy-access.jsonl", enabled)
        self.assertIn("roll_size 10MiB", enabled)
        self.assertIn("roll_keep 2", enabled)
        self.assertIn("roll_uncompressed", enabled)
        self.assertNotIn("roll_disabled", enabled)
        self.assertNotIn("output file /var/log/asf/caddy-access.jsonl", disabled)
        self.assertIn("                allow example.com", disabled)

    def test_policy_invariants_are_explicit_and_complete(self) -> None:
        policy = render_caddyfile(("example.com",))
        # Plain (non-CONNECT) proxying must be denied with an explicit 403
        # before the request can reach forward_proxy: forwardproxy's own
        # plain-path denials surface as ambiguous 502s.
        self.assertIn("@plain not method CONNECT", policy)
        self.assertIn("respond @plain 403", policy)
        self.assertLess(
            policy.index("respond @plain 403"),
            policy.index("forward_proxy {"),
        )
        rules = [
            line.strip()
            for line in policy.splitlines()
            if line.strip().startswith(("allow ", "deny "))
        ]
        self.assertEqual(rules[-1], "deny all")
        self.assertNotIn("deny *", policy)
        self.assertEqual(policy.count("ports "), 1)
        self.assertIn(f"ports {ALLOWED_PORT}", policy)
        first_allow = policy.index("allow example.com")
        for network in PRIVATE_DENY_RULES:
            with self.subTest(network=network):
                marker = f"deny {network}"
                self.assertIn(marker, policy)
                self.assertLess(policy.index(marker), first_allow)

    def test_renderer_rejects_non_hostname_caddy_syntax(self) -> None:
        for domain in (
            "localhost",
            "EXAMPLE.com",
            "*.example.com",
            "https://example.com",
            "example.com:443",
            "example.com\n                deny all",
            "-leading.example",
            "trailing-.example",
        ):
            with self.subTest(domain=domain):
                with self.assertRaises(ValidationError):
                    render_caddyfile((domain,))

    def test_containerfile_keeps_pins_and_unprivileged_runtime(self) -> None:
        containerfile = render_containerfile()
        self.assertIn(f"FROM {CADDY_BUILDER_IMAGE} AS build", containerfile)
        self.assertIn(
            f"xcaddy build {CADDY_VERSION} --with {CADDY_FORWARDPROXY}",
            containerfile,
        )
        self.assertIn(f"FROM {CADDY_RUNTIME_IMAGE}", containerfile)
        self.assertIn("USER 10001:10001", containerfile)
        self.assertIn("ENTRYPOINT []", containerfile)
        self.assertRegex(caddy_image_tag(), r"^asf-proxy-caddy:[0-9a-f]{16}$")

    def test_non_proxy_or_tampered_plan_is_rejected(self) -> None:
        request = self.request()
        bad = replace(request.plan, network_mode="isolated")
        with self.assertRaises(ProxyError):
            ProxyRequest(self.paths, request.manifest, bad)
        proxy = request.plan.container(SessionRole.PROXY)
        assert proxy is not None
        bad_proxy = replace(proxy, capabilities=frozenset({"net_raw"}))
        support = tuple(
            bad_proxy if item.role is SessionRole.PROXY else item
            for item in request.plan.support_containers
        )
        with self.assertRaises(ConfigurationError):
            ProxyRequest(
                self.paths,
                request.manifest,
                replace(request.plan, support_containers=support),
            )

    def test_load_request_consumes_and_validates_persisted_plan(self) -> None:
        expected = self.persist()
        loaded = load_request(self.root, "claude")
        self.assertEqual(loaded.plan, expected.plan)
        payload = json.loads(runtime_plan_path(self.paths, "claude").read_text())
        payload["support_containers"][1]["name"] = "tampered-proxy"
        runtime_plan_path(self.paths, "claude").write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(ConfigurationError):
            load_request(self.root, "claude")

    def test_proxy_directory_symlink_is_rejected(self) -> None:
        request = self.request()
        target = Path(self.tempdir.name) / "outside"
        target.mkdir()
        request.config_dir.parent.mkdir(parents=True, exist_ok=True)
        request.config_dir.symlink_to(target, target_is_directory=True)
        runner = RecordingRunner()
        service = ProxyService(PodmanClient(engine=sys.executable, runner=runner))
        with self.assertRaises(ProxyError):
            service.start(request, output=io.StringIO())


class ProxyLifecycleTests(ProxyTestBase):
    def service(self, runner: RecordingRunner, **kwargs) -> ProxyService:
        return ProxyService(
            PodmanClient(engine=sys.executable, runner=runner),
            readiness_delay=0,
            sleep=lambda _seconds: None,
            **kwargs,
        )

    def test_start_uses_only_planned_names_networks_labels_and_hardening(self) -> None:
        request = self.request(broker=True)
        runner = RecordingRunner(readiness_failures=1)
        output = io.StringIO()
        self.service(runner).start(request, output=output)

        self.assertTrue(request.policy_path.is_file())
        policy = request.policy_path.read_text(encoding="utf-8")
        self.assertNotIn("allow api.anthropic.com", policy)
        self.assertIn("Egress proxy ready", output.getvalue())
        start = next(
            call for call in runner.calls
            if "run" in call and "-d" in call and request.container.name in call
        )
        self.assertIn(request.container.name, start)
        self.assertIn(
            f"{request.internal_network}:alias={PROXY_INTERNAL_ALIAS}", start
        )
        self.assertIn(request.egress_network, start)
        self.assertIn(request.plan.sandbox_label, start)
        self.assertIn("asf.role=proxy", start)
        self.assertIn("--cap-drop=ALL", start)
        self.assertIn("--security-opt=no-new-privileges", start)
        self.assertIn("--userns=keep-id:uid=10001,gid=10001", start)
        self.assertTrue(
            any(
                arg.startswith("type=bind,src=")
                and arg.endswith(",dst=/var/log/asf,rw=true")
                for arg in start
            )
        )
        self.assertNotIn("--cap-add=NET_ADMIN", start)
        readiness = [
            call
            for call in runner.calls
            if ("nc", "-z", "127.0.0.1", str(PROXY_PORT))
            == call[-4:]
        ]
        self.assertEqual(len(readiness), 2)

    def test_validation_happens_before_long_lived_container(self) -> None:
        request = self.request()
        runner = RecordingRunner(fail_contains="caddy validate")
        with self.assertRaises(ProxyLifecycleError):
            self.service(runner).start(request, output=io.StringIO())
        self.assertFalse(any("-d" in call for call in runner.calls))

    def test_readiness_failure_keeps_failure_explicit(self) -> None:
        request = self.request()
        runner = RecordingRunner(readiness_failures=3)
        with self.assertRaisesRegex(ProxyLifecycleError, "did not start"):
            self.service(runner, readiness_attempts=3).start(request, output=io.StringIO())
        self.assertTrue(any("logs" in call for call in runner.calls))

    def test_policy_and_containerfile_are_replaced_atomically(self) -> None:
        request = self.request(access_logs=False)
        request.config_dir.mkdir(parents=True)
        request.policy_path.write_text("old", encoding="utf-8")
        (request.config_dir / "Containerfile").write_text("old", encoding="utf-8")
        runner = RecordingRunner()
        self.service(runner).start(request, output=io.StringIO())
        self.assertNotEqual(request.policy_path.read_text(), "old")
        self.assertNotEqual((request.config_dir / "Containerfile").read_text(), "old")
        self.assertFalse(
            any(
                path.name.startswith(".Caddyfile.")
                for path in request.config_dir.iterdir()
            )
        )


class ProductionBoundaryTests(unittest.TestCase):
    def test_runtime_uses_the_single_python_proxy_service(self) -> None:
        source = (ROOT / "asf" / "runtime.py").read_text(encoding="utf-8")
        self.assertIn("ProxyService", source)
        self.assertIn("self.proxy_service.start", source)
        self.assertFalse((ROOT / "lib").exists())


if __name__ == "__main__":
    unittest.main()
