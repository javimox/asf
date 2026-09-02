#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from asf.config import AsfConfig

ROOT = Path(__file__).resolve().parents[1]


def parse_shell_assignments(path: Path) -> dict[str, str]:
    return dict(AsfConfig.load(path).values)


class DependencyPinTests(unittest.TestCase):
    def test_top_level_dependencies_are_pinned(self) -> None:
        config = parse_shell_assignments(ROOT / "asf.conf")
        required = {
            "NODE_IMAGE",
            "UV_IMAGE",
            "SEMGREP_VERSION",
            "CLAUDE_CODE_VERSION",
            "CODEX_CLI_VERSION",
            "HERMES_AGENT_COMMIT",
            "GIT_DELTA_VERSION",
            "FZF_VERSION",
            "FZF_SHA256_AMD64",
            "FZF_SHA256_ARM64",
            "ZSH_IN_DOCKER_VERSION",
            "TIRITH_VERSION",
            "TIRITH_SHA256_AMD64",
            "TIRITH_SHA256_ARM64",
        }
        # asf.conf holds build, broker, and hardening settings, so assert the
        # build pins are all present rather than that they are the only keys.
        missing = required - set(config)
        self.assertEqual(missing, set(), f"missing build pins in asf.conf: {missing}")
        dependencies = {k: config[k] for k in required}
        for value in dependencies.values():
            self.assertNotIn(":latest", value)
            self.assertNotIn(":main", value)
        self.assertRegex(dependencies["HERMES_AGENT_COMMIT"], r"^[0-9a-f]{40}$")
        self.assertRegex(dependencies["FZF_SHA256_AMD64"], r"^[0-9a-f]{64}$")
        self.assertRegex(dependencies["FZF_SHA256_ARM64"], r"^[0-9a-f]{64}$")
        self.assertRegex(dependencies["CODEX_CLI_VERSION"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(dependencies["TIRITH_VERSION"], r"^\d+\.\d+\.\d+$")
        self.assertRegex(dependencies["TIRITH_SHA256_AMD64"], r"^[0-9a-f]{64}$")
        self.assertRegex(dependencies["TIRITH_SHA256_ARM64"], r"^[0-9a-f]{64}$")

    def test_every_dockerfile_arg_has_a_pin(self) -> None:
        # Replaces the old exact-set assertion: drift is now caught by checking
        # that each build ARG the Dockerfile expects is actually pinned.
        config = parse_shell_assignments(ROOT / "asf.conf")
        dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        args = set(re.findall(r"^ARG\s+([A-Z_][A-Z0-9_]*)", dockerfile, re.MULTILINE))
        # Supplied by the devcontainer CLI or the generator, not by asf.conf.
        supplied_elsewhere = {"TZ", "AGENT", "USERNAME", "_DEV_CONTAINERS_BASE_IMAGE"}
        for arg in args - supplied_elsewhere:
            self.assertIn(arg, config, f"Dockerfile ARG {arg} has no pin in asf.conf")

    def test_image_references_keep_exact_tags_with_optional_digests(self) -> None:
        config = parse_shell_assignments(ROOT / "asf.conf")
        patterns = {
            "NODE_IMAGE": r"^node:\d+\.\d+\.\d+-bookworm-slim(?:@sha256:[0-9a-f]{64})?$",
            "UV_IMAGE": r"^ghcr\.io/astral-sh/uv:\d+\.\d+\.\d+(?:@sha256:[0-9a-f]{64})?$",
            "LITELLM_IMAGE": r"^ghcr\.io/berriai/litellm:v\d+\.\d+\.\d+(?:@sha256:[0-9a-f]{64})?$",
        }
        for key, pattern in patterns.items():
            with self.subTest(key=key):
                self.assertRegex(config[key], pattern)
                self.assertNotIn("main-stable", config[key])

    def test_release_pin_script_preserves_tags_and_adds_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            script = tools / "pin_digests.sh"
            script.write_text(
                (ROOT / "tools" / "pin_digests.sh").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            script.chmod(0o755)
            references = {
                "NODE_IMAGE": "node:22.23.1-bookworm-slim",
                "UV_IMAGE": "ghcr.io/astral-sh/uv:0.11.31",
                "LITELLM_IMAGE": "ghcr.io/berriai/litellm:v1.93.0",
            }
            (root / "asf.conf").write_text(
                "".join(f"{key}={value}\n" for key, value in references.items()),
                encoding="utf-8",
            )
            engine = root / "fake-podman"
            digest = "a" * 64
            engine.write_text(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                "  pull) exit 0 ;;\n"
                f"  image) printf '%s\\n' 'example.invalid/image@sha256:{digest}' ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            engine.chmod(0o755)
            environment = dict(os.environ, ENGINE=str(engine))
            subprocess.run(
                ("bash", str(script)),
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )

            pinned = dict(AsfConfig.load(root / "asf.conf").values)
            for key, reference in references.items():
                self.assertEqual(pinned[key], f"{reference}@sha256:{digest}")

    def test_hermes_tirith_is_build_time_pinned_and_runtime_offline(self) -> None:
        dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        manifest = (ROOT / "agents" / "hermes" / "runtime.yml").read_text(
            encoding="utf-8"
        )
        config = (ROOT / "agents" / "hermes" / "config.yaml").read_text(
            encoding="utf-8"
        )
        setup = (ROOT / "agents" / "hermes" / "setup.sh").read_text(
            encoding="utf-8"
        )
        compat = (
            ROOT / "agents" / "hermes" / "patches" / "tirith-fail-closed.patch"
        ).read_text(encoding="utf-8")

        self.assertIn("tirith-${TIRITH_TARGET}.tar.gz", dockerfile)
        self.assertIn("sha256sum --check --strict", dockerfile)
        self.assertIn("tirith --version", dockerfile)
        self.assertIn("hermes-tirith-fail-closed.patch", dockerfile)
        self.assertIn('git -C "$HERMES_REPO" apply --check', dockerfile)
        self.assertIn('allow_domains: []', manifest)
        self.assertNotIn('github.com', manifest)
        self.assertIn('TIRITH_OFFLINE: "1"', manifest)
        self.assertIn('tirith_path: "/usr/local/bin/tirith"', config)
        self.assertIn('TIRITH_BIN="/usr/local/bin/tirith"', setup)
        self.assertIn('exit 1', setup)
        self.assertIn('cfg["tirith_fail_open"]', compat)
        self.assertIn('"action": "block"', compat)

    def test_codex_is_pinned_and_uses_native_chatgpt_login_path(self) -> None:
        dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(encoding="utf-8")
        manifest = (ROOT / "agents" / "codex" / "runtime.yml").read_text(encoding="utf-8")
        setup = (ROOT / "agents" / "codex" / "setup.sh").read_text(encoding="utf-8")

        self.assertIn('@openai/codex@${CODEX_CLI_VERSION}', dockerfile)
        self.assertIn('adapter: codex', manifest)
        self.assertIn('broker: false', manifest)
        self.assertIn('target: /home/node/.codex', manifest)
        self.assertIn('CODEX_HOME: /home/node/.codex', manifest)
        self.assertIn('verify_domain: chatgpt.com', manifest)
        self.assertIn('- chatgpt.com', manifest)
        self.assertIn('- auth.openai.com', manifest)
        self.assertNotIn('api.openai.com', manifest)
        self.assertNotIn('secrets:', manifest)
        self.assertFalse((ROOT / "secrets" / "codex.env.example").exists())
        self.assertIn('codex login --device-auth', setup)
        self.assertIn('codex login status', setup)

    def test_shared_agent_image_includes_runtime_python_dependencies(self) -> None:
        dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertRegex(dockerfile, re.compile(r"^\s*python3-yaml\s*\\$", re.MULTILINE))

    def test_shared_agent_image_keeps_routed_tools_minimal(self) -> None:
        dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("iputils-ping", dockerfile)
        self.assertNotRegex(dockerfile, re.compile(r"^\s*nmap\s*\\$", re.MULTILINE))

    def test_routed_scanner_example_documents_microvm_negative_control(self) -> None:
        manifest = (ROOT / "agents" / "routed-scanner" / "runtime.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("isolation: microvm", manifest)
        self.assertIn("blocked_address:", manifest)

    def test_crun_tap_runtime_is_auditable_and_ci_tracks_latest(self) -> None:
        runtime_dir = ROOT / "tools" / "krun-runtime"
        script = (runtime_dir / "build.sh").read_text(encoding="utf-8")
        patch = (
            runtime_dir / "patches" / "crun-tap-reference.patch"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github" / "workflows" / "crun-tap.yml"
        ).read_text(encoding="utf-8")

        self.assertRegex(
            (runtime_dir / "VERSION").read_text().strip(),
            r"^\d+\.\d+(?:\.\d+)?$",
        )
        self.assertRegex(
            (runtime_dir / "COMMIT").read_text().strip(), r"^[0-9a-f]{40}$"
        )
        self.assertIn('python3 - "$SRC/src/libcrun/handlers/krun.c"', script)
        self.assertIn("source.count(declaration) != 1", script)
        self.assertIn("configure_vm.count(passt) != 1", script)
        self.assertIn("releases/latest", script)
        self.assertIn("PINNED_COMMIT", script)
        self.assertIn("EXPECTED_COMMIT", script)
        self.assertIn("krun_add_net_tap", patch)
        self.assertIn('find_annotation (container, "krun.tap_name")', patch)
        # Review CI is deterministic; scheduled/manual CI tests upstream latest.
        self.assertIn("$(cat tools/krun-runtime/VERSION)", workflow)
        self.assertIn("selector=latest", workflow)
        self.assertIn("LIBKRUNFW_SHA256", workflow)
        self.assertIn("tests/test_krun_tap_ci.sh", workflow)
        self.assertIn("verify-runtime.sh", workflow)
        # Source and provenance are committed; the local executable is not.
        self.assertFalse((runtime_dir / "bin" / "crun").exists())
        self.assertIn(
            "/tools/krun-runtime/bin/",
            (ROOT / ".gitignore").read_text(encoding="utf-8"),
        )


    def test_dockerfile_does_not_pipe_remote_scripts_to_shell(self) -> None:
        dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(encoding="utf-8")
        self.assertNotRegex(dockerfile, re.compile(r"curl[^\n|]*\|\s*(?:bash|sh)"))
        self.assertNotRegex(dockerfile, re.compile(r"wget[^\n|]*\|\s*(?:bash|sh)"))
        self.assertIn('semgrep==${SEMGREP_VERSION}', dockerfile)
        self.assertIn('${HERMES_AGENT_COMMIT}/scripts/install.sh', dockerfile)
        self.assertNotIn('WARNING: Hermes install failed', dockerfile)
        self.assertNotIn(":latest", dockerfile)
        self.assertNotIn(":main", dockerfile)
        self.assertNotIn('SHELL [', dockerfile)
        self.assertNotIn('| head -n1', dockerfile)
        self.assertIn('-p fzf', dockerfile)
        self.assertNotIn('/usr/share/doc/fzf/examples/', dockerfile)
        self.assertNotRegex(dockerfile, re.compile(r'^\s+fzf\s+\\$', re.MULTILINE))
        self.assertIn('fzf-${FZF_VERSION}-linux_${FZF_ARCH}.tar.gz', dockerfile)
        self.assertIn('sha256sum --check --strict', dockerfile)
        self.assertIn('fzf --version', dockerfile)
        self.assertIn('Verifying the Hermes CLI installation', dockerfile)
        self.assertIn('timeout 120 /home/node/.local/bin/hermes --help', dockerfile)
        self.assertIn('Hermes CLI verification failed or exceeded 120 seconds', dockerfile)
        self.assertIn('Podman is now saving the Hermes image layer', dockerfile)

    def test_core_startup_failures_are_not_hidden(self) -> None:
        on_start = (ROOT / ".devcontainer" / "on-start.sh").read_text(encoding="utf-8")
        runtime = (ROOT / "asf" / "runtime.py").read_text(encoding="utf-8")
        sandbox = (ROOT / "sandbox.sh").read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", on_start)
        self.assertIn("RUNTIME_NAME=\"${ASF_AGENT:?", on_start)
        self.assertNotIn("${AGENT}", on_start)
        self.assertIn("exec python3 -m asf", sandbox)
        self.assertIn("run_open_session", runtime)
        self.assertNotIn("Agent session exited with status", runtime)
        lifecycle = (ROOT / "asf" / "open_lifecycle.py").read_text(encoding="utf-8")
        self.assertIn("Agent session exited with status", lifecycle)
        self.assertIn("shell=False", lifecycle)

    def test_real_integration_uses_a_service_command_not_stdin_forwarding(self) -> None:
        integration = (ROOT / "tests" / "test_integration.sh").read_text(encoding="utf-8")
        self.assertIn('"  mode: service\\n"', integration)
        self.assertIn('/workspace/sandbox/tests/integration-session-checks.sh', integration)
        self.assertIn('session_output=$(./sandbox.sh open claude 2>&1)', integration)
        self.assertNotIn('./sandbox.sh open claude 2>&1 <<CHECKS', integration)

    def test_mapfile_does_not_guard_process_substitution_status(self) -> None:
        """Ban a shell form that can never observe the producer's failure."""
        # Join backslash continuations first: the offending form is often
        # written across several lines, which a per-line scan would miss.
        pattern = re.compile(r"mapfile[^\n]*< <\(.*?\)[^\n]*\|\|", re.DOTALL)
        offenders: list[str] = []
        for path in sorted((ROOT / "lib").glob("*.sh")):
            raw = path.read_text(encoding="utf-8")
            logical = raw.replace("\\\n", " ")
            for number, line in enumerate(logical.splitlines(), 1):
                if pattern.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}: {line.strip()[:120]}")
        self.assertEqual(
            offenders,
            [],
            "capture producer output and check its status before mapfile:\n"
            + "\n".join(offenders),
        )

    def test_network_verifiers_share_one_typed_engine(self) -> None:
        startup = (ROOT / "asf" / "startup_verification.py").read_text(encoding="utf-8")
        security = (ROOT / "asf" / "security_test.py").read_text(encoding="utf-8")
        self.assertIn("VerificationEngine", startup)
        self.assertIn("VerificationEngine", security)
        self.assertFalse((ROOT / "lib").exists())

    def test_routed_cleanup_removes_initializer_and_gateway(self) -> None:
        cleanup = (ROOT / "asf" / "cleanup.py").read_text(encoding="utf-8")
        ownership = (ROOT / "asf" / "ownership.py").read_text(encoding="utf-8")
        self.assertIn("ResourceKind.GATEWAY_INIT_CONTAINER", cleanup)
        self.assertIn("ResourceKind.GATEWAY_CONTAINER", cleanup)
        self.assertIn("ResourceKind.GATEWAY_INIT_CONTAINER", ownership)
        self.assertIn("ResourceKind.GATEWAY_CONTAINER", ownership)

    def test_routed_cleanup_owns_reservation_release(self) -> None:
        cleanup = (ROOT / "asf" / "cleanup.py").read_text(encoding="utf-8")
        allocator = (ROOT / "asf" / "routed_allocation.py").read_text(encoding="utf-8")
        self.assertIn("ResourceKind.SUBNET_RESERVATION", cleanup)
        self.assertIn(
            "self._remove_file(resource, self._expected_reservation(resource))",
            cleanup,
        )
        self.assertIn("reservation_path", allocator)
        self.assertIn("def _write(", allocator)

    def test_routed_cleanup_avoids_one_step_forced_removal(self) -> None:
        cleanup = (ROOT / "asf" / "cleanup.py").read_text(encoding="utf-8")
        routed_cleanup = cleanup.split("def _remove_routed_container", 1)[1].split(
            "def _inspect_after_failed_stop", 1
        )[0]
        self.assertIn('"stop"', routed_cleanup)
        self.assertIn('"rm"', routed_cleanup)
        self.assertNotIn('"--force"', routed_cleanup)

    def test_routed_gateway_holder_is_signal_aware(self) -> None:
        routed = (ROOT / "asf" / "routed.py").read_text(encoding="utf-8")
        self.assertIn("trap 'exit 0' TERM INT HUP", routed)
        self.assertIn("/usr/local/bin/asf-gateway-holder", routed)
        self.assertIn("--stop-timeout=2", routed)
        self.assertNotIn('CMD ["sleep", "infinity"]', routed)


    def test_routed_integration_prints_success_evidence(self) -> None:
        integration = (ROOT / "tests" / "test_routed_integration.sh").read_text(encoding="utf-8")
        expected = (
            "External routed lifecycle",
            "allowed TCP %s reached",
            "known-open TCP %s denied by routed policy",
            "runtime has no IPv4 default route",
            "runtime effective and bounding capabilities are zero",
            "capability-less gateway ready; NET_ADMIN initializer exited",
            "containers, networks, and subnet reservation cleaned up",
        )
        for evidence in expected:
            self.assertIn(evidence, integration)


    def test_routed_security_check_accepts_host_route_without_slash32(self):
        executor = (ROOT / "asf" / "verification" / "executors.py").read_text()
        self.assertNotIn("grep -q '^${cidr} via '", executor)
        self.assertIn('grep -Eq "(^|[[:space:]])via[[:space:]]+"', executor)



if __name__ == "__main__":
    unittest.main()
