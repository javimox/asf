#!/usr/bin/env python3
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def parse_shell_assignments(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip('"\'')
    return result


class DependencyPinTests(unittest.TestCase):
    def test_top_level_dependencies_are_pinned(self) -> None:
        config = parse_shell_assignments(ROOT / "asf.conf")
        required = {
            "NODE_IMAGE",
            "UV_IMAGE",
            "SEMGREP_VERSION",
            "CLAUDE_CODE_VERSION",
            "HERMES_AGENT_COMMIT",
            "GIT_DELTA_VERSION",
            "FZF_VERSION",
            "FZF_SHA256_AMD64",
            "FZF_SHA256_ARM64",
            "ZSH_IN_DOCKER_VERSION",
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

    def test_broker_image_uses_exact_release_tag(self) -> None:
        broker = parse_shell_assignments(ROOT / "asf.conf")
        image = broker["LITELLM_IMAGE"]
        self.assertRegex(image, r":v\d+\.\d+\.\d+$")
        self.assertNotIn("main-stable", image)

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
        runtime = (ROOT / "asf" / "runtime.py").read_text(encoding="utf-8")
        security = (ROOT / "asf" / "security_test.py").read_text(encoding="utf-8")
        self.assertIn("VerificationEngine", runtime)
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
