"""Phase 2D live-security command tests across every supported mode."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from asf.manifest import ManifestError
from asf.paths import RepoPaths
from asf.podman import PodmanClient
from asf.process import CommandResult
from asf.security_test import (
    OutputEvent,
    OutputStream,
    SecurityTestResult,
    run_security_test_command,
)


class FakePodmanRunner:
    def __init__(
        self,
        paths: RepoPaths,
        runtime: str,
        mode: str,
        *,
        broker: bool,
        stale: bool = False,
        infrastructure_failure: bool = False,
        gateway_inspect_failure: bool = False,
    ) -> None:
        self.paths = paths
        self.runtime = runtime
        self.mode = mode
        self.broker = broker
        self.stale = stale
        self.infrastructure_failure = infrastructure_failure
        self.gateway_inspect_failure = gateway_inspect_failure
        names = paths.identity.network_names(runtime)
        self.containers: dict[str, dict[str, object]] = {
            "runtime-id": self._container(
                "runtime-id",
                paths.identity.container_name(runtime),
                "runtime",
                (names.internal, names.scan) if mode == "routed" else (names.internal,),
                running=not stale,
                user="1000:1000",
            )
        }
        if broker:
            self.containers["broker-id"] = self._container(
                "broker-id", "broker", "broker", (names.internal, names.provider)
            )
        if mode == "proxy":
            self.containers["proxy-id"] = self._container(
                "proxy-id",
                "proxy",
                "proxy",
                (names.egress, names.internal),
                user="10001:10001",
            )
        if mode == "routed":
            self.containers["gateway-id"] = self._container(
                "gateway-id",
                "gateway",
                "routed-gateway",
                (names.routed_egress, names.scan),
            )

    def _container(
        self,
        identifier: str,
        name: str,
        role: str,
        networks: tuple[str, ...],
        *,
        running: bool = True,
        user: str = "",
    ) -> dict[str, object]:
        labels = {
            "asf.sandbox": str(self.paths.root),
            "asf.agent": self.runtime,
            "asf.role": role,
        }
        if role == "runtime":
            labels["asf.session"] = self.paths.identity.session_key(self.runtime)
        return {
            "Id": identifier,
            "Name": name,
            "Config": {"Image": "image:test", "Labels": labels, "User": user},
            "State": {
                "Status": "running" if running else "exited",
                "Running": running,
                "ExitCode": 0,
            },
            "NetworkSettings": {"Networks": {item: {} for item in networks}},
            "HostConfig": {"ReadonlyRootfs": True, "PortBindings": {}},
        }

    def __call__(
        self,
        argv,
        *,
        timeout: float,
        input_text: str | None = None,
        **_kwargs,
    ) -> CommandResult:
        args = tuple(str(item) for item in argv)
        if args[1:3] == ("ps", "-q") or args[1] == "ps":
            include_stopped = "--all" in args
            filters = [args[index + 1] for index, value in enumerate(args) if value == "--filter"]
            found = []
            for identifier, item in self.containers.items():
                state = item["State"]
                assert isinstance(state, dict)
                if not include_stopped and not state["Running"]:
                    continue
                labels = item["Config"]["Labels"]  # type: ignore[index]
                if all(
                    filter_value.removeprefix("label=").split("=", 1)[0] in labels
                    and labels[filter_value.removeprefix("label=").split("=", 1)[0]]
                    == filter_value.removeprefix("label=").split("=", 1)[1]
                    for filter_value in filters
                ):
                    found.append(identifier)
            return CommandResult(args, 0, "".join(f"{item}\n" for item in found), "")
        if args[1:4] == ("inspect", "--type", "container"):
            refs = args[4:]
            if self.gateway_inspect_failure and "gateway-id" in refs:
                return CommandResult(args, 125, "", "gateway inspect failed")
            missing = [ref for ref in refs if ref not in self.containers]
            if missing:
                return CommandResult(args, 125, "", "Error: no such container")
            return CommandResult(
                args,
                0,
                json.dumps([self.containers[ref] for ref in refs]),
                "",
            )
        if args[1] == "exec":
            offset = 3 if len(args) > 2 and args[2] == "-i" else 2
            reference = args[offset]
            command = args[offset + 1 :]
            return self._exec(args, reference, command, input_text)
        raise AssertionError(f"unexpected Podman command: {args}")

    def _exec(
        self,
        argv: tuple[str, ...],
        reference: str,
        command: tuple[str, ...],
        input_text: str | None,
    ) -> CommandResult:
        rendered = " ".join(command)
        if reference == "proxy-id" and command == ("cat", "/etc/caddy/Caddyfile"):
            manifest = self.paths.identity.runtime_manifest(self.runtime).read_text()
            domains = []
            in_allow = False
            for line in manifest.splitlines():
                if line.strip() == "allow_domains:":
                    in_allow = True
                    continue
                if in_allow and line.startswith("    - "):
                    domains.append(line.split("-", 1)[1].strip())
                elif in_allow and line and not line.startswith(" "):
                    in_allow = False
            if self.broker:
                domains = [item for item in domains if item != "api.anthropic.com"]
            policy = (
                ":3128 {\n  forward_proxy {\n    ports 443\n    acl {\n"
                "      deny 10.0.0.0/8\n      deny 169.254.0.0/16\n"
                + "".join(f"      allow {item}\n" for item in sorted(domains))
                + "      deny all\n    }\n  }\n}\n"
            )
            return CommandResult(argv, 0, policy, "")
        if command and command[0] == "printenv":
            return CommandResult(argv, 1, "", "")
        if input_text is not None:
            if self.infrastructure_failure and "example.com:443" in input_text:
                return CommandResult(argv, 125, "", "engine failure")
            allowed = "statsig.com:443" in input_text
            code, status = (20, 200) if allowed else (40, 403)
            return CommandResult(argv, code, f"HTTP/1.1 {status} Result\n", "")
        if command and command[0] == "nc":
            port = command[-1]
            if reference == "runtime-id" and self.mode == "routed":
                return CommandResult(argv, 0 if port == "18080" else 1, "", "")
            return CommandResult(argv, 0, "", "")
        if command[:2] == ("sh", "-c") and "route show default" in command[2]:
            return CommandResult(argv, 22, "", "")
        if command[:4] in (("ip", "-4", "route", "get"), ("ip", "-6", "route", "get")):
            return CommandResult(argv, 2, "", "RTNETLINK: Network is unreachable")
        if "getent ahostsv4" in rendered:
            return CommandResult(argv, 1, "", "")
        if ".asf-write-test" in rendered or "/etc/.asf-write-test" in rendered:
            return CommandResult(argv, 1, "", "Read-only file system")
        if "ip -4 route show" in rendered and "grep -Eq" in rendered:
            return CommandResult(argv, 0, "192.0.2.0/24 via 10.0.0.1\n", "")
        return CommandResult(argv, 0, "", "")


class SecurityCommandTests(unittest.TestCase):
    def make_checkout(
        self,
        mode: str,
        *,
        broker: bool,
        allow_domains: tuple[str, ...] = ("api.anthropic.com", "statsig.com"),
        verify_domain: str | None = "statsig.com",
        stale: bool = False,
        infrastructure_failure: bool = False,
        gateway_inspect_failure: bool = False,
        event_sink=None,
    ):
        temporary = tempfile.TemporaryDirectory()
        try:
            root = Path(temporary.name) / "asf"
            (root / "agents" / "claude").mkdir(parents=True)
            (root / ".devcontainer").mkdir()
            (root / "secrets").mkdir()
            (root / "sandbox.sh").write_text("#!/bin/sh\n")
            (root / "asf.conf").write_text(
                f"BROKER_ENABLED={'true' if broker else 'false'}\n"
            )
            llm = (
                "llm:\n  broker: true\n  protocol: anthropic\n"
                "  provider: anthropic\n"
                if broker
                else "llm:\n  broker: false\n"
            )
            network = ["network:", f"  mode: {mode}"]
            if mode == "proxy":
                if verify_domain is not None:
                    network.append(f"  verify_domain: {verify_domain}")
                if allow_domains:
                    network.append("  allow_domains:")
                    network.extend(f"    - {item}" for item in allow_domains)
                else:
                    network.append("  allow_domains: []")
            elif mode == "routed":
                network.extend(
                    (
                        "  allow:",
                        "    - cidr: 192.0.2.2/32",
                        "      protocol: tcp",
                        "      ports: [18080]",
                        "  verify:",
                        "    address: 192.0.2.2",
                        "    protocol: tcp",
                        "    port: 18080",
                        "    blocked_port: 19999",
                    )
                )
            manifest = (
                "name: claude\nadapter: claude\n"
                + llm
                + "\n".join(network)
                + "\nsecrets:\n  files: [claude.env]\n"
            )
            (root / "agents" / "claude" / "runtime.yml").write_text(manifest)
            (root / "secrets" / "claude.env").write_text(
                "ANTHROPIC_API_KEY=provider-secret\n"
            )
            paths = RepoPaths.for_root(root)
            runner = FakePodmanRunner(
                paths,
                "claude",
                mode,
                broker=broker,
                stale=stale,
                infrastructure_failure=infrastructure_failure,
                gateway_inspect_failure=gateway_inspect_failure,
            )
            result = run_security_test_command(
                ("test", "claude"),
                paths,
                podman=PodmanClient(runner=runner),
                require_available=False,
                event_sink=event_sink,
            )
            return temporary, result
        except BaseException:
            temporary.cleanup()
            raise

    @staticmethod
    def combined(result) -> str:
        return "".join(event.text for event in result.events)

    def test_proxy_broker_enabled_report(self) -> None:
        temporary, result = self.make_checkout("proxy", broker=True)
        self.addCleanup(temporary.cleanup)
        output = self.combined(result)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Testing claude security boundaries", output)
        self.assertIn("LiteLLM broker is running", output)
        self.assertIn("Caddy policy matches the effective manifest", output)
        self.assertIn("Security test passed:", output)

    def test_proxy_broker_disabled_and_empty_allowlist(self) -> None:
        temporary, result = self.make_checkout(
            "proxy",
            broker=False,
            allow_domains=(),
            verify_domain=None,
        )
        self.addCleanup(temporary.cleanup)
        output = self.combined(result)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("LiteLLM broker is running", output)
        self.assertIn("no external allow path declared", output)

    def test_isolated_broker_enabled_and_disabled(self) -> None:
        for broker in (True, False):
            with self.subTest(broker=broker):
                temporary, result = self.make_checkout("isolated", broker=broker)
                self.addCleanup(temporary.cleanup)
                output = self.combined(result)
                self.assertEqual(result.returncode, 0)
                self.assertIn("external DNS is unavailable", output)
                self.assertEqual("LiteLLM broker is running" in output, broker)

    def test_routed_report(self) -> None:
        temporary, result = self.make_checkout("routed", broker=False)
        self.addCleanup(temporary.cleanup)
        output = self.combined(result)
        self.assertEqual(result.returncode, 0)
        self.assertIn("routed gateway is running", output)
        self.assertIn("known-open blocked routed port is denied", output)
        self.assertIn("NET_ADMIN initializer has exited", output)

    def test_routed_gateway_inspect_failure_stays_in_the_report(self) -> None:
        temporary, result = self.make_checkout(
            "routed",
            broker=False,
            gateway_inspect_failure=True,
        )
        self.addCleanup(temporary.cleanup)
        output = self.combined(result)
        self.assertEqual(result.returncode, 1)
        self.assertIn("routed gateway capability mode is inspectable", output)
        self.assertIn("test infrastructure failed", output)

    def test_missing_positive_control_fails_manifest_validation(self) -> None:
        with self.assertRaises(ManifestError):
            self.make_checkout(
                "proxy",
                broker=False,
                allow_domains=("statsig.com",),
                verify_domain=None,
            )

    def test_stale_session_is_not_treated_as_running(self) -> None:
        temporary, result = self.make_checkout(
            "isolated", broker=False, stale=True
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(result.returncode, 1)
        self.assertIn("No running claude container", self.combined(result))

    def test_expected_deny_plus_infrastructure_failure_fails(self) -> None:
        temporary, result = self.make_checkout(
            "proxy",
            broker=False,
            infrastructure_failure=True,
        )
        self.addCleanup(temporary.cleanup)
        output = self.combined(result)
        self.assertEqual(result.returncode, 1)
        self.assertIn("test infrastructure failed: 125", output)
        self.assertIn("Security test failed:", output)


    def test_event_sink_streams_the_same_ordered_events(self) -> None:
        streamed: list[OutputEvent] = []
        temporary, result = self.make_checkout(
            "proxy",
            broker=False,
            event_sink=streamed.append,
        )
        self.addCleanup(temporary.cleanup)
        self.assertEqual(tuple(streamed), result.events)
        self.assertGreater(len(streamed), 1)
        self.assertIn("Testing claude", streamed[0].text)

    def test_events_preserve_stream_selection(self) -> None:
        temporary, result = self.make_checkout("proxy", broker=False)
        self.addCleanup(temporary.cleanup)
        self.assertTrue(all(event.stream is OutputStream.STDOUT for event in result.events))

    def test_result_model_is_immutable_and_validated(self) -> None:
        event = OutputEvent(OutputStream.STDOUT, "ok\n")
        result = SecurityTestResult(0, [event])  # type: ignore[arg-type]
        self.assertEqual(result.events, (event,))
        with self.assertRaises(TypeError):
            SecurityTestResult(True, (event,))  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            SecurityTestResult(-1, (event,))
        with self.assertRaises(TypeError):
            SecurityTestResult(1, ("bad",))  # type: ignore[arg-type]

    def test_production_bash_security_implementation_is_removed(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertFalse((root / "lib").exists())
        sandbox = (root / "sandbox.sh").read_text()
        self.assertIn("exec python3 -m asf", sandbox)
        self.assertNotIn("cmd_test", sandbox)


if __name__ == "__main__":
    unittest.main()
