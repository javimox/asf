"""Focused tests for the host-side observe command."""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from collections.abc import Sequence
from ipaddress import IPv4Network
from pathlib import Path
from typing import Any
from unittest.mock import patch

from asf.broker_metadata import prepare_broker_request_log
from asf.cli import main
from asf.manifest import load_model
from asf.observability import run_observe_command
from asf.runs import begin_run, write_run_policy
from asf.paths import RepoPaths
from asf.podman import PodmanClient
from asf.process import CommandResult
from asf.routed_allocation import RoutedSubnetAllocation
from asf.runtime_plan import build_runtime_plan
from asf.session_events import record_session_event


def make_checkout(root: Path) -> RepoPaths:
    (root / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
    (root / ".devcontainer").mkdir()
    runtime = root / "agents" / "hermes"
    runtime.mkdir(parents=True)
    (runtime / "runtime.yml").write_text(
        """name: hermes
adapter: hermes
runtime:
  isolation: microvm
network:
  mode: routed
  allow:
    - cidr: 192.0.2.10/32
capabilities: [net_raw]
llm:
  broker: true
  protocol: openai
  provider: openai
  api_key_env: OPENAI_API_KEY
"""
    )
    with patch.dict(os.environ, {"XDG_STATE_HOME": str(root.parent / "state")}):
        return RepoPaths.for_root(root)


def inspection(container_id: str, name: str, role: str, pid: int) -> str:
    labels = {"asf.agent": "hermes", "asf.role": role}
    return json.dumps(
        [
            {
                "Id": container_id,
                "Name": name,
                "Config": {"Image": "test:image", "Labels": labels},
                "State": {"Status": "running", "Running": True, "Pid": pid},
                "NetworkSettings": {"Networks": {}},
            }
        ]
    )


class ObserveRunner:
    def __init__(self, *, network_observer: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.network_observer = network_observer

    def __call__(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        timeout: float,
        **_: Any,
    ) -> CommandResult:
        del timeout
        call = tuple(os.fspath(value) for value in argv)
        self.calls.append(call)
        command = call[1:]
        stdout = ""
        stderr = ""
        returncode = 0

        if command[:1] == ("ps",):
            joined = " ".join(command)
            if "asf.session=" in joined:
                stdout = "runtime-id\n"
            elif "asf.role=broker" in joined:
                stdout = "broker-id\n"
            elif "asf.role=routed-gateway" in joined:
                stdout = "gateway-id\n"
            elif "asf.role=routed-init" in joined:
                stdout = ""
            elif "asf.role=network-observer" in joined:
                stdout = "observer-id\n" if self.network_observer else ""
        elif command[:3] == ("inspect", "--type", "container"):
            reference = command[3]
            if reference == "runtime-id":
                stdout = inspection(reference, "hermes-runtime", "runtime", 101)
            elif reference == "broker-id":
                stdout = inspection(reference, "hermes-broker", "broker", 102)
            elif reference == "gateway-id":
                stdout = inspection(reference, "hermes-gateway", "routed-gateway", 103)
            elif reference == "observer-id":
                stdout = inspection(reference, "hermes-capture", "network-observer", 104)
            else:
                returncode = 125
                stderr = "Error: no such container\n"
        else:
            raise AssertionError(f"unexpected command: {call}")

        return CommandResult(call, returncode, stdout, stderr)


class ObserveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "asf"
        root.mkdir()
        self.environment = patch.dict(
            os.environ, {"XDG_STATE_HOME": str(Path(self.temporary.name) / "state")}
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.paths = make_checkout(root)
        self.observation = begin_run(self.paths, "hermes")
        self._snapshot_policy()
        self.runner = ObserveRunner()
        self.podman = PodmanClient(engine="/bin/true", runner=self.runner)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _snapshot_policy(self) -> None:
        manifest = load_model(self.paths.identity.runtime_manifest("hermes"))
        plan = build_runtime_plan(
            manifest,
            paths=self.paths,
            owner_pid=4242,
            broker_globally_enabled=True,
            routed_subnets=RoutedSubnetAllocation(
                IPv4Network("10.76.1.0/24"),
                IPv4Network("10.77.1.0/24"),
                IPv4Network("10.79.1.0/24"),
            ),
        )
        write_run_policy(self.paths, plan, manifest)

    @patch("asf.observability._read_proc_status")
    def test_observe_reports_policy_and_host_boundary(self, read_status) -> None:
        read_status.return_value = {
            "CapEff": "0000000000000000",
            "CapBnd": "0000000000000000",
            "NoNewPrivs": "1",
        }
        record_session_event(self.paths, "hermes", "session_start")
        record_session_event(self.paths, "hermes", "broker_ready")
        broker_log = prepare_broker_request_log(self.paths, "hermes")
        broker_log.write_text(
            '{"event":"llm_request_complete","latency_ms":321,"model":"gpt-5.5","total_tokens":42,"ts":"2026-08-21T21:00:00+00:00"}\n',
            encoding="utf-8",
        )
        result = run_observe_command(
            ("observe", "hermes"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("ASF observation [hermes]", result.stdout)
        self.assertIn(f"run id:    {self.observation.session_id}", result.stdout)
        self.assertIn("isolation: microvm", result.stdout)
        self.assertIn("network:   routed", result.stdout)
        self.assertIn("capabilities: net_raw", result.stdout)
        self.assertIn("192.0.2.10/32 all IP traffic", result.stdout)
        self.assertIn("runtime/VMM", result.stdout)
        self.assertIn("LiteLLM broker", result.stdout)
        self.assertIn("routed gateway", result.stdout)
        self.assertIn("caps=none", result.stdout)
        self.assertIn("routed initializer  absent (expected after setup)", result.stdout)
        self.assertIn("recent lifecycle", result.stdout)
        self.assertIn("session_start", result.stdout)
        self.assertIn("broker_ready", result.stdout)
        self.assertIn("recent broker requests", result.stdout)
        self.assertIn("llm_request_complete", result.stdout)
        self.assertIn("model=gpt-5.5", result.stdout)
        self.assertIn("latency=321ms", result.stdout)
        self.assertIn("tokens=42", result.stdout)
        self.assertIn("llm prompts: disabled", result.stdout)
        self.assertEqual(read_status.call_count, 3)

    @patch("asf.observability._read_proc_status")
    def test_observe_reports_opt_in_prompt_capture_path(self, read_status) -> None:
        read_status.return_value = {
            "CapEff": "0000000000000000",
            "CapBnd": "0000000000000000",
            "NoNewPrivs": "1",
        }
        manifest = self.paths.identity.runtime_manifest("hermes")
        text = manifest.read_text(encoding="utf-8")
        text += "observability:\n  llm_prompts: true\n"
        manifest.write_text(text, encoding="utf-8")
        self._snapshot_policy()
        result = run_observe_command(
            ("observe", "hermes"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertIn("llm prompts: enabled", result.stdout)
        self.assertIn("llm-prompts.jsonl", result.stdout)
        self.assertNotIn("prompt contents", result.stdout)

    @patch("asf.observability._read_proc_status")
    def test_observe_reports_on_demand_capture_files(self, read_status) -> None:
        read_status.return_value = {
            "CapEff": "0000000000000000",
            "CapBnd": "0000000000000000",
            "NoNewPrivs": "1",
        }
        first = self.observation.directory / "network-20260825T220733Z.pcap"
        latest = self.observation.directory / "network-20260825T221418Z.pcap"
        first.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        latest.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 2044)
        os.chmod(first, 0o600)
        os.chmod(latest, 0o600)

        result = run_observe_command(
            ("observe", "hermes"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )

        self.assertIn("network capture", result.stdout)
        self.assertIn("status:   inactive", result.stdout)
        self.assertIn("captures: 2", result.stdout)
        self.assertIn("network-20260825T221418Z.pcap (2.0 KiB)", result.stdout)
        self.assertIn("tcpdump -nn -r", result.stdout)
        self.assertNotIn("recent network activity", result.stdout)
        self.assertNotIn("policy-match=", result.stdout)

    @patch("asf.observability._read_proc_status")
    def test_observe_reports_active_capture(self, read_status) -> None:
        read_status.return_value = {
            "CapEff": "0000000000002000",
            "CapBnd": "0000000000002000",
            "NoNewPrivs": "1",
        }
        capture = self.observation.directory / "network-20260825T220733Z.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        podman = PodmanClient(
            engine="/bin/true", runner=ObserveRunner(network_observer=True)
        )

        result = run_observe_command(
            ("observe", "hermes"),
            self.paths,
            podman=podman,
            require_available=False,
        )

        self.assertIn("packet capture", result.stdout)
        self.assertIn("caps=net_raw", result.stdout)
        self.assertIn("status:   active", result.stdout)
        self.assertIn("current:", result.stdout)
        self.assertIn(capture.name, result.stdout)

    @patch("asf.observability._read_proc_status")
    def test_observe_escapes_control_characters_from_log_fields(self, read_status) -> None:
        read_status.return_value = {
            "CapEff": "0000000000000000",
            "CapBnd": "0000000000000000",
            "NoNewPrivs": "1",
        }
        broker_log = prepare_broker_request_log(self.paths, "hermes")
        broker_log.write_text(
            '{"event":"llm_request_failed","model":"gpt\\u001b[31mRED\\u001b[0m\\n",'
            '"ts":"2026-08-21T21:00:00+00:00"}\n',
            encoding="utf-8",
        )
        result = run_observe_command(
            ("observe", "hermes"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertNotIn("\x1b", result.stdout)
        self.assertIn("model=gpt\\x1b[31mRED\\x1b[0m\\x0a", result.stdout)

    @patch("asf.observability._read_proc_status")
    def test_observe_decodes_capability_masks(self, read_status) -> None:
        read_status.return_value = {
            "CapEff": "0000000000003000",
            "CapBnd": "0000000000003000",
            "NoNewPrivs": "1",
        }
        result = run_observe_command(
            ("observe", "hermes"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertIn("caps=net_admin,net_raw", result.stdout)

    @patch("asf.observability._read_proc_status")
    def test_observe_uses_frozen_policy_not_edited_manifest(self, read_status) -> None:
        read_status.return_value = {
            "CapEff": "0000000000000000",
            "CapBnd": "0000000000000000",
            "NoNewPrivs": "1",
        }
        manifest = self.paths.identity.runtime_manifest("hermes")
        manifest.write_text(
            """name: hermes
adapter: hermes
runtime:
  isolation: container
network:
  mode: proxy
  verify_domain: example.com
  allow_domains: [example.com]
llm:
  broker: false
""",
            encoding="utf-8",
        )
        result = run_observe_command(
            ("observe", "hermes"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertIn("isolation: microvm", result.stdout)
        self.assertIn("network:   routed", result.stdout)
        self.assertIn("broker:    enabled", result.stdout)
        self.assertIn("192.0.2.10/32 all IP traffic", result.stdout)

    @patch("asf.observability._read_proc_status")
    def test_cli_exposes_observe(self, read_status) -> None:
        read_status.return_value = {
            "CapEff": "0000000000000000",
            "CapBnd": "0000000000000000",
            "NoNewPrivs": "1",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        code = main(
            ("observe", "hermes"),
            root=self.paths.root,
            stdout=stdout,
            stderr=stderr,
            podman=self.podman,
        )
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("ASF observation [hermes]", stdout.getvalue())

    def test_usage_is_small(self) -> None:
        result = run_observe_command(
            ("observe", "hermes", "extra"),
            self.paths,
            podman=self.podman,
            require_available=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "Usage: ./sandbox.sh observe [agent]\n")


if __name__ == "__main__":
    unittest.main()
