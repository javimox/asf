#!/usr/bin/env python3
"""Focused tests for the Phase 4E host configuration reader."""

from __future__ import annotations

import socket
import tempfile
import unittest
from pathlib import Path

from asf.config import AsfConfig, AsfConfigError
from asf.manifest import load_model

ROOT = Path(__file__).resolve().parents[1]


class AsfConfigTests(unittest.TestCase):
    def write_config(self, directory: Path, text: str) -> Path:
        path = directory / "asf.conf"
        path.write_text(text, encoding="utf-8")
        return path

    def test_current_configuration_is_parsed_without_execution(self) -> None:
        config = AsfConfig.load(ROOT / "asf.conf")
        self.assertTrue(config.broker_enabled)
        self.assertEqual(config.broker_image, "ghcr.io/berriai/litellm:v1.93.0")
        self.assertEqual(config.broker_startup_timeout, 60)
        self.assertTrue(config.caddy_access_logs)
        self.assertEqual(
            config.build_arguments()[0],
            "NODE_IMAGE=node:22.23.1-bookworm-slim",
        )
        self.assertEqual(len(config.build_arguments()), 10)

    def test_comments_quotes_and_last_assignment_win(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self.write_config(
                Path(temporary),
                'VALUE=first\nVALUE="second value" # comment\nEMPTY=""\n',
            )
            config = AsfConfig.load(path)
            self.assertEqual(config.text("VALUE"), "second value")
            self.assertEqual(config.text("EMPTY"), "")
            with self.assertRaises(TypeError):
                config.values["VALUE"] = "changed"  # type: ignore[index]

    def test_unsupported_syntax_symlinks_and_invalid_values_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bad = self.write_config(root, "VALUE=one two\n")
            with self.assertRaises(AsfConfigError):
                AsfConfig.load(bad)
            bad.write_text("BROKER_ENABLED=perhaps\n", encoding="utf-8")
            with self.assertRaises(AsfConfigError):
                AsfConfig.load(bad).broker_enabled
            for expansion in ("VALUE=$(id)\n", "VALUE=$HOME\n", "VALUE=`id`\n"):
                bad.write_text(expansion, encoding="utf-8")
                with self.assertRaisesRegex(
                    AsfConfigError, "Shell expansion is not supported"
                ):
                    AsfConfig.load(bad)
            target = root / "real.conf"
            target.write_text("BROKER_ENABLED=true\n", encoding="utf-8")
            link = root / "linked.conf"
            link.symlink_to(target)
            with self.assertRaises(AsfConfigError):
                AsfConfig.load(link)

    def test_missing_build_pin_keeps_the_accepted_error_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = AsfConfig.load(
                self.write_config(Path(temporary), "NODE_IMAGE=x\n")
            )
            with self.assertRaisesRegex(
                AsfConfigError,
                r"Missing required value in asf\.conf \(build section\): UV_IMAGE",
            ):
                config.build_arguments()

    def test_hardening_arguments_preserve_mandatory_and_optional_controls(self) -> None:
        config = AsfConfig.load(ROOT / "asf.conf")
        manifest = load_model(ROOT / "agents" / "claude" / "runtime.yml")
        arguments = config.hardening_arguments(manifest)
        self.assertEqual(
            arguments[:5],
            (
                "--mount=type=tmpfs,target=/workspace/sandbox/secrets,ro=true,"
                "tmpfs-size=1048576,tmpfs-mode=0755,notmpcopyup",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--sysctl=net.ipv4.ip_forward=0",
                "--sysctl=net.ipv6.conf.all.forwarding=0",
            ),
        )
        self.assertIn("--pids-limit=256", arguments)
        self.assertIn("--memory=3g", arguments)
        self.assertIn("--tmpfs=/run:rw,nosuid,nodev,noexec,size=64m", arguments)
        self.assertIn("--ipc=private", arguments)
        self.assertNotIn("--cap-add=NET_ADMIN", arguments)

    def test_proxy_implementation_is_caddy_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            AsfConfig.load(
                self.write_config(root, "PROXY_IMPL=caddy\n")
            ).require_caddy()
            with self.assertRaises(AsfConfigError):
                AsfConfig.load(
                    self.write_config(root, "PROXY_IMPL=tinyproxy\n")
                ).require_caddy()

    def test_ssh_forwarding_requires_a_real_socket(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            socket_path = root / "agent.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(socket_path))
                config = AsfConfig.load(
                    self.write_config(
                        root,
                        "SSH_AGENT_FORWARDING=true\n"
                        f'SSH_AGENT_SOCKET="{socket_path}"\n',
                    )
                )
                self.assertEqual(config.ssh_agent_socket(), socket_path)
            socket_path.unlink()
            with self.assertRaises(AsfConfigError):
                config.ssh_agent_socket()


if __name__ == "__main__":
    unittest.main()
