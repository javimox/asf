#!/usr/bin/env python3
"""Typed-model and compatibility tests for :mod:`asf.manifest`."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asf.errors import ConfigurationError  # noqa: E402
from asf.manifest import (  # noqa: E402
    ManifestError,
    load,
    load_model,
    parse,
    validate,
)
from asf.models import RuntimeManifest  # noqa: E402

MINIMAL = {
    "name": "demo",
    "llm": {"broker": True, "protocol": "openai", "provider": "openai"},
}


class TypedManifestTests(unittest.TestCase):
    def test_manifest_error_uses_shared_configuration_hierarchy(self) -> None:
        self.assertTrue(issubclass(ManifestError, ConfigurationError))
        self.assertEqual(ManifestError("failure").exit_code, 1)

    def test_parse_returns_immutable_defaults(self) -> None:
        model = parse({"name": "demo"})
        self.assertIsInstance(model, RuntimeManifest)
        self.assertEqual(model.name, "demo")
        self.assertEqual(model.adapter, "generic")
        self.assertEqual(model.runtime.mode, "interactive")
        self.assertEqual(model.runtime.command, ())
        self.assertIsNone(model.llm)
        self.assertEqual(model.network.mode, "proxy")
        self.assertFalse(model.observability.llm_prompts)
        self.assertEqual(model.capabilities, frozenset())
        with self.assertRaises(FrozenInstanceError):
            model.name = "changed"  # type: ignore[misc]

    def test_empty_llm_mapping_disables_the_broker(self) -> None:
        model = parse({"name": "demo", "llm": {}})
        self.assertIsNone(model.llm)

    def test_proxy_manifest_becomes_typed_model(self) -> None:
        model = load_model(ROOT / "agents" / "hermes" / "runtime.yml")
        self.assertEqual(model.name, "hermes")
        self.assertEqual(model.adapter, "hermes")
        self.assertEqual(model.state_volumes[0].key, "config")
        self.assertEqual(model.llm.protocol, "openai")
        self.assertTrue(model.llm.broker)
        self.assertEqual(model.network.mode, "proxy")
        self.assertEqual(model.network.allow_domains, ())
        self.assertIsNone(model.network.verify_domain)
        self.assertEqual(
            model.environment_dict()["HERMES_YOLO_MODE"],
            "0",
        )
        self.assertEqual(model.environment_dict()["TIRITH_OFFLINE"], "1")

    def test_prompt_observability_is_explicit_and_typed(self) -> None:
        model = parse(
            {
                **MINIMAL,
                "observability": {"llm_prompts": True},
            }
        )
        self.assertTrue(model.observability.llm_prompts)

    def test_prompt_observability_requires_broker(self) -> None:
        with self.assertRaisesRegex(ManifestError, "requires llm.broker: true"):
            validate(
                {
                    "name": "demo",
                    "llm": {"broker": False},
                    "observability": {"llm_prompts": True},
                }
            )

    def test_prompt_observability_requires_a_configured_broker(self) -> None:
        with self.assertRaisesRegex(ManifestError, "requires llm.broker: true"):
            validate(
                {
                    "name": "demo",
                    "llm": {},
                    "observability": {"llm_prompts": True},
                }
            )

    def test_prompt_observability_rejects_non_boolean(self) -> None:
        with self.assertRaisesRegex(ManifestError, "must be true or false"):
            validate(
                {
                    **MINIMAL,
                    "observability": {"llm_prompts": "yes"},
                }
            )

    def test_network_capture_is_not_a_manifest_setting(self) -> None:
        with self.assertRaisesRegex(ManifestError, "unknown key.*network_capture"):
            validate(
                {
                    "name": "demo",
                    "observability": {"network_capture": True},
                }
            )

    def test_routed_manifest_uses_ipaddress_types(self) -> None:
        model = parse(
            {
                **MINIMAL,
                "network": {
                    "mode": "routed",
                    "allow": [
                        {
                            "cidr": "192.0.2.0/24",
                            "protocol": "tcp",
                            "ports": [443],
                        }
                    ],
                    "verify": {
                        "address": "192.0.2.9",
                        "protocol": "tcp",
                        "port": 443,
                        "blocked_port": 22,
                    },
                },
            }
        )
        rule = model.network.routed_rules[0]
        verification = model.network.routed_verification
        self.assertEqual(rule.destination, IPv4Network("192.0.2.0/24"))
        self.assertEqual(rule.ports, (443,))
        self.assertEqual(verification.address, IPv4Address("192.0.2.9"))
        self.assertEqual(verification.allowed_port, 443)
        self.assertTrue(rule.permits(verification.address, "tcp", 443))
        self.assertFalse(rule.permits(verification.address, "tcp", 22))

    def test_routed_manifest_does_not_require_live_verification(self) -> None:
        model = parse(
            {
                **MINIMAL,
                "network": {
                    "mode": "routed",
                    "allow": [
                        {
                            "cidr": "192.0.2.9/32",
                            "protocol": "tcp",
                            "ports": [443],
                        }
                    ],
                },
            }
        )
        self.assertIsNone(model.network.routed_verification)

    def test_routed_destination_only_rule_uses_separate_negative_control(self) -> None:
        model = parse(
            {
                **MINIMAL,
                "network": {
                    "mode": "routed",
                    "allow": [{"cidr": "192.0.2.9/32"}],
                    "verify": {
                        "address": "192.0.2.9",
                        "protocol": "tcp",
                        "port": 443,
                        "blocked_address": "198.51.100.9",
                        "blocked_port": 443,
                    },
                },
            }
        )
        rule = model.network.routed_rules[0]
        verification = model.network.routed_verification
        self.assertIsNone(rule.protocol)
        self.assertIsNone(rule.ports)
        self.assertEqual(verification.denied_address, IPv4Address("198.51.100.9"))

    def test_routed_ports_without_protocol_are_rejected(self) -> None:
        with self.assertRaises(ManifestError):
            validate(
                {
                    **MINIMAL,
                    "network": {
                        "mode": "routed",
                        "allow": [{"cidr": "192.0.2.9/32", "ports": [443]}],
                        "verify": {
                            "address": "192.0.2.9",
                            "protocol": "tcp",
                            "port": 443,
                            "blocked_address": "198.51.100.9",
                            "blocked_port": 443,
                        },
                    },
                }
            )



class ValidationBoundaryTests(unittest.TestCase):
    def test_security_identifiers_use_full_string_matching(self) -> None:
        bad_values = (
            {**MINIMAL, "name": "demo\n"},
            {
                **MINIMAL,
                "llm": {
                    "broker": True,
                    "protocol": "openai",
                    "provider": "openai\n",
                },
            },
            {**MINIMAL, "env": {"MODE\n": "safe"}},
            {**MINIMAL, "secrets": {"files": ["demo.env\n"]}},
        )
        for data in bad_values:
            with self.subTest(data=data), self.assertRaises(ManifestError):
                validate(data)

    def test_non_text_unknown_keys_do_not_leak_sorting_errors(self) -> None:
        with self.assertRaises(ManifestError) as caught:
            validate({**MINIMAL, 7: "unexpected"})
        self.assertIn("unknown key", str(caught.exception))
        self.assertIn("7", str(caught.exception))

    def test_nested_mapping_types_are_checked_even_when_falsey(self) -> None:
        for build in (None, [], ""):
            with self.subTest(build=build), self.assertRaises(ManifestError):
                validate({**MINIMAL, "runtime": {"build": build}})

    def test_duplicate_capabilities_are_rejected_after_normalisation(self) -> None:
        for capabilities in (
            ["net_raw", "net_raw"],
            ["net_raw", "NET_RAW"],
        ):
            with self.subTest(capabilities=capabilities):
                with self.assertRaises(ManifestError):
                    validate({**MINIMAL, "capabilities": capabilities})

    def test_tirith_build_pins_are_asf_owned(self) -> None:
        for name in (
            "TIRITH_VERSION",
            "TIRITH_SHA256_AMD64",
            "TIRITH_SHA256_ARM64",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(
                ManifestError, "cannot override ASF-owned build inputs"
            ):
                validate(
                    {
                        **MINIMAL,
                        "runtime": {"build": {"args": {name: "override"}}},
                    }
                )

    def test_build_argument_names_and_os_boundary_values_are_validated(self) -> None:
        invalid = (
            {**MINIMAL, "runtime": {"build": {"args": {"bad name": "1"}}}},
            {**MINIMAL, "runtime": {"build": {"args": {"SAFE": "x\x00y"}}}},
            {
                **MINIMAL,
                "runtime": {
                    "mode": "service",
                    "command": ["python", "x\x00y"],
                },
            },
            {**MINIMAL, "env": {"MODE": "safe\x00unsafe"}},
            {
                **MINIMAL,
                "filesystem": {
                    "state": [{"key": "cache", "target": "/cache\x00bad"}]
                },
            },
        )
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(ManifestError):
                validate(data)

    def test_load_wraps_missing_invalid_and_non_utf8_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with self.assertRaises(ManifestError):
                load(base / "missing.yml")

            invalid_yaml = base / "invalid.yml"
            invalid_yaml.write_text("name: [", encoding="utf-8")
            with self.assertRaises(ManifestError) as invalid:
                load(invalid_yaml)
            self.assertIn(str(invalid_yaml), str(invalid.exception))

            binary = base / "binary.yml"
            binary.write_bytes(b"name: \xff\n")
            with self.assertRaises(ManifestError) as undecodable:
                load(binary)
            self.assertIn("UTF-8", str(undecodable.exception))

    def test_missing_yaml_dependency_is_reported_without_import_time_exit(self) -> None:
        with mock.patch("asf.manifest.yaml", None):
            with self.assertRaises(ManifestError) as caught:
                load("manifest.yml")
        self.assertIn("PyYAML is required", str(caught.exception))


class ManifestCliTests(unittest.TestCase):
    def test_module_cli_emits_json(self) -> None:
        manifest = ROOT / "agents" / "claude" / "runtime.yml"
        result = subprocess.run(
            [sys.executable, "-m", "asf.manifest", manifest, "--emit", "json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["name"], "claude")

    def test_module_cli_preserves_invalid_manifest_exit_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.yml"
            path.write_text("name: Invalid\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "asf.manifest", path],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr.startswith("Invalid runtime manifest: "))


if __name__ == "__main__":
    unittest.main()
