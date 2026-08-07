#!/usr/bin/env python3
"""Manifest schema and validation tests."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from asf import manifest as load_runtime

ManifestError = load_runtime.ManifestError

MINIMAL = {
    "name": "demo",
    "llm": {"broker": True, "protocol": "openai", "provider": "openai"},
}


class ValidationTests(unittest.TestCase):
    def test_minimal_manifest_is_valid(self) -> None:
        self.assertEqual(load_runtime.validate(dict(MINIMAL))["name"], "demo")

    def test_name_is_required_and_constrained(self) -> None:
        with self.assertRaises(ManifestError):
            load_runtime.validate({"llm": {}})
        for bad in ("Demo", "de mo", "-demo", "de/mo"):
            with self.assertRaises(ManifestError, msg=bad):
                load_runtime.validate({**MINIMAL, "name": bad})

    def test_unknown_keys_are_rejected_at_every_level(self) -> None:
        # A typo must fail loudly, not be silently ignored.
        cases = [
            {**MINIMAL, "netwrok": {}},
            {**MINIMAL, "llm": {**MINIMAL["llm"], "protocl": "openai"}},
            {**MINIMAL, "runtime": {"moed": "service"}},
            {**MINIMAL, "secrets": {"file": ["a.env"]}},
            {**MINIMAL, "filesystem": {"stat": []}},
        ]
        for case in cases:
            with self.assertRaises(ManifestError):
                load_runtime.validate(case)

    def test_protocol_and_provider_are_validated(self) -> None:
        with self.assertRaises(ManifestError):
            load_runtime.validate({**MINIMAL, "llm": {"protocol": "grpc", "provider": "openai"}})
        with self.assertRaises(ManifestError):
            load_runtime.validate({**MINIMAL, "llm": {"protocol": "openai", "provider": "Open AI"}})

    def test_broker_false_skips_provider_requirement(self) -> None:
        manifest = load_runtime.validate({"name": "demo", "llm": {"broker": False}})
        self.assertFalse(manifest["llm"]["broker"])

    def test_missing_llm_section_does_not_enable_a_broker(self) -> None:
        model = load_runtime.parse({"name": "demo"})
        self.assertIsNone(model.llm)

    def test_service_requires_a_command_and_interactive_rejects_one(self) -> None:
        with self.assertRaises(ManifestError):
            load_runtime.validate({**MINIMAL, "runtime": {"mode": "service"}})
        with self.assertRaises(ManifestError):
            load_runtime.validate({
                **MINIMAL,
                "runtime": {"mode": "interactive", "command": ["sleep", "1"]},
            })

    def test_secret_files_are_plain_filenames(self) -> None:
        valid = load_runtime.validate({
            **MINIMAL, "secrets": {"files": ["common.env", "demo.env"]}
        })
        self.assertEqual(valid["secrets"]["files"], ["common.env", "demo.env"])
        for bad in ("../host.env", "dir/key.env", "/tmp/key.env", ""):
            with self.assertRaises(ManifestError, msg=bad):
                load_runtime.validate({**MINIMAL, "secrets": {"files": [bad]}})

    def test_state_entries_need_key_and_absolute_target(self) -> None:
        with self.assertRaises(ManifestError):
            load_runtime.validate(
                {**MINIMAL, "filesystem": {"state": [{"key": "config", "target": "relative"}]}}
            )
        with self.assertRaises(ManifestError):
            load_runtime.validate({**MINIMAL, "filesystem": {"state": [{"key": "config"}]}})

    def test_env_values_must_be_strings(self) -> None:
        # Catches the YAML footgun where `MODE: 0` parses as an int.
        with self.assertRaises(ManifestError):
            load_runtime.validate({**MINIMAL, "env": {"MODE": 0}})
        with self.assertRaises(ManifestError):
            load_runtime.validate({**MINIMAL, "env": {"lowercase": "x"}})

    def test_manifest_cannot_override_adapter_or_deployment_pins(self) -> None:
        for name in ("AGENT", "SEMGREP_VERSION", "NODE_IMAGE"):
            with self.subTest(name=name), self.assertRaises(ManifestError):
                load_runtime.validate({
                    **MINIMAL,
                    "runtime": {"build": {"args": {name: "override"}}},
                })

    def test_llm_security_identifiers_are_not_free_form(self) -> None:
        for direct_domain in ("https://api.openai.com", "api.openai.com:443", "*.openai.com"):
            with self.subTest(direct_domain=direct_domain), self.assertRaises(ManifestError):
                load_runtime.validate({
                    **MINIMAL,
                    "llm": {
                        "broker": True,
                        "protocol": "openai",
                        "provider": "openai",
                        "direct_domain": direct_domain,
                    },
                })
        with self.assertRaises(ManifestError):
            load_runtime.validate({
                **MINIMAL,
                "llm": {
                    "broker": True,
                    "protocol": "openai",
                    "provider": "openai",
                    "models": ["valid-model", "bad model"],
                },
            })


class NetworkModeTests(unittest.TestCase):
    """The network section is the security-relevant part of a manifest."""

    def routed(self, **network):
        base = {
            "mode": "routed",
            "allow": [
                {"cidr": "192.168.50.0/24", "protocol": "tcp", "ports": [8080]}
            ],
            "verify": {
                "address": "192.168.50.9",
                "protocol": "tcp",
                "port": 8080,
                "blocked_port": 8081,
            },
        }
        base.update(network)
        return {**MINIMAL, "network": base}

    def test_modes_are_constrained(self) -> None:
        for mode in ("isolated", "proxy", "routed"):
            manifest = {**MINIMAL, "network": {"mode": mode}}
            if mode == "routed":
                manifest["network"].update({
                    "allow": [
                        {"cidr": "10.0.0.1/32", "protocol": "tcp", "ports": [8080]}
                    ],
                    "verify": {
                        "address": "10.0.0.1",
                        "protocol": "tcp",
                        "port": 8080,
                        "blocked_port": 8081,
                    },
                })
            load_runtime.validate(manifest)
        with self.assertRaises(ManifestError):
            load_runtime.validate({**MINIMAL, "network": {"mode": "bridge"}})

    def test_keys_belong_to_exactly_one_mode(self) -> None:
        # A key the mode ignores would be a setting that silently does nothing.
        with self.assertRaises(ManifestError):
            load_runtime.validate({**MINIMAL, "network": {
                "mode": "isolated", "allow_domains": ["pypi.org"]}})
        with self.assertRaises(ManifestError):
            load_runtime.validate({**MINIMAL, "network": {
                "mode": "proxy", "allow": [
                    {"cidr": "10.0.0.1/32", "protocol": "icmp_echo"}]}})

    def test_proxy_and_routed_cannot_combine(self) -> None:
        with self.assertRaises(ManifestError) as ctx:
            load_runtime.validate(self.routed(allow_domains=["pypi.org"]))
        self.assertIn("cannot use proxy and routed together", str(ctx.exception))

    def test_proxy_external_allowlist_requires_explicit_positive_control(self) -> None:
        with self.assertRaises(ManifestError) as ctx:
            load_runtime.validate({**MINIMAL, "network": {
                "mode": "proxy", "allow_domains": ["pypi.org"]}})
        self.assertIn("verify_domain", str(ctx.exception))

        load_runtime.validate({**MINIMAL, "network": {
            "mode": "proxy",
            "allow_domains": ["pypi.org"],
            "verify_domain": "pypi.org",
        }})

    def test_empty_proxy_allowlist_needs_no_positive_control(self) -> None:
        load_runtime.validate({**MINIMAL, "network": {
            "mode": "proxy", "allow_domains": []}})

    def test_routed_requires_literal_ipv4(self) -> None:
        for bad in ("example.com", "10.0.0.0/33", "999.1.1.1", "::1", ""):
            with self.assertRaises(ManifestError, msg=bad):
                load_runtime.validate(self.routed(allow=[
                    {"cidr": bad, "protocol": "tcp", "ports": "any"}]))

    def test_routed_default_route_is_rejected(self) -> None:
        with self.assertRaises(ManifestError) as ctx:
            load_runtime.validate(self.routed(allow=[
                {"cidr": "0.0.0.0/0", "protocol": "tcp", "ports": "any"}
            ]))
        self.assertIn("default route", str(ctx.exception))

    def test_one_protocol_per_rule(self) -> None:
        with self.assertRaises(ManifestError):
            load_runtime.validate(self.routed(allow=[
                {"cidr": "10.0.0.1/32", "protocol": ["tcp", "udp"], "ports": "any"}]))
        with self.assertRaises(ManifestError):
            load_runtime.validate(self.routed(allow=[
                {"cidr": "10.0.0.1/32", "protocol": "sctp", "ports": "any"}]))

    def test_ports_with_icmp_is_an_error_not_ignored(self) -> None:
        with self.assertRaises(ManifestError) as ctx:
            load_runtime.validate(self.routed(allow=[
                {"cidr": "10.0.0.1/32", "protocol": "icmp_echo", "ports": [8]}]))
        self.assertIn("icmp_echo", str(ctx.exception))

    def test_tcp_requires_ports(self) -> None:
        with self.assertRaises(ManifestError):
            load_runtime.validate(self.routed(allow=[
                {"cidr": "10.0.0.1/32", "protocol": "tcp"}]))
        for bad in ([], [0], [70000], ["80"], [True], [80, 80]):
            with self.assertRaises(ManifestError, msg=str(bad)):
                load_runtime.validate(self.routed(allow=[
                    {"cidr": "10.0.0.1/32", "protocol": "tcp", "ports": bad}]))

    def test_verify_block_is_validated(self) -> None:
        load_runtime.validate(self.routed(
            verify={"address": "192.168.50.9", "protocol": "tcp", "port": 8080,
                    "blocked_port": 8081}))
        with self.assertRaises(ManifestError):
            load_runtime.validate(self.routed(
                verify={"address": "host.example", "protocol": "tcp", "port": 80,
                        "blocked_port": 81}))
        with self.assertRaises(ManifestError):
            load_runtime.validate(self.routed(
                verify={"address": "10.0.0.1", "protocol": "icmp_echo", "port": 80,
                        "blocked_port": 81}))
        with self.assertRaises(ManifestError):
            load_runtime.validate(self.routed(
                verify={"address": "192.168.50.9", "protocol": "tcp", "port": True,
                        "blocked_port": 81}))


    def test_verify_blocked_port_must_be_denied(self) -> None:
        with self.assertRaises(ManifestError):
            load_runtime.validate(self.routed(
                allow=[{"cidr": "192.168.50.0/24", "protocol": "tcp", "ports": "any"}],
                verify={"address": "192.168.50.9", "protocol": "tcp",
                        "port": 8080, "blocked_port": 8081},
            ))

class CapabilityTests(unittest.TestCase):
    def test_net_admin_is_never_permitted(self) -> None:
        for cap in ("net_admin", "NET_ADMIN", "sys_admin", "NET_BIND_SERVICE"):
            with self.assertRaises(ManifestError, msg=cap):
                load_runtime.validate({**MINIMAL, "capabilities": [cap]})

    def test_net_raw_is_the_only_opt_in(self) -> None:
        model = load_runtime.parse({**MINIMAL, "capabilities": ["net_raw"]})
        self.assertEqual(model.capabilities, frozenset({"net_raw"}))


class SerializationTests(unittest.TestCase):
    def test_routed_rules_preserve_cidr_and_ports(self) -> None:
        model = load_runtime.parse({**MINIMAL, "network": {
            "mode": "routed",
            "allow": [{"cidr": "192.168.50.0/24", "protocol": "tcp", "ports": [161, 8080]}],
            "verify": {"address": "192.168.50.9", "protocol": "tcp",
                       "port": 8080, "blocked_port": 8081},
        }})
        rule = model.network.routed_rules[0]
        self.assertEqual(str(rule.destination), "192.168.50.0/24")
        self.assertEqual(rule.ports, (161, 8080))

    def test_cidr_host_bits_are_rejected(self) -> None:
        self.assertFalse(load_runtime._valid_cidr("192.168.50.7/24"))
        self.assertTrue(load_runtime._valid_cidr("192.168.50.0/24"))
        self.assertTrue(load_runtime._valid_cidr("192.168.50.7/32"))

    def test_internal_port_validator_is_strict(self) -> None:
        self.assertTrue(load_runtime._valid_port(443))
        self.assertFalse(load_runtime._valid_port(0))

    def test_verify_address_is_not_a_network(self) -> None:
        self.assertTrue(load_runtime._valid_address("192.0.2.2"))
        self.assertFalse(load_runtime._valid_address("192.0.2.0/24"))


class ShippedManifestTests(unittest.TestCase):
    def test_every_shipped_manifest_is_valid(self) -> None:
        manifests = sorted((ROOT / "agents").glob("*/runtime.yml"))
        self.assertTrue(manifests, "no runtime manifests found")
        for path in manifests:
            with self.subTest(manifest=path.name):
                manifest = load_runtime.load(path)
                # The directory name is the runtime's identity.
                self.assertEqual(manifest["name"], path.parent.name)

    def test_every_runtime_declares_a_complete_allowlist(self) -> None:
        # There is no implicit base list: a manifest's allow_domains IS the
        # policy. A proxy-mode runtime with none can reach nothing external.
        for path in sorted((ROOT / "agents").glob("*/runtime.yml")):
            manifest = load_runtime.load(path)
            net = manifest.get("network", {})
            if net.get("mode", "proxy") != "proxy":
                continue
            with self.subTest(runtime=path.parent.name):
                self.assertIn("allow_domains", net,
                              "proxy-mode runtime must declare its allowlist explicitly")

    def test_typed_shipped_runtime_fields_are_preserved(self) -> None:
        hermes = load_runtime.load_model(ROOT / "agents" / "hermes" / "runtime.yml")
        self.assertEqual(hermes.adapter, "hermes")
        self.assertEqual(hermes.state_volumes[0].target, "/home/node/.hermes")
        self.assertEqual(hermes.llm.protocol, "openai")
        self.assertEqual(
            hermes.environment_dict()["HERMES_WRITE_SAFE_ROOT"],
            "/workspace/repos:/home/node/.hermes",
        )

    def test_service_command_preserves_argument_boundaries(self) -> None:
        model = load_runtime.parse({
            **MINIMAL,
            "runtime": {"mode": "service", "command": ["python", "-c", "print(1 + 2)"]},
        })
        self.assertEqual(model.runtime.command, ("python", "-c", "print(1 + 2)"))


if __name__ == "__main__":
    unittest.main()
