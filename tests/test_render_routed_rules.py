#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from asf.models import RoutedRule
from asf.routed_policy import render_routed_policy

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "render_routed_rules.py"
spec = importlib.util.spec_from_file_location("render_routed_rules", MODULE_PATH)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RoutedRulesTests(unittest.TestCase):
    def test_every_rule_binds_interfaces_source_destination_and_protocol(self) -> None:
        output = module.render(
            [
                {"cidr": "192.168.50.0/24", "protocol": "tcp", "ports": [80, 443]},
                {"cidr": "192.168.60.1/32", "protocol": "udp", "ports": "any"},
                {"cidr": "192.168.70.1/32", "protocol": "icmp_echo"},
            ],
            "10.203.10.10",
            "eth0",
            "eth1",
        )
        self.assertIn('iifname "eth0" oifname "eth1"', output)
        self.assertIn("ip saddr 10.203.10.10", output)
        self.assertIn("ip daddr 192.168.50.0/24 tcp dport { 80, 443 }", output)
        self.assertIn("ip daddr 192.168.60.1/32 meta l4proto udp ct state", output)
        self.assertIn("ip daddr 192.168.70.1/32 icmp type echo-request", output)
        any_tcp = module.render(
            [{"cidr": "192.168.80.1/32", "protocol": "tcp", "ports": "any"}],
            "10.203.10.10", "eth0", "eth1",
        )
        self.assertIn("ip daddr 192.168.80.1/32 meta l4proto tcp ct state", any_tcp)
        self.assertIn("policy drop", output)

    def test_destination_only_rule_has_no_protocol_or_port_match(self) -> None:
        output = module.render(
            [{"cidr": "192.168.80.1/32"}],
            "10.203.10.10",
            "scan0",
            "egress0",
        )
        self.assertIn(
            'iifname "scan0" oifname "egress0" ip saddr 10.203.10.10 '
            'ip daddr 192.168.80.1/32 accept',
            output,
        )
        self.assertNotIn("l4proto", output)
        self.assertNotIn("dport", output)
        self.assertIn("ip daddr 192.168.80.1/32 masquerade", output)

    def test_nat_is_limited_to_declared_destinations(self) -> None:
        output = module.render(
            [
                {"cidr": "192.168.50.0/24", "protocol": "tcp", "ports": [443]},
                {"cidr": "192.168.50.0/24", "protocol": "udp", "ports": [161]},
            ],
            "10.203.10.10",
            "scan0",
            "egress0",
        )
        self.assertEqual(output.count("ip daddr 192.168.50.0/24 masquerade"), 1)
        self.assertNotIn("masquerade\n", output.replace(
            "ip saddr 10.203.10.10 ip daddr 192.168.50.0/24 masquerade\n", ""
        ))


    def test_separate_blocked_probe_is_nat_only(self) -> None:
        output = render_routed_policy(
            (RoutedRule(IPv4Network("192.168.252.2/32")),),
            IPv4Address("10.203.10.10"),
            "scan0",
            "egress0",
            blocked_probe_address=IPv4Address("192.168.252.3"),
        )
        self.assertIn(
            "ip saddr 10.203.10.10 ip daddr 192.168.252.3/32 masquerade",
            output,
        )
        self.assertNotIn("ip daddr 192.168.252.3/32 accept", output)

    def test_blocked_probe_inside_allowed_destination_does_not_duplicate_nat(self) -> None:
        output = render_routed_policy(
            (RoutedRule(IPv4Network("192.168.252.2/32"), "tcp", (18080,)),),
            IPv4Address("10.203.10.10"),
            "scan0",
            "egress0",
            blocked_probe_address=IPv4Address("192.168.252.2"),
        )
        self.assertEqual(
            output.count("ip saddr 10.203.10.10 ip daddr 192.168.252.2/32 masquerade"),
            1,
        )

    def test_routed_tap_broker_is_limited_to_tcp_4000(self) -> None:
        output = render_routed_policy(
            (RoutedRule(IPv4Network("192.168.252.2/32")),),
            IPv4Address("10.77.40.10"),
            "scan0",
            "egress0",
            tap_source_ip=IPv4Address("10.76.40.2"),
            tap_interface="tap0",
            broker_address=IPv4Address("10.77.40.3"),
        )
        self.assertIn(
            'iifname "tap0" oifname "scan0" ip saddr 10.76.40.2 '
            'ip daddr 10.77.40.3 tcp dport 4000 ct state new,established accept',
            output,
        )
        self.assertIn(
            'iifname "scan0" oifname "tap0" ip saddr 10.77.40.3 '
            'ip daddr 10.76.40.2 ct state established,related accept',
            output,
        )
        self.assertIn(
            "ip saddr 10.76.40.2 ip daddr 10.77.40.3/32 masquerade",
            output,
        )
        self.assertNotIn("udp dport 4000", output)

    def test_reply_rule_is_bound_to_the_runtime_ip(self) -> None:
        output = module.render(
            [{"cidr": "192.168.50.1/32", "protocol": "tcp", "ports": [8080]}],
            "10.203.10.10",
            "scan0",
            "egress0",
        )
        self.assertIn(
            'iifname "egress0" oifname "scan0" ip daddr 10.203.10.10 '
            "ct state established,related accept",
            output,
        )


if __name__ == "__main__":
    unittest.main()
