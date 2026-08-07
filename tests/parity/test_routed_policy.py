#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from asf.models import RoutedRule
from asf.routed_policy import render_routed_policy

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "parity" / "routed_policy_vectors.json"


class RoutedPolicyParityTests(unittest.TestCase):
    def test_python_matches_frozen_pre_migration_rulesets(self) -> None:
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(document["version"], 1)
        for vector in document["vectors"]:
            with self.subTest(vector=vector["name"]):
                rules = tuple(
                    RoutedRule(
                        IPv4Network(item["cidr"], strict=True),
                        item["protocol"],
                        (
                            tuple(item["ports"])
                            if isinstance(item.get("ports"), list)
                            else item.get("ports")
                        ),
                    )
                    for item in vector["rules"]
                )
                rendered = render_routed_policy(
                    rules,
                    IPv4Address(vector["source_ip"]),
                    vector["scan_interface"],
                    vector["egress_interface"],
                )
                self.assertEqual(rendered, vector["expected"])


if __name__ == "__main__":
    unittest.main()
