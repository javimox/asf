#!/usr/bin/env python3
"""Compatibility wrapper for :mod:`asf.routed_policy`."""
from __future__ import annotations

import argparse
import json
from ipaddress import IPv4Address, IPv4Network

from asf.models import RoutedRule
from asf.routed_policy import render_routed_policy


def render(rules: list[dict], source_ip: str, scan_if: str, egress_if: str) -> str:
    typed = tuple(
        RoutedRule(
            IPv4Network(item["cidr"], strict=True),
            item["protocol"],
            (
                tuple(item["ports"])
                if isinstance(item.get("ports"), list)
                else item.get("ports")
            ),
        )
        for item in rules
    )
    return render_routed_policy(
        typed,
        IPv4Address(source_ip),
        scan_if,
        egress_if,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-json", required=True)
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--scan-if", required=True)
    parser.add_argument("--egress-if", required=True)
    args = parser.parse_args()
    rules = json.loads(args.rules_json)
    if not isinstance(rules, list) or not rules:
        raise SystemExit("routed rules must be a non-empty JSON list")
    print(render(rules, args.source_ip, args.scan_if, args.egress_if), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
