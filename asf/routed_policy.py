"""Deterministic nftables rendering for routed ASF sessions."""
from __future__ import annotations

from ipaddress import IPv4Address

from .models import RoutedRule

__all__ = ["render_routed_policy"]


def _transport_match(rule: RoutedRule) -> str:
    if rule.ports == "any":
        return f"meta l4proto {rule.protocol}"
    assert isinstance(rule.ports, tuple)
    if len(rule.ports) == 1:
        return f"{rule.protocol} dport {rule.ports[0]}"
    joined = ", ".join(str(port) for port in rule.ports)
    return f"{rule.protocol} dport {{ {joined} }}"


def render_routed_policy(
    rules: tuple[RoutedRule, ...],
    source_ip: IPv4Address,
    scan_interface: str,
    egress_interface: str,
) -> str:
    if not rules:
        raise ValueError("routed rules must not be empty")
    for value in (scan_interface, egress_interface):
        if not value or any(character.isspace() for character in value):
            raise ValueError("interface names must be non-empty without whitespace")
    lines = [
        "flush ruleset",
        "table inet asf_filter {",
        "  chain input {",
        "    type filter hook input priority filter; policy drop;",
        '    iifname "lo" accept',
        "  }",
        "  chain output {",
        "    type filter hook output priority filter; policy drop;",
        '    oifname "lo" accept',
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter; policy drop;",
        (
            f'    iifname "{egress_interface}" oifname "{scan_interface}" '
            f"ip daddr {source_ip} ct state established,related accept"
        ),
    ]
    destinations: list[str] = []
    for rule in rules:
        destination = str(rule.destination)
        if destination not in destinations:
            destinations.append(destination)
        prefix = (
            f'    iifname "{scan_interface}" oifname "{egress_interface}" '
            f"ip saddr {source_ip} ip daddr {destination}"
        )
        if rule.protocol in {"tcp", "udp"}:
            lines.append(
                f"{prefix} {_transport_match(rule)} "
                "ct state new,established accept"
            )
        elif rule.protocol == "icmp_echo":
            lines.append(f"{prefix} icmp type echo-request accept")
        else:  # pragma: no cover - typed manifest makes this unreachable
            raise ValueError(f"unsupported protocol: {rule.protocol}")
    lines.extend(["  }", "}", "table ip asf_nat {", "  chain postrouting {"])
    lines.append("    type nat hook postrouting priority srcnat; policy accept;")
    for destination in destinations:
        lines.append(
            f"    ip saddr {source_ip} ip daddr {destination} masquerade"
        )
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"
