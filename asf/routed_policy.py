"""Deterministic nftables rendering for routed ASF sessions."""
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network

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
    *,
    tap_source_ip: IPv4Address | None = None,
    tap_interface: str | None = None,
    blocked_probe_address: IPv4Address | None = None,
    broker_address: IPv4Address | None = None,
    broker_port: int = 4000,
) -> str:
    if not rules:
        raise ValueError("routed rules must not be empty")
    for value in (scan_interface, egress_interface):
        if not value or any(character.isspace() for character in value):
            raise ValueError("interface names must be non-empty without whitespace")
    if (tap_source_ip is None) != (tap_interface is None):
        raise ValueError("tap source and interface must be supplied together")
    if tap_interface is not None and (
        not tap_interface or any(character.isspace() for character in tap_interface)
    ):
        raise ValueError("interface names must be non-empty without whitespace")
    if broker_address is not None:
        if tap_source_ip is None or tap_interface is None:
            raise ValueError("broker routing requires the TAP source and interface")
        if (
            isinstance(broker_port, bool)
            or not isinstance(broker_port, int)
            or not 1 <= broker_port <= 65535
        ):
            raise ValueError("broker port must be between 1 and 65535")

    paths = [(source_ip, scan_interface)]
    if tap_source_ip is not None and tap_interface is not None:
        paths.append((tap_source_ip, tap_interface))

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
    ]
    for path_source, ingress in paths:
        lines.append(
            f'    iifname "{egress_interface}" oifname "{ingress}" '
            f"ip daddr {path_source} ct state established,related accept"
        )
    if broker_address is not None:
        assert tap_source_ip is not None and tap_interface is not None
        lines.append(
            f'    iifname "{scan_interface}" oifname "{tap_interface}" '
            f"ip saddr {broker_address} ip daddr {tap_source_ip} "
            "ct state established,related accept"
        )
        lines.append(
            f'    iifname "{tap_interface}" oifname "{scan_interface}" '
            f"ip saddr {tap_source_ip} ip daddr {broker_address} "
            f"tcp dport {broker_port} ct state new,established accept"
        )
    destinations: list[IPv4Network] = []
    for rule in rules:
        destination = rule.destination
        if destination not in destinations:
            destinations.append(destination)
        for path_source, ingress in paths:
            prefix = (
                f'    iifname "{ingress}" oifname "{egress_interface}" '
                f"ip saddr {path_source} ip daddr {destination}"
            )
            if rule.protocol is None:
                lines.append(f"{prefix} accept")
            elif rule.protocol in {"tcp", "udp"}:
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
    nat_destinations = list(destinations)
    if blocked_probe_address is not None and not any(
        blocked_probe_address in destination for destination in nat_destinations
    ):
        nat_destinations.append(IPv4Network(f"{blocked_probe_address}/32"))
    for path_source, _ in paths:
        for destination in nat_destinations:
            lines.append(
                f"    ip saddr {path_source} ip daddr {destination} masquerade"
            )
    if broker_address is not None:
        assert tap_source_ip is not None
        lines.append(
            f"    ip saddr {tap_source_ip} ip daddr {broker_address}/32 masquerade"
        )
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"
