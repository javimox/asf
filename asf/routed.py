"""Routed gateway lifecycle for ASF.

The module executes one already-validated runtime plan.  It does not allocate
subnets or create networks; those remain separate, focused responsibilities.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import tempfile
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Sequence, TextIO

from .broker import BROKER_PORT
from .errors import ConfigurationError, InfrastructureError
from .models import RuntimeManifest
from .podman import PodmanClient, PodmanError
from .runtime_plan import (
    GeneratedFileKind,
    NetworkRole,
    RuntimePlan,
    routed_broker_address,
)
from .routed_policy import render_routed_policy
from .session import SessionRole

__all__ = [
    "ROUTED_TAP_NAME",
    "ROUTED_GATEWAY_IMAGE_BASE",
    "ROUTED_GATEWAY_IMAGE_REV",
    "NO_CAPABILITIES",
    "GatewayHardening",
    "RoutedGateway",
    "RoutedGatewayError",
    "RoutedRequest",
    "RoutedService",
    "routed_tap_addresses",
    "parse_gateway_hardening",
    "validate_capability_boundary",
]

ROUTED_GATEWAY_IMAGE_REV = "v2"
ROUTED_GATEWAY_IMAGE_BASE = (
    "docker.io/library/alpine@sha256:"
    "d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
)
_BLUE = "\033[0;34m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[1;33m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_INTERFACE_RE = re.compile(r"^\d+:\s+([^\s]+)\s+inet\s+([^/\s]+)/")
NO_CAPABILITIES = "0000000000000000"
ROUTED_TAP_NAME = "tap0"
_CAPABILITY_MASK_RE = re.compile(r"^[0-9a-f]{16}$")
_NET_ADMIN_BIT = 1 << 12
_LOADER = r'''
set -eu
if [ -n "${ASF_TAP_NAME:-}" ]; then
    ip tuntap add dev "$ASF_TAP_NAME" mode tap user 0
    ip addr add "$ASF_TAP_GATEWAY/30" dev "$ASF_TAP_NAME"
    ip link set "$ASF_TAP_NAME" up
fi
for target in "$@"; do
    routes=$(ip route show "$target" via "$ASF_GW_SCAN_IP") || {
        echo "could not query the gateway self-route for $target" >&2
        exit 1
    }
    if [ -n "$routes" ]; then
        ip route del "$target" via "$ASF_GW_SCAN_IP" || {
            echo "could not remove gateway self-route for $target" >&2
            exit 1
        }
    fi
done
nft -f -
nft list table inet asf_filter >/dev/null
'''.strip()
_HOLDER = """#!/bin/sh
set -eu
trap 'exit 0' TERM INT HUP
while :; do
    sleep 86400 &
    wait "$!"
done
"""


class RoutedGatewayError(InfrastructureError):
    """The routed gateway could not be created or proven safe."""


def routed_tap_addresses(plan: RuntimePlan) -> tuple[IPv4Address, IPv4Address]:
    """Return gateway and guest addresses for the krun TAP point-to-point link."""

    internal = plan.network(NetworkRole.INTERNAL)
    if internal is None or internal.subnet is None:
        raise ConfigurationError("routed TAP requires the planned internal subnet")
    subnet = next(internal.subnet.subnets(new_prefix=30))
    return subnet.network_address + 1, subnet.network_address + 2


@dataclass(frozen=True, slots=True)
class GatewayHardening:
    """Observed gateway hardening and forwarding state."""

    effective: str
    bounding: str
    no_new_privileges: bool
    forwarding_v4: bool
    forwarding_v6: bool

    @property
    def capability_less(self) -> bool:
        return self.effective == NO_CAPABILITIES and self.bounding == NO_CAPABILITIES

    @property
    def operational(self) -> bool:
        return (
            self.no_new_privileges
            and self.forwarding_v4
            and not self.forwarding_v6
        )

    @property
    def acceptable(self) -> bool:
        return self.capability_less and self.operational

    @property
    def persistent_acceptable(self) -> bool:
        try:
            effective = int(self.effective, 16)
            bounding = int(self.bounding, 16)
        except ValueError:
            return False
        return (
            self.operational
            and bool(effective & _NET_ADMIN_BIT)
            and bool(bounding & _NET_ADMIN_BIT)
        )

    def reasons(self, *, persistent: bool = False) -> tuple[str, ...]:
        found: list[str] = []
        if persistent:
            if not self.persistent_acceptable:
                try:
                    effective = int(self.effective, 16)
                    bounding = int(self.bounding, 16)
                except ValueError:
                    found.append("capability masks are unreadable")
                else:
                    if not effective & _NET_ADMIN_BIT:
                        found.append("effective NET_ADMIN is missing")
                    if not bounding & _NET_ADMIN_BIT:
                        found.append("bounding NET_ADMIN is missing")
        else:
            if self.effective != NO_CAPABILITIES:
                found.append(f"effective capabilities are {self.effective}")
            if self.bounding != NO_CAPABILITIES:
                found.append(f"bounding capabilities are {self.bounding}")
        if not self.no_new_privileges:
            found.append("no-new-privileges is not set")
        if not self.forwarding_v4:
            found.append("IPv4 forwarding is off")
        if self.forwarding_v6:
            found.append("IPv6 forwarding is on")
        return tuple(found)


def parse_gateway_hardening(
    status_text: str, forwarding_v4: str, forwarding_v6: str
) -> GatewayHardening:
    """Parse gateway evidence; malformed or incomplete output fails closed.

    The current lifecycle reads ``/proc/1/status`` directly.  The compact
    three-field form remains accepted for compatibility with existing callers
    and frozen tests.
    """

    parts = status_text.split()
    if len(parts) == 3 and all(
        _CAPABILITY_MASK_RE.fullmatch(value) for value in parts[:2]
    ):
        effective, bounding, no_new_privileges = parts
    else:
        fields: dict[str, str] = {}
        for line in status_text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            fields[key] = value.strip()
        effective = fields.get("CapEff", "")
        bounding = fields.get("CapBnd", "")
        no_new_privileges = fields.get("NoNewPrivs", "")
        if not (
            _CAPABILITY_MASK_RE.fullmatch(effective)
            and _CAPABILITY_MASK_RE.fullmatch(bounding)
            and no_new_privileges in {"0", "1"}
        ):
            return GatewayHardening(
                "unreadable", "unreadable", False, False, True
            )

    return GatewayHardening(
        effective=effective,
        bounding=bounding,
        no_new_privileges=no_new_privileges == "1",
        forwarding_v4=forwarding_v4.strip() == "1",
        forwarding_v6=forwarding_v6.strip() == "1",
    )


@dataclass(frozen=True, slots=True)
class RoutedRequest:
    manifest: RuntimeManifest
    plan: RuntimePlan
    allow_persistent_net_admin: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, RuntimeManifest):
            raise TypeError("manifest must be a RuntimeManifest")
        if not isinstance(self.plan, RuntimePlan):
            raise TypeError("plan must be a RuntimePlan")
        if self.plan.network_mode != "routed":
            raise ConfigurationError("routed gateway requires a routed runtime plan")
        if self.manifest.name != self.plan.runtime:
            raise ConfigurationError("manifest and routed plan runtime differ")
        if not self.manifest.network.routed_rules:
            raise ConfigurationError("routed gateway requires a non-empty policy")
        if not isinstance(self.allow_persistent_net_admin, bool):
            raise TypeError("allow_persistent_net_admin must be boolean")
        for role in (NetworkRole.SCAN, NetworkRole.ROUTED_EGRESS):
            if self.plan.network(role) is None:
                raise ConfigurationError(f"routed plan is missing {role.value} network")
        for role in (SessionRole.ROUTED_GATEWAY, SessionRole.ROUTED_INIT):
            if self.plan.container(role) is None:
                raise ConfigurationError(
                    f"routed plan is missing {role.value} container"
                )

    @property
    def gateway(self):
        value = self.plan.container(SessionRole.ROUTED_GATEWAY)
        assert value is not None
        return value

    @property
    def initializer(self):
        value = self.plan.container(SessionRole.ROUTED_INIT)
        assert value is not None
        return value

    @property
    def scan_network(self):
        value = self.plan.network(NetworkRole.SCAN)
        assert value is not None
        return value

    @property
    def egress_network(self):
        value = self.plan.network(NetworkRole.ROUTED_EGRESS)
        assert value is not None
        return value

    @property
    def runtime_scan_ip(self) -> IPv4Address:
        for attachment in self.plan.runtime_container.attachments:
            if attachment.network == self.scan_network.name:
                if attachment.address is None:
                    break
                return attachment.address
        raise ConfigurationError("routed runtime has no fixed scan address")

    @property
    def gateway_scan_ip(self) -> IPv4Address:
        for attachment in self.gateway.attachments:
            if attachment.network == self.scan_network.name:
                if attachment.address is None:
                    break
                return attachment.address
        raise ConfigurationError("routed gateway has no fixed scan address")

    @property
    def gateway_egress_ip(self) -> IPv4Address:
        for attachment in self.gateway.attachments:
            if attachment.network == self.egress_network.name:
                if attachment.address is None:
                    break
                return attachment.address
        raise ConfigurationError("routed gateway has no fixed egress address")

    @property
    def policy_path(self) -> Path:
        matches = [
            item.destination
            for item in self.plan.generated_files
            if item.kind is GeneratedFileKind.ROUTED_POLICY
        ]
        if len(matches) != 1:
            raise ConfigurationError("routed plan needs one policy destination")
        return matches[0]

    @property
    def destinations(self) -> tuple[IPv4Network, ...]:
        seen: set[IPv4Network] = set()
        values: list[IPv4Network] = []
        for rule in self.manifest.network.routed_rules:
            if rule.destination not in seen:
                seen.add(rule.destination)
                values.append(rule.destination)
        return tuple(values)

    @property
    def uses_tap(self) -> bool:
        return self.manifest.runtime.isolation == "microvm"

    @property
    def tap_gateway_ip(self) -> IPv4Address:
        return routed_tap_addresses(self.plan)[0]

    @property
    def tap_guest_ip(self) -> IPv4Address:
        return routed_tap_addresses(self.plan)[1]

    @property
    def broker_address(self) -> IPv4Address | None:
        return routed_broker_address(self.plan)


@dataclass(frozen=True, slots=True)
class RoutedGateway:
    """Pure command builder for the gateway and its short-lived initializer."""

    request: RoutedRequest
    image: str
    engine: str = "podman"

    def __post_init__(self) -> None:
        if not isinstance(self.request, RoutedRequest):
            raise TypeError("request must be a RoutedRequest")
        if not isinstance(self.image, str) or not self.image.strip():
            raise ConfigurationError("routed gateway image is required")
        if not isinstance(self.engine, str) or not self.engine.strip():
            raise ConfigurationError("Podman engine is required")

    def gateway_argv(self, *, persistent_net_admin: bool = False) -> tuple[str, ...]:
        request = self.request
        argv: list[str] = [
            self.engine,
            "run",
            "-d",
            "--name",
            request.gateway.name,
        ]
        attachments = request.gateway.attachments
        if len(attachments) != 2:
            raise RoutedGatewayError(
                "routed gateway must join exactly two planned networks"
            )
        for attachment in attachments:
            if attachment.address is None:
                raise RoutedGatewayError(
                    f"gateway attachment to {attachment.network} has no fixed address"
                )
            argv.extend(("--network", f"{attachment.network}:ip={attachment.address}"))
        argv.extend(
            (
                "--label",
                request.plan.sandbox_label,
                "--label",
                "asf.role=routed-gateway",
                "--label",
                f"asf.agent={request.plan.runtime}",
                "--label",
                "asf.persistent-net-admin="
                f"{'true' if persistent_net_admin else 'false'}",
                "--sysctl",
                "net.ipv4.ip_forward=1",
                "--sysctl",
                "net.ipv6.conf.all.forwarding=0",
                "--cap-drop=ALL",
            )
        )
        if persistent_net_admin:
            argv.append("--cap-add=NET_ADMIN")
            if request.uses_tap:
                argv.extend(("--device", "/dev/net/tun"))
        argv.extend(
            (
                "--security-opt=no-new-privileges",
                "--read-only",
                "--tmpfs",
                "/run:rw,nosuid,nodev,noexec,size=4m",
                "--stop-timeout=2",
                "--pids-limit=32",
                "--memory=64m",
                self.image,
            )
        )
        return tuple(argv)

    def inspect_argv(self) -> tuple[str, ...]:
        return (
            self.engine,
            "exec",
            self.request.gateway.name,
            "cat",
            "/proc/1/status",
        )

    def forwarding_argv(self, family: int) -> tuple[str, ...]:
        if family not in {4, 6}:
            raise ValueError("IP family must be 4 or 6")
        path = (
            "/proc/sys/net/ipv4/ip_forward"
            if family == 4
            else "/proc/sys/net/ipv6/conf/all/forwarding"
        )
        return (self.engine, "exec", self.request.gateway.name, "cat", path)

    def initializer_argv(self) -> tuple[str, ...]:
        request = self.request
        argv: list[str] = [
            self.engine,
            "run",
            "--rm",
            "--name",
            request.initializer.name,
            "--network",
            f"container:{request.gateway.name}",
            "--label",
            request.plan.sandbox_label,
            "--label",
            "asf.role=routed-init",
            "--label",
            f"asf.agent={request.plan.runtime}",
            "--cap-drop=ALL",
            "--cap-add=NET_ADMIN",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/run:rw,nosuid,nodev,noexec,size=2m",
            "--pids-limit=16",
            "--memory=32m",
        ]
        if request.uses_tap:
            argv.extend(
                (
                    "--device",
                    "/dev/net/tun",
                    "-e",
                    f"ASF_TAP_NAME={ROUTED_TAP_NAME}",
                    "-e",
                    f"ASF_TAP_GATEWAY={request.tap_gateway_ip}",
                )
            )
        argv.extend(
            (
                "-e",
                f"ASF_GW_SCAN_IP={request.gateway_scan_ip}",
                "-i",
                self.image,
                "sh",
                "-euc",
                _LOADER,
                "sh",
                *(str(item) for item in request.destinations),
            )
        )
        return tuple(argv)

    def persistent_loader_argv(self) -> tuple[str, ...]:
        request = self.request
        argv: list[str] = [
            self.engine,
            "exec",
            "-i",
        ]
        if request.uses_tap:
            argv.extend(
                (
                    "-e",
                    f"ASF_TAP_NAME={ROUTED_TAP_NAME}",
                    "-e",
                    f"ASF_TAP_GATEWAY={request.tap_gateway_ip}",
                )
            )
        argv.extend(
            (
                "-e",
                f"ASF_GW_SCAN_IP={request.gateway_scan_ip}",
                request.gateway.name,
                "sh",
                "-euc",
                _LOADER,
                "sh",
                *(str(item) for item in request.destinations),
            )
        )
        return tuple(argv)

    def tap_inspect_argv(self) -> tuple[str, ...]:
        return (
            self.engine,
            "exec",
            self.request.gateway.name,
            "ip",
            "-o",
            "-4",
            "addr",
            "show",
            "dev",
            ROUTED_TAP_NAME,
        )


def validate_capability_boundary(
    gateway_argv: Sequence[str],
    initializer_argv: Sequence[str] | None,
    *,
    gateway_name: str,
    persistent: bool,
) -> None:
    """Fail closed if command construction weakens the capability boundary."""

    gateway = tuple(gateway_argv)
    if "--cap-drop=ALL" not in gateway:
        raise ConfigurationError("routed gateway must drop all capabilities")
    if "--security-opt=no-new-privileges" not in gateway:
        raise ConfigurationError("routed gateway must set no-new-privileges")
    gateway_has_net_admin = "--cap-add=NET_ADMIN" in gateway
    if gateway_has_net_admin != persistent:
        raise ConfigurationError(
            "routed gateway NET_ADMIN does not match fallback mode"
        )
    if persistent:
        if initializer_argv is not None:
            raise ConfigurationError("persistent gateway must not use an initializer")
        return
    if initializer_argv is None:
        raise ConfigurationError("capability-less gateway requires an initializer")
    initializer = tuple(initializer_argv)
    required = (
        "--rm",
        "--cap-drop=ALL",
        "--cap-add=NET_ADMIN",
        "--security-opt=no-new-privileges",
    )
    missing = [value for value in required if value not in initializer]
    if missing:
        raise ConfigurationError(
            "routed initializer is missing: " + ", ".join(missing)
        )
    if f"container:{gateway_name}" not in initializer:
        raise ConfigurationError(
            "routed initializer must share the gateway network namespace"
        )
    if "-d" in initializer:
        raise ConfigurationError("routed initializer must not be long-lived")


@dataclass(frozen=True, slots=True)
class RoutedService:
    podman: PodmanClient

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")

    def require_host(self) -> None:
        if platform.system() != "Linux":
            raise RoutedGatewayError("Routed mode is supported on Linux hosts only")
        result = self.podman.observe(
            (
                str(self.podman.engine),
                "info",
                "--format",
                "{{.Host.Security.Rootless}} {{.Host.NetworkBackend}}",
            ),
            timeout=30,
        )
        if not result.succeeded:
            raise RoutedGatewayError("Could not inspect the Podman networking backend")
        fields = result.stdout.split()
        if len(fields) != 2:
            raise RoutedGatewayError("Podman returned an incomplete networking backend")
        rootless, backend = fields
        if rootless != "true":
            raise RoutedGatewayError("Routed mode requires rootless Podman")
        if backend != "netavark":
            raise RoutedGatewayError(
                f"Routed mode requires Netavark, not {backend or 'unknown'}"
            )

    def start(self, request: RoutedRequest, *, output: TextIO) -> None:
        image = self._ensure_image(output=output)
        commands = RoutedGateway(request, image, str(self.podman.engine))
        default_holder = commands.gateway_argv(persistent_net_admin=False)
        initializer = commands.initializer_argv()
        validate_capability_boundary(
            default_holder,
            initializer,
            gateway_name=request.gateway.name,
            persistent=False,
        )

        output.write(f"  {_BLUE}→{_RESET} Starting capability-less routed gateway\n")
        persistent = False
        result = self.podman.observe(default_holder, timeout=60)
        hardening = (
            self._inspect_hardening(commands)
            if result.succeeded
            else GatewayHardening("unreadable", "unreadable", False, False, True)
        )
        if not result.succeeded or not hardening.acceptable:
            self.podman.observe(
                (str(self.podman.engine), "rm", "-f", request.gateway.name),
                timeout=30,
            )
            if not request.allow_persistent_net_admin:
                detail = "; ".join(hardening.reasons())
                suffix = f": {detail}" if detail else ""
                raise RoutedGatewayError(
                    "This host cannot run the capability-less routed gateway"
                    f"{suffix}"
                )
            output.write(
                f"  {_YELLOW}⚠ Using persistent NET_ADMIN on the "
                f"routed gateway.{_RESET}\n"
            )
            persistent = True
            persistent_holder = commands.gateway_argv(persistent_net_admin=True)
            validate_capability_boundary(
                persistent_holder,
                None,
                gateway_name=request.gateway.name,
                persistent=True,
            )
            result = self.podman.observe(persistent_holder, timeout=60)
            if not result.succeeded:
                raise RoutedGatewayError("Could not start the routed gateway")
            hardening = self._inspect_hardening(commands)
            if not hardening.persistent_acceptable:
                detail = "; ".join(hardening.reasons(persistent=True))
                suffix = f": {detail}" if detail else ""
                raise RoutedGatewayError(
                    f"Persistent routed gateway failed verification{suffix}"
                )

        scan_interface, egress_interface = self._interface_names(request, image)
        verification = request.manifest.network.routed_verification
        policy = render_routed_policy(
            request.manifest.network.routed_rules,
            request.runtime_scan_ip,
            scan_interface,
            egress_interface,
            tap_source_ip=(request.tap_guest_ip if request.uses_tap else None),
            tap_interface=(ROUTED_TAP_NAME if request.uses_tap else None),
            blocked_probe_address=(
                verification.denied_address if verification is not None else None
            ),
            broker_address=request.broker_address,
            broker_port=BROKER_PORT,
        )
        self._write_policy(request.policy_path, policy)
        output.write(f"  {_BLUE}→{_RESET} Loading routed nftables policy\n")
        self._load_policy(commands, policy, persistent=persistent)
        if request.uses_tap:
            self._assert_tap_ready(commands, request.tap_gateway_ip)
        if persistent:
            output.write(
                f"  {_GREEN}✓{_RESET} Routed gateway ready "
                f"{_YELLOW}(persistent NET_ADMIN enabled){_RESET}\n"
            )
        else:
            self._assert_initializer_exited(request.initializer.name)
            final_hardening = self._inspect_hardening(commands)
            if not final_hardening.acceptable:
                detail = "; ".join(final_hardening.reasons())
                suffix = f": {detail}" if detail else ""
                raise RoutedGatewayError(
                    f"Routed gateway changed after policy loading{suffix}"
                )
            output.write(
                f"  {_GREEN}✓{_RESET} Routed gateway ready "
                f"{_DIM}(NET_ADMIN initializer exited){_RESET}\n"
            )

    def holder_argv(
        self,
        request: RoutedRequest,
        image: str,
        *,
        persistent: bool,
    ) -> tuple[str, ...]:
        return RoutedGateway(
            request, image, str(self.podman.engine)
        ).gateway_argv(persistent_net_admin=persistent)

    def initializer_argv(
        self,
        request: RoutedRequest,
        image: str,
    ) -> tuple[str, ...]:
        return RoutedGateway(
            request, image, str(self.podman.engine)
        ).initializer_argv()

    def _inspect_hardening(self, commands: RoutedGateway) -> GatewayHardening:
        try:
            status = self.podman.observe(commands.inspect_argv(), timeout=10)
            forwarding4 = self.podman.observe(
                commands.forwarding_argv(4), timeout=10
            )
            forwarding6 = self.podman.observe(
                commands.forwarding_argv(6), timeout=10
            )
        except PodmanError:
            return GatewayHardening(
                "unreadable", "unreadable", False, False, True
            )
        if not (status.succeeded and forwarding4.succeeded and forwarding6.succeeded):
            return GatewayHardening(
                "unreadable", "unreadable", False, False, True
            )
        return parse_gateway_hardening(
            status.stdout, forwarding4.stdout, forwarding6.stdout
        )

    def _interface_names(
        self, request: RoutedRequest, image: str
    ) -> tuple[str, str]:
        result = self.podman.observe(
            (
                str(self.podman.engine),
                "run",
                "--rm",
                "--network",
                f"container:{request.gateway.name}",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=2m",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=16",
                "--memory=32m",
                image,
                "ip",
                "-o",
                "-4",
                "addr",
                "show",
            ),
            timeout=30,
        )
        if not result.succeeded:
            raise RoutedGatewayError("Could not inspect routed gateway interfaces")
        by_address: dict[str, str] = {}
        for line in result.stdout.splitlines():
            match = _INTERFACE_RE.match(line)
            if match:
                by_address[match.group(2)] = match.group(1).rstrip(":")
        try:
            return (
                by_address[str(request.gateway_scan_ip)],
                by_address[str(request.gateway_egress_ip)],
            )
        except KeyError as exc:
            raise RoutedGatewayError(
                "Could not identify routed gateway interfaces"
            ) from exc

    def _load_policy(
        self,
        commands: RoutedGateway,
        policy: str,
        *,
        persistent: bool,
    ) -> None:
        argv = (
            commands.persistent_loader_argv()
            if persistent
            else commands.initializer_argv()
        )
        result = self.podman.observe(argv, timeout=60, input_text=policy)
        if not result.succeeded:
            detail = result.stderr.strip() or result.stdout.strip()
            suffix = f": {detail}" if detail else ""
            raise RoutedGatewayError(f"Could not load routed nftables policy{suffix}")

    def _assert_initializer_exited(self, container: str) -> None:
        result = self.podman.observe(
            (str(self.podman.engine), "container", "exists", container),
            timeout=10,
        )
        if result.returncode == 1:
            return
        if result.returncode == 0:
            raise RoutedGatewayError(
                "Routed NET_ADMIN initializer remained after policy loading"
            )
        detail = result.stderr.strip() or result.stdout.strip()
        suffix = f": {detail}" if detail else ""
        raise RoutedGatewayError(
            f"Could not verify routed initializer exit{suffix}"
        )

    def _assert_tap_ready(
        self, commands: RoutedGateway, gateway_ip: IPv4Address
    ) -> None:
        result = self.podman.observe(commands.tap_inspect_argv(), timeout=10)
        if not result.succeeded or f" {gateway_ip}/30 " not in f" {result.stdout} ":
            raise RoutedGatewayError("Routed krun TAP interface is not ready")

    def _ensure_image(self, *, output: TextIO) -> str:
        material = (
            f"{ROUTED_GATEWAY_IMAGE_REV}|{ROUTED_GATEWAY_IMAGE_BASE}|"
            "iproute2|nftables|signal-aware-holder-v1"
        )
        fingerprint = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
        tag = f"asf-routed-gateway:{fingerprint}"
        exists = self.podman.observe(
            (str(self.podman.engine), "image", "exists", tag), timeout=30
        )
        if exists.succeeded:
            return tag
        output.write(
            f"  {_BLUE}→{_RESET} Building routed gateway image "
            f"{_DIM}(first run only){_RESET}\n"
        )
        with tempfile.TemporaryDirectory(prefix="asf-routed-gateway-") as directory:
            root = Path(directory)
            holder = root / "asf-gateway-holder"
            holder.write_text(_HOLDER, encoding="utf-8")
            holder.chmod(0o755)
            (root / "Containerfile").write_text(
                f"FROM {ROUTED_GATEWAY_IMAGE_BASE}\n"
                "RUN apk add --no-cache iproute2 nftables\n"
                "COPY asf-gateway-holder /usr/local/bin/asf-gateway-holder\n"
                "ENTRYPOINT []\n"
                'CMD ["/usr/local/bin/asf-gateway-holder"]\n',
                encoding="utf-8",
            )
            built = self.podman.observe(
                (
                    str(self.podman.engine),
                    "build",
                    "-q",
                    "-t",
                    tag,
                    directory,
                ),
                timeout=900,
            )
        if not built.succeeded:
            raise RoutedGatewayError("Could not build the routed gateway image")
        return tag

    @staticmethod
    def _write_policy(path: Path, policy: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.is_symlink():
            raise RoutedGatewayError(f"unsafe routed policy path: {path}")
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{path.name}.",
                delete=False,
            ) as handle:
                handle.write(policy)
                handle.flush()
                os.fsync(handle.fileno())
                temporary = Path(handle.name)
            temporary.replace(path)
        except OSError as exc:
            raise RoutedGatewayError(f"Could not write routed policy: {exc}") from exc
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
