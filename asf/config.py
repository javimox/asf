"""Small, safe reader for the trusted ASF host configuration.

``asf.conf`` is intentionally simple assignment syntax.  Python lifecycle
code reads only values it owns and never executes the file as shell code.
"""
from __future__ import annotations

import math
import os
import re
import shlex
from ipaddress import IPv4Network
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .errors import ConfigurationError, ValidationError
from .models import RuntimeManifest

__all__ = ["AsfConfig", "AsfConfigError"]

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EXPANSION_RE = re.compile(r"\$(?:\(|\{|[A-Za-z_])|`")
_BUILD_NAMES = (
    "NODE_IMAGE",
    "UV_IMAGE",
    "SEMGREP_VERSION",
    "CLAUDE_CODE_VERSION",
    "HERMES_AGENT_COMMIT",
    "GIT_DELTA_VERSION",
    "FZF_VERSION",
    "FZF_SHA256_AMD64",
    "FZF_SHA256_ARM64",
    "ZSH_IN_DOCKER_VERSION",
    "TIRITH_VERSION",
    "TIRITH_SHA256_AMD64",
    "TIRITH_SHA256_ARM64",
)


class AsfConfigError(ConfigurationError):
    """The host configuration cannot be interpreted safely."""


@dataclass(frozen=True, slots=True)
class AsfConfig:
    path: Path
    values: Mapping[str, str]

    def __post_init__(self) -> None:
        path = Path(self.path)
        values = dict(self.values)
        if not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in values.items()
        ):
            raise TypeError("configuration values must be text mappings")
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "values", MappingProxyType(values))

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "AsfConfig":
        target = Path(path)
        if target.is_symlink():
            raise AsfConfigError(f"asf.conf must not be a symlink: {target}")
        try:
            text = target.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise AsfConfigError(f"Missing asf.conf: {target}") from exc
        except UnicodeDecodeError as exc:
            raise AsfConfigError(f"asf.conf is not valid UTF-8: {target}") from exc
        except OSError as exc:
            raise AsfConfigError(f"Cannot read asf.conf: {target}: {exc}") from exc

        values: dict[str, str] = {}
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise AsfConfigError(
                    f"Unsupported asf.conf syntax on line {number}: {raw.strip()}"
                )
            name, expression = line.split("=", 1)
            name = name.strip()
            if _NAME_RE.fullmatch(name) is None:
                raise AsfConfigError(
                    f"Invalid setting name on line {number}: {name!r}"
                )
            if _EXPANSION_RE.search(expression):
                raise AsfConfigError(
                    f"Shell expansion is not supported for {name} on line {number}"
                )
            try:
                lexer = shlex.shlex(expression, posix=True)
                lexer.whitespace_split = True
                lexer.commenters = "#"
                tokens = list(lexer)
            except ValueError as exc:
                raise AsfConfigError(
                    f"Invalid value for {name} on line {number}: {exc}"
                ) from exc
            if len(tokens) > 1:
                raise AsfConfigError(
                    f"{name} must be one shell-style value, not a command"
                )
            value = tokens[0] if tokens else ""
            if any(character in value for character in ("\x00", "\n", "\r")):
                raise AsfConfigError(f"{name} contains invalid characters")
            values[name] = value
        return cls(target, values)

    def text(self, name: str, default: str = "") -> str:
        return self.values.get(name, default)

    def required(self, name: str) -> str:
        value = self.text(name)
        if not value:
            raise AsfConfigError(f"Missing required value in asf.conf: {name}")
        return value

    def boolean(self, name: str, default: bool = False) -> bool:
        raw = self.text(name, "true" if default else "false")
        if raw == "true":
            return True
        if raw == "false":
            return False
        raise AsfConfigError(f"{name} must be true or false")

    def integer(self, name: str, default: int, *, minimum: int = 0) -> int:
        raw = self.text(name, str(default))
        try:
            value = int(raw)
        except ValueError as exc:
            raise AsfConfigError(f"{name} must be an integer") from exc
        if value < minimum:
            raise AsfConfigError(f"{name} must be at least {minimum}")
        return value

    def number(self, name: str, default: float, *, minimum: float = 0.0) -> float:
        raw = self.text(name, str(default))
        try:
            value = float(raw)
        except ValueError as exc:
            raise AsfConfigError(f"{name} must be a number") from exc
        if not math.isfinite(value) or value < minimum:
            raise AsfConfigError(f"{name} must be finite and at least {minimum}")
        return value

    @property
    def broker_enabled(self) -> bool:
        return self.boolean("BROKER_ENABLED", False)

    @property
    def broker_image(self) -> str:
        return self.required("LITELLM_IMAGE")

    @property
    def broker_startup_timeout(self) -> int:
        return self.integer("LITELLM_STARTUP_TIMEOUT", 60, minimum=1)

    @property
    def broker_detailed_debug(self) -> bool:
        return self.boolean("LITELLM_DETAILED_DEBUG", False)


    @property
    def routed_subnet_pool(self) -> IPv4Network:
        raw = self.text("ASF_SUBNET_POOL", "10.203.0.0/16")
        try:
            return IPv4Network(raw, strict=True)
        except ValueError as exc:
            raise AsfConfigError(
                "ASF_SUBNET_POOL must be a canonical IPv4 CIDR"
            ) from exc

    @property
    def routed_subnet_prefix(self) -> int:
        value = self.integer("ASF_SUBNET_PREFIX", 24, minimum=1)
        if value > 28:
            raise AsfConfigError("ASF_SUBNET_PREFIX must be 28 or smaller")
        return value

    @property
    def routed_allow_persistent_net_admin(self) -> bool:
        return self.boolean("ROUTED_ALLOW_PERSISTENT_NET_ADMIN", False)

    @property
    def caddy_access_logs(self) -> bool:
        return self.boolean("CADDY_ACCESS_LOGS", True)

    def require_caddy(self) -> None:
        implementation = self.text("PROXY_IMPL", "caddy")
        if implementation != "caddy":
            raise AsfConfigError(
                f"PROXY_IMPL={implementation} is not supported by the ASF "
                "production lifecycle; Caddy is required"
            )

    def build_arguments(self) -> tuple[str, ...]:
        arguments: list[str] = []
        for name in _BUILD_NAMES:
            value = self.text(name)
            if not value:
                raise AsfConfigError(
                    f"Missing required value in asf.conf (build section): {name}"
                )
            arguments.append(f"{name}={value}")
        return tuple(arguments)

    def hardening_arguments(self, manifest: RuntimeManifest) -> tuple[str, ...]:
        if not isinstance(manifest, RuntimeManifest):
            raise TypeError("manifest must be a RuntimeManifest")
        args: list[str] = [
            "--mount=type=tmpfs,target=/workspace/sandbox/secrets,ro=true,"
            "tmpfs-size=1048576,tmpfs-mode=0755,notmpcopyup",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--sysctl=net.ipv4.ip_forward=0",
            "--sysctl=net.ipv6.conf.all.forwarding=0",
        ]
        for capability in manifest.capabilities:
            if capability != "net_raw":
                raise ValidationError(
                    f"Unsupported capability in runtime manifest: {capability}"
                )
            args.append("--cap-add=NET_RAW")

        if not self.boolean("EXTENDED_HARDENING_ENABLED", True):
            return tuple(args)

        direct = (
            ("PIDS_LIMIT", "--pids-limit="),
            ("MEM_LIMIT", "--memory="),
            ("MEM_RESERVATION", "--memory-reservation="),
            ("CPUS", "--cpus="),
        )
        for name, prefix in direct:
            value = self.text(name)
            if value:
                args.append(prefix + value)

        nofile = self.text("ULIMIT_NOFILE_SOFT")
        if nofile:
            args.append(
                f"--ulimit=nofile={nofile}:"
                f"{self.text('ULIMIT_NOFILE_HARD', nofile)}"
            )
        core = self.text("ULIMIT_CORE")
        if core:
            args.append(f"--ulimit=core={core}:{core}")

        if self.boolean("TMPFS_ENABLED", True):
            tmp = self.text("TMPFS_TMP")
            run = self.text("TMPFS_RUN")
            if tmp:
                args.append(f"--tmpfs=/tmp:{tmp}")
            if run:
                args.append(f"--tmpfs=/run:{run}")
        if self.boolean("IPC_PRIVATE", True):
            args.append("--ipc=private")
        return tuple(args)

    def ssh_agent_socket(self) -> Path | None:
        if not self.boolean("SSH_AGENT_FORWARDING", False):
            return None
        raw = self.text("SSH_AGENT_SOCKET")
        if not raw:
            raise AsfConfigError(
                "SSH_AGENT_FORWARDING=true but SSH_AGENT_SOCKET is empty"
            )
        socket = Path(raw).expanduser()
        if not socket.is_socket():
            raise AsfConfigError(
                f"SSH agent socket not found (or not a socket): {socket}"
            )
        return socket
