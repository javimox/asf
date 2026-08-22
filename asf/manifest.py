"""Load, validate, and model an ASF runtime manifest.

The YAML schema and stable serialization contracts are validated here. Internal
callers use the immutable :func:`parse` and :func:`load_model` APIs; diagnostics
and fixtures consume the same canonical validated representation.

A manifest declares one sandboxed workload. This loader is the single place
that knows the manifest's shape; the CLI and Dev Container renderer consume its
output instead of hardcoding per-agent behaviour.

Design rules:
  • Unknown keys are REJECTED, never ignored — a typo must not silently disable
    a setting, and a field that does nothing must not look like it works.
  • Only fields ASF actually consumes today are accepted. Fields still owned
    by other files (per-runtime repos.yml files and asf.conf) are deliberately
    absent; see MANIFEST SCOPE in agents/claude/runtime.yml.

Validate manifests with ``python3 -m asf.manifest <runtime.yml>``.
"""
from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import sys
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    yaml = None

from .errors import ConfigurationError
from .models import (
    BuildArgument,
    EnvironmentVariable,
    LlmSettings,
    NetworkPolicy,
    ObservabilitySettings,
    RoutedRule,
    RoutedVerification,
    RuntimeManifest,
    RuntimeSettings,
    StateVolume,
)

__all__ = [
    "ManifestError",
    "load",
    "load_model",
    "main",
    "parse",
    "validate",
]

_PYYAML_REQUIRED = (
    "PyYAML is required to read runtime manifests.\n"
    "  Debian/Ubuntu: sudo apt install python3-yaml\n"
    "  Arch:          sudo pacman -S python-yaml\n"
    "  macOS:         brew install libyaml && pip3 install pyyaml\n"
    "  pip:           pip install --user pyyaml"
)

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
SLUG_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
BUILD_ARG_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A plain hostname: no scheme, no path, no port, no wildcard. The proxy
# allowlist must be exact — a wildcard is a policy hole, not a convenience.
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                       r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
SECRET_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
PROTOCOLS = ("anthropic", "openai")
MODES = ("interactive", "service")
ISOLATIONS = ("container", "microvm")

# key -> (type, required). Nested sections are validated by the functions below.
TOP_LEVEL = {
    "name": (str, True),
    "description": (str, False),
    "adapter": (str, False),
    "runtime": (dict, False),
    "filesystem": (dict, False),
    "llm": (dict, False),
    "secrets": (dict, False),
    "network": (dict, False),
    "observability": (dict, False),
    "env": (dict, False),
    "capabilities": (list, False),
}
RUNTIME_KEYS = {"build", "command", "isolation", "mode"}
BUILD_KEYS = {"args"}
DEPLOYMENT_BUILD_ARGS = {
    "AGENT",
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
}
FILESYSTEM_KEYS = {"state"}
STATE_KEYS = {"key", "target"}
LLM_KEYS = {"broker", "protocol", "provider", "api_key_env", "direct_domain", "models"}
SECRETS_KEYS = {"files"}
NETWORK_KEYS = {"mode", "allow_domains", "verify_domain", "allow", "verify"}
OBSERVABILITY_KEYS = {"llm_prompts", "network_activity"}
NETWORK_MODES = ("isolated", "proxy", "routed")
ROUTED_RULE_KEYS = {"cidr", "protocol", "ports"}
VERIFY_KEYS = {"address", "protocol", "port", "blocked_port", "blocked_address"}
ROUTED_PROTOCOLS = ("tcp", "udp", "icmp_echo")

# Closed vocabulary. NET_ADMIN is deliberately absent: enforcement lives
# outside the runtime, so no runtime needs it, and allowing it would let a
# manifest undo the design.
ALLOWED_CAPABILITIES = {"net_raw"}


class ManifestError(ConfigurationError):
    """Raised with a message naming the file and the offending key."""


def _reject_unknown(section: str, got: dict, allowed: set[str]) -> None:
    unknown = [key for key in got if key not in allowed]
    if unknown:
        rendered = sorted(
            key if isinstance(key, str) else repr(key)
            for key in unknown
        )
        raise ManifestError(
            f"unknown key(s) in '{section}': {', '.join(rendered)} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )


def _str_list(section: str, value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ManifestError(f"'{section}' must be a list of strings")
    return value


def _valid_cidr(value: str) -> bool:
    """A literal IPv4 network in canonical form.

    strict=True rejects host bits (192.168.50.7/24), so a manifest must name
    the actual network. Ambiguity in a security manifest is worse than a
    slightly stricter parser.
    """
    if not isinstance(value, str):
        return False
    try:
        IPv4Network(value, strict=True)
    except ValueError:
        return False
    return True


def _valid_address(value: str) -> bool:
    """Exactly one IPv4 address — not a network. `10.0.0.0/24` is rejected."""
    if not isinstance(value, str):
        return False
    try:
        IPv4Address(value)
    except ValueError:
        return False
    return True


def _valid_port(value: Any) -> bool:
    # bool is a subclass of int in Python; YAML `true` must not silently mean
    # port 1 in a security policy.
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def validate(data: Any) -> dict[str, Any]:
    """Validate and return the original manifest mapping."""
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a YAML mapping")

    _reject_unknown("(top level)", data, set(TOP_LEVEL))
    for key, (expected, required) in TOP_LEVEL.items():
        if key not in data:
            if required:
                raise ManifestError(f"missing required key: '{key}'")
            continue
        if not isinstance(data[key], expected):
            raise ManifestError(f"'{key}' must be {expected.__name__}")

    if not NAME_RE.fullmatch(data["name"]):
        raise ManifestError(
            f"invalid name {data['name']!r}: must match {NAME_RE.pattern}"
        )

    runtime = data.get("runtime", {})
    _reject_unknown("runtime", runtime, RUNTIME_KEYS)
    mode = runtime.get("mode", "interactive")
    if mode not in MODES:
        raise ManifestError(f"runtime.mode must be one of {MODES}, got {mode!r}")
    isolation = runtime.get("isolation", "container")
    if isolation not in ISOLATIONS:
        raise ManifestError(
            f"runtime.isolation must be one of {ISOLATIONS}, got {isolation!r}"
        )
    if "command" in runtime:
        command = _str_list("runtime.command", runtime["command"])
        if not command or any(not item for item in command):
            raise ManifestError("runtime.command must contain non-empty strings")
        if any("\x00" in item for item in command):
            raise ManifestError("runtime.command cannot contain NUL bytes")
    if mode == "service" and not runtime.get("command"):
        raise ManifestError("runtime.mode: service requires runtime.command")
    if mode == "interactive" and "command" in runtime:
        raise ManifestError(
            "runtime.command is only valid with runtime.mode: service; "
            "interactive runtimes start a shell"
        )
    build = runtime.get("build", {})
    if "build" in runtime and not isinstance(build, dict):
        raise ManifestError("runtime.build must be a mapping")
    if isinstance(build, dict):
        _reject_unknown("runtime.build", build, BUILD_KEYS)
        args = build.get("args", {})
        if not isinstance(args, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in args.items()
        ):
            raise ManifestError(
                "runtime.build.args must be a string->string mapping"
            )
        for key, value in args.items():
            if not BUILD_ARG_RE.fullmatch(key):
                raise ManifestError(
                    f"runtime.build.args key {key!r} must be a build-argument name"
                )
            if "\x00" in value:
                raise ManifestError(
                    f"runtime.build.args[{key}] cannot contain a NUL byte"
                )
        reserved = sorted(set(args) & DEPLOYMENT_BUILD_ARGS)
        if reserved:
            raise ManifestError(
                "runtime.build.args cannot override ASF-owned build inputs: "
                + ", ".join(reserved)
                + ". Adapter identity comes from 'adapter'; dependency pins "
                  "come from asf.conf."
            )

    filesystem = data.get("filesystem", {})
    _reject_unknown("filesystem", filesystem, FILESYSTEM_KEYS)
    state_entries = filesystem.get("state", [])
    if not isinstance(state_entries, list):
        raise ManifestError("filesystem.state must be a list")
    state_keys: set[str] = set()
    state_targets: set[str] = set()
    for entry in state_entries:
        if not isinstance(entry, dict):
            raise ManifestError("filesystem.state entries must be mappings")
        _reject_unknown("filesystem.state[]", entry, STATE_KEYS)
        for field in STATE_KEYS:
            if field not in entry or not isinstance(entry[field], str):
                raise ManifestError(f"filesystem.state[] needs a string '{field}'")
        if not NAME_RE.fullmatch(entry["key"]):
            raise ManifestError(
                f"filesystem.state[].key {entry['key']!r} must match {NAME_RE.pattern}"
            )
        if not entry["target"].startswith("/"):
            raise ManifestError("filesystem.state[].target must be an absolute path")
        if "\x00" in entry["target"]:
            raise ManifestError("filesystem.state[].target cannot contain a NUL byte")
        if "," in entry["target"]:
            raise ManifestError(
                "filesystem.state[].target cannot contain ',' because Podman "
                "uses commas to delimit --mount fields"
            )
        if entry["key"] in state_keys:
            raise ManifestError(f"duplicate filesystem.state key: {entry['key']!r}")
        if entry["target"] in state_targets:
            raise ManifestError(
                f"duplicate filesystem.state target: {entry['target']!r}"
            )
        state_keys.add(entry["key"])
        state_targets.add(entry["target"])

    llm = data.get("llm", {})
    _reject_unknown("llm", llm, LLM_KEYS)
    if llm:
        if "broker" in llm and not isinstance(llm["broker"], bool):
            raise ManifestError("llm.broker must be true or false")
        if llm.get("broker", True):
            protocol = llm.get("protocol")
            if protocol not in PROTOCOLS:
                raise ManifestError(
                    f"llm.protocol must be one of {PROTOCOLS}, got {protocol!r}"
                )
            provider = llm.get("provider", "")
            if not SLUG_RE.fullmatch(provider):
                raise ManifestError(
                    f"llm.provider {provider!r} must match {SLUG_RE.pattern}"
                )
        for field in ("api_key_env", "direct_domain"):
            if field in llm and not isinstance(llm[field], str):
                raise ManifestError(f"llm.{field} must be a string")
        if "api_key_env" in llm and not ENV_RE.fullmatch(llm["api_key_env"]):
            raise ManifestError("llm.api_key_env must be an environment-variable name")
        if llm.get("direct_domain") and not DOMAIN_RE.fullmatch(llm["direct_domain"]):
            raise ManifestError(
                "llm.direct_domain must be one plain hostname "
                "(no scheme, path, port or wildcard)"
            )
        if "models" in llm:
            models = _str_list("llm.models", llm["models"])
            if any(not MODEL_RE.fullmatch(model) for model in models):
                raise ManifestError(
                    "llm.models entries may contain only letters, digits, "
                    "'.', '_', ':', and '-'"
                )
            if len(models) != len(set(models)):
                raise ManifestError("llm.models must not contain duplicates")

    observability = data.get("observability", {})
    _reject_unknown("observability", observability, OBSERVABILITY_KEYS)
    llm_prompts = observability.get("llm_prompts", False)
    if not isinstance(llm_prompts, bool):
        raise ManifestError("observability.llm_prompts must be true or false")
    if llm_prompts and not (llm and llm.get("broker", True)):
        raise ManifestError(
            "observability.llm_prompts requires llm.broker: true; "
            "prompt capture happens at the LiteLLM broker"
        )
    network_activity = observability.get("network_activity", False)
    if not isinstance(network_activity, bool):
        raise ManifestError("observability.network_activity must be true or false")

    secrets = data.get("secrets", {})
    _reject_unknown("secrets", secrets, SECRETS_KEYS)
    if "files" in secrets:
        secret_files = _str_list("secrets.files", secrets["files"])
        for filename in secret_files:
            if not SECRET_FILE_RE.fullmatch(filename):
                raise ManifestError(
                    f"secrets.files entry {filename!r} must be a plain filename "
                    "(no path separators)"
                )

    network = data.get("network", {})
    _reject_unknown("network", network, NETWORK_KEYS)
    mode = network.get("mode", "proxy")
    if mode not in NETWORK_MODES:
        raise ManifestError(
            f"network.mode must be one of {NETWORK_MODES}, got {mode!r}"
        )
    if network_activity and not (mode == "routed" and isolation == "microvm"):
        raise ManifestError(
            "observability.network_activity requires network.mode: routed and "
            "runtime.isolation: microvm; TAP observation is only available there"
        )

    # Each key belongs to exactly one mode. Accepting a key the mode ignores
    # would be a setting that silently does nothing.
    proxy_only = tuple(
        key for key in ("allow_domains", "verify_domain") if key in network
    )
    if proxy_only and mode != "proxy":
        names = ", ".join(f"network.{key}" for key in proxy_only)
        verb = "is" if len(proxy_only) == 1 else "are"
        raise ManifestError(
            f"{names} {verb} only valid with mode: proxy; "
            f"remove {'this field' if len(proxy_only) == 1 else 'these fields'} "
            f"when using mode: {mode}"
        )
    if ("allow" in network or "verify" in network) and mode != "routed":
        raise ManifestError("network.allow/verify are only valid with mode: routed")

    allow_domains = network.get("allow_domains", [])
    if not isinstance(allow_domains, list):
        raise ManifestError("network.allow_domains must be a list of hostnames")
    for domain in allow_domains:
        if not isinstance(domain, str) or not DOMAIN_RE.fullmatch(domain):
            raise ManifestError(
                f"network.allow_domains entry {domain!r} is not a plain hostname "
                "(no scheme, no path, no wildcard)"
            )

    # The positive control must be one of the declared domains, or it can never
    # succeed. Sorting in the proxy layer means manifest order cannot select it,
    # so it is named explicitly.
    verify_domain = network.get("verify_domain")
    if mode == "proxy" and allow_domains and verify_domain is None:
        raise ManifestError(
            "proxy mode with external destinations requires network.verify_domain; "
            "name one allowlisted host as the deterministic positive control"
        )
    if verify_domain is not None:
        if not isinstance(verify_domain, str) or not DOMAIN_RE.fullmatch(verify_domain):
            raise ManifestError("network.verify_domain must be a plain hostname")
        if verify_domain not in allow_domains:
            raise ManifestError(
                f"network.verify_domain {verify_domain!r} is not in allow_domains; "
                "the positive control must be a permitted destination"
            )

    if mode == "routed":
        rules = network.get("allow", [])
        if not isinstance(rules, list) or not rules:
            raise ManifestError("mode: routed requires a non-empty network.allow list")
        for rule in rules:
            if not isinstance(rule, dict):
                raise ManifestError("network.allow entries must be mappings")
            _reject_unknown("network.allow[]", rule, ROUTED_RULE_KEYS)

            cidr = rule.get("cidr")
            if not isinstance(cidr, str) or not _valid_cidr(cidr):
                raise ManifestError(
                    f"network.allow[].cidr {cidr!r} must be a literal IPv4 "
                    "network in canonical form (e.g. 192.168.50.0/24 or "
                    "192.168.50.7/32). Host bits must be zero, and names are "
                    "not resolved in routed mode."
                )
            if IPv4Network(cidr, strict=True).prefixlen == 0:
                raise ManifestError(
                    "network.allow[].cidr cannot be 0.0.0.0/0; routed mode "
                    "never gives a runtime a default route"
                )

            proto = rule.get("protocol")
            if proto is None:
                if "ports" in rule:
                    raise ManifestError(
                        "network.allow[]: 'ports' requires 'protocol'; omit both "
                        "to allow all IP traffic to the destination"
                    )
            elif proto not in ROUTED_PROTOCOLS:
                raise ManifestError(
                    f"network.allow[].protocol must be one of {ROUTED_PROTOCOLS}, "
                    f"got {proto!r} (one protocol per rule)"
                )
            elif proto == "icmp_echo":
                if "ports" in rule:
                    raise ManifestError(
                        "network.allow[]: 'ports' is not valid with protocol "
                        "icmp_echo (ICMP has no ports)"
                    )
            else:
                ports = rule.get("ports")
                if ports is None:
                    raise ManifestError(
                        f"network.allow[]: protocol {proto} requires 'ports' "
                        "(a list, or the string 'any')"
                    )
                if ports != "any":
                    if not isinstance(ports, list) or not ports:
                        raise ManifestError(
                            "network.allow[].ports must be 'any' or a non-empty list"
                        )
                    for port in ports:
                        if not _valid_port(port):
                            raise ManifestError(
                                f"network.allow[].ports entry {port!r} is not a "
                                "port number 1-65535"
                            )
                    if len(ports) != len(set(ports)):
                        raise ManifestError(
                            "network.allow[].ports must not contain duplicates"
                        )

        verify = network.get("verify")
        if verify is not None:
            if not isinstance(verify, dict):
                raise ManifestError("network.verify must be a mapping")
            _reject_unknown("network.verify", verify, VERIFY_KEYS)
            if not _valid_address(verify.get("address", "")):
                raise ManifestError(
                    "network.verify.address must be one literal IPv4 address "
                    "(not a network)"
                )
            if verify.get("protocol") != "tcp":
                raise ManifestError("network.verify.protocol must be tcp in routed v1")
            port = verify.get("port")
            blocked_port = verify.get("blocked_port")
            blocked_address = verify.get("blocked_address", verify.get("address"))
            if not _valid_address(blocked_address):
                raise ManifestError(
                    "network.verify.blocked_address must be one literal IPv4 address"
                )
            if not _valid_port(port):
                raise ManifestError("network.verify.port must be a port number 1-65535")
            if not _valid_port(blocked_port):
                raise ManifestError(
                    "network.verify.blocked_port must be a port number 1-65535"
                )
            if blocked_address == verify.get("address") and blocked_port == port:
                raise ManifestError(
                    "network.verify blocked endpoint must differ from the allowed endpoint"
                )

            # The positive control must be permitted by the policy it tests.
            # Otherwise it can never pass, and startup fails for a reason that
            # has nothing to do with enforcement being broken.
            addr = IPv4Address(verify["address"])
            vproto = verify["protocol"]
            covered = False
            for rule in rules:
                if addr not in IPv4Network(rule["cidr"], strict=True):
                    continue
                rproto = rule.get("protocol")
                if rproto is None:
                    covered = True
                    break
                if rproto != vproto:
                    continue
                rports = rule.get("ports")
                if rports == "any" or (isinstance(rports, list) and port in rports):
                    covered = True
                    break
            if not covered:
                raise ManifestError(
                    f"network.verify ({verify['address']} {vproto}/{port}) is not "
                    "permitted by any network.allow rule, so the positive control "
                    "could never succeed. Add a matching rule, or point verify at "
                    "a destination the policy allows."
                )

            denied_addr = IPv4Address(blocked_address)
            blocked_covered = False
            for rule in rules:
                if denied_addr not in IPv4Network(rule["cidr"], strict=True):
                    continue
                rproto = rule.get("protocol")
                if rproto is None:
                    blocked_covered = True
                    break
                if rproto != "tcp":
                    continue
                rports = rule.get("ports")
                if rports == "any" or (
                    isinstance(rports, list) and blocked_port in rports
                ):
                    blocked_covered = True
                    break
            if blocked_covered:
                raise ManifestError(
                    f"network.verify blocked endpoint {blocked_address}:{blocked_port} "
                    "is permitted by network.allow; it must name a known-open TCP "
                    "endpoint that policy intentionally blocks"
                )

    caps = data.get("capabilities", [])
    normalised_caps: set[str] = set()
    for cap in caps:
        if not isinstance(cap, str) or cap.lower() not in ALLOWED_CAPABILITIES:
            raise ManifestError(
                f"capability {cap!r} is not supported. Allowed: "
                f"{sorted(ALLOWED_CAPABILITIES)}. NET_ADMIN is never permitted: "
                "enforcement lives outside the runtime."
            )
        normalised = cap.lower()
        if normalised in normalised_caps:
            raise ManifestError("capabilities must not contain duplicates")
        normalised_caps.add(normalised)

    env = data.get("env", {})
    for key, value in env.items():
        if not isinstance(key, str) or not ENV_RE.fullmatch(key):
            raise ManifestError(
                f"env key {key!r} must be an environment-variable name"
            )
        if not isinstance(value, str):
            raise ManifestError(f"env[{key}] must be a string (quote numbers)")
        if "\x00" in value:
            raise ManifestError(f"env[{key}] cannot contain a NUL byte")

    return data



def parse(data: Any) -> RuntimeManifest:
    """Validate external manifest data and return an immutable typed model."""

    return _to_model(validate(data))


def _to_model(data: Mapping[str, Any]) -> RuntimeManifest:
    runtime_data = data.get("runtime", {})
    build_data = runtime_data.get("build", {}).get("args", {})
    runtime = RuntimeSettings(
        mode=runtime_data.get("mode", "interactive"),
        isolation=runtime_data.get("isolation", "container"),
        command=tuple(runtime_data.get("command", ())),
        build_arguments=tuple(
            BuildArgument(name, value) for name, value in build_data.items()
        ),
    )

    state_volumes = tuple(
        StateVolume(entry["key"], entry["target"])
        for entry in data.get("filesystem", {}).get("state", ())
    )

    llm_data = data.get("llm")
    llm = None
    if llm_data:
        llm = LlmSettings(
            broker=llm_data.get("broker", True),
            protocol=llm_data.get("protocol"),
            provider=llm_data.get("provider"),
            api_key_env=llm_data.get("api_key_env", ""),
            direct_domain=llm_data.get("direct_domain", ""),
            models=tuple(llm_data.get("models", ())),
        )

    network_data = data.get("network", {})
    routed_rules = tuple(
        RoutedRule(
            destination=IPv4Network(rule["cidr"], strict=True),
            protocol=rule.get("protocol"),
            ports=(
                tuple(rule["ports"])
                if isinstance(rule.get("ports"), list)
                else rule.get("ports")
            ),
        )
        for rule in network_data.get("allow", ())
    )
    verify_data = network_data.get("verify")
    routed_verification = None
    if verify_data is not None:
        routed_verification = RoutedVerification(
            address=IPv4Address(verify_data["address"]),
            protocol=verify_data["protocol"],
            allowed_port=verify_data["port"],
            blocked_port=verify_data["blocked_port"],
            blocked_address=(
                IPv4Address(verify_data["blocked_address"])
                if "blocked_address" in verify_data
                else None
            ),
        )
    network = NetworkPolicy(
        mode=network_data.get("mode", "proxy"),
        allow_domains=tuple(network_data.get("allow_domains", ())),
        verify_domain=network_data.get("verify_domain"),
        routed_rules=routed_rules,
        routed_verification=routed_verification,
    )
    observability_data = data.get("observability", {})
    observability = ObservabilitySettings(
        llm_prompts=observability_data.get("llm_prompts", False),
        network_activity=observability_data.get("network_activity", False),
    )

    return RuntimeManifest(
        name=data["name"],
        description=data.get("description", ""),
        adapter=data.get("adapter", "generic"),
        runtime=runtime,
        state_volumes=state_volumes,
        llm=llm,
        secret_files=tuple(data.get("secrets", {}).get("files", ())),
        network=network,
        observability=observability,
        environment=tuple(
            EnvironmentVariable(name, value)
            for name, value in data.get("env", {}).items()
        ),
        capabilities=frozenset(
            capability.lower() for capability in data.get("capabilities", ())
        ),
    )


def load(path: str | Path) -> dict[str, Any]:
    try:
        manifest_path = Path(path)
    except TypeError as exc:
        raise ManifestError(f"manifest path must be text or path-like: {path!r}") from exc
    if yaml is None:  # pragma: no cover - environment dependent
        raise ManifestError(_PYYAML_REQUIRED)
    try:
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ManifestError(f"manifest not found: {manifest_path}") from None
    except UnicodeError as exc:
        raise ManifestError(
            f"manifest is not valid UTF-8: {manifest_path}: {exc}"
        ) from None
    except ValueError as exc:
        raise ManifestError(f"invalid manifest path {manifest_path!s}: {exc}") from None
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {manifest_path}: {exc}") from None
    except yaml.YAMLError as exc:
        raise ManifestError(f"invalid YAML in {manifest_path}: {exc}") from None
    try:
        return validate(raw)
    except ManifestError as exc:
        raise ManifestError(f"{manifest_path}: {exc}") from None


def load_model(path: str | Path) -> RuntimeManifest:
    """Load one YAML manifest as an immutable typed model."""

    return _to_model(load(path))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--emit", choices=("json",), default=None)
    args = parser.parse_args()

    try:
        manifest = load(args.path)
    except ManifestError as exc:
        print(f"Invalid runtime manifest: {exc}", file=sys.stderr)
        return 1

    if args.emit == "json":
        print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
