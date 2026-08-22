"""Per-run directories for host-side ASF observability artifacts."""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Network
from pathlib import Path
from typing import TYPE_CHECKING

from .atomic import write_text_atomic
from .models import RoutedRule, RuntimeManifest
from .paths import RepoPaths

if TYPE_CHECKING:
    from .runtime_plan import RuntimePlan

__all__ = [
    "ObservationSession",
    "begin_observation_session",
    "current_observation_session",
    "observation_artifact",
    "ObservationPolicy",
    "read_observation_policy",
    "write_observation_policy",
]

_ROOT = "observability"
_CURRENT = "current"
_POLICY = "policy.json"
_SESSION_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")


@dataclass(frozen=True, slots=True)
class ObservationSession:
    runtime: str
    session_id: str
    directory: Path


@dataclass(frozen=True, slots=True)
class ObservationPolicy:
    """Policy values frozen at session start for trustworthy observation."""

    runtime: str
    isolation: str
    network_mode: str
    broker_enabled: bool
    llm_prompts: bool
    network_activity: bool
    capabilities: frozenset[str]
    routed_rules: tuple[RoutedRule, ...]


def begin_observation_session(paths: RepoPaths, runtime: str) -> ObservationSession:
    """Create and select one private observability directory for this open."""

    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    session_id = f"{now}-{secrets.token_hex(4)}"
    root = paths.session_artifact(runtime, _ROOT)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)

    directory = paths.session_artifact(runtime, _ROOT, session_id)
    directory.mkdir(mode=0o700, exist_ok=False)

    current = paths.session_artifact(runtime, _ROOT, _CURRENT)
    write_text_atomic(current, session_id + "\n")
    os.chmod(current, 0o600)
    return ObservationSession(runtime, session_id, directory)


def current_observation_session(
    paths: RepoPaths,
    runtime: str,
) -> ObservationSession | None:
    """Return the latest/current observability directory for one runtime."""

    current = paths.session_artifact(runtime, _ROOT, _CURRENT)
    try:
        session_id = current.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not _SESSION_RE.fullmatch(session_id):
        return None
    directory = paths.session_artifact(runtime, _ROOT, session_id)
    if not directory.is_dir() or directory.is_symlink():
        return None
    return ObservationSession(runtime, session_id, directory)


def observation_artifact(paths: RepoPaths, runtime: str, name: str) -> Path:
    """Return one artifact in the selected per-run observability directory."""

    session = current_observation_session(paths, runtime)
    if session is None:
        raise FileNotFoundError(f"no observability session for {runtime}")
    return paths.session_artifact(runtime, _ROOT, session.session_id, name)


def write_observation_policy(
    paths: RepoPaths,
    plan: "RuntimePlan",
    manifest: RuntimeManifest,
) -> Path:
    """Persist the small, non-secret policy snapshot used by ``observe``."""

    if plan.runtime != manifest.name:
        raise ValueError("runtime plan and manifest names differ")
    session = current_observation_session(paths, plan.runtime)
    if session is None:
        raise FileNotFoundError(f"no observability session for {plan.runtime}")
    path = paths.session_artifact(plan.runtime, _ROOT, session.session_id, _POLICY)
    payload = {
        "runtime": plan.runtime,
        "session_id": session.session_id,
        "isolation": plan.runtime_isolation,
        "network_mode": plan.network_mode,
        "broker_enabled": plan.broker_enabled,
        "llm_prompts": bool(
            plan.broker_enabled and manifest.observability.llm_prompts
        ),
        "network_activity": manifest.observability.network_activity,
        "capabilities": sorted(manifest.capabilities),
        "routed_allow": [
            {
                "cidr": str(rule.destination),
                **({"protocol": rule.protocol} if rule.protocol is not None else {}),
                **(
                    {"ports": list(rule.ports)}
                    if isinstance(rule.ports, tuple)
                    else ({"ports": rule.ports} if rule.ports is not None else {})
                ),
            }
            for rule in manifest.network.routed_rules
        ],
    }
    write_text_atomic(
        path,
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    )
    os.chmod(path, 0o600)
    return path


def read_observation_policy(paths: RepoPaths, runtime: str) -> ObservationPolicy:
    """Load the exact policy snapshot associated with the selected run."""

    session = current_observation_session(paths, runtime)
    if session is None:
        raise ValueError(f"observation policy snapshot is unavailable for {runtime}")
    path = paths.session_artifact(runtime, _ROOT, session.session_id, _POLICY)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"observation policy snapshot is unavailable for {runtime}"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("runtime") != runtime
        or payload.get("session_id") != session.session_id
    ):
        raise ValueError(f"observation policy snapshot is invalid for {runtime}")
    try:
        raw_caps = payload["capabilities"]
        raw_rules = payload["routed_allow"]
        if not isinstance(raw_caps, list) or not all(
            isinstance(value, str) for value in raw_caps
        ):
            raise TypeError
        if any(value not in {"net_raw"} for value in raw_caps):
            raise TypeError
        if not isinstance(raw_rules, list):
            raise TypeError
        rules: list[RoutedRule] = []
        for raw in raw_rules:
            if not isinstance(raw, dict) or not isinstance(raw.get("cidr"), str):
                raise TypeError
            protocol = raw.get("protocol")
            if protocol is not None and protocol not in {"tcp", "udp", "icmp_echo"}:
                raise TypeError
            ports = raw.get("ports")
            if isinstance(ports, list):
                ports = tuple(ports)
            if ports is not None and ports != "any" and not (
                isinstance(ports, tuple)
                and all(
                    isinstance(port, int)
                    and not isinstance(port, bool)
                    and 1 <= port <= 65535
                    for port in ports
                )
            ):
                raise TypeError
            rules.append(
                RoutedRule(IPv4Network(raw["cidr"], strict=True), protocol, ports)
            )
        isolation = payload["isolation"]
        network_mode = payload["network_mode"]
        broker_enabled = payload["broker_enabled"]
        llm_prompts = payload["llm_prompts"]
        network_activity = payload["network_activity"]
        if isolation not in {"container", "microvm"}:
            raise TypeError
        if network_mode not in {"proxy", "isolated", "routed"}:
            raise TypeError
        if not all(
            isinstance(value, bool)
            for value in (broker_enabled, llm_prompts, network_activity)
        ):
            raise TypeError
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"observation policy snapshot is invalid for {runtime}") from exc
    return ObservationPolicy(
        runtime=runtime,
        isolation=isolation,
        network_mode=network_mode,
        broker_enabled=broker_enabled,
        llm_prompts=llm_prompts,
        network_activity=network_activity,
        capabilities=frozenset(raw_caps),
        routed_rules=tuple(rules),
    )
