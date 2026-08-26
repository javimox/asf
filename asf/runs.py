"""One private directory per ``open`` for every host-side session artifact.

Each ``open`` mints a single session identifier and a matching directory:

.. code-block:: text

    .devcontainer/sessions/<agent>/runs/<session-id>/
      policy.json               frozen isolation/network/capability policy
      events.jsonl              host-written lifecycle events
      verification-report.json  startup verification verdicts
      cleanup-report.json       teardown actions and outcomes
      broker-requests.jsonl     LiteLLM request metadata (broker sessions)
      llm-prompts.jsonl         opt-in prompt capture (broker sessions)
      egress-metadata.json      proxy-mode Caddy evidence bookkeeping
      egress-summary.json       proxy-mode CONNECT summary at teardown
      caddy/                    raw Caddy access logs (the only path Caddy sees)
      network-<ts>.pcap         on-demand routed microVM packet captures

``runs/current`` names the latest session id. Directories are ``0700`` and
files ``0600``. The newest :data:`MAX_RETAINED_RUNS` runs are retained; older
ones are removed when the next session starts.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Network
from pathlib import Path
from typing import TYPE_CHECKING

from .atomic import write_text_atomic
from .models import RoutedRule, RuntimeManifest
from .paths import RepoPaths
from .schema import Schema

if TYPE_CHECKING:
    from .runtime_plan import RuntimePlan

__all__ = [
    "MAX_RETAINED_RUNS",
    "RunPolicy",
    "SessionRun",
    "begin_run",
    "current_run",
    "prune_runs",
    "read_run_policy",
    "run_artifact",
    "runs_root",
    "write_run_policy",
]

MAX_RETAINED_RUNS = 12

_ROOT = "runs"
_CURRENT = "current"
_POLICY = "policy.json"
_SESSION_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
_schema = Schema(ValueError)


@dataclass(frozen=True, slots=True)
class SessionRun:
    runtime: str
    session_id: str
    directory: Path


@dataclass(frozen=True, slots=True)
class RunPolicy:
    """Policy values frozen at session start for trustworthy observation."""

    runtime: str
    isolation: str
    network_mode: str
    broker_enabled: bool
    llm_prompts: bool
    capabilities: frozenset[str]
    routed_rules: tuple[RoutedRule, ...]


def runs_root(paths: RepoPaths, runtime: str) -> Path:
    return paths.session_artifact(runtime, _ROOT)


def begin_run(paths: RepoPaths, runtime: str) -> SessionRun:
    """Create and select one private run directory, retiring the oldest."""

    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    session_id = f"{now}-{secrets.token_hex(4)}"
    root = runs_root(paths, runtime)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)

    directory = paths.session_artifact(runtime, _ROOT, session_id)
    directory.mkdir(mode=0o700, exist_ok=False)

    current = paths.session_artifact(runtime, _ROOT, _CURRENT)
    write_text_atomic(current, session_id + "\n")
    os.chmod(current, 0o600)
    prune_runs(paths, runtime)
    return SessionRun(runtime, session_id, directory)


def current_run(paths: RepoPaths, runtime: str) -> SessionRun | None:
    """Return the selected run directory for one runtime, if any."""

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
    return SessionRun(runtime, session_id, directory)


def run_artifact(paths: RepoPaths, runtime: str, name: str) -> Path:
    """Return one artifact path inside the selected run directory."""

    run = current_run(paths, runtime)
    if run is None:
        raise FileNotFoundError(f"no session run for {runtime}")
    return paths.session_artifact(runtime, _ROOT, run.session_id, name)


def prune_runs(
    paths: RepoPaths,
    runtime: str,
    *,
    keep: int = MAX_RETAINED_RUNS,
) -> tuple[str, ...]:
    """Remove all but the newest ``keep`` run directories; never the current one.

    Runs are ordered by their timestamp prefix, then by directory mtime to
    break same-second ties. Returns the removed session ids.
    """

    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
        raise ValueError("keep must be a positive integer")
    root = runs_root(paths, runtime)
    if not root.is_dir() or root.is_symlink():
        return ()
    selected = current_run(paths, runtime)
    candidates = [
        entry.name
        for entry in sorted(
            (
                entry
                for entry in root.iterdir()
                if _SESSION_RE.fullmatch(entry.name)
                and entry.is_dir()
                and not entry.is_symlink()
            ),
            key=lambda entry: (entry.name[:16], entry.stat().st_mtime_ns),
        )
    ]
    removed: list[str] = []
    for session_id in candidates[:-keep] if len(candidates) > keep else ():
        if selected is not None and session_id == selected.session_id:
            continue
        shutil.rmtree(root / session_id)
        removed.append(session_id)
    return tuple(removed)


def write_run_policy(
    paths: RepoPaths,
    plan: "RuntimePlan",
    manifest: RuntimeManifest,
) -> Path:
    """Persist the small, non-secret policy snapshot used by ``observe``."""

    if plan.runtime != manifest.name:
        raise ValueError("runtime plan and manifest names differ")
    run = current_run(paths, plan.runtime)
    if run is None:
        raise FileNotFoundError(f"no session run for {plan.runtime}")
    path = run.directory / _POLICY
    payload = {
        "runtime": plan.runtime,
        "session_id": run.session_id,
        "isolation": plan.runtime_isolation,
        "network_mode": plan.network_mode,
        "broker_enabled": plan.broker_enabled,
        "llm_prompts": bool(
            plan.broker_enabled and manifest.observability.llm_prompts
        ),
        "capabilities": sorted(manifest.capabilities),
        "routed_allow": [_routed_rule_dict(rule) for rule in manifest.network.routed_rules],
    }
    write_text_atomic(
        path,
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
    )
    os.chmod(path, 0o600)
    return path


def read_run_policy(paths: RepoPaths, runtime: str) -> RunPolicy:
    """Load the exact policy snapshot associated with the selected run."""

    run = current_run(paths, runtime)
    if run is None:
        raise ValueError(f"policy snapshot is unavailable for {runtime}")
    path = run.directory / _POLICY
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"policy snapshot is unavailable for {runtime}") from exc
    try:
        return _parse_policy(payload, runtime, run.session_id)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"policy snapshot is invalid for {runtime}: {exc}") from exc


def _parse_policy(payload: object, runtime: str, session_id: str) -> RunPolicy:
    what = "policy snapshot"
    data = _schema.mapping(payload, what)
    if data.get("runtime") != runtime or data.get("session_id") != session_id:
        raise ValueError(f"{what} identity does not match the selected run")
    capabilities = _schema.text_list(data["capabilities"], f"{what} capabilities")
    for capability in capabilities:
        _schema.one_of(capability, f"{what} capability", ("net_raw",))
    rules = tuple(
        _parse_routed_rule(raw, f"{what} routed_allow")
        for raw in _schema.mapping_list(data["routed_allow"], f"{what} routed_allow")
    )
    return RunPolicy(
        runtime=runtime,
        isolation=_schema.one_of(
            data["isolation"], f"{what} isolation", ("container", "microvm")
        ),
        network_mode=_schema.one_of(
            data["network_mode"], f"{what} network_mode", ("proxy", "isolated", "routed")
        ),
        broker_enabled=_schema.boolean(data["broker_enabled"], f"{what} broker_enabled"),
        llm_prompts=_schema.boolean(data["llm_prompts"], f"{what} llm_prompts"),
        capabilities=frozenset(capabilities),
        routed_rules=rules,
    )


def _routed_rule_dict(rule: RoutedRule) -> dict[str, object]:
    payload: dict[str, object] = {"cidr": str(rule.destination)}
    if rule.protocol is not None:
        payload["protocol"] = rule.protocol
    if isinstance(rule.ports, tuple):
        payload["ports"] = list(rule.ports)
    elif rule.ports is not None:
        payload["ports"] = rule.ports
    return payload


def _parse_routed_rule(raw: object, what: str) -> RoutedRule:
    data = _schema.mapping(raw, what)
    cidr = _schema.text(data.get("cidr"), f"{what} cidr")
    protocol = data.get("protocol")
    if protocol is not None:
        _schema.one_of(protocol, f"{what} protocol", ("tcp", "udp", "icmp_echo"))
    ports = data.get("ports")
    if isinstance(ports, list):
        ports = tuple(
            _schema.integer(port, f"{what} port", minimum=1) for port in ports
        )
        if any(port > 65535 for port in ports):
            raise ValueError(f"{what} port must be at most 65535")
    elif ports is not None and ports != "any":
        raise ValueError(f"{what} ports must be a list, \"any\" or absent")
    return RoutedRule(IPv4Network(cidr, strict=True), protocol, ports)
