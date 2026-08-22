"""Per-run network-attempt metadata captured outside the routed guest."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .observation_sessions import observation_artifact
from .paths import RepoPaths

__all__ = ["prepare_network_activity_log", "read_network_activity"]


def prepare_network_activity_log(paths: RepoPaths, runtime: str) -> Path:
    """Create the private file mounted into the network observer."""

    path = observation_artifact(paths, runtime, "network-activity.jsonl")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return path


def read_network_activity(
    paths: RepoPaths,
    runtime: str,
    *,
    limit: int = 12,
) -> tuple[dict[str, Any], ...]:
    """Return the newest valid network-attempt records for the current run."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("network activity limit must be a positive integer")
    try:
        path = observation_artifact(paths, runtime, "network-activity.jsonl")
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()

    records: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("event") in {
            "network_attempt",
            "network_activity_truncated",
        }:
            records.append(value)
    return tuple(records)
