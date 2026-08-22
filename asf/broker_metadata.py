"""Small host-visible metadata log written by the trusted LiteLLM broker."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .observation_sessions import observation_artifact
from .paths import RepoPaths

__all__ = [
    "prepare_broker_prompt_log",
    "prepare_broker_request_log",
    "read_broker_requests",
]


def _prepare_log(paths: RepoPaths, runtime: str, name: str) -> Path:
    path = observation_artifact(paths, runtime, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return path


def prepare_broker_request_log(paths: RepoPaths, runtime: str) -> Path:
    """Create this run's broker metadata file with private permissions."""

    return _prepare_log(paths, runtime, "broker-requests.jsonl")


def prepare_broker_prompt_log(paths: RepoPaths, runtime: str) -> Path:
    """Create this run's opt-in prompt log with private permissions."""

    return _prepare_log(paths, runtime, "llm-prompts.jsonl")


def read_broker_requests(
    paths: RepoPaths,
    runtime: str,
    *,
    limit: int = 8,
) -> tuple[dict[str, Any], ...]:
    """Return the newest valid broker request records for the selected run."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("request limit must be a positive integer")
    try:
        path = observation_artifact(paths, runtime, "broker-requests.jsonl")
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()

    records: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and isinstance(value.get("event"), str):
            records.append(value)
    return tuple(records)
