"""Small host-owned lifecycle event log for ASF sessions."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .observation_sessions import current_observation_session, observation_artifact
from .paths import RepoPaths

__all__ = ["record_session_event", "read_session_events"]


def record_session_event(
    paths: RepoPaths,
    runtime: str,
    event: str,
    **fields: Any,
) -> None:
    """Append one best-effort lifecycle event without affecting enforcement."""

    try:
        session = current_observation_session(paths, runtime)
        if session is None:
            return
        path = observation_artifact(paths, runtime, "events.jsonl")
        payload = {
            **fields,
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "runtime": runtime,
            "session_id": session.session_id,
        }
        data = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.fchmod(fd, 0o600)
            while data:
                written = os.write(fd, data)
                data = data[written:]
        finally:
            os.close(fd)
    except (OSError, TypeError, ValueError):
        return


def read_session_events(
    paths: RepoPaths,
    runtime: str,
    *,
    limit: int = 8,
) -> tuple[dict[str, Any], ...]:
    """Return the newest valid lifecycle records for the selected run."""

    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("event limit must be a positive integer")
    try:
        path: Path = observation_artifact(paths, runtime, "events.jsonl")
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
