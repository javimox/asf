"""Read-only routed subnet reservation state used by cleanup discovery."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_network
from pathlib import Path

from .errors import ValidationError
from .session_lock import process_alive

__all__ = [
    "Reservation",
    "read_reservation",
    "reservation_dir",
    "reservation_path",
]


def reservation_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base:
        return Path(base) / "asf-subnets"
    return Path(tempfile.gettempdir()) / f"asf-subnets-{os.getuid()}"


def reservation_path(session: str, directory: Path | None = None) -> Path:
    if not isinstance(session, str) or not session or "\x00" in session:
        raise ValidationError("reservation session must be non-empty safe text")
    root = reservation_dir() if directory is None else Path(directory)
    digest = hashlib.sha256(session.encode("utf-8")).hexdigest()[:24]
    return root / f"{digest}.json"


@dataclass(frozen=True, slots=True)
class Reservation:
    path: Path
    session: str = ""
    owner_pid: int | None = None
    subnets: tuple[IPv4Network, ...] = ()
    unreadable: bool = False
    present: bool = False

    @property
    def exists(self) -> bool:
        return self.present

    @property
    def owner_alive(self) -> bool:
        return process_alive(self.owner_pid)

    @property
    def is_stale(self) -> bool:
        return self.exists and (self.unreadable or not self.owner_alive)


def read_reservation(session: str, directory: Path | None = None) -> Reservation:
    path = reservation_path(session, directory)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return Reservation(path=path)
    except OSError:
        return Reservation(path=path, unreadable=True, present=True)

    # Never follow a reservation symlink into an attacker-controlled location.
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        return Reservation(path=path, unreadable=True, present=True)

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return Reservation(path=path, unreadable=True, present=True)

    if not isinstance(payload, dict):
        return Reservation(path=path, unreadable=True, present=True)

    missing = object()
    raw_pid = payload.get("pid", missing)
    if raw_pid is missing:
        pid = None
    elif isinstance(raw_pid, bool) or not isinstance(raw_pid, int) or raw_pid <= 0:
        return Reservation(path=path, unreadable=True, present=True)
    else:
        pid = raw_pid

    values = payload.get("subnets")
    if not isinstance(values, list):
        return Reservation(path=path, unreadable=True, present=True)

    subnets: list[IPv4Network] = []
    for value in values:
        try:
            parsed = ip_network(value, strict=True)
        except (TypeError, ValueError):
            return Reservation(path=path, unreadable=True, present=True)
        if not isinstance(parsed, IPv4Network):
            return Reservation(path=path, unreadable=True, present=True)
        subnets.append(parsed)

    recorded_session = payload.get("session", "")
    if not isinstance(recorded_session, str):
        return Reservation(path=path, unreadable=True, present=True)

    return Reservation(
        path=path,
        session=recorded_session,
        owner_pid=pid,
        subnets=tuple(subnets),
        unreadable=False,
        present=True,
    )
