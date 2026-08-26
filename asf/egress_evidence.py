"""Per-run Caddy evidence and conservative allowlist advice.

Caddy writes JSON access records into the ``caddy/`` subdirectory of the
current session run (see :mod:`asf.runs`); that subdirectory is the only path
the proxy container can write to. At teardown ASF summarises CONNECT attempts
into ``egress-summary.json`` and appends a bounded history record. Advice is
read-only: it never edits a runtime manifest or weakens policy automatically.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Mapping, Sequence

from .atomic import write_text_atomic
from .errors import ConfigurationError, ValidationError
from .manifest import DOMAIN_RE, load_model
from .paths import RepoPaths
from .runs import SessionRun, current_run

__all__ = [
    "ACCESS_LOG_CONTAINER_PATH",
    "ACCESS_LOG_DIRNAME",
    "ADVICE_WINDOW",
    "EgressAdviceResult",
    "EgressEvidenceError",
    "EgressSessionContext",
    "EgressSessionEvidence",
    "begin_egress_session",
    "current_egress_session",
    "finalize_egress_session",
    "load_evidence_history",
    "mark_egress_session_active",
    "run_advise_command",
]

ACCESS_LOG_FILENAME = "caddy-access.jsonl"
ACCESS_LOG_PREFIX = "caddy-access"
ACCESS_LOG_CONTAINER_PATH = f"/var/log/asf/{ACCESS_LOG_FILENAME}"
ACCESS_LOG_DIRNAME = "caddy"
_HISTORY_FILENAME = "egress-history.json"
_METADATA_FILENAME = "egress-metadata.json"
_SUMMARY_FILENAME = "egress-summary.json"
_MAX_HISTORY = 100
ADVICE_WINDOW = 12
_MIN_DENIED_ATTEMPTS = 3
_MIN_DENIED_SESSIONS = 2
_PROBE_HEADER = "x-asf-probe"
_PROBE_VALUE = "verification"


class EgressEvidenceError(ConfigurationError):
    """Stored egress evidence is missing, unsafe, or malformed."""


@dataclass(frozen=True, slots=True)
class EgressSessionContext:
    runtime: str
    session_id: str
    directory: Path
    access_log_path: Path
    metadata_path: Path


@dataclass(frozen=True, slots=True)
class EgressSessionEvidence:
    runtime: str
    session_id: str
    started_at: str
    ended_at: str
    allowlisted_domains: tuple[str, ...]
    connect_attempts: int
    allowlisted_connects: Mapping[str, int]
    denied_connects: Mapping[str, int]
    ignored_probe_connects: int = 0
    malformed_lines: int = 0

    def __post_init__(self) -> None:
        if not self.runtime or not self.session_id:
            raise ValidationError("egress evidence identity must be non-empty")
        object.__setattr__(self, "allowlisted_domains", tuple(self.allowlisted_domains))
        object.__setattr__(self, "allowlisted_connects", dict(self.allowlisted_connects))
        object.__setattr__(self, "denied_connects", dict(self.denied_connects))

    def to_json_dict(self) -> dict:
        return {
            "runtime": self.runtime,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "allowlisted_domains": list(self.allowlisted_domains),
            "connect_attempts": self.connect_attempts,
            "allowlisted_connects": dict(sorted(self.allowlisted_connects.items())),
            "denied_connects": dict(sorted(self.denied_connects.items())),
            "ignored_probe_connects": self.ignored_probe_connects,
            "malformed_lines": self.malformed_lines,
        }

    @classmethod
    def from_json_dict(cls, payload: object) -> "EgressSessionEvidence":
        if not isinstance(payload, dict):
            raise EgressEvidenceError("egress history entry must be a JSON object")
        runtime = _required_text(payload, "runtime")
        session_id = _required_text(payload, "session_id")
        started_at = _required_text(payload, "started_at")
        ended_at = _required_text(payload, "ended_at")
        allowlisted = _text_list(
            payload.get("allowlisted_domains"), "allowlisted_domains"
        )
        connect_attempts = _nonnegative_int(
            payload.get("connect_attempts"), "connect_attempts"
        )
        allowed = _count_mapping(
            payload.get("allowlisted_connects"), "allowlisted_connects"
        )
        denied = _count_mapping(payload.get("denied_connects"), "denied_connects")
        ignored = _nonnegative_int(
            payload.get("ignored_probe_connects", 0), "ignored_probe_connects"
        )
        malformed = _nonnegative_int(
            payload.get("malformed_lines", 0), "malformed_lines"
        )
        return cls(
            runtime=runtime,
            session_id=session_id,
            started_at=started_at,
            ended_at=ended_at,
            allowlisted_domains=allowlisted,
            connect_attempts=connect_attempts,
            allowlisted_connects=allowed,
            denied_connects=denied,
            ignored_probe_connects=ignored,
            malformed_lines=malformed,
        )


@dataclass(frozen=True, slots=True)
class EgressAdviceResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


def begin_egress_session(
    paths: RepoPaths,
    runtime: str,
    allowlisted_domains: Sequence[str],
) -> EgressSessionContext:
    """Create the Caddy log directory and bookkeeping for the current run."""

    if not isinstance(paths, RepoPaths):
        raise TypeError("paths must be RepoPaths")
    allowlisted = tuple(sorted(set(allowlisted_domains)))
    if not all(
        isinstance(domain, str) and DOMAIN_RE.fullmatch(domain)
        for domain in allowlisted
    ):
        raise ValidationError("egress evidence allowlist contains an invalid hostname")

    run = current_run(paths, runtime)
    if run is None:
        raise EgressEvidenceError(f"no session run to attach egress evidence to for {runtime}")
    metadata_path = run.directory / _METADATA_FILENAME
    if metadata_path.exists() or metadata_path.is_symlink():
        raise EgressEvidenceError(
            f"egress evidence already exists for the current {runtime} run"
        )
    directory = run.directory / ACCESS_LOG_DIRNAME
    if directory.is_symlink():
        raise EgressEvidenceError(f"Caddy log directory must not be a symlink: {directory}")
    directory.mkdir(mode=0o700, exist_ok=False)
    metadata = {
        "runtime": runtime,
        "session_id": run.session_id,
        "started_at": _utc_now(),
        "active": False,
        "allowlisted_domains": list(allowlisted),
        "directory": str(directory.relative_to(paths.root)),
    }
    _write_json(metadata_path, metadata)
    return _context(paths, run, directory)


def current_egress_session(
    paths: RepoPaths,
    runtime: str,
) -> EgressSessionContext | None:
    """Return the current run's evidence context while logging is unfinished."""

    loaded = _load_unfinished(paths, runtime)
    if loaded is None:
        return None
    run, metadata = loaded
    return _context(paths, run, _metadata_directory(paths, run, metadata))


def mark_egress_session_active(paths: RepoPaths, runtime: str) -> None:
    """Mark the current run's evidence as belonging to a started agent session."""

    loaded = _load_unfinished(paths, runtime)
    if loaded is None:
        raise EgressEvidenceError(f"no unfinished egress evidence for {runtime}")
    run, metadata = loaded
    metadata["active"] = True
    _write_json(run.directory / _METADATA_FILENAME, metadata)


def finalize_egress_session(
    paths: RepoPaths,
    runtime: str,
) -> EgressSessionEvidence | None:
    """Parse the current run's Caddy log and append one idempotent history record."""

    loaded = _load_unfinished(paths, runtime)
    if loaded is None:
        return None
    run, metadata = loaded
    directory = _metadata_directory(paths, run, metadata)
    active = metadata.get("active")
    if not isinstance(active, bool):
        raise EgressEvidenceError("egress evidence active flag must be boolean")

    metadata["ended_at"] = _utc_now()
    if not active:
        # Only startup probes could have reached Caddy; keep the bookkeeping,
        # drop the raw log.
        metadata["state"] = "aborted-before-runtime-start"
        shutil.rmtree(directory)
        _write_json(run.directory / _METADATA_FILENAME, metadata)
        return None

    evidence = _parse_access_logs(directory, metadata)
    summary = run.directory / _SUMMARY_FILENAME
    _write_json(summary, evidence.to_json_dict())
    _append_history(paths, runtime, evidence)
    metadata["state"] = "recorded"
    metadata["summary"] = str(summary.relative_to(paths.root))
    _write_json(run.directory / _METADATA_FILENAME, metadata)
    return evidence


def _load_unfinished(
    paths: RepoPaths, runtime: str
) -> tuple[SessionRun, dict] | None:
    """Return the current run and its metadata while evidence is unfinished."""

    run = current_run(paths, runtime)
    if run is None:
        return None
    metadata_path = run.directory / _METADATA_FILENAME
    if not metadata_path.exists():
        return None
    metadata = _read_json_object(metadata_path, required=True)
    if _required_text(metadata, "runtime") != runtime:
        raise EgressEvidenceError("egress evidence runtime does not match")
    if _required_text(metadata, "session_id") != run.session_id:
        raise EgressEvidenceError("egress evidence does not belong to the current run")
    if "state" in metadata:
        return None
    return run, metadata


def _context(paths: RepoPaths, run: SessionRun, directory: Path) -> EgressSessionContext:
    return EgressSessionContext(
        run.runtime,
        run.session_id,
        directory,
        directory / ACCESS_LOG_FILENAME,
        run.directory / _METADATA_FILENAME,
    )


def load_evidence_history(paths: RepoPaths, runtime: str) -> tuple[EgressSessionEvidence, ...]:
    path = paths.session_artifact(runtime, _HISTORY_FILENAME)
    if not path.exists():
        return ()
    payload = _read_json(path)
    if not isinstance(payload, list):
        raise EgressEvidenceError("egress history must be a JSON array")
    return tuple(EgressSessionEvidence.from_json_dict(item) for item in payload)


def run_advise_command(
    arguments: Sequence[str],
    paths: RepoPaths,
) -> EgressAdviceResult:
    if isinstance(arguments, (str, bytes)):
        raise TypeError("advise arguments must be a sequence")
    argv = tuple(arguments)
    if not argv or argv[0] != "advise":
        raise ValidationError("unsupported advise command")
    if len(argv) != 2:
        return EgressAdviceResult(1, stderr="Usage: ./sandbox.sh advise <agent>\n")

    runtime = argv[1]
    manifest = load_model(paths.identity.runtime_manifest(runtime))
    if manifest.network.mode != "proxy":
        return EgressAdviceResult(
            0,
            stdout=(
                f"{runtime} uses network mode {manifest.network.mode}; "
                "Caddy allowlist advice is available only for proxy mode.\n"
            ),
        )

    history = load_evidence_history(paths, runtime)
    recent = history[-ADVICE_WINDOW:]
    configured = set(manifest.network.allow_domains)
    lines = [
        f"Egress policy advice for {runtime} "
        f"({len(recent)} recorded session{'s' if len(recent) != 1 else ''}; "
        f"window {ADVICE_WINDOW})"
    ]

    recommendations: list[str] = []
    if len(recent) == ADVICE_WINDOW:
        for domain in sorted(configured):
            if all(domain in item.allowlisted_domains for item in recent) and all(
                item.allowlisted_connects.get(domain, 0) == 0 for item in recent
            ):
                recommendations.append(
                    f"  - {domain} was allowlisted but unused in your last "
                    f"{ADVICE_WINDOW} sessions — consider removing it."
                )
    else:
        lines.append(
            f"  Removal advice needs {ADVICE_WINDOW} completed proxy sessions; "
            f"{len(recent)} recorded."
        )

    denied_totals: Counter[str] = Counter()
    denied_sessions: Counter[str] = Counter()
    for item in recent:
        for domain, count in item.denied_connects.items():
            if count > 0:
                denied_totals[domain] += count
                denied_sessions[domain] += 1
    for domain, count in sorted(
        denied_totals.items(), key=lambda item: (-item[1], item[0])
    ):
        if domain in configured:
            continue
        sessions = denied_sessions[domain]
        if count < _MIN_DENIED_ATTEMPTS or sessions < _MIN_DENIED_SESSIONS:
            continue
        noun = "CONNECT" if count == 1 else "CONNECTs"
        recommendations.append(
            f"  - The agent attempted {count} denied {noun} to {domain} "
            f"across {sessions} sessions — consider adding it."
        )

    if recommendations:
        lines.extend(recommendations)
    else:
        lines.append("  No allowlist changes are supported by the recorded evidence.")
    return EgressAdviceResult(0, stdout="\n".join(lines) + "\n")


def _parse_access_logs(directory: Path, metadata: dict) -> EgressSessionEvidence:
    allowlisted = _text_list(
        metadata.get("allowlisted_domains"), "allowlisted_domains"
    )
    allowed_set = set(allowlisted)
    allowed: Counter[str] = Counter()
    denied: Counter[str] = Counter()
    connect_attempts = 0
    ignored_probes = 0
    malformed = 0

    for access_log in _access_log_paths(directory):
        try:
            with access_log.open("r", encoding="utf-8") as stream:
                for raw in stream:
                    if not raw.strip():
                        continue
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        malformed += 1
                        continue
                    if not isinstance(entry, dict):
                        malformed += 1
                        continue
                    request = entry.get("request")
                    if not isinstance(request, dict):
                        continue
                    if str(request.get("method", "")).upper() != "CONNECT":
                        continue
                    if _is_verification_probe(request.get("headers")):
                        ignored_probes += 1
                        continue
                    host = _hostname(request.get("host"))
                    if not host:
                        malformed += 1
                        continue
                    connect_attempts += 1
                    if host in allowed_set:
                        allowed[host] += 1
                        continue
                    status = entry.get("status")
                    if (
                        isinstance(status, int)
                        and not isinstance(status, bool)
                        and status in {403, 407}
                        and _is_advisable_hostname(host)
                    ):
                        denied[host] += 1
        except UnicodeDecodeError as exc:
            raise EgressEvidenceError(
                f"Caddy access log is not valid UTF-8: {access_log}"
            ) from exc

    return EgressSessionEvidence(
        runtime=_required_text(metadata, "runtime"),
        session_id=_required_text(metadata, "session_id"),
        started_at=_required_text(metadata, "started_at"),
        ended_at=_required_text(metadata, "ended_at"),
        allowlisted_domains=allowlisted,
        connect_attempts=connect_attempts,
        allowlisted_connects=dict(allowed),
        denied_connects=dict(denied),
        ignored_probe_connects=ignored_probes,
        malformed_lines=malformed,
    )


def _append_history(
    paths: RepoPaths, runtime: str, evidence: EgressSessionEvidence
) -> None:
    history = list(load_evidence_history(paths, runtime))
    if not any(item.session_id == evidence.session_id for item in history):
        history.append(evidence)
        history = history[-_MAX_HISTORY:]
        payload = [item.to_json_dict() for item in history]
        _write_json(paths.session_artifact(runtime, _HISTORY_FILENAME), payload)


def _access_log_paths(directory: Path) -> tuple[Path, ...]:
    logs: list[Path] = []
    for path in directory.iterdir():
        if not path.name.startswith(ACCESS_LOG_PREFIX):
            continue
        if path.is_symlink() or not path.is_file():
            raise EgressEvidenceError(
                f"Caddy access log is not a safe regular file: {path}"
            )
        logs.append(path)
    return tuple(sorted(logs, key=lambda item: (item.stat().st_mtime_ns, item.name)))




def _metadata_directory(paths: RepoPaths, run: SessionRun, metadata: dict) -> Path:
    relative = _required_text(metadata, "directory")
    expected = run.directory / ACCESS_LOG_DIRNAME
    try:
        recorded = paths.child(*Path(relative).parts)
    except (OSError, ValidationError) as exc:
        raise EgressEvidenceError(
            f"invalid egress evidence directory: {relative}"
        ) from exc
    if recorded != expected:
        raise EgressEvidenceError("egress evidence directory does not match the current run")
    if recorded.is_symlink() or not recorded.is_dir():
        raise EgressEvidenceError(
            f"egress evidence directory is unavailable: {recorded}"
        )
    return recorded


def _hostname(value: object) -> str:
    if not isinstance(value, str) or not value:
        return ""
    authority = value.strip().lower()
    if authority.startswith("["):
        end = authority.find("]")
        return authority[1:end] if end > 1 else ""
    if authority.count(":") == 1:
        host, port = authority.rsplit(":", 1)
        if port.isdigit():
            authority = host
    return authority.rstrip(".")


def _is_advisable_hostname(host: str) -> bool:
    """Return whether a denied authority is a hostname suitable for advice."""

    if DOMAIN_RE.fullmatch(host) is None:
        return False
    try:
        ip_address(host)
    except ValueError:
        return True
    return False


def _is_verification_probe(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    for name, raw in value.items():
        if str(name).lower() != _PROBE_HEADER:
            continue
        values = raw if isinstance(raw, list) else [raw]
        return any(str(item).lower() == _PROBE_VALUE for item in values)
    return False


def _read_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file():
        raise EgressEvidenceError(
            f"egress evidence file is unavailable or unsafe: {path}"
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise EgressEvidenceError(f"egress evidence is not valid UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise EgressEvidenceError(f"egress evidence is not valid JSON: {path}: {exc}") from exc


def _read_json_object(path: Path, *, required: bool) -> dict:
    if not path.exists() and not required:
        return {}
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise EgressEvidenceError(f"egress evidence must be a JSON object: {path}")
    return payload


def _write_json(path: Path, payload: object) -> None:
    if path.is_symlink():
        raise EgressEvidenceError(
            f"egress evidence path must not be a symlink: {path}"
        )
    write_text_atomic(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _required_text(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if (
        not isinstance(value, str)
        or not value
        or any(c in value for c in ("\x00", "\n", "\r"))
    ):
        raise EgressEvidenceError(f"egress evidence {name} must be non-empty text")
    return value


def _text_list(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise EgressEvidenceError(f"egress evidence {name} must be a list")
    if not all(isinstance(item, str) and item for item in value):
        raise EgressEvidenceError(
            f"egress evidence {name} must contain non-empty text"
        )
    return tuple(value)


def _count_mapping(value: object, name: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise EgressEvidenceError(f"egress evidence {name} must be an object")
    result: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str) or not key:
            raise EgressEvidenceError(
                f"egress evidence {name} keys must be non-empty text"
            )
        result[key] = _nonnegative_int(count, f"{name}.{key}")
    return result


def _nonnegative_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EgressEvidenceError(
            f"egress evidence {name} must be a non-negative integer"
        )
    return value


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
