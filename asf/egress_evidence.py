"""Per-session Caddy evidence and conservative allowlist advice.

Caddy writes JSON access records into one dedicated session evidence directory.
At teardown ASF summarises CONNECT attempts, appends a bounded history record,
and leaves both the raw JSONL and the summary available for audit.  Advice is
read-only: it never edits a runtime manifest or weakens policy automatically.
"""

from __future__ import annotations

import json
import secrets
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

__all__ = [
    "ACCESS_LOG_CONTAINER_PATH",
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
_CURRENT_FILENAME = "egress-current.json"
_HISTORY_FILENAME = "egress-history.json"
_METADATA_FILENAME = "metadata.json"
_SUMMARY_FILENAME = "summary.json"
_EVIDENCE_DIRNAME = "evidence"
_MAX_HISTORY = 100
ADVICE_WINDOW = 12
_MAX_RAW_SESSIONS = ADVICE_WINDOW
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
    """Create one new dedicated evidence directory and current-session pointer."""

    if not isinstance(paths, RepoPaths):
        raise TypeError("paths must be RepoPaths")
    allowlisted = tuple(sorted(set(allowlisted_domains)))
    if not all(
        isinstance(domain, str) and DOMAIN_RE.fullmatch(domain)
        for domain in allowlisted
    ):
        raise ValidationError("egress evidence allowlist contains an invalid hostname")

    now = _utc_now()
    compact = now.replace("-", "").replace(":", "").replace(".", "")
    session_id = f"{compact}-{secrets.token_hex(4)}"
    current_path = paths.session_artifact(runtime, _CURRENT_FILENAME)
    if current_path.exists() or current_path.is_symlink():
        raise EgressEvidenceError(
            f"unfinished egress evidence already exists for {runtime}; "
            "recover it before starting"
        )
    evidence_root = paths.session_artifact(runtime, _EVIDENCE_DIRNAME)
    if evidence_root.is_symlink():
        raise EgressEvidenceError(
            f"egress evidence root must not be a symlink: {evidence_root}"
        )
    evidence_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    directory = evidence_root / session_id
    if directory.is_symlink():
        raise EgressEvidenceError(
            f"egress evidence directory must not be a symlink: {directory}"
        )
    directory.mkdir(mode=0o700, exist_ok=False)
    access_log_path = directory / ACCESS_LOG_FILENAME
    metadata_path = directory / _METADATA_FILENAME
    metadata = {
        "runtime": runtime,
        "session_id": session_id,
        "started_at": now,
        "active": False,
        "allowlisted_domains": list(allowlisted),
        "directory": str(directory.relative_to(paths.root)),
    }
    _write_json(metadata_path, metadata)
    _write_json(current_path, metadata)
    return EgressSessionContext(
        runtime, session_id, directory, access_log_path, metadata_path
    )


def current_egress_session(
    paths: RepoPaths,
    runtime: str,
) -> EgressSessionContext | None:
    """Return the validated current evidence context, when logging is active."""

    current_path = paths.session_artifact(runtime, _CURRENT_FILENAME)
    if not current_path.exists():
        return None
    metadata = _read_json_object(current_path, required=True)
    if _required_text(metadata, "runtime") != runtime:
        raise EgressEvidenceError("egress evidence runtime does not match")
    directory = _metadata_directory(paths, runtime, metadata)
    session_id = _required_text(metadata, "session_id")
    return EgressSessionContext(
        runtime,
        session_id,
        directory,
        directory / ACCESS_LOG_FILENAME,
        directory / _METADATA_FILENAME,
    )


def mark_egress_session_active(paths: RepoPaths, runtime: str) -> None:
    """Mark the current proxy evidence as belonging to a started agent session."""

    current_path = paths.session_artifact(runtime, _CURRENT_FILENAME)
    metadata = _read_json_object(current_path, required=True)
    if _required_text(metadata, "runtime") != runtime:
        raise EgressEvidenceError("egress evidence runtime does not match")
    metadata["active"] = True
    directory = _metadata_directory(paths, runtime, metadata)
    _write_json(directory / _METADATA_FILENAME, metadata)
    _write_json(current_path, metadata)


def finalize_egress_session(
    paths: RepoPaths,
    runtime: str,
) -> EgressSessionEvidence | None:
    """Parse the current Caddy log and append one idempotent history record."""

    current_path = paths.session_artifact(runtime, _CURRENT_FILENAME)
    if not current_path.exists():
        return None
    metadata = _read_json_object(current_path, required=True)
    if _required_text(metadata, "runtime") != runtime:
        raise EgressEvidenceError("egress evidence runtime does not match")
    directory = _metadata_directory(paths, runtime, metadata)
    active = metadata.get("active")
    if not isinstance(active, bool):
        raise EgressEvidenceError("egress evidence active flag must be boolean")

    metadata["ended_at"] = _utc_now()
    if not active:
        metadata["state"] = "aborted-before-runtime-start"
        _write_json(directory / _METADATA_FILENAME, metadata)
        shutil.rmtree(directory)
        current_path.unlink(missing_ok=True)
        return None

    evidence = _parse_access_logs(directory, metadata)
    _write_json(directory / _SUMMARY_FILENAME, evidence.to_json_dict())
    _append_history(paths, runtime, evidence)
    metadata["state"] = "recorded"
    metadata["summary"] = str((directory / _SUMMARY_FILENAME).relative_to(paths.root))
    _write_json(directory / _METADATA_FILENAME, metadata)
    current_path.unlink(missing_ok=True)
    return evidence


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
    raw_history = history[-_MAX_RAW_SESSIONS:]
    _prune_evidence_directories(
        paths, runtime, {item.session_id for item in raw_history}
    )


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


def _prune_evidence_directories(
    paths: RepoPaths,
    runtime: str,
    retained_session_ids: set[str],
) -> None:
    root = paths.session_artifact(runtime, _EVIDENCE_DIRNAME)
    if not root.exists():
        return
    if root.is_symlink() or not root.is_dir():
        raise EgressEvidenceError(
            f"egress evidence root is unavailable or unsafe: {root}"
        )
    for directory in root.iterdir():
        if directory.name in retained_session_ids:
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise EgressEvidenceError(
                f"egress evidence session path is unavailable or unsafe: {directory}"
            )
        shutil.rmtree(directory)


def _metadata_directory(paths: RepoPaths, runtime: str, metadata: dict) -> Path:
    session_id = _required_text(metadata, "session_id")
    relative = _required_text(metadata, "directory")
    expected = paths.session_artifact(runtime, _EVIDENCE_DIRNAME, session_id)
    try:
        recorded = paths.child(*Path(relative).parts)
    except (OSError, ValidationError) as exc:
        raise EgressEvidenceError(
            f"invalid egress evidence directory: {relative}"
        ) from exc
    if recorded != expected:
        raise EgressEvidenceError("egress evidence directory does not match session identity")
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
