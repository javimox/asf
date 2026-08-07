"""Per-runtime repository configuration and CLI operations.

Each runtime owns ``agents/<runtime>/repos.yml``.  The file is parsed with
PyYAML and contains a top-level ``repos`` list. Entries may be simple path
strings (implicitly ``rw``) or mappings with ``path`` and optional ``mode`` keys.
Repository mode defaults to ``rw``; ``ro`` produces a read-only bind mount.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - dependency check covers this
    yaml = None

from .atomic import write_text_atomic
from .errors import ConfigurationError

__all__ = [
    "RepositoryCommandResult",
    "RepositoryConfigError",
    "RepositoryEntry",
    "RepositoryStore",
    "expand_home",
    "posix_basename",
    "read_entries",
    "run_repository_command",
]

_GREEN: Final = "\033[0;32m"
_YELLOW: Final = "\033[1;33m"
_RED: Final = "\033[0;31m"
_BLUE: Final = "\033[0;34m"
_DIM: Final = "\033[2m"
_RESET: Final = "\033[0m"
_VALID_MODES: Final = frozenset({"ro", "rw"})
_PYYAML_REQUIRED: Final = "PyYAML is required to read repository configuration"


class RepositoryConfigError(ConfigurationError):
    """A per-runtime repository file could not be read or updated."""


@dataclass(frozen=True, slots=True)
class RepositoryEntry:
    """One repository exposed to a runtime."""

    path: str
    mode: str = "rw"

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path or "\x00" in self.path:
            raise RepositoryConfigError("repository path must be non-empty text")
        if self.mode not in _VALID_MODES:
            raise RepositoryConfigError(
                f"repository mode must be 'ro' or 'rw', got {self.mode!r}"
            )

    @property
    def name(self) -> str:
        return posix_basename(self.path)

    @property
    def exists(self) -> bool:
        return os.path.isdir(self.path)


@dataclass(frozen=True, slots=True)
class RepositoryCommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True, slots=True)
class RepositoryStore:
    """Read and update one runtime's ``repos.yml`` file."""

    path: Path
    runtime: str
    home: str
    cwd: str

    @classmethod
    def for_file(
        cls,
        path: str | os.PathLike[str],
        *,
        runtime: str,
        home: str | None = None,
        cwd: str | os.PathLike[str] | None = None,
    ) -> "RepositoryStore":
        home_value = os.environ.get("HOME", "") if home is None else home
        cwd_value = _logical_cwd() if cwd is None else os.fspath(cwd)
        return cls(Path(path), runtime, home_value, cwd_value)

    def entries(self) -> tuple[RepositoryEntry, ...]:
        return read_entries(self.path, self.home)

    def add(self, raw: str, mode: str = "rw") -> RepositoryCommandResult:
        if not raw:
            return RepositoryCommandResult(
                1,
                stderr=(
                    "Usage: ./sandbox.sh repo add <agent> ~/path/to/repo "
                    "[--mode ro|rw]\n"
                ),
            )
        if mode not in _VALID_MODES:
            return RepositoryCommandResult(
                1,
                stderr="Repository mode must be 'ro' or 'rw'.\n",
            )

        expanded = expand_home(raw, self.home)
        if not os.path.isdir(expanded):
            return RepositoryCommandResult(
                1,
                stderr=f"{_RED}Not a directory: {expanded}{_RESET}\n",
            )

        canonical = _logical_abspath(expanded, self.cwd)
        entries = list(self.entries())
        name = posix_basename(canonical)

        for index, entry in enumerate(entries):
            if entry.path == canonical:
                if entry.mode == mode:
                    return RepositoryCommandResult(
                        0,
                        stdout=(
                            f"{_YELLOW}Already listed:{_RESET} {name} "
                            f"({_mode_label(mode)})\n"
                        ),
                    )
                entries[index] = RepositoryEntry(canonical, mode)
                self._write(entries)
                return RepositoryCommandResult(
                    0,
                    stdout=(
                        f"{_GREEN}Updated:{_RESET} {name} "
                        f"({_mode_label(mode)})\n"
                        f"  Run {_BLUE}./sandbox.sh open {self.runtime}{_RESET} "
                        "to apply\n"
                    ),
                )

        collision = next((entry for entry in entries if entry.name == name), None)
        if collision is not None:
            return RepositoryCommandResult(
                1,
                stdout=(
                    f"{_RED}Basename collision:{_RESET} another repo is already "
                    f"named {_BLUE}{name}{_RESET}\n"
                    f"  Existing: {_DIM}{collision.path}{_RESET}\n"
                    "  Rename or symlink one of them before adding.\n"
                ),
            )

        entries.append(RepositoryEntry(canonical, mode))
        self._write(entries)
        return RepositoryCommandResult(
            0,
            stdout=(
                f"{_GREEN}Added:{_RESET} {name} ({_mode_label(mode)})\n"
                f"  Run {_BLUE}./sandbox.sh open {self.runtime}{_RESET} to apply\n"
            ),
        )

    def remove(self, name: str) -> RepositoryCommandResult:
        if not name:
            return RepositoryCommandResult(
                1,
                stderr="Usage: ./sandbox.sh repo remove <agent> <repo-name>\n",
            )

        entries = list(self.entries())
        kept = [entry for entry in entries if entry.name != name]
        if len(kept) == len(entries):
            return RepositoryCommandResult(
                0,
                stdout=(
                    f"{_YELLOW}Not found: {name}{_RESET}\n"
                    f"  Run ./sandbox.sh repo list {self.runtime} to see "
                    "what is configured\n"
                ),
            )

        self._write(kept)
        return RepositoryCommandResult(
            0,
            stdout=(
                f"{_GREEN}Removed:{_RESET} {name}\n"
                f"  Run {_BLUE}./sandbox.sh open {self.runtime}{_RESET} to apply\n"
            ),
        )

    def list(self) -> RepositoryCommandResult:
        entries = self.entries()
        output = [f"\n  Repositories for {_BLUE}{self.runtime}{_RESET}\n\n"]
        for entry in entries:
            mode = _mode_label(entry.mode)
            if entry.exists:
                output.append(
                    f"  {_GREEN}✓{_RESET}  {entry.name:<24} "
                    f"{mode:<10} {_DIM}{entry.path}{_RESET}\n"
                )
            else:
                output.append(
                    f"  {_RED}✗{_RESET}  {entry.name:<24} "
                    f"{mode:<10} {_RED}not found{_RESET}\n"
                )

        if not entries:
            output.extend(
                (
                    f"  {_YELLOW}No repos configured.{_RESET}\n",
                    "  Add one:  ./sandbox.sh repo add "
                    f"{self.runtime} ~/path/to/repo\n",
                )
            )
        output.append("\n")
        return RepositoryCommandResult(0, stdout="".join(output))

    def _write(self, entries: list[RepositoryEntry]) -> None:
        _write_entries(self.path, entries)


def read_entries(
    repos_file: str | os.PathLike[str],
    home: str | None = None,
) -> tuple[RepositoryEntry, ...]:
    """Parse and validate one YAML-native repository file."""

    if yaml is None:
        raise RepositoryConfigError(_PYYAML_REQUIRED)

    path = Path(repos_file)
    home_value = os.environ.get("HOME", "") if home is None else home
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ()
    except (OSError, UnicodeDecodeError) as exc:
        raise RepositoryConfigError(
            f"Cannot read repository configuration: {path}: {exc}"
        ) from exc

    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RepositoryConfigError(
            f"Invalid repository YAML in {path}: {exc}"
        ) from exc

    if document is None:
        return ()
    if not isinstance(document, dict):
        raise RepositoryConfigError(
            f"Repository configuration must be a YAML mapping: {path}"
        )
    unknown = set(document) - {"repos"}
    if unknown:
        raise RepositoryConfigError(
            f"Unknown repository configuration key(s) in {path}: "
            + ", ".join(sorted(str(key) for key in unknown))
        )

    raw_entries = document.get("repos", [])
    if raw_entries is None:
        raw_entries = []
    if not isinstance(raw_entries, list):
        raise RepositoryConfigError(f"'repos' must be a YAML list: {path}")

    entries: list[RepositoryEntry] = []
    paths_seen: set[str] = set()
    names_seen: set[str] = set()
    for index, raw in enumerate(raw_entries):
        if isinstance(raw, str):
            raw_path = raw
            mode = "rw"
        elif isinstance(raw, dict):
            unknown_entry = set(raw) - {"path", "mode"}
            if unknown_entry:
                raise RepositoryConfigError(
                    f"Unknown key(s) in repos[{index}]: "
                    + ", ".join(sorted(str(key) for key in unknown_entry))
                )
            raw_path = raw.get("path")
            mode = raw.get("mode", "rw")
        else:
            raise RepositoryConfigError(
                f"repos[{index}] must be a path string or mapping"
            )

        if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
            raise RepositoryConfigError(
                f"repos[{index}].path must be non-empty text"
            )
        if not isinstance(mode, str) or mode not in _VALID_MODES:
            raise RepositoryConfigError(
                f"repos[{index}].mode must be 'ro' or 'rw'"
            )
        expanded = expand_home(raw_path, home_value)
        if not os.path.isabs(expanded):
            raise RepositoryConfigError(
                f"repos[{index}].path must be absolute or start with '~'"
            )
        entry = RepositoryEntry(expanded, mode)
        if entry.path in paths_seen:
            raise RepositoryConfigError(
                f"Duplicate repository path in {path}: {entry.path}"
            )
        if entry.name in names_seen:
            raise RepositoryConfigError(
                f"Duplicate repository basename in {path}: {entry.name}"
            )
        paths_seen.add(entry.path)
        names_seen.add(entry.name)
        entries.append(entry)
    return tuple(entries)


def run_repository_command(
    command: str,
    operand: str,
    store: RepositoryStore,
    *,
    mode: str = "rw",
) -> RepositoryCommandResult:
    if command == "add":
        return store.add(operand, mode)
    if command == "remove":
        return store.remove(operand)
    if command == "list":
        return store.list()
    raise ValueError(f"unsupported repository command: {command}")


def posix_basename(path: str) -> str:
    if not path:
        return ""
    stripped = path.rstrip("/")
    if not stripped:
        return "/"
    return stripped.rsplit("/", 1)[-1]


def expand_home(value: str, home: str) -> str:
    return f"{home}{value[1:]}" if value.startswith("~") else value


def _write_entries(path: Path, entries: list[RepositoryEntry]) -> None:
    if yaml is None:
        raise RepositoryConfigError(_PYYAML_REQUIRED)
    document = {
        "repos": [
            {"path": entry.path, "mode": entry.mode}
            for entry in entries
        ]
    }
    payload = yaml.safe_dump(
        document,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
    )
    existing_mode: int | None = None
    try:
        existing_mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RepositoryConfigError(
            f"Cannot inspect repository configuration: {path}: {exc}"
        ) from exc
    try:
        write_text_atomic(path, payload)
        os.chmod(path, 0o600 if existing_mode is None else existing_mode)
    except OSError as exc:
        raise RepositoryConfigError(
            f"Cannot update repository configuration: {path}: {exc}"
        ) from exc


def _mode_label(mode: str) -> str:
    return "read-only" if mode == "ro" else "read-write"


def _logical_cwd() -> str:
    value = os.environ.get("PWD", "")
    if value and os.path.isabs(value):
        try:
            if os.path.samefile(value, os.getcwd()):
                return value
        except OSError:
            pass
    return os.getcwd()


def _logical_abspath(path: str, cwd: str) -> str:
    if os.path.isabs(path):
        return os.path.normpath(path)
    return os.path.normpath(os.path.join(cwd, path))
