"""Canonical and containment-safe filesystem paths for ASF.

The module owns the fixed layout of an ASF checkout. Runtime-scoped names stay
owned by :class:`asf.identity.ResourceIdentity`; :class:`RepoPaths` keeps the
matching identity so generated paths that identity does not name can still be
placed safely below the correct session directory.

"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from .errors import ValidationError
from .identity import ResourceIdentity, validate_runtime_name

__all__ = [
    "PathEscapeError",
    "RepoPaths",
    "RepositoryNotFoundError",
    "RepositoryPathError",
]

_REQUIRED_MARKERS: Final = (
    ("sandbox.sh", "file"),
    ("agents", "directory"),
    (".devcontainer", "directory"),
)


class RepositoryPathError(ValidationError):
    """A repository or generated path could not be resolved safely."""


class RepositoryNotFoundError(RepositoryPathError):
    """The requested directory is not a complete ASF checkout."""


class PathEscapeError(RepositoryPathError):
    """A child path escaped the directory that was meant to contain it."""


@dataclass(frozen=True, slots=True)
class RepoPaths:
    """Physical ASF checkout and its stable repository locations."""

    root: Path
    _identity: ResourceIdentity = field(init=False, repr=False, compare=False)
    _state_home: Path = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            raw = Path(self.root)
        except TypeError as exc:
            raise RepositoryNotFoundError(
                f"repository root must be text or path-like: {self.root!r}"
            ) from exc

        try:
            physical = raw.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RepositoryNotFoundError(
                f"cannot resolve repository root: {raw}"
            ) from exc

        if not physical.is_dir() or not _looks_like_repository(physical):
            raise RepositoryNotFoundError(f"not an ASF repository: {physical}")

        object.__setattr__(self, "root", physical)
        object.__setattr__(
            self,
            "_identity",
            ResourceIdentity.from_physical_path(physical),
        )
        object.__setattr__(self, "_state_home", _resolve_state_home())
        try:
            self.state_dir.relative_to(self.root)
        except ValueError:
            pass
        else:
            raise RepositoryPathError(
                f"ASF state directory must be outside the repository: {self.state_dir}"
            )

    @classmethod
    def discover(
        cls,
        start: str | os.PathLike[str] | None = None,
    ) -> "RepoPaths":
        """Find the nearest physical ASF checkout at or above ``start``.

        With no explicit start, discovery is anchored to this module rather
        than the current working directory. This mirrors Bash deriving
        ``SCRIPT_DIR`` from ``BASH_SOURCE`` and prevents Python from selecting
        a different checkout merely because the user changed directory.
        """

        try:
            raw = Path(__file__) if start is None else Path(start)
        except TypeError as exc:
            raise RepositoryNotFoundError(
                f"repository search path must be text or path-like: {start!r}"
            ) from exc

        try:
            physical = raw.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise RepositoryNotFoundError(
                f"cannot resolve repository search path: {raw}"
            ) from exc

        current = physical.parent if physical.is_file() else physical
        if not current.is_dir():
            raise RepositoryNotFoundError(
                f"repository search path is not a file or directory: {physical}"
            )

        for candidate in (current, *current.parents):
            if _looks_like_repository(candidate):
                return cls(candidate)

        raise RepositoryNotFoundError(
            f"no ASF repository found at or above: {physical}"
        )

    @classmethod
    def for_root(cls, root: str | os.PathLike[str]) -> "RepoPaths":
        """Construct paths from an explicit checkout, resolving symlinks."""

        try:
            return cls(root=Path(root))
        except TypeError as exc:
            raise RepositoryNotFoundError(
                f"repository root must be text or path-like: {root!r}"
            ) from exc

    @classmethod
    def from_checkout(cls, root: str | os.PathLike[str]) -> "RepoPaths":
        """Readable alias for :meth:`for_root`."""

        return cls.for_root(root)

    @property
    def identity(self) -> ResourceIdentity:
        """Identity calculated from exactly the same physical checkout root."""

        return self._identity

    # Canonical fixed-layout properties.
    @property
    def config_file(self) -> Path:
        return self.root / "asf.conf"

    def agent_repos_file(self, runtime: str) -> Path:
        """Return one runtime's machine-local repository configuration."""

        return self.identity.runtime_manifest(runtime).parent / "repos.yml"

    @property
    def agents_dir(self) -> Path:
        return self.root / "agents"

    @property
    def secrets_dir(self) -> Path:
        return self.root / "secrets"

    @property
    def tools_dir(self) -> Path:
        return self.root / "tools"

    @property
    def tests_dir(self) -> Path:
        return self.root / "tests"

    @property
    def devcontainer_dir(self) -> Path:
        return self.root / ".devcontainer"

    @property
    def sessions_dir(self) -> Path:
        return self.devcontainer_dir / "sessions"

    @property
    def state_dir(self) -> Path:
        """Checkout-scoped host state that is never placed inside the checkout."""

        return _safe_child(self._state_home, ("asf", self.identity.prefix))

    @property
    def devcontainer_base(self) -> Path:
        return self.devcontainer_dir / "devcontainer.base.json"

    @property
    def broker_probe_tool(self) -> Path:
        return self.tools_dir / "broker_probe.py"

    @property
    def litellm_entrypoint(self) -> Path:
        return self.tools_dir / "litellm_entrypoint.py"

    @property
    def litellm_observer(self) -> Path:
        return self.tools_dir / "litellm_observer.py"

    def child(self, *parts: str | os.PathLike[str]) -> Path:
        """Return a physical child path contained by the checkout root.

        Existing symlink prefixes are resolved even when the final child does
        not exist. A symlink inside the checkout therefore cannot redirect a
        future write outside the checkout.
        """

        return _safe_child(self.root, parts)

    def state_artifact(
        self,
        runtime: str,
        *parts: str | os.PathLike[str],
    ) -> Path:
        """Return a safe host-only state path for one runtime."""

        runtime = validate_runtime_name(runtime)
        session = _safe_child(self.state_dir, ("sessions", runtime))
        return _safe_child(session, parts)

    def session_artifact(
        self,
        runtime: str,
        *parts: str | os.PathLike[str],
    ) -> Path:
        """Return a safe generated path below one runtime session directory.

        ``ResourceIdentity`` supplies the session directory. The containment
        layer then proves that directory itself, and the requested artifact,
        remain inside this checkout even if an attacker planted a symlink.
        """

        lexical_session = self.identity.session_dir(runtime)
        relative_session = lexical_session.relative_to(self.root)
        physical_session = _safe_child(self.root, relative_session.parts)
        return _safe_child(physical_session, parts)


def _resolve_state_home() -> Path:
    """Return the XDG state home, falling back to ``~/.local/state``."""

    configured = os.environ.get("XDG_STATE_HOME")
    if configured:
        candidate = Path(configured)
        if candidate.is_absolute():
            return candidate
    return Path.home() / ".local" / "state"


def _looks_like_repository(candidate: Path) -> bool:
    for name, kind in _REQUIRED_MARKERS:
        marker = candidate / name
        if kind == "file" and not marker.is_file():
            return False
        if kind == "directory" and not marker.is_dir():
            return False
    return True


def _safe_child(
    base: Path,
    parts: tuple[str | os.PathLike[str], ...],
) -> Path:
    if not parts:
        raise RepositoryPathError("at least one child path component is required")

    candidate = base
    for index, part in enumerate(parts):
        try:
            value = os.fspath(part)
        except TypeError as exc:
            raise RepositoryPathError(
                f"path component {index} must be text or path-like"
            ) from exc
        if not isinstance(value, str):
            raise RepositoryPathError(
                f"path component {index} must resolve to text"
            )
        if not value:
            raise RepositoryPathError(f"path component {index} is empty")
        if "\x00" in value:
            raise RepositoryPathError(
                f"path component {index} contains a NUL byte"
            )

        component = Path(value)
        if component.is_absolute():
            raise PathEscapeError(f"absolute child path is not allowed: {value!r}")
        if ".." in component.parts:
            raise PathEscapeError(f"child path contains traversal: {value!r}")
        candidate /= component

    try:
        physical_base = base.resolve(strict=False)
        physical_candidate = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise RepositoryPathError(f"cannot resolve child path: {candidate}") from exc

    try:
        relative = physical_candidate.relative_to(physical_base)
    except ValueError as exc:
        raise PathEscapeError(
            f"child path escapes {physical_base}: {physical_candidate}"
        ) from exc

    if relative == Path("."):
        raise PathEscapeError(f"child path does not name a child of {physical_base}")

    return physical_candidate
