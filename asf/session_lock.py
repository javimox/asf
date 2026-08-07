"""Atomic, ownership-safe ASF session locks.

ASF keeps one lock directory per runtime so two ``open`` commands cannot own
the same session concurrently.  The lock format remains compatible with the
accepted Bash implementation: ``.devcontainer/.open-lock-<runtime>/pid``.

This module adds the guarantees needed before cleanup moves to Python:

* acquisition uses atomic directory creation;
* a live owner is never evicted;
* stale replacement is race-safe;
* release removes only the exact lock acquired by this process;
* malformed or symlinked stale locks are removed without following links.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .errors import InfrastructureError, ValidationError
from .identity import ResourceIdentity, validate_runtime_name

__all__ = [
    "CLAIM_GRACE_SECONDS",
    "AcquiredSessionLock",
    "SessionAlreadyRunningError",
    "SessionLockAcquireError",
    "SessionLockError",
    "SessionLockManager",
    "SessionLockOwnershipError",
    "SessionLockSnapshot",
    "process_alive",
]


CLAIM_GRACE_SECONDS = 5.0


class SessionLockError(InfrastructureError):
    """Base class for session-lock failures."""


class SessionAlreadyRunningError(SessionLockError):
    """A live process already owns the requested runtime lock."""

    def __init__(self, runtime: str, pid: int | None) -> None:
        self.runtime = runtime
        self.pid = pid
        owner = str(pid) if pid is not None else "unknown"
        super().__init__(f"a {runtime} session (PID {owner}) is already running")


class SessionLockAcquireError(SessionLockError):
    """A session lock could not be created or replaced safely."""


class SessionLockOwnershipError(SessionLockError):
    """A caller attempted to release a lock it no longer owns."""


@dataclass(frozen=True, slots=True)
class SessionLockSnapshot:
    """Read-only state of one runtime lock."""

    path: Path
    pid: int | None
    owner_alive: bool
    device: int = 0
    inode: int = 0
    age_seconds: float | None = None
    claim_in_progress: bool = False

    @property
    def exists(self) -> bool:
        return True

    @property
    def being_claimed(self) -> bool:
        return self.claim_in_progress

    @property
    def is_stale(self) -> bool:
        return not self.owner_alive and not self.being_claimed


@dataclass(frozen=True, slots=True)
class AcquiredSessionLock:
    """Identity token proving ownership of one acquired lock directory."""

    runtime: str
    path: Path
    owner_pid: int
    device: int
    inode: int


ProcessAlive = Callable[[int | None], bool]


class SessionLockManager:
    """Acquire, inspect, and release checkout-scoped runtime locks."""

    def __init__(
        self,
        identity: ResourceIdentity,
        *,
        process_alive: ProcessAlive | None = None,
    ) -> None:
        if not isinstance(identity, ResourceIdentity):
            raise TypeError("identity must be a ResourceIdentity")
        self._identity = identity
        self._process_alive = _process_alive if process_alive is None else process_alive

    @property
    def identity(self) -> ResourceIdentity:
        return self._identity

    def inspect(self, runtime: str) -> SessionLockSnapshot | None:
        """Return the current lock without following a top-level symlink."""

        path = self._lock_path(validate_runtime_name(runtime), create_parent=False)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SessionLockAcquireError(
                f"cannot inspect session lock {path}: {exc}"
            ) from exc

        physical_directory = stat.S_ISDIR(metadata.st_mode) and not path.is_symlink()
        pid = _read_pid(path / "pid") if physical_directory else None
        age_seconds = max(0.0, time.time() - metadata.st_mtime)
        claim_in_progress = (
            physical_directory
            and pid is None
            and age_seconds < CLAIM_GRACE_SECONDS
        )
        try:
            alive = bool(self._process_alive(pid))
        except Exception as exc:  # injected liveness checks must fail closed
            raise SessionLockAcquireError(
                f"cannot determine owner of session lock {path}: {exc}"
            ) from exc
        return SessionLockSnapshot(
            path=path,
            pid=pid,
            owner_alive=alive,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            age_seconds=age_seconds,
            claim_in_progress=claim_in_progress,
        )

    def acquire(
        self,
        runtime: str,
        *,
        owner_pid: int | None = None,
    ) -> AcquiredSessionLock:
        """Acquire a runtime lock, replacing only a confirmed stale lock."""

        runtime = validate_runtime_name(runtime)
        pid = os.getpid() if owner_pid is None else _validate_pid(owner_pid)
        path = self._lock_path(runtime, create_parent=True)

        try:
            return self._create(runtime, path, pid)
        except FileExistsError:
            existing = self.inspect(runtime)
            if existing is not None and (
                existing.owner_alive or existing.being_claimed
            ):
                raise SessionAlreadyRunningError(runtime, existing.pid)
            return self._replace_stale(runtime, path, pid)
        except OSError as exc:
            raise SessionLockAcquireError(
                f"could not acquire session lock {path}: {exc}"
            ) from exc

    def owned_token(
        self,
        runtime: str,
        owner_pid: int,
    ) -> AcquiredSessionLock:
        """Return a release token for the exact live lock owned by ``owner_pid``.

        ``open`` acquires the Bash-compatible lock before replacing itself with
        the Python session supervisor.  The PID is preserved across ``exec``,
        so this method can safely adopt that existing lock without recreating
        it or weakening the ownership checks used by :meth:`release`.
        """

        runtime = validate_runtime_name(runtime)
        pid = _validate_pid(owner_pid)
        snapshot = self.inspect(runtime)
        if snapshot is None:
            raise SessionLockOwnershipError(
                f"session lock is missing for owned cleanup: {runtime}"
            )
        if snapshot.pid != pid:
            owner = "unknown" if snapshot.pid is None else str(snapshot.pid)
            raise SessionLockOwnershipError(
                f"session lock for {runtime} belongs to PID {owner}, not {pid}"
            )
        if not snapshot.owner_alive:
            raise SessionLockOwnershipError(
                f"session lock owner PID {pid} is not alive for {runtime}"
            )
        return AcquiredSessionLock(
            runtime=runtime,
            path=snapshot.path,
            owner_pid=pid,
            device=snapshot.device,
            inode=snapshot.inode,
        )

    def release(self, lock: AcquiredSessionLock) -> None:
        """Release only the exact directory represented by ``lock``."""

        if not isinstance(lock, AcquiredSessionLock):
            raise TypeError("lock must be an AcquiredSessionLock")
        path = lock.path
        quarantine = path.with_name(
            f"{path.name}.release-{lock.owner_pid}-{uuid.uuid4().hex}"
        )
        try:
            os.replace(path, quarantine)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise SessionLockOwnershipError(
                f"could not isolate owned session lock {path}: {exc}"
            ) from exc

        try:
            metadata = quarantine.lstat()
        except OSError as exc:
            if not os.path.lexists(path):
                try:
                    os.replace(quarantine, path)
                except OSError:
                    pass
            raise SessionLockOwnershipError(
                f"cannot inspect isolated session lock {quarantine}: {exc}"
            ) from exc
        current_pid = (
            _read_pid(quarantine / "pid")
            if quarantine.is_dir() and not quarantine.is_symlink()
            else None
        )
        if (
            metadata.st_dev != lock.device
            or metadata.st_ino != lock.inode
            or current_pid != lock.owner_pid
        ):
            if not os.path.lexists(path):
                try:
                    os.replace(quarantine, path)
                except OSError:
                    pass
            raise SessionLockOwnershipError(
                f"session lock ownership changed before release: {path}"
            )
        try:
            _remove_path(quarantine)
        except OSError as exc:
            raise SessionLockOwnershipError(
                f"could not release session lock {path}: {exc}"
            ) from exc

    def remove_stale(self, runtime: str) -> bool:
        """Remove one confirmed stale lock without following symlinks.

        Returns ``False`` when the lock disappeared before cleanup. A live or
        in-progress owner is never removed.
        """

        runtime = validate_runtime_name(runtime)
        snapshot = self.inspect(runtime)
        if snapshot is None:
            return False
        if snapshot.owner_alive or snapshot.being_claimed:
            raise SessionLockOwnershipError(
                f"refusing to remove active session lock {snapshot.path}"
            )

        path = snapshot.path
        quarantine = path.with_name(
            f"{path.name}.cleanup-{os.getpid()}-{uuid.uuid4().hex}"
        )
        try:
            os.replace(path, quarantine)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise SessionLockOwnershipError(
                f"could not isolate stale session lock {path}: {exc}"
            ) from exc

        try:
            metadata = quarantine.lstat()
            current_pid = (
                _read_pid(quarantine / "pid")
                if quarantine.is_dir() and not quarantine.is_symlink()
                else None
            )
            if (
                metadata.st_dev != snapshot.device
                or metadata.st_ino != snapshot.inode
                or current_pid != snapshot.pid
            ):
                raise SessionLockOwnershipError(
                    f"session lock changed before stale cleanup: {path}"
                )
            _remove_path(quarantine)
        except Exception:
            if os.path.lexists(quarantine) and not os.path.lexists(path):
                try:
                    os.replace(quarantine, path)
                except OSError:
                    pass
            raise
        return True

    @contextmanager
    def hold(
        self,
        runtime: str,
        *,
        owner_pid: int | None = None,
    ) -> Iterator[AcquiredSessionLock]:
        """Context manager that releases its lock after success or failure."""

        acquired = self.acquire(runtime, owner_pid=owner_pid)
        try:
            yield acquired
        finally:
            self.release(acquired)

    def _lock_path(self, runtime: str, *, create_parent: bool) -> Path:
        root = self._identity.script_dir
        parent = root / ".devcontainer"
        try:
            root.lstat()
        except OSError as exc:
            raise SessionLockAcquireError(
                f"cannot inspect ASF checkout root {root}: {exc}"
            ) from exc
        if not root.is_dir() or root.is_symlink():
            raise SessionLockAcquireError(
                f"ASF checkout root is not a physical directory: {root}"
            )
        try:
            if create_parent:
                parent.mkdir(mode=0o700, exist_ok=True)
            parent.lstat()
        except FileNotFoundError:
            if not create_parent:
                return self._identity.session_lock(runtime)
            raise SessionLockAcquireError(
                f"missing ASF session directory: {parent}"
            )
        except OSError as exc:
            raise SessionLockAcquireError(
                f"cannot prepare ASF session directory {parent}: {exc}"
            ) from exc
        if not parent.is_dir() or parent.is_symlink():
            raise SessionLockAcquireError(
                f"ASF session directory is not a physical checkout directory: {parent}"
            )
        return self._identity.session_lock(runtime)

    def _create(
        self,
        runtime: str,
        path: Path,
        owner_pid: int,
    ) -> AcquiredSessionLock:
        path.mkdir(mode=0o700)
        try:
            _write_pid(path / "pid", owner_pid)
            if _read_pid(path / "pid") != owner_pid:
                raise SessionLockAcquireError(
                    f"session lock owner could not be confirmed: {path}"
                )
            metadata = path.lstat()
        except Exception:
            _remove_path(path)
            raise
        return AcquiredSessionLock(
            runtime=runtime,
            path=path,
            owner_pid=owner_pid,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )

    def _replace_stale(
        self,
        runtime: str,
        path: Path,
        owner_pid: int,
    ) -> AcquiredSessionLock:
        quarantine = path.with_name(
            f"{path.name}.stale-{owner_pid}-{uuid.uuid4().hex}"
        )
        try:
            os.replace(path, quarantine)
        except FileNotFoundError:
            # Another contender removed the stale lock.  Compete for the now
            # absent canonical path rather than assuming ownership.
            try:
                return self._create(runtime, path, owner_pid)
            except FileExistsError as exc:
                current = self.inspect(runtime)
                if current is not None and (
                    current.owner_alive or current.being_claimed
                ):
                    raise SessionAlreadyRunningError(runtime, current.pid) from exc
                raise SessionLockAcquireError(
                    f"session lock changed while replacing stale state: {path}"
                ) from exc
        except OSError as exc:
            raise SessionLockAcquireError(
                f"could not quarantine stale session lock {path}: {exc}"
            ) from exc

        try:
            acquired = self._create(runtime, path, owner_pid)
        except FileExistsError as exc:
            _remove_path(quarantine)
            raise SessionLockAcquireError(
                "another process acquired session lock while stale state "
                f"was removed: {path}"
            ) from exc
        except Exception as exc:
            if not os.path.lexists(path):
                try:
                    os.replace(quarantine, path)
                except OSError as restore_error:
                    raise SessionLockAcquireError(
                        f"could not restore stale session lock {path}: "
                        f"{restore_error}"
                    ) from exc
            else:
                _remove_path(quarantine)
            if isinstance(exc, SessionLockError):
                raise
            raise SessionLockAcquireError(
                f"could not replace stale session lock {path}: {exc}"
            ) from exc
        try:
            _remove_path(quarantine)
        except OSError as exc:
            try:
                self.release(acquired)
            except SessionLockError:
                pass
            raise SessionLockAcquireError(
                f"could not remove stale session lock {quarantine}: {exc}"
            ) from exc
        return acquired


def _validate_pid(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationError(f"owner PID must be a positive integer: {value!r}")
    return value


def _write_pid(path: Path, pid: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        data = f"{pid}\n".encode("ascii")
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise OSError("short write while recording session lock owner")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_pid(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value > 0 else None


def _process_alive(pid: int | None) -> bool:
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        return exc.errno == errno.EPERM
    return True


def process_alive(pid: int | None) -> bool:
    """Return whether ``pid`` names a live process using ``kill -0``."""

    return _process_alive(pid)


def _remove_path(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()
