"""Collision-safe subnet allocation for routed ASF sessions.

The allocator is deliberately small: one user-wide lock protects discovery,
selection, and reservation.  The caller keeps that lock until the planned
Podman networks have been created, then releases it by leaving the context.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Callable, Iterator, Sequence
from xml.etree import ElementTree

from .errors import InfrastructureError, ValidationError
from .podman import PodmanClient
from .process import CommandError, CommandResult, run
from .runtime_plan import RoutedSubnetAllocation
from .subnets import reservation_dir, reservation_path

__all__ = [
    "DEFAULT_POOL",
    "DEFAULT_PREFIX",
    "RoutedAllocationError",
    "RoutedAllocator",
    "allocate",
    "allocation_lock",
    "host_routes",
    "libvirt_subnets",
    "podman_subnets",
    "release_reservation",
    "reserved_subnets",
    "write_reservation",
]

DEFAULT_POOL = IPv4Network("10.203.0.0/16")
DEFAULT_PREFIX = 24
MAX_PROBES = 256
_LOCK_TIMEOUT = 60.0
_LOCK_POLL = 0.05
_ROUTE_TYPES = {
    "local", "broadcast", "unreachable", "prohibit", "blackhole", "throw",
    "nat", "multicast", "anycast",
}
_ROUTE_DEST_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+(?:/\d+)?$")
CommandRunner = Callable[..., CommandResult]


class RoutedAllocationError(InfrastructureError):
    """Routed subnet discovery, reservation, or allocation failed closed."""


def _candidates(
    session: str,
    pool: IPv4Network,
    prefix: int,
) -> Iterator[IPv4Network]:
    if prefix < pool.prefixlen:
        raise ValidationError(
            f"pool {pool} is smaller than requested /{prefix} subnets"
        )
    if prefix > 28:
        raise ValidationError(
            "routed session subnets must be /28 or larger for fixed addresses"
        )
    count = 1 << (prefix - pool.prefixlen)
    block_size = 1 << (32 - prefix)
    seed = int(hashlib.sha256(session.encode("utf-8")).hexdigest()[:8], 16)
    start = seed % count
    for offset in range(min(count, MAX_PROBES)):
        index = (start + offset) % count
        address = int(pool.network_address) + index * block_size
        yield IPv4Network((address, prefix))


def allocate(
    session: str,
    count: int,
    pool: IPv4Network,
    prefix: int,
    avoid: Sequence[IPv4Network],
) -> tuple[IPv4Network, ...]:
    if not isinstance(session, str) or not session:
        raise ValidationError("allocation session must be non-empty text")
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise ValidationError("allocation count must be positive")
    chosen: list[IPv4Network] = []
    occupied = tuple(avoid)
    for candidate in _candidates(session, pool, prefix):
        if any(candidate.overlaps(item) for item in (*occupied, *chosen)):
            continue
        chosen.append(candidate)
        if len(chosen) == count:
            return tuple(chosen)
    raise RoutedAllocationError(
        f"could not find {count} free /{prefix} subnet(s) in {pool} after "
        f"{MAX_PROBES} probes"
    )




def _run_output(
    runner: CommandRunner,
    argv: tuple[str, ...],
    timeout: float,
) -> str:
    try:
        result = runner(argv, timeout=timeout)
    except CommandError as exc:
        raise RoutedAllocationError(
            f"could not run {' '.join(argv)}: {exc}"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        suffix = f": {detail}" if detail else ""
        raise RoutedAllocationError(
            f"command failed ({result.returncode}): {' '.join(argv)}{suffix}"
        )
    return result.stdout


def podman_subnets(
    engine: str = "podman",
    *,
    runner: CommandRunner = run,
) -> list[IPv4Network]:
    ids = _run_output(runner, (engine, "network", "ls", "-q"), 20).splitlines()
    found: list[IPv4Network] = []
    for network_id in (item.strip() for item in ids if item.strip()):
        raw = _run_output(
            runner, (engine, "network", "inspect", network_id), 20
        )
        try:
            documents = json.loads(raw or "[]")
        except json.JSONDecodeError as exc:
            raise RoutedAllocationError(
                f"Podman returned malformed subnet data for {network_id}"
            ) from exc
        if (
            not isinstance(documents, list)
            or len(documents) != 1
            or not isinstance(documents[0], dict)
        ):
            raise RoutedAllocationError(
                f"Podman inspect for {network_id} did not return one object"
            )
        entries = documents[0].get("subnets") or documents[0].get("Subnets") or []
        if not isinstance(entries, list):
            raise RoutedAllocationError(
                f"Podman subnets for {network_id} is not a list"
            )
        for entry in entries:
            if not isinstance(entry, dict):
                raise RoutedAllocationError(
                    f"Podman subnet entry for {network_id} is not an object"
                )
            value = entry.get("subnet") or entry.get("Subnet")
            if not value:
                continue
            try:
                parsed = ip_network(value, strict=False)
            except ValueError as exc:
                raise RoutedAllocationError(
                    f"Podman network {network_id} has invalid subnet {value!r}"
                ) from exc
            if isinstance(parsed, IPv4Network):
                found.append(parsed)
    return found


def host_routes(*, runner: CommandRunner = run) -> list[IPv4Network]:
    output = _run_output(
        runner, ("ip", "-4", "route", "show", "table", "all"), 10
    )
    found: list[IPv4Network] = []
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        index = 1 if fields[0] in _ROUTE_TYPES and len(fields) > 1 else 0
        destination = fields[index]
        if (
            destination == "default"
            or _ROUTE_DEST_RE.fullmatch(destination) is None
        ):
            continue
        try:
            found.append(IPv4Network(destination, strict=False))
        except ValueError as exc:
            raise RoutedAllocationError(
                f"host route contains invalid destination {destination!r}"
            ) from exc
    return found


def libvirt_subnets(
    command: str = "virsh",
    *,
    runner: CommandRunner = run,
) -> list[IPv4Network]:
    if shutil.which(command) is None:
        return []
    names = [
        line.strip()
        for line in _run_output(
            runner, (command, "net-list", "--all", "--name"), 20
        ).splitlines()
        if line.strip()
    ]
    found: list[IPv4Network] = []
    for name in names:
        xml_text = _run_output(runner, (command, "net-dumpxml", name), 20)
        try:
            root = ElementTree.fromstring(xml_text)
        except ElementTree.ParseError as exc:
            raise RoutedAllocationError(
                f"libvirt network {name} returned malformed XML"
            ) from exc
        for element in root.findall("ip"):
            address = element.get("address", "")
            prefix = element.get("prefix") or element.get("netmask")
            if not address or not prefix or ":" in address:
                continue
            try:
                found.append(IPv4Network(f"{address}/{prefix}", strict=False))
            except ValueError as exc:
                raise RoutedAllocationError(
                    f"libvirt network {name} has invalid IPv4 range"
                ) from exc
    return found


@contextmanager
def allocation_lock(
    directory: Path,
    *,
    timeout: float = _LOCK_TIMEOUT,
    sleeper: Callable[[float], None] = time.sleep,
) -> Iterator[None]:
    root = Path(directory)
    try:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink() or not stat.S_ISDIR(root.stat().st_mode):
            raise RoutedAllocationError(f"reservation directory is unsafe: {root}")
        os.chmod(root, 0o700)
        lock_path = root / ".lock"
        handle = lock_path.open("a+", encoding="utf-8")
        os.chmod(lock_path, 0o600)
    except OSError as exc:
        raise RoutedAllocationError(
            f"could not use routed subnet reservation directory {root}: {exc}"
        ) from exc

    with handle:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RoutedAllocationError(
                        "timed out waiting for the routed subnet lock"
                    ) from None
                sleeper(_LOCK_POLL)
            except OSError as exc:
                raise RoutedAllocationError(
                    f"could not lock routed subnet reservations: {exc}"
                ) from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def reserved_subnets(
    directory: Path,
    excluding_session: str = "",
) -> list[IPv4Network]:
    root = Path(directory)
    own = reservation_path(excluding_session, root) if excluding_session else None
    found: list[IPv4Network] = []
    for path in root.glob("*.json"):
        if path == own:
            continue
        try:
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise ValueError("not a regular file")
            data = json.loads(path.read_text(encoding="utf-8"))
            pid = data.get("pid")
            if pid is None or not _pid_alive(pid):
                path.unlink(missing_ok=True)
                continue
            values = data["subnets"]
            if not isinstance(values, list):
                raise ValueError("subnets is not a list")
            for value in values:
                parsed = ip_network(value, strict=True)
                if not isinstance(parsed, IPv4Network):
                    raise ValueError("IPv6 reservation")
                found.append(parsed)
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise RoutedAllocationError(
                f"invalid subnet reservation {path}: {exc}"
            ) from exc
    return found


def write_reservation(
    directory: Path,
    session: str,
    pool: IPv4Network,
    prefix: int,
    subnets: Sequence[IPv4Network],
    *,
    owner_pid: int | None = None,
) -> None:
    pid = os.getpid() if owner_pid is None else owner_pid
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise RoutedAllocationError("reservation owner PID must be positive")
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not stat.S_ISDIR(root.stat().st_mode):
        raise RoutedAllocationError(f"reservation directory is unsafe: {root}")
    os.chmod(root, 0o700)
    target = reservation_path(session, root)
    if target.is_symlink():
        raise RoutedAllocationError(
            f"reservation path must not be a symlink: {target}"
        )
    payload = {
        "session": session,
        "pid": pid,
        "pool": str(pool),
        "prefix": prefix,
        "subnets": [str(item) for item in subnets],
    }
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=root,
            prefix=f".{target.name}.",
            delete=False,
        ) as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        os.chmod(temporary, 0o600)
        temporary.replace(target)
    except OSError as exc:
        raise RoutedAllocationError(
            f"could not write subnet reservation {target}: {exc}"
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def release_reservation(directory: Path, session: str) -> None:
    target = reservation_path(session, Path(directory))
    if target.is_symlink():
        target.unlink(missing_ok=True)
        return
    target.unlink(missing_ok=True)

@dataclass(frozen=True, slots=True)
class RoutedAllocator:
    podman: PodmanClient
    runner: CommandRunner = field(default=run, repr=False, compare=False)
    reservation_root: Path = field(default_factory=reservation_dir)
    sleeper: Callable[[float], None] = field(
        default=time.sleep, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")
        if not callable(self.runner) or not callable(self.sleeper):
            raise TypeError("runner and sleeper must be callable")
        object.__setattr__(self, "reservation_root", Path(self.reservation_root))

    @contextmanager
    def reserve(
        self,
        *,
        session: str,
        owner_pid: int,
        pool: IPv4Network,
        prefix: int,
        avoid: Sequence[IPv4Network],
        skip_libvirt: bool = False,
    ) -> Iterator[RoutedSubnetAllocation]:
        if isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid <= 0:
            raise ValidationError("reservation owner PID must be positive")
        with self._lock():
            occupied = list(avoid)
            occupied.extend(self._podman_subnets())
            occupied.extend(self._host_routes())
            if not skip_libvirt:
                occupied.extend(self._libvirt_subnets())
            occupied.extend(self._reserved_subnets(excluding_session=session))
            self._release(session)
            selected = allocate(session, 3, pool, prefix, occupied)
            self._write(session, owner_pid, pool, prefix, selected)
            yield RoutedSubnetAllocation(*selected)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        with allocation_lock(
            self.reservation_root,
            sleeper=self.sleeper,
        ):
            yield

    def _podman_subnets(self) -> list[IPv4Network]:
        return podman_subnets(str(self.podman.engine), runner=self.runner)

    def _host_routes(self) -> list[IPv4Network]:
        return host_routes(runner=self.runner)

    def _libvirt_subnets(self) -> list[IPv4Network]:
        return libvirt_subnets(runner=self.runner)

    def _reserved_subnets(self, *, excluding_session: str) -> list[IPv4Network]:
        return reserved_subnets(self.reservation_root, excluding_session)

    def _write(
        self,
        session: str,
        owner_pid: int,
        pool: IPv4Network,
        prefix: int,
        subnets: Sequence[IPv4Network],
    ) -> None:
        write_reservation(
            self.reservation_root,
            session,
            pool,
            prefix,
            subnets,
            owner_pid=owner_pid,
        )

    def _release(self, session: str) -> None:
        release_reservation(self.reservation_root, session)

    def _command(self, argv: tuple[str, ...], timeout: float) -> str:
        return _run_output(self.runner, argv, timeout)


def _pid_alive(pid: object) -> bool:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
