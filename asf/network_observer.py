"""On-demand routed TAP packet capture."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from .errors import InfrastructureError
from .runs import current_run, read_run_policy
from .paths import RepoPaths
from .podman import ObjectKind, PodmanClient
from .session import NoRunningSessionError, SessionDiscovery, SessionRole, SessionStatus
from .session_events import record_session_event

__all__ = [
    "CaptureResult",
    "NetworkCaptureError",
    "NetworkCaptureService",
    "run_capture_command",
]

_CAPTURE_INTERFACE = "tap0"
_CAPTURE_SNAPLEN = 0
_STOP_TIMEOUT = 5
_USAGE = "Usage: ./sandbox.sh capture {start|stop} [agent]\n"


class NetworkCaptureError(InfrastructureError):
    """A routed TAP packet capture could not be managed safely."""


@dataclass(frozen=True, slots=True)
class CaptureResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


def run_capture_command(
    arguments: Sequence[str],
    paths: RepoPaths,
    *,
    podman: PodmanClient | None = None,
    require_available: bool = True,
) -> CaptureResult:
    """Start or stop packet capture for one running routed microVM."""

    if isinstance(arguments, (str, bytes)):
        raise TypeError("capture arguments must be a sequence")
    argv = tuple(arguments)
    if (
        len(argv) not in {2, 3}
        or not argv
        or argv[0] != "capture"
        or argv[1] not in {"start", "stop"}
    ):
        return CaptureResult(1, stderr=_USAGE)

    client = PodmanClient() if podman is None else podman
    if require_available:
        client.require_available()
    discovery = SessionDiscovery.from_paths(paths, podman=client)
    requested = argv[2] if len(argv) == 3 else None
    runtime = discovery.resolve_runtime(requested)
    session = discovery.session(runtime)
    if session.status is not SessionStatus.RUNNING:
        raise NoRunningSessionError(f"no running session for {runtime}")

    service = NetworkCaptureService(client)
    observer = session.role(SessionRole.NETWORK_OBSERVER)

    if argv[1] == "stop":
        if observer is None:
            return CaptureResult(stdout="Packet capture is not running.\n")
        run = current_run(paths, runtime)
        latest = _latest_capture(run.directory) if run is not None else None
        service.stop(observer.container_id)
        if run is not None:
            record_session_event(
                paths,
                runtime,
                "network_capture_stopped",
                **({"file": latest.name} if latest is not None else {}),
            )
        suffix = f": {_display_path(paths, latest)}" if latest is not None else "."
        return CaptureResult(stdout=f"Packet capture stopped{suffix}\n")

    try:
        policy = read_run_policy(paths, runtime)
    except ValueError as exc:
        raise NetworkCaptureError(
            f"cannot read the policy snapshot for running session {runtime}"
        ) from exc
    if policy.isolation != "microvm" or policy.network_mode != "routed":
        raise NetworkCaptureError("packet capture requires a routed microVM session")
    run = current_run(paths, runtime)
    if run is None:
        raise NetworkCaptureError(
            f"observation session is unavailable for running session {runtime}"
        )

    if observer is not None and observer.is_running:
        latest = _latest_capture(run.directory)
        suffix = f": {_display_path(paths, latest)}" if latest is not None else "."
        return CaptureResult(stdout=f"Packet capture already running{suffix}\n")
    if observer is not None:
        service.stop(observer.container_id)

    gateway = session.role(SessionRole.ROUTED_GATEWAY)
    if gateway is None or not gateway.is_running:
        raise NetworkCaptureError("routed gateway is not running")
    if session.lock is None or session.lock.pid is None:
        raise NetworkCaptureError("running session lock has no owner PID")

    observer_name = paths.identity.ephemeral_container(
        runtime, "network-observer", session.lock.pid
    )
    capture_path = _prepare_capture(run.directory)
    try:
        service.start(
            runtime,
            gateway.name,
            gateway.inspect.image,
            observer_name,
            capture_path,
            sandbox_label=paths.identity.sandbox_label,
        )
    except Exception:
        try:
            helper_exists = client.exists(observer_name, ObjectKind.CONTAINER)
        except Exception:
            helper_exists = True
        if not helper_exists:
            try:
                capture_path.unlink()
            except FileNotFoundError:
                pass
        raise

    record_session_event(
        paths,
        runtime,
        "network_capture_started",
        file=capture_path.name,
    )
    return CaptureResult(
        stdout=f"Packet capture started: {_display_path(paths, capture_path)}\n"
    )


def _prepare_capture(directory: Path) -> Path:
    """Reserve one private timestamped PCAP path without overwriting evidence."""

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for index in range(1, 1000):
        suffix = "" if index == 1 else f"-{index}"
        path = directory / f"network-{stamp}{suffix}.pcap"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        return path
    raise NetworkCaptureError("could not allocate a unique packet capture filename")


def _latest_capture(directory: Path) -> Path | None:
    captures = tuple(
        path
        for path in directory.glob("network-*.pcap")
        if path.is_file() and not path.is_symlink()
    )
    if not captures:
        return None
    return max(captures, key=lambda path: (path.stat().st_mtime_ns, path.name))


def _display_path(paths: RepoPaths, path: Path | None) -> str:
    if path is None:
        return "unavailable"
    try:
        return str(path.relative_to(paths.root))
    except ValueError:
        return str(path)


@dataclass(slots=True)
class NetworkCaptureService:
    podman: PodmanClient = field(default_factory=PodmanClient)
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)

    def start(
        self,
        runtime: str,
        gateway: str,
        image: str,
        container: str,
        capture_path: Path,
        *,
        sandbox_label: str,
    ) -> None:
        argv = (
            str(self.podman.engine),
            "run",
            "-d",
            "--name",
            container,
            "--network",
            f"container:{gateway}",
            "--label",
            sandbox_label,
            "--label",
            "asf.role=network-observer",
            "--label",
            f"asf.agent={runtime}",
            "--cap-drop=ALL",
            "--cap-add=NET_RAW",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=2m",
            "--pids-limit=16",
            "--memory=32m",
            "--stop-signal=SIGINT",
            "-v",
            f"{capture_path}:/asf/network.pcap:rw",
            image,
            "tcpdump",
            "-p",
            "-i",
            _CAPTURE_INTERFACE,
            "-s",
            str(_CAPTURE_SNAPLEN),
            "-U",
            "-w",
            "/asf/network.pcap",
        )
        result = self.podman.observe(argv, timeout=60)
        if not result.succeeded:
            detail = result.stderr.strip() or result.stdout.strip()
            raise NetworkCaptureError(
                "could not start routed packet capture"
                + (f": {detail}" if detail else "")
            )
        try:
            self._wait_ready(container)
        except Exception:
            self.stop(container)
            raise

    def stop(self, container: str) -> None:
        if not self.podman.exists(container, ObjectKind.CONTAINER):
            return
        inspection = self.podman.inspect_container(container, timeout=10)
        if inspection.running:
            result = self.podman.observe(
                (
                    str(self.podman.engine),
                    "stop",
                    "--ignore",
                    "--time",
                    str(_STOP_TIMEOUT),
                    container,
                ),
                timeout=_STOP_TIMEOUT + self.podman.timeout,
            )
            if not result.succeeded:
                detail = result.stderr.strip() or result.stdout.strip()
                raise NetworkCaptureError(
                    "could not stop packet capture"
                    + (f": {detail}" if detail else "")
                )
        result = self.podman.observe(
            (str(self.podman.engine), "rm", "--ignore", container),
            timeout=self.podman.timeout,
        )
        if not result.succeeded:
            detail = result.stderr.strip() or result.stdout.strip()
            raise NetworkCaptureError(
                "could not remove packet capture helper"
                + (f": {detail}" if detail else "")
            )

    def _wait_ready(self, container: str) -> None:
        for attempt in range(3):
            inspection = self.podman.inspect_container(container, timeout=10)
            if not inspection.running:
                detail = self._log_tail(container)
                raise NetworkCaptureError(
                    "routed packet capture exited during startup"
                    + (f": {detail}" if detail else "")
                )
            if attempt == 2:
                return
            self.sleep(0.1)

    def _log_tail(self, container: str) -> str:
        try:
            result = self.podman.container_logs(container, tail=20)
        except Exception:
            return ""
        return (result.stderr.strip() or result.stdout.strip()).replace("\n", " | ")
