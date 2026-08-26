"""Cleanup and signal supervision for ``sandbox.sh open``.

All network modes are sequenced by :mod:`asf.runtime`. Interactive and
service sessions use this module to supervise the interactive or service child, restore the
terminal, and tear down resources through the same
:class:`~asf.stop.StopService` and :class:`~asf.cleanup.CleanupExecutor` used
by ``sandbox.sh stop``.

The internal ``cleanup`` action exposes the same owned cleanup path for tests and
recovery tooling; it contains no independent resource-removal logic.
"""

from __future__ import annotations

import os
import math
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import TextIO

from .errors import AsfError, InfrastructureError, ValidationError
from .stop import (
    StopEmitter,
    StopEvent,
    StopReport,
    StopService,
    emit_stop_completion,
)

__all__ = [
    "OpenCleanupResult",
    "OpenCleanupService",
    "OpenLifecycleError",
    "OpenSignal",
    "SessionProcessResult",
    "SessionProcessSupervisor",
    "restore_terminal",
    "run_open_session",
]

_RED = "\033[0;31m"
_YELLOW = "\033[0;33m"
_RESET = "\033[0m"
_SHOW_CURSOR = "\033[?25h"


class OpenLifecycleError(InfrastructureError):
    """The open-session supervisor could not start or finish safely."""


def restore_terminal(stream: TextIO | None = None) -> bool:
    """Restore the minimum terminal state an interrupted session may damage.

    Only a real TTY is changed.  Echo and canonical input are re-enabled and
    the cursor is shown before cleanup starts.  Redirected output is left
    byte-for-byte untouched.
    """

    target = sys.stderr if stream is None else stream
    try:
        if not target.isatty():
            return False
    except (AttributeError, ValueError):
        return False

    restored = False
    try:
        import termios

        descriptor = target.fileno()
        attributes = termios.tcgetattr(descriptor)
        attributes[3] |= termios.ECHO | termios.ICANON
        termios.tcsetattr(descriptor, termios.TCSADRAIN, attributes)
        restored = True
    except (AttributeError, ImportError, OSError, ValueError):
        pass

    try:
        target.write(_SHOW_CURSOR)
        target.flush()
        restored = True
    except (AttributeError, OSError, ValueError):
        pass
    return restored


class OpenSignal(str, Enum):
    HUP = "HUP"
    INT = "INT"
    TERM = "TERM"

    @property
    def number(self) -> int:
        return {
            OpenSignal.HUP: signal.SIGHUP,
            OpenSignal.INT: signal.SIGINT,
            OpenSignal.TERM: signal.SIGTERM,
        }[self]

    @property
    def exit_code(self) -> int:
        return 128 + int(self.number)

    @classmethod
    def parse(cls, value: str | None) -> "OpenSignal | None":
        if value in (None, ""):
            return None
        try:
            return cls(value.upper())
        except (AttributeError, ValueError) as exc:
            raise ValidationError(f"unsupported open-session signal: {value}") from exc


@dataclass(frozen=True, slots=True)
class SessionProcessResult:
    returncode: int
    signal: OpenSignal | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.returncode, bool)
            or not isinstance(self.returncode, int)
            or self.returncode < 0
        ):
            raise ValidationError("session returncode must be non-negative")
        if self.signal is not None and not isinstance(self.signal, OpenSignal):
            raise TypeError("signal must be an OpenSignal or None")


PopenFactory = Callable[..., subprocess.Popen[bytes]]


@dataclass(slots=True)
class SessionProcessSupervisor:
    """Run one fixed argv and forward HUP/INT/TERM to the child."""

    popen_factory: PopenFactory = field(default=subprocess.Popen, repr=False)
    signal_grace_seconds: float = 2.0
    poll_interval: float = 0.1
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)

    def __post_init__(self) -> None:
        if not callable(self.popen_factory) or not callable(self.clock):
            raise TypeError("popen_factory and clock must be callable")
        for name in ("signal_grace_seconds", "poll_interval"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a number")
            number = float(value)
            if not math.isfinite(number) or number < 0:
                raise ValidationError(f"{name} must be finite and non-negative")
            object.__setattr__(self, name, number)
        if self.poll_interval <= 0:
            raise ValidationError("poll_interval must be positive")

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
    ) -> SessionProcessResult:
        command = _normalise_child_argv(argv)
        child_env = None if env is None else {**os.environ, **env}
        try:
            if child_env is None:
                child = self.popen_factory(command, shell=False)
            else:
                child = self.popen_factory(command, shell=False, env=child_env)
        except FileNotFoundError as exc:
            raise OpenLifecycleError(
                f"session command not found: {command[0]}"
            ) from exc
        except OSError as exc:
            raise OpenLifecycleError(
                f"could not start session command {command[0]}: {exc}"
            ) from exc

        received: list[OpenSignal] = []
        previous: dict[int, signal.Handlers] = {}

        def handler(signum: int, _frame: object) -> None:
            parsed = _signal_from_number(signum)
            if parsed is not None and not received:
                received.append(parsed)
            try:
                child.send_signal(signum)
            except ProcessLookupError:
                pass

        deadline: float | None = None
        try:
            for item in OpenSignal:
                previous[item.number] = signal.getsignal(item.number)
                signal.signal(item.number, handler)
            while True:
                try:
                    returncode = child.wait(timeout=self.poll_interval)
                    break
                except subprocess.TimeoutExpired:
                    if not received:
                        continue
                    if deadline is None:
                        deadline = self.clock() + self.signal_grace_seconds
                    if self.clock() < deadline:
                        continue
                    try:
                        child.kill()
                    except ProcessLookupError:
                        pass
                    returncode = child.wait()
                    break
        finally:
            for signum, old_handler in previous.items():
                signal.signal(signum, old_handler)

        if received:
            return SessionProcessResult(received[0].exit_code, received[0])
        if returncode < 0:
            parsed = _signal_from_number(-returncode)
            return SessionProcessResult(128 + (-returncode), parsed)
        return SessionProcessResult(returncode)


@dataclass(frozen=True, slots=True)
class OpenCleanupResult:
    report: StopReport
    returncode: int
    stdout: str
    stderr: str
    events: tuple[StopEvent, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.report, StopReport):
            raise TypeError("report must be a StopReport")
        if (
            isinstance(self.returncode, bool)
            or not isinstance(self.returncode, int)
            or self.returncode < 0
        ):
            raise ValidationError("cleanup returncode must be non-negative")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("stdout and stderr must be text")
        object.__setattr__(self, "events", tuple(self.events))


@dataclass(frozen=True, slots=True)
class OpenCleanupService:
    """Clean the session whose lock is owned by the current open PID."""

    stop_service: StopService

    def release_lock(self, runtime: str, owner_pid: int) -> None:
        """Release only the opener lock while preserving detached resources."""

        manager = self.stop_service.discovery.lock_manager()
        manager.release(manager.owned_token(runtime, owner_pid))

    def cleanup(
        self,
        runtime: str,
        owner_pid: int,
        *,
        event_sink: Callable[[StopEvent], None] | None = None,
    ) -> OpenCleanupResult:
        service = self.stop_service
        if not isinstance(service, StopService):
            raise TypeError("stop_service must be a StopService")
        lock = service.discovery.lock_manager().owned_token(runtime, owner_pid)
        emitter = StopEmitter(event_sink)
        report = service.stop_runtime(
            runtime,
            emitter=emitter,
            acquired_lock=lock,
        )
        emit_stop_completion(report, emitter)
        return OpenCleanupResult(
            report=report,
            returncode=0 if report.succeeded else 1,
            stdout=emitter.stdout,
            stderr=emitter.stderr,
            events=tuple(emitter.events),
        )


def run_open_session(
    child_argv: Sequence[str],
    *,
    cleanup: OpenCleanupService,
    runtime: str,
    owner_pid: int,
    supervisor: SessionProcessSupervisor | None = None,
    event_sink: Callable[[StopEvent], None] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    environment: Mapping[str, str] | None = None,
    preserve_if_running: Callable[[], bool] | None = None,
) -> int:
    """Run the session command and clean it unless an attached runtime remains live."""

    process = SessionProcessSupervisor() if supervisor is None else supervisor
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    process_result: SessionProcessResult | None = None
    process_error: OpenLifecycleError | None = None
    try:
        if environment is None:
            process_result = process.run(child_argv)
        else:
            process_result = process.run(child_argv, env=environment)
    except OpenLifecycleError as exc:
        process_error = exc
    finally:
        # A raw or interrupted devcontainer TTY must be usable before cleanup
        # emits diagnostics or waits on Podman.
        restore_terminal(errors)

    if (
        process_error is None
        and process_result is not None
        and process_result.signal is None
        and process_result.returncode == 0
        and preserve_if_running is not None
    ):
        try:
            still_running = bool(preserve_if_running())
        except AsfError as exc:
            errors.write(
                f"{_YELLOW}Could not verify detached session state; cleaning up.{_RESET}\n"
                f"  {exc}\n"
            )
        else:
            if still_running:
                try:
                    cleanup.release_lock(runtime, owner_pid)
                except AsfError as exc:
                    errors.write(
                        f"{_RED}Could not release detached session lock.{_RESET}\n"
                        f"  {exc}\n"
                    )
                    return exc.exit_code
                output.write(
                    f"\n{_YELLOW}Detached from {runtime}; the krun microVM is still running.{_RESET}\n"
                    f"  Reattach: ./sandbox.sh shell {runtime}\n"
                    f"  Stop:     ./sandbox.sh stop {runtime}\n"
                )
                output.flush()
                return 0

    cleanup_result: OpenCleanupResult | None = None
    cleanup_error: AsfError | None = None
    try:
        cleanup_result = cleanup.cleanup(
            runtime,
            owner_pid,
            event_sink=event_sink,
        )
    except AsfError as exc:
        cleanup_error = exc
        errors.write(
            f"{_RED}ASF session cleanup failed for {runtime}.{_RESET}\n"
            f"  {exc}\n"
        )

    if process_error is not None:
        errors.write(f"{_RED}{process_error}{_RESET}\n")
        return 1

    assert process_result is not None
    if process_result.signal is not None:
        return process_result.returncode
    if process_result.returncode != 0:
        errors.write(
            f"{_RED}Agent session exited with status "
            f"{process_result.returncode}.{_RESET}\n"
        )
        return process_result.returncode
    if cleanup_error is not None:
        return cleanup_error.exit_code
    assert cleanup_result is not None
    return cleanup_result.returncode

def _normalise_child_argv(argv: Sequence[str]) -> list[str]:
    if isinstance(argv, (str, bytes)):
        raise TypeError("session argv must be a sequence")
    command = list(argv)
    if not command:
        raise ValidationError("session command must not be empty")
    for index, argument in enumerate(command):
        if not isinstance(argument, str):
            raise TypeError(f"session argv[{index}] must be text")
        if "\x00" in argument:
            raise ValidationError(f"session argv[{index}] contains a NUL byte")
    return command


def _signal_from_number(signum: int) -> OpenSignal | None:
    for item in OpenSignal:
        if item.number == signum:
            return item
    return None
