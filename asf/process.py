"""Safe subprocess execution for ASF host-side orchestration.

Commands are executed directly from argument vectors. This module never uses a
shell, never uses ``eval``, and keeps stdout and stderr separate.

Use :func:`run` for ordinary commands: nonzero status raises. Use
:func:`probe` when a nonzero status is a valid observation. Timeouts and start
failures always raise, so "the probe did not run" cannot be mistaken for an
expected policy denial.
"""

from __future__ import annotations

import math
import os
import shlex
import subprocess
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import NoReturn, Sequence, TextIO, TypeAlias

from .errors import InfrastructureError
from .secrets import SecretValue, redact

__all__ = [
    "CommandError",
    "CommandFailedError",
    "CommandNotFoundError",
    "CommandResult",
    "CommandStartError",
    "CommandTimeoutError",
    "SensitiveArgument",
    "probe",
    "replace",
    "run",
    "run_streaming",
    "sensitive",
]

_REDACTED = "***"


class SensitiveArgument:
    """A command argument whose value must not appear in diagnostics."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("sensitive argument must be a string")
        if "\x00" in value:
            raise ValueError("sensitive argument contains a NUL byte")
        self.__value = value

    def reveal(self) -> str:
        """Return the value at the subprocess boundary."""

        return self.__value

    def __repr__(self) -> str:
        return "SensitiveArgument(***)"

    def __str__(self) -> str:
        return _REDACTED


CommandArgument: TypeAlias = (
    str | os.PathLike[str] | SensitiveArgument | SecretValue
)


def sensitive(value: str) -> SensitiveArgument:
    """Mark one command argument as sensitive."""

    return SensitiveArgument(value)


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Completed command with a redacted argument vector."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str = field(repr=False)
    stderr: str = field(repr=False)

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0

    @property
    def command(self) -> str:
        return _format_command(self.argv)


class CommandError(InfrastructureError):
    """Base class for subprocess infrastructure and status failures."""

    def __init__(
        self,
        message: str,
        *,
        argv: tuple[str, ...],
        returncode: int | None = None,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.argv = argv
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    @property
    def command(self) -> str:
        return _format_command(self.argv)


class CommandNotFoundError(CommandError):
    """The command executable could not be found."""


class CommandStartError(CommandError):
    """The operating system could not start the command."""


class CommandTimeoutError(CommandError):
    """The command exceeded its timeout and was killed."""

    def __init__(
        self,
        *,
        argv: tuple[str, ...],
        timeout: float,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        super().__init__(
            f"command timed out after {_format_timeout(timeout)}: "
            f"{_format_command(argv)}",
            argv=argv,
            stdout=stdout,
            stderr=stderr,
        )
        self.timeout = timeout


class CommandFailedError(CommandError):
    """The command completed with a nonzero status."""

    def __init__(self, result: CommandResult) -> None:
        super().__init__(
            f"command exited with status {result.returncode}: {result.command}",
            argv=result.argv,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        self.result = result


def replace(
    argv: Sequence[CommandArgument],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> NoReturn:
    """Replace the current process with a validated command vector.

    This is reserved for intentionally unbounded interactive or follow-mode
    commands such as ``podman logs -f``. It preserves direct signal and terminal
    behavior without introducing ``shell=True`` or an arbitrary no-timeout
    subprocess path.
    """

    actual_argv, display_argv, _ = _normalise_argv(argv)
    normalised_cwd = _normalise_cwd(cwd)
    child_env = _merged_environment(env)
    if normalised_cwd is not None:
        try:
            os.chdir(normalised_cwd)
        except OSError as exc:
            detail = exc.strerror or str(exc)
            raise CommandStartError(
                f"could not enter working directory for command: "
                f"{_format_command(display_argv)}: {detail}",
                argv=display_argv,
            ) from exc
    try:
        os.execvpe(actual_argv[0], actual_argv, os.environ if child_env is None else child_env)
    except FileNotFoundError as exc:
        raise CommandNotFoundError(
            f"command not found: {_format_command(display_argv)}",
            argv=display_argv,
        ) from exc
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise CommandStartError(
            f"could not replace process: {_format_command(display_argv)}: {detail}",
            argv=display_argv,
        ) from exc


def run(
    argv: Sequence[CommandArgument],
    *,
    timeout: float,
    capture: bool = True,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Run a command and raise :class:`CommandFailedError` on nonzero status.

    ``env`` overlays the inherited environment, matching ordinary Bash command
    execution. ``capture=False`` lets an interactive child use the parent's
    streams; the returned stdout and stderr are then empty strings.
    """

    result = probe(
        argv,
        timeout=timeout,
        capture=capture,
        cwd=cwd,
        env=env,
        input_text=input_text,
    )
    if not result.succeeded:
        raise CommandFailedError(result)
    return result


def run_streaming(
    argv: Sequence[CommandArgument],
    *,
    timeout: float,
    output: TextIO,
    error: TextIO,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    redact_values: Sequence[str | SecretValue] = (),
) -> CommandResult:
    """Run a command while forwarding redacted stdout and stderr.

    The two streams are drained concurrently so a verbose child cannot block
    on a full pipe.  Values supplied through ``redact_values`` reach the child
    unchanged through ``env`` but are removed before any output is forwarded
    or retained in a failure object.
    """

    actual_argv, display_argv, argv_secrets = _normalise_argv(argv)
    normalised_cwd = _normalise_cwd(cwd)
    child_env = _merged_environment(env)
    _validate_timeout(timeout)
    if not hasattr(output, "write") or not hasattr(error, "write"):
        raise TypeError("output and error must be writable text streams")

    extra_secrets: list[str] = []
    for index, value in enumerate(redact_values):
        secret = value.reveal() if isinstance(value, SecretValue) else value
        if not isinstance(secret, str):
            raise TypeError(f"redact_values[{index}] must be text or SecretValue")
        if secret and secret not in extra_secrets:
            extra_secrets.append(secret)
    secrets = tuple(dict.fromkeys((*argv_secrets, *extra_secrets)))

    try:
        process = subprocess.Popen(
            actual_argv,
            cwd=normalised_cwd,
            env=child_env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            shell=False,
        )
    except FileNotFoundError as exc:
        if exc.filename == actual_argv[0]:
            raise CommandNotFoundError(
                f"command not found: {_format_command(display_argv)}",
                argv=display_argv,
            ) from exc
        detail = exc.strerror or str(exc)
        raise CommandStartError(
            f"could not start command: {_format_command(display_argv)}: "
            f"{detail}: {exc.filename}",
            argv=display_argv,
        ) from exc
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise CommandStartError(
            f"could not start command: {_format_command(display_argv)}: {detail}",
            argv=display_argv,
        ) from exc

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []

    def forward(source: TextIO, target: TextIO, retained: list[str]) -> None:
        try:
            for chunk in iter(source.readline, ""):
                safe = _censor(chunk, secrets)
                retained.append(safe)
                target.write(safe)
                target.flush()
        finally:
            source.close()

    assert process.stdout is not None and process.stderr is not None
    threads = (
        threading.Thread(
            target=forward,
            args=(process.stdout, output, stdout_parts),
            daemon=True,
        ),
        threading.Thread(
            target=forward,
            args=(process.stderr, error, stderr_parts),
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()

    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        for thread in threads:
            thread.join()
        raise CommandTimeoutError(
            argv=display_argv,
            timeout=timeout,
            stdout="".join(stdout_parts),
            stderr="".join(stderr_parts),
        ) from exc

    for thread in threads:
        thread.join()
    result = CommandResult(
        argv=display_argv,
        returncode=returncode,
        stdout="".join(stdout_parts),
        stderr="".join(stderr_parts),
    )
    if not result.succeeded:
        raise CommandFailedError(result)
    return result


def probe(
    argv: Sequence[CommandArgument],
    *,
    timeout: float,
    capture: bool = True,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Run a command where a nonzero status is a valid observation."""

    actual_argv, display_argv, secrets = _normalise_argv(argv)
    normalised_cwd = _normalise_cwd(cwd)
    child_env = _merged_environment(env)
    _validate_input_text(input_text)
    _validate_timeout(timeout)
    pipe = subprocess.PIPE if capture else None

    try:
        completed = subprocess.run(
            actual_argv,
            cwd=normalised_cwd,
            env=child_env,
            input=input_text,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=pipe,
            stderr=pipe,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        if exc.filename == actual_argv[0]:
            raise CommandNotFoundError(
                f"command not found: {_format_command(display_argv)}",
                argv=display_argv,
            ) from exc

        detail = exc.strerror or str(exc)
        raise CommandStartError(
            f"could not start command: {_format_command(display_argv)}: "
            f"{detail}: {exc.filename}",
            argv=display_argv,
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandTimeoutError(
            argv=display_argv,
            timeout=timeout,
            stdout=_censor(_timeout_text(exc.stdout), secrets),
            stderr=_censor(_timeout_text(exc.stderr), secrets),
        ) from exc
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise CommandStartError(
            f"could not start command: {_format_command(display_argv)}: {detail}",
            argv=display_argv,
        ) from exc

    return CommandResult(
        argv=display_argv,
        returncode=completed.returncode,
        stdout=_censor(completed.stdout or "", secrets),
        stderr=_censor(completed.stderr or "", secrets),
    )


def _normalise_argv(
    argv: Sequence[CommandArgument],
) -> tuple[list[str], tuple[str, ...], tuple[str, ...]]:
    if isinstance(argv, (str, bytes)):
        raise TypeError("argv must be a sequence of arguments, not a string")

    actual: list[str] = []
    display: list[str] = []
    secrets: list[str] = []

    for index, argument in enumerate(argv):
        if isinstance(argument, (SensitiveArgument, SecretValue)):
            value = argument.reveal()
            shown = _REDACTED
            secrets.append(value)
        else:
            value = os.fspath(argument)
            if not isinstance(value, str):
                raise TypeError(f"argv[{index}] must resolve to text")
            shown = value

        if "\x00" in value:
            raise ValueError(f"argv[{index}] contains a NUL byte")

        actual.append(value)
        display.append(shown)

    if not actual:
        raise ValueError("argv must not be empty")
    if not actual[0]:
        raise ValueError("command executable must not be empty")

    return actual, tuple(display), tuple(dict.fromkeys(secrets))


def _normalise_cwd(cwd: str | os.PathLike[str] | None) -> str | None:
    if cwd is None:
        return None

    value = os.fspath(cwd)
    if not isinstance(value, str):
        raise TypeError("cwd must resolve to text")
    if "\x00" in value:
        raise ValueError("cwd contains a NUL byte")
    return value


def _merged_environment(env: Mapping[str, str] | None) -> dict[str, str] | None:
    if env is None:
        return None
    if not isinstance(env, Mapping):
        raise TypeError("env must be a mapping of text keys to text values")

    merged = os.environ.copy()
    for key, value in env.items():
        if not isinstance(key, str):
            raise TypeError("environment variable names must be strings")
        if not key or "=" in key or "\x00" in key:
            raise ValueError(f"invalid environment variable name: {key!r}")
        if not isinstance(value, str):
            raise TypeError(f"environment variable {key!r} must have a string value")
        if "\x00" in value:
            raise ValueError(f"environment variable {key!r} contains a NUL byte")
        merged[key] = value
    return merged


def _validate_input_text(input_text: str | None) -> None:
    if input_text is not None and not isinstance(input_text, str):
        raise TypeError("input_text must be text or None")


def _validate_timeout(timeout: float) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a positive number")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be finite and greater than zero")


def _censor(text: str, secrets: Sequence[str]) -> str:
    return redact(text, secrets)


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _format_command(argv: Sequence[str]) -> str:
    return " ".join(shlex.quote(_escape_control_characters(arg)) for arg in argv)


def _escape_control_characters(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def _format_timeout(timeout: float) -> str:
    return f"{timeout:g}s"
