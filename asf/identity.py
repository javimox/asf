"""Stable ASF resource identity and naming.

Resource names are a permanent contract: sessions must produce the same names
across versions so that any ASF invocation can discover and clean up resources
created by an earlier one. The reference vectors in ``tests/reference/`` pin them.

Two naming risks cannot be verified on Linux and must be checked on macOS:

* BSD ``tr -c`` complements byte values and should agree with GNU, but the
  reference fixtures freeze whichever one generated them.
* ``cd && pwd -P`` returns the case stored on disk; ``Path.resolve`` keeps the
  caller's spelling. On APFS a mis-cased invocation hashes differently.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final, Literal, Sequence

from .errors import ValidationError
from .models import RuntimeManifest

__all__ = [
    "CheckoutPathError",
    "InvalidNameError",
    "NetworkNames",
    "ResourceIdentity",
    "state_volume_names",
    "sanitize_checkout_basename",
    "validate_runtime_name",
]

_INVALID_BASENAME_RUN: Final = re.compile(r"[^A-Za-z0-9_.-]+")
_HYPHEN_RUN: Final = re.compile(r"-+")
_RUNTIME_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9_-]*$", re.ASCII)
_RESOURCE_SUFFIX: Final = re.compile(r"^[a-z0-9][a-z0-9_.-]*$", re.ASCII)
_IMAGE_REVISION: Final = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$", re.ASCII)
_PODMAN_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", re.ASCII)

_BASENAME_LIMIT: Final = 48
_HASH_LENGTH: Final = 12
_DEFAULT_BASENAME: Final = "sandbox"


EphemeralRole = Literal["proxy", "litellm", "gateway", "network-observer"]
_EPHEMERAL_ROLES: Final = frozenset({"proxy", "litellm", "gateway", "network-observer"})


class CheckoutPathError(ValidationError):
    """The checkout path is missing, not a directory, or not canonical."""


class InvalidNameError(ValidationError):
    """A runtime name, suffix, revision, or PID is unsafe."""


@dataclass(frozen=True, slots=True)
class NetworkNames:
    """All possible network names for one runtime session."""

    internal: str
    egress: str
    provider: str
    scan: str
    routed_egress: str


@dataclass(frozen=True, slots=True)
class ResourceIdentity:
    """Checkout-scoped resource identity.

    ``script_dir`` is the physical absolute checkout path, equivalent to the
    value produced by Bash's ``pwd -P`` in ``sandbox.sh``.
    """

    script_dir: Path
    prefix: str

    @classmethod
    def from_checkout(cls, checkout_dir: str | os.PathLike[str]) -> "ResourceIdentity":
        """Create an identity from an existing checkout directory."""

        raw = Path(checkout_dir)
        try:
            physical = raw.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise CheckoutPathError(
                f"cannot resolve checkout directory: {raw}"
            ) from exc

        if not physical.is_dir():
            raise CheckoutPathError(f"checkout path is not a directory: {physical}")

        return cls.from_physical_path(physical)

    @classmethod
    def from_physical_path(
        cls, physical_path: str | os.PathLike[str]
    ) -> "ResourceIdentity":
        """Create an identity from an already-canonical absolute path.

        This filesystem-independent constructor is intended for differential
        and reference-vector tests. Production code should use ``from_checkout``.
        """

        path_text = os.fspath(physical_path)
        if not isinstance(path_text, str):
            raise CheckoutPathError("checkout path must be text")
        if "\x00" in path_text:
            raise CheckoutPathError("checkout path contains a NUL byte")
        if not os.path.isabs(path_text):
            raise CheckoutPathError(f"checkout path must be absolute: {path_text!r}")
        # `pwd -P` never emits `..`, `.`, or a trailing slash. Rejecting them
        # keeps an unreachable path out of the reference fixtures.
        if os.path.normpath(path_text) != path_text:
            raise CheckoutPathError(
                f"checkout path must already be canonical: {path_text!r}"
            )

        script_dir = Path(path_text)
        basename = sanitize_checkout_basename(script_dir.name)
        digest = hashlib.sha256(os.fsencode(path_text)).hexdigest()[:_HASH_LENGTH]
        return cls(script_dir=script_dir, prefix=f"{basename}-{digest}")

    # ── session identity ─────────────────────────────────────────────────────

    def session_key(self, runtime: str) -> str:
        return f"{self.prefix}-{validate_runtime_name(runtime)}"

    def container_name(self, runtime: str) -> str:
        return self.session_key(runtime)

    def session_label(self, runtime: str) -> str:
        return f"asf.session={self.session_key(runtime)}"

    @property
    def sandbox_label(self) -> str:
        """Label applied to every network created by this checkout."""

        return f"asf.sandbox={self.script_dir}"

    @property
    def is_podman_safe(self) -> bool:
        """Whether the prefix is a legal Podman resource name.

        A checkout named ``.asf`` or ``_worktree`` survives sanitization but
        Podman rejects it. Checked on demand, so reference vectors can still
        record what Bash produces for such a checkout.
        """

        return _PODMAN_NAME.fullmatch(self.prefix) is not None

    # ── generated paths ──────────────────────────────────────────────────────

    def session_dir(self, runtime: str) -> Path:
        """Directory holding every generated artefact for one session.

        Public so callers needing a generated path this module does not name
        can derive it explicitly, rather than reaching through a sibling path.
        """

        return (
            self.script_dir
            / ".devcontainer"
            / "sessions"
            / validate_runtime_name(runtime)
        )

    def config_json(self, runtime: str) -> Path:
        return self.session_dir(runtime) / "devcontainer.json"

    def proxy_config_dir(self, runtime: str) -> Path:
        return self.session_dir(runtime) / "proxy"

    def broker_state(self, runtime: str) -> Path:
        runtime = validate_runtime_name(runtime)
        return self.script_dir / ".devcontainer" / f".broker-host-{runtime}"

    def session_lock(self, runtime: str) -> Path:
        """Lock directory created with ``mkdir``; holds the owner PID."""

        runtime = validate_runtime_name(runtime)
        return self.script_dir / ".devcontainer" / f".open-lock-{runtime}"

    def runtime_manifest(self, runtime: str) -> Path:
        return (
            self.script_dir / "agents" / validate_runtime_name(runtime) / "runtime.yml"
        )

    # ── networks and volumes ─────────────────────────────────────────────────

    def subnet_reservation_session(self, runtime: str) -> str:
        return self.session_key(runtime)

    def network_names(self, runtime: str) -> NetworkNames:
        base = self.session_key(runtime)
        return NetworkNames(
            internal=f"{base}-internal",
            egress=f"{base}-egress",
            provider=f"{base}-provider",
            scan=f"{base}-scan",
            routed_egress=f"{base}-routed-egress",
        )

    def volume_name(self, suffix: str) -> str:
        return f"{self.prefix}-{_validate_resource_suffix(suffix)}"

    def state_volume(self, runtime: str, key: str) -> str:
        """Manifest-declared state volume. Both halves validated separately."""

        return f"{self.session_key(runtime)}-{_validate_state_key(key)}"

    def shell_history_volume(self, runtime: str) -> str:
        return f"{self.session_key(runtime)}-shell-history"

    # ── PID-scoped names ─────────────────────────────────────────────────────
    # The owner PID is passed explicitly and must identify the top-level
    # session launcher; ``sandbox.sh`` ``exec``s Python so the launcher PID
    # is stable for the whole session.

    def ephemeral_container(
        self, runtime: str, role: EphemeralRole, owner_pid: int
    ) -> str:
        """Return a PID-scoped support-container name."""

        if role not in _EPHEMERAL_ROLES:
            raise InvalidNameError(f"unsupported ephemeral role: {role!r}")
        return f"{self.session_key(runtime)}-{role}-{_validate_pid(owner_pid)}"

    def gateway_init_container(self, runtime: str, owner_pid: int) -> str:
        """The temporary NET_ADMIN initializer, which exits before runtime use."""

        return f"{self.ephemeral_container(runtime, 'gateway', owner_pid)}-init"

    def broker_secret(self, runtime: str, owner_pid: int) -> str:
        return f"{self.session_key(runtime)}-provider-{_validate_pid(owner_pid)}"

    def broker_secret_prefix(self, runtime: str) -> str:
        """Stem used to find provider secrets left by a dead session.

        ``podman secret ls`` has no reliable label filter, so stale discovery
        matches on this PID-independent prefix when recovering stale sessions.
        """

        return f"{self.session_key(runtime)}-provider-"

    # ── images ───────────────────────────────────────────────────────────────

    def probe_image(self, revision: str) -> str:
        if not isinstance(revision, str) or not _IMAGE_REVISION.fullmatch(revision):
            raise InvalidNameError(f"invalid probe image revision: {revision!r}")
        return f"{self.prefix}-probe:{revision}"

    # ── reference-vector support ───────────────────────────────────────────────────────

    def snapshot(
        self,
        runtime: str,
        *,
        probe_revision: str,
        owner_pid: int | None = None,
        state_keys: Sequence[str] = (),
    ) -> dict[str, object]:
        """Return a deterministic, JSON-friendly reference-vector snapshot.

        ``state_keys`` are sorted so a caller's ordering cannot change the
        result. PID-scoped names appear only when ``owner_pid`` is given.
        """

        runtime = validate_runtime_name(runtime)
        if isinstance(state_keys, (str, bytes)):
            raise TypeError("state_keys must be a sequence of names")
        result: dict[str, object] = {
            "script_dir": str(self.script_dir),
            "prefix": self.prefix,
            "is_podman_safe": self.is_podman_safe,
            "sandbox_label": self.sandbox_label,
            "session_key": self.session_key(runtime),
            "container_name": self.container_name(runtime),
            "session_label": self.session_label(runtime),
            "config_json": str(self.config_json(runtime)),
            "proxy_config_dir": str(self.proxy_config_dir(runtime)),
            "broker_state": str(self.broker_state(runtime)),
            "session_lock": str(self.session_lock(runtime)),
            "runtime_manifest": str(self.runtime_manifest(runtime)),
            "subnet_reservation_session": self.subnet_reservation_session(runtime),
            "networks": asdict(self.network_names(runtime)),
            "shell_history_volume": self.shell_history_volume(runtime),
            "state_volumes": {
                key: self.state_volume(runtime, key) for key in sorted(state_keys)
            },
            "broker_secret_prefix": self.broker_secret_prefix(runtime),
            "probe_image": self.probe_image(probe_revision),
        }
        if owner_pid is not None:
            result.update(
                {
                    "proxy_container": self.ephemeral_container(
                        runtime, "proxy", owner_pid
                    ),
                    "broker_container": self.ephemeral_container(
                        runtime, "litellm", owner_pid
                    ),
                    "broker_secret": self.broker_secret(runtime, owner_pid),
                    "gateway_container": self.ephemeral_container(
                        runtime, "gateway", owner_pid
                    ),
                    "gateway_init_container": self.gateway_init_container(
                        runtime, owner_pid
                    ),
                }
            )
        return result


def sanitize_checkout_basename(basename: str) -> str:
    """Mirror ``tr -cs '[:alnum:]_.-' '-'`` under an ASCII contract.

    Working on text rather than bytes is equivalent: every non-ASCII UTF-8
    byte is outside the allowed set, so a multi-byte character is always a run
    of invalid bytes, and the squeeze collapses runs the same way either way.
    Both strips remove one hyphen, and truncation is last — matching Bash,
    where a truncated name may still end in ``-``.
    """

    if not isinstance(basename, str):
        raise CheckoutPathError("checkout basename must be text")
    if "\x00" in basename:
        raise CheckoutPathError("checkout basename contains a NUL byte")

    translated = _INVALID_BASENAME_RUN.sub("-", basename)
    squeezed = _HYPHEN_RUN.sub("-", translated)
    trimmed = squeezed.removeprefix("-").removesuffix("-")
    return (trimmed or _DEFAULT_BASENAME)[:_BASENAME_LIMIT]


def validate_runtime_name(runtime: str) -> str:
    """Validate the runtime-name grammar already enforced by load_runtime.py."""

    if not isinstance(runtime, str) or not _RUNTIME_NAME.fullmatch(runtime):
        raise InvalidNameError(
            f"invalid runtime name {runtime!r}: must match {_RUNTIME_NAME.pattern}"
        )
    return runtime


def _validate_state_key(key: str) -> str:
    """State keys follow load_runtime.py's NAME_RE, which forbids dots.

    Stricter than the generic volume suffix: a dotted key would pass Podman
    but never survive manifest validation, so rejecting it here fails at the
    call site rather than three layers later.
    """

    if not isinstance(key, str) or not _RUNTIME_NAME.fullmatch(key):
        raise InvalidNameError(
            f"invalid state key {key!r}: must match {_RUNTIME_NAME.pattern}"
        )
    return key


def _validate_resource_suffix(suffix: str) -> str:
    if not isinstance(suffix, str) or not _RESOURCE_SUFFIX.fullmatch(suffix):
        raise InvalidNameError(
            f"invalid resource suffix {suffix!r}: "
            f"must match {_RESOURCE_SUFFIX.pattern}"
        )
    return suffix


def _validate_pid(owner_pid: int) -> int:
    if isinstance(owner_pid, bool) or not isinstance(owner_pid, int) or owner_pid <= 0:
        raise InvalidNameError(f"owner PID must be a positive integer: {owner_pid!r}")
    return owner_pid


def state_volume_names(
    identity: ResourceIdentity,
    runtime: str,
    manifest: RuntimeManifest,
) -> tuple[str, ...]:
    """Return exactly the persistent volumes owned by ``reset``.

    Manifest-declared state volumes retain manifest order and shell history is
    always last. Names come from deterministic resource identity, never from a
    broad Podman listing.
    """

    return tuple(
        identity.state_volume(runtime, entry.key)
        for entry in manifest.state_volumes
    ) + (identity.shell_history_volume(runtime),)
