"""Opaque secret values for ASF's Python implementation.

``SecretValue`` deliberately does not inherit from :class:`str` or participate
in dataclass serialization. Accidental logging, interpolation, dataclass
``repr`` output, and ``dataclasses.asdict`` therefore keep the redacted object
rather than exposing the underlying credential. The value is exposed only
through :meth:`SecretValue.reveal` or the explicit subprocess-boundary adapter
:meth:`SecretValue.as_sensitive_argument`.
"""

from __future__ import annotations

import hmac
from collections.abc import Iterable
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .process import SensitiveArgument

__all__ = ["REDACTED", "SecretValue", "redact"]

REDACTED = "***"
_REDACTED = REDACTED


class SecretValue:
    """One immutable opaque text secret.

    This is a leakage-prevention primitive, not encrypted storage. Code that
    already holds the object can deliberately call :meth:`reveal`; normal
    formatting, copying, and representations remain redacted.
    """

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("secret value must be a string")
        object.__setattr__(self, "_SecretValue__value", value)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("SecretValue is immutable")

    def reveal(self) -> str:
        """Return the underlying value at a controlled boundary."""

        return self.__value

    def as_sensitive_argument(self) -> "SensitiveArgument":
        """Return a redacting subprocess argument for this secret.

        The import is local so the general secret abstraction does not create
        an import cycle with :mod:`asf.process`.
        """

        from .process import SensitiveArgument

        return SensitiveArgument(self.__value)

    def __copy__(self) -> "SecretValue":
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> "SecretValue":
        memo[id(self)] = self
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretValue):
            return NotImplemented
        return hmac.compare_digest(self.__value, other.__value)

    def __hash__(self) -> int:
        return hash(self.__value)

    def __repr__(self) -> str:
        return "SecretValue(***)"

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, format_spec: str) -> str:
        if format_spec:
            raise ValueError("format specifications are not supported for secrets")
        return _REDACTED




def redact(text: str, secrets: Iterable[SecretValue | str]) -> str:
    """Replace secret values in text, longest first.

    Empty values are ignored so a missing credential cannot expand every
    character boundary into a redaction marker.
    """

    values = sorted(
        (
            item.reveal() if isinstance(item, SecretValue) else item
            for item in secrets
        ),
        key=len,
        reverse=True,
    )
    for value in values:
        if value:
            text = text.replace(value, REDACTED)
    return text
