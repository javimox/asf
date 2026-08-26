"""Small shared validators for untrusted JSON and mapping payloads.

Several modules read JSON that ASF itself wrote earlier (runtime plans,
policy snapshots, evidence metadata) or that another process produced
(``podman inspect``). Each used to carry its own ``_require_text`` /
``_require_bool`` copies with slightly different error types. ``Schema``
keeps the behavior but lets each module bind its own exception class once.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Iterable

__all__ = ["Schema"]


class Schema:
    """Validators that raise one caller-chosen exception type."""

    __slots__ = ("_error",)

    def __init__(self, error: type[Exception]) -> None:
        if not isinstance(error, type) or not issubclass(error, Exception):
            raise TypeError("error must be an exception class")
        self._error = error

    def fail(self, message: str) -> Exception:
        return self._error(message)

    def text(self, value: Any, what: str, *, allow_empty: bool = True) -> str:
        if not isinstance(value, str) or (not allow_empty and not value):
            noun = "text" if allow_empty else "non-empty text"
            raise self.fail(f"{what} must be {noun}")
        return value

    def integer(self, value: Any, what: str, *, minimum: int | None = None) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise self.fail(f"{what} must be an integer")
        if minimum is not None and value < minimum:
            noun = "a non-negative integer" if minimum == 0 else f"at least {minimum}"
            raise self.fail(f"{what} must be {noun}")
        return value

    def boolean(self, value: Any, what: str) -> bool:
        if not isinstance(value, bool):
            raise self.fail(f"{what} must be boolean")
        return value

    def mapping(self, value: Any, what: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise self.fail(f"{what} must be an object")
        if not all(isinstance(key, str) for key in value):
            raise self.fail(f"{what} keys must be text")
        return value

    def text_list(
        self, value: Any, what: str, *, allow_empty_items: bool = True
    ) -> list[str]:
        if not isinstance(value, list) or not all(
            isinstance(item, str) and (allow_empty_items or item) for item in value
        ):
            noun = "text values" if allow_empty_items else "non-empty text"
            raise self.fail(f"{what} must be a list of {noun}")
        return value

    def mapping_list(self, value: Any, what: str) -> list[Mapping[str, Any]]:
        if not isinstance(value, list) or not all(
            isinstance(item, Mapping) for item in value
        ):
            raise self.fail(f"{what} must be a list of objects")
        if any(not all(isinstance(name, str) for name in item) for item in value):
            raise self.fail(f"{what} object keys must be text")
        return value

    def one_of(self, value: Any, what: str, choices: Iterable[Any]) -> Any:
        allowed = tuple(choices)
        if value not in allowed:
            rendered = ", ".join(str(choice) for choice in allowed)
            raise self.fail(f"{what} must be one of: {rendered}")
        return value

    def exact_keys(self, payload: Mapping[str, Any], expected: set[str], what: str) -> None:
        actual = set(payload)
        if actual != expected:
            missing = sorted(expected - actual)
            unknown = sorted(actual - expected)
            details = []
            if missing:
                details.append("missing " + ", ".join(missing))
            if unknown:
                details.append("unknown " + ", ".join(unknown))
            raise self.fail(f"invalid {what} fields: " + "; ".join(details))
