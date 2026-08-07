"""Shared exception hierarchy for ASF's Python implementation.

The hierarchy is intentionally small. Subsystems define their own leaf errors
under these generic categories, while the CLI catches :class:`AsfError` once.

Deliberate ASF failures exit with status 1; the permanent CLI vectors pin
that contract.
"""

from __future__ import annotations

__all__ = [
    "AsfError",
    "ConfigurationError",
    "InfrastructureError",
    "UsageError",
    "ValidationError",
]


class AsfError(Exception):
    """Base class for expected ASF failures."""

    exit_code = 1


class UsageError(AsfError):
    """The CLI invocation is incomplete or invalid."""


class ValidationError(AsfError):
    """User-controlled configuration or input failed validation."""


class ConfigurationError(ValidationError):
    """ASF configuration is missing, inconsistent, or unsupported."""


class InfrastructureError(AsfError):
    """A required host command or external resource failed."""
