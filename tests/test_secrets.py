#!/usr/bin/env python3
"""Focused tests for opaque ASF secret values."""

from __future__ import annotations

import sys
import unittest
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asf.process import SensitiveArgument  # noqa: E402
from asf.secrets import REDACTED, SecretValue, redact  # noqa: E402


class SecretValueTests(unittest.TestCase):
    def test_secret_is_not_a_string_subclass(self) -> None:
        secret = SecretValue("token")
        self.assertNotIsInstance(secret, str)

    def test_reveal_is_explicit(self) -> None:
        secret = SecretValue("token")
        self.assertEqual(secret.reveal(), "token")

    def test_string_repr_and_format_are_redacted(self) -> None:
        secret = SecretValue("top-secret")
        self.assertEqual(str(secret), "***")
        self.assertEqual(repr(secret), "SecretValue(***)")
        self.assertEqual(f"{secret}", "***")
        self.assertNotIn("top-secret", str(secret))
        self.assertNotIn("top-secret", repr(secret))

    def test_format_specification_cannot_transform_the_secret(self) -> None:
        with self.assertRaises(ValueError):
            format(SecretValue("token"), ">20")

    def test_dataclass_repr_does_not_expose_nested_secret(self) -> None:
        @dataclass
        class Credentials:
            token: SecretValue

        credentials = Credentials(SecretValue("credential-value"))
        shown = repr(credentials)
        converted = asdict(credentials)
        self.assertIn("SecretValue(***)", shown)
        self.assertNotIn("credential-value", shown)
        self.assertIsInstance(converted["token"], SecretValue)
        self.assertNotIn("credential-value", repr(converted))

    def test_value_is_immutable_and_hashable(self) -> None:
        secret = SecretValue("token")
        with self.assertRaises((AttributeError, TypeError)):
            secret._SecretValue__value = "changed"  # type: ignore[misc]
        self.assertEqual({secret}, {SecretValue("token")})

    def test_non_text_value_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            SecretValue(123)  # type: ignore[arg-type]

    def test_empty_and_multiline_text_remain_valid_secrets(self) -> None:
        self.assertEqual(SecretValue("").reveal(), "")
        self.assertEqual(SecretValue("line1\nline2").reveal(), "line1\nline2")


    def test_redactor_accepts_opaque_secret_values(self) -> None:
        secret = SecretValue("long-token")
        self.assertEqual(REDACTED, "***")
        self.assertEqual(
            redact("long-token token", ["token", secret]),
            "*** ***",
        )

    def test_equality_is_value_based_and_hash_consistent(self) -> None:
        first = SecretValue("same")
        second = SecretValue("same")
        other = SecretValue("different")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertEqual(hash(first), hash(second))

    def test_subprocess_adapter_retains_redaction(self) -> None:
        argument = SecretValue("token").as_sensitive_argument()
        self.assertIsInstance(argument, SensitiveArgument)
        self.assertEqual(argument.reveal(), "token")
        self.assertEqual(str(argument), "***")
        self.assertNotIn("token", repr(argument))


if __name__ == "__main__":
    unittest.main()
