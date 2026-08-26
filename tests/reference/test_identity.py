#!/usr/bin/env python3
"""Parity and contract tests for asf.identity.

``ReferenceVectorTests`` and ``IdentityContractTests`` are permanent: they pin the
naming contract against ``identity_vectors.json`` and against the filesystem,
and must keep passing after Bash is gone.

The vectors were captured from the accepted Bash baseline and remain as a
permanent contract after the Bash implementation was removed.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS_FILE = Path(__file__).with_name("identity_vectors.json")

# The suite runs from a checkout, not an installed package. A plain import is
# required rather than importlib file-loading, because asf.identity imports
# asf.errors.
sys.path.insert(0, str(ROOT))

from asf import identity  # noqa: E402


def load_vectors() -> dict:
    return json.loads(VECTORS_FILE.read_text(encoding="utf-8"))


class ReferenceVectorTests(unittest.TestCase):
    """Permanent. Requires neither Bash nor a filesystem."""

    def test_prefixes_and_podman_safety(self) -> None:
        for vector in load_vectors()["prefix_vectors"]:
            with self.subTest(vector["name"]):
                resource = identity.ResourceIdentity.from_physical_path(
                    vector["checkout"]
                )
                self.assertEqual(resource.prefix, vector["prefix"])
                self.assertEqual(resource.is_podman_safe, vector["is_podman_safe"])

    def test_snapshots_match_frozen_vectors(self) -> None:
        for vector in load_vectors()["vectors"]:
            with self.subTest(checkout=vector["checkout"], runtime=vector["runtime"]):
                resource = identity.ResourceIdentity.from_physical_path(
                    vector["checkout"]
                )
                actual = resource.snapshot(
                    vector["runtime"],
                    probe_revision=vector["probe_revision"],
                    owner_pid=vector.get("owner_pid"),
                    state_keys=tuple(vector.get("state_keys", ())),
                )
                self.assertEqual(actual, vector["expected"])

    def test_stale_discovery_prefix_is_pid_independent(self) -> None:
        """Stale recovery finds orphaned secrets by prefix, so a Python session
        must be discoverable after its owner PID is no longer known."""
        resource = identity.ResourceIdentity.from_physical_path("/opt/asf")
        stem = resource.broker_secret_prefix("hermes")
        for pid in (1, 4242, 999999):
            self.assertTrue(resource.broker_secret("hermes", pid).startswith(stem))


class IdentityContractTests(unittest.TestCase):
    """Permanent. Rules the vectors alone would not make legible."""

    def test_basename_sanitization_matches_bash_rules(self) -> None:
        cases = {
            "asf": "asf",
            "Agent Sandboxing Framework": "Agent-Sandboxing-Framework",
            "a--b": "a-b",
            "--a--": "a",
            "-.-foo": ".-foo",  # one leading hyphen removed, not all
            "café": "caf",
            "!!!": "sandbox",
            "a" * 60: "a" * 48,
            "a" * 47 + "--tail": "a" * 47 + "-",  # truncation runs after trimming
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(identity.sanitize_checkout_basename(raw), expected)

    def test_same_basename_in_different_paths_has_different_prefix(self) -> None:
        first = identity.ResourceIdentity.from_physical_path("/work/a/asf")
        second = identity.ResourceIdentity.from_physical_path("/work/b/asf")
        self.assertNotEqual(first.prefix, second.prefix)

    def test_from_checkout_resolves_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "My Repo!!v2"
            link = root / "link"
            checkout.mkdir()
            link.symlink_to(checkout, target_is_directory=True)
            self.assertEqual(
                identity.ResourceIdentity.from_checkout(link),
                identity.ResourceIdentity.from_checkout(checkout),
            )

    def test_noncanonical_or_missing_checkout_paths_are_rejected(self) -> None:
        for path in ("relative/path", "/tmp/a/../b", "/tmp/path/"):
            with self.subTest(path=path), self.assertRaises(
                identity.CheckoutPathError
            ):
                identity.ResourceIdentity.from_physical_path(path)
        with self.assertRaises(identity.CheckoutPathError):
            identity.ResourceIdentity.from_checkout("/definitely/missing/asf")
        with tempfile.NamedTemporaryFile() as handle:
            with self.assertRaises(identity.CheckoutPathError):
                identity.ResourceIdentity.from_checkout(handle.name)

    def test_invalid_names_and_pids_are_rejected(self) -> None:
        resource = identity.ResourceIdentity.from_physical_path("/opt/asf")

        for runtime in ("", "Demo", "-demo", "de/mo", "../demo", "demo.v2"):
            with self.subTest(runtime=runtime), self.assertRaises(
                identity.InvalidNameError
            ):
                resource.container_name(runtime)

        for key in ("", "Cache", "cache.v1", "../cache"):
            with self.subTest(state_key=key), self.assertRaises(
                identity.InvalidNameError
            ):
                resource.state_volume("hermes", key)

        for revision in ("", "-v2", "v2:latest", "../v2"):
            with self.subTest(revision=revision), self.assertRaises(
                identity.InvalidNameError
            ):
                resource.probe_image(revision)

        for pid in (0, -1, True, "123"):
            with self.subTest(pid=pid), self.assertRaises(identity.InvalidNameError):
                resource.ephemeral_container("hermes", "proxy", pid)

        with self.assertRaises(identity.InvalidNameError):
            resource.ephemeral_container("hermes", "unknown", 123)

    def test_identity_errors_reach_the_cli_handler(self) -> None:
        """Naming errors must be catchable as AsfError with a stable status."""
        from asf.errors import AsfError

        with self.assertRaises(AsfError) as caught:
            identity.ResourceIdentity.from_physical_path("relative/path")
        self.assertEqual(caught.exception.exit_code, 1)


    def test_probe_revision_and_state_keys_are_explicit(self) -> None:
        resource = identity.ResourceIdentity.from_physical_path("/opt/asf")
        with self.assertRaises(TypeError):
            resource.probe_image()  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            resource.snapshot("hermes")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            resource.snapshot(
                "hermes", probe_revision="v2", state_keys="config"
            )

    def test_snapshot_is_deterministic(self) -> None:
        resource = identity.ResourceIdentity.from_physical_path("/opt/asf")
        first = resource.snapshot(
            "hermes",
            probe_revision="v2",
            owner_pid=4242,
            state_keys=("workspace", "config"),
        )
        second = resource.snapshot(
            "hermes",
            probe_revision="v2",
            owner_pid=4242,
            state_keys=("config", "workspace"),
        )
        self.assertEqual(first, second)
        self.assertEqual(list(first["state_volumes"]), ["config", "workspace"])


if __name__ == "__main__":
    unittest.main()
