#!/usr/bin/env python3
"""Focused tests for ASF repository and generated-session paths."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asf.errors import AsfError, ValidationError  # noqa: E402
from asf.identity import InvalidNameError, ResourceIdentity  # noqa: E402
from asf.paths import (  # noqa: E402
    PathEscapeError,
    RepoPaths,
    RepositoryNotFoundError,
    RepositoryPathError,
)


def make_fake_checkout(root: Path) -> Path:
    """Create the minimum tree accepted as an ASF checkout."""

    root.mkdir(parents=True, exist_ok=True)
    (root / "sandbox.sh").write_text("#!/usr/bin/env bash\n")
    (root / "agents").mkdir()
    (root / "containers").mkdir()
    return root


class DiscoveryTests(unittest.TestCase):
    def test_discover_finds_the_checkout_containing_the_package(self) -> None:
        self.assertEqual(RepoPaths.discover().root, ROOT.resolve())

    def test_discover_is_independent_of_current_working_directory(self) -> None:
        original = Path.cwd()
        self.addCleanup(os.chdir, original)
        with tempfile.TemporaryDirectory() as elsewhere:
            os.chdir(elsewhere)
            self.assertEqual(RepoPaths.discover().root, ROOT.resolve())

    def test_discover_walks_up_from_a_directory_or_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkout = make_fake_checkout(Path(temporary) / "checkout")
            nested = checkout / "agents" / "hermes"
            nested.mkdir()
            marker = nested / "runtime.yml"
            marker.write_text("name: hermes\n")
            for start in (nested, marker):
                with self.subTest(start=start):
                    self.assertEqual(
                        RepoPaths.discover(start).root,
                        checkout.resolve(),
                    )

    def test_for_root_and_from_checkout_resolve_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkout = make_fake_checkout(Path(temporary) / "checkout")
            link = Path(temporary) / "link"
            link.symlink_to(checkout, target_is_directory=True)
            self.assertEqual(RepoPaths.for_root(link).root, checkout.resolve())
            self.assertEqual(
                RepoPaths.from_checkout(link).root,
                checkout.resolve(),
            )

    def test_direct_construction_enforces_and_canonicalises_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkout = make_fake_checkout(Path(temporary) / "checkout")
            link = Path(temporary) / "link"
            link.symlink_to(checkout, target_is_directory=True)
            self.assertEqual(RepoPaths(link).root, checkout.resolve())

            incomplete = Path(temporary) / "incomplete"
            incomplete.mkdir()
            with self.assertRaises(RepositoryNotFoundError):
                RepoPaths(incomplete)

    def test_missing_incomplete_and_file_roots_are_rejected(self) -> None:
        with self.assertRaises(RepositoryNotFoundError):
            RepoPaths.discover("/definitely/missing/checkout")

        with tempfile.TemporaryDirectory() as temporary:
            partial = Path(temporary) / "partial"
            partial.mkdir()
            (partial / "sandbox.sh").write_text("")
            regular_file = Path(temporary) / "regular-file"
            regular_file.write_text("not a checkout")

            for constructor in (
                lambda: RepoPaths.for_root(partial),
                lambda: RepoPaths.from_checkout(partial),
                lambda: RepoPaths.for_root(regular_file),
                lambda: RepoPaths.discover(partial),
            ):
                with self.subTest(constructor=constructor):
                    with self.assertRaises(RepositoryNotFoundError):
                        constructor()

    def test_non_pathlike_inputs_are_rejected_as_repository_errors(self) -> None:
        for constructor in (
            lambda: RepoPaths.for_root(123),
            lambda: RepoPaths.discover(123),
        ):
            with self.subTest(constructor=constructor):
                with self.assertRaises(RepositoryNotFoundError):
                    constructor()


class LayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.paths = RepoPaths.discover()

    def test_fixed_locations(self) -> None:
        root = self.paths.root
        expected = {
            "config_file": root / "asf.conf",
            "agents_dir": root / "agents",
            "secrets_dir": root / "secrets",
            "tools_dir": root / "tools",
            "tests_dir": root / "tests",
            "containers_dir": root / "containers",
            "runtime_state_dir": root / ".asf",
            "sessions_dir": root / ".asf" / "sessions",
            "broker_probe_tool": root / "tools" / "broker_probe.py",
            "litellm_entrypoint": root / "tools" / "litellm_entrypoint.py",
            "litellm_observer": root / "tools" / "litellm_observer.py",
        }
        for name, value in expected.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(self.paths, name), value)
        self.assertEqual(
            self.paths.agent_repos_file("claude"),
            root / "agents" / "claude" / "repos.yml",
        )

    def test_layout_matches_the_current_checkout(self) -> None:
        for path in (
            self.paths.config_file,
            self.paths.identity.runtime_manifest("claude"),
        ):
            with self.subTest(path=path):
                self.assertTrue(path.is_file())
        for path in (
            self.paths.agents_dir,
            self.paths.tools_dir,
            self.paths.containers_dir,
        ):
            with self.subTest(path=path):
                self.assertTrue(path.is_dir())

    def test_model_is_immutable(self) -> None:
        with self.assertRaises(Exception):
            self.paths.root = Path("/tmp")  # type: ignore[misc]
        with self.assertRaises(Exception):
            self.paths._identity = None  # type: ignore[misc]

    def test_identity_uses_exactly_the_same_physical_root(self) -> None:
        expected = ResourceIdentity.from_checkout(self.paths.root)
        self.assertEqual(self.paths.identity.script_dir, self.paths.root)
        self.assertEqual(self.paths.identity.prefix, expected.prefix)


class SafeChildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.paths = RepoPaths.discover()

    def test_joins_nested_text_and_pathlike_components(self) -> None:
        self.assertEqual(
            self.paths.child("agents", Path("hermes") / "runtime.yml"),
            self.paths.root / "agents" / "hermes" / "runtime.yml",
        )

    def test_absolute_and_parent_traversal_are_rejected(self) -> None:
        bad_parts = (
            ("/etc/passwd",),
            ("..",),
            ("agents", "..", "tools"),
            ("../outside",),
            ("agents/../tools",),
        )
        for parts in bad_parts:
            with self.subTest(parts=parts), self.assertRaises(PathEscapeError):
                self.paths.child(*parts)

    def test_empty_dot_nul_and_nontext_components_are_rejected(self) -> None:
        for parts in ((), ("",), ("a\x00b",), (b"bytes",)):
            with self.subTest(parts=parts), self.assertRaises(
                RepositoryPathError
            ):
                self.paths.child(*parts)  # type: ignore[arg-type]
        with self.assertRaises(PathEscapeError):
            self.paths.child(".")

    def test_external_symlink_rejects_existing_and_future_children(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            outside_path = Path(outside)
            (outside_path / "existing").write_text("outside")
            link = self.paths.root / "asf-test-external-link"
            link.symlink_to(outside_path, target_is_directory=True)
            self.addCleanup(link.unlink)

            for child in ("existing", "future", "future/deeper"):
                with self.subTest(child=child), self.assertRaises(
                    PathEscapeError
                ):
                    self.paths.child(link.name, child)

    def test_internal_symlink_is_allowed_and_returns_physical_path(self) -> None:
        link = self.paths.root / "asf-test-internal-link"
        link.symlink_to(self.paths.agents_dir, target_is_directory=True)
        self.addCleanup(link.unlink)
        self.assertEqual(
            self.paths.child(link.name, "hermes"),
            self.paths.agents_dir / "hermes",
        )

    def test_path_errors_are_shared_validation_errors(self) -> None:
        for cls in (RepositoryPathError, RepositoryNotFoundError, PathEscapeError):
            with self.subTest(cls=cls):
                self.assertTrue(issubclass(cls, ValidationError))
                self.assertTrue(issubclass(cls, AsfError))


class StateArtifactTests(unittest.TestCase):
    def test_uses_xdg_state_home_outside_the_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            checkout = make_fake_checkout(base / "checkout")
            state_home = base / "state"
            with mock.patch.dict(
                os.environ, {"XDG_STATE_HOME": str(state_home)}
            ):
                paths = RepoPaths.for_root(checkout)

            expected = (
                state_home
                / "asf"
                / paths.identity.prefix
                / "sessions"
                / "hermes"
                / "runs"
                / "current"
            )
            actual = paths.state_artifact("hermes", "runs", "current")
            self.assertEqual(actual, expected)
            with self.assertRaises(ValueError):
                actual.relative_to(paths.root)

    def test_unset_xdg_state_home_falls_back_to_local_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            checkout = make_fake_checkout(base / "checkout")
            home = base / "home"
            home.mkdir()
            with mock.patch.dict(os.environ, {"HOME": str(home)}):
                os.environ.pop("XDG_STATE_HOME", None)
                paths = RepoPaths.for_root(checkout)

            self.assertEqual(
                paths.state_dir,
                home / ".local" / "state" / "asf" / paths.identity.prefix,
            )

    def test_state_directory_inside_checkout_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkout = make_fake_checkout(Path(temporary) / "checkout")
            with mock.patch.dict(
                os.environ, {"XDG_STATE_HOME": str(checkout / ".state")}
            ):
                with self.assertRaisesRegex(
                    RepositoryPathError, "must be outside the repository"
                ):
                    RepoPaths.for_root(checkout)

    def test_validates_state_runtime_and_artifact_components(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            checkout = make_fake_checkout(base / "checkout")
            with mock.patch.dict(
                os.environ, {"XDG_STATE_HOME": str(base / "state")}
            ):
                paths = RepoPaths.for_root(checkout)

            with self.assertRaises(InvalidNameError):
                paths.state_artifact("../escape", "runs")
            for parts in ((), ("..",), ("/etc/passwd",), ("",)):
                with self.subTest(parts=parts), self.assertRaises(
                    RepositoryPathError
                ):
                    paths.state_artifact("hermes", *parts)


class SessionArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.paths = RepoPaths.discover()

    def test_reuses_the_identity_session_directory(self) -> None:
        expected = self.paths.identity.session_dir("hermes") / "routed.nft"
        actual = self.paths.session_artifact("hermes", "routed.nft")
        self.assertEqual(actual, expected)
        self.assertEqual(
            actual.parent,
            self.paths.identity.session_dir("hermes"),
        )

    def test_validates_runtime_and_artifact_components(self) -> None:
        with self.assertRaises(InvalidNameError):
            self.paths.session_artifact("../escape", "routed.nft")

        for parts in ((), ("..", "other.nft"), ("/etc/passwd",), ("",)):
            with self.subTest(parts=parts), self.assertRaises(
                RepositoryPathError
            ):
                self.paths.session_artifact("hermes", *parts)

    def test_session_directory_symlink_cannot_redirect_future_writes(self) -> None:
        session_root = self.paths.sessions_dir
        session_root.mkdir(parents=True, exist_ok=True)
        runtime_link = session_root / "asf-test-runtime"
        with tempfile.TemporaryDirectory() as outside:
            runtime_link.symlink_to(outside, target_is_directory=True)
            self.addCleanup(runtime_link.unlink)
            with self.assertRaises(PathEscapeError):
                self.paths.session_artifact(
                    "asf-test-runtime",
                    "future",
                    "policy.nft",
                )


if __name__ == "__main__":
    unittest.main()
