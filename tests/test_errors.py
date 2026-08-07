#!/usr/bin/env python3
"""Focused tests for ASF's shared exception hierarchy."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from asf import errors  # noqa: E402
from asf.errors import (  # noqa: E402
    AsfError,
    ConfigurationError,
    InfrastructureError,
    UsageError,
    ValidationError,
)

_PUBLIC = (
    AsfError,
    UsageError,
    ValidationError,
    ConfigurationError,
    InfrastructureError,
)


class HierarchyTests(unittest.TestCase):
    def test_every_error_is_an_asf_error(self) -> None:
        for cls in _PUBLIC:
            with self.subTest(cls.__name__):
                self.assertTrue(issubclass(cls, AsfError))
                self.assertTrue(issubclass(cls, Exception))

    def test_categories_have_the_intended_relationships(self) -> None:
        self.assertTrue(issubclass(ConfigurationError, ValidationError))
        self.assertFalse(issubclass(ValidationError, InfrastructureError))
        self.assertFalse(issubclass(InfrastructureError, ValidationError))
        self.assertFalse(issubclass(UsageError, ValidationError))

    def test_asf_error_is_not_an_interpreter_exit(self) -> None:
        self.assertFalse(issubclass(AsfError, SystemExit))
        self.assertFalse(issubclass(AsfError, KeyboardInterrupt))


class ExitCodeTests(unittest.TestCase):
    def test_expected_errors_keep_bash_compatible_exit_status(self) -> None:
        for cls in _PUBLIC:
            with self.subTest(cls.__name__):
                error = cls("failure")
                self.assertEqual(cls.exit_code, 1)
                self.assertEqual(error.exit_code, 1)
                self.assertEqual(str(error), "failure")
                self.assertEqual(error.args, ("failure",))

    def test_subclasses_inherit_the_exit_status(self) -> None:
        class LeafError(ValidationError):
            pass

        self.assertEqual(LeafError("failure").exit_code, 1)

    def test_leaf_errors_can_override_exit_status_without_mutating_base(self) -> None:
        class InterruptedError(InfrastructureError):
            exit_code = 130

        self.assertEqual(InterruptedError("stopped").exit_code, 130)
        self.assertEqual(InfrastructureError("failure").exit_code, 1)
        self.assertEqual(AsfError.exit_code, 1)


class SubsystemIntegrationTests(unittest.TestCase):
    def test_identity_errors_are_validation_errors(self) -> None:
        from asf.identity import CheckoutPathError, InvalidNameError

        for cls in (CheckoutPathError, InvalidNameError):
            with self.subTest(cls.__name__):
                self.assertTrue(issubclass(cls, ValidationError))
                self.assertFalse(issubclass(cls, InfrastructureError))

    def test_path_errors_are_validation_errors(self) -> None:
        from asf.paths import (
            PathEscapeError,
            RepositoryNotFoundError,
            RepositoryPathError,
        )

        for cls in (RepositoryPathError, RepositoryNotFoundError, PathEscapeError):
            with self.subTest(cls.__name__):
                self.assertTrue(issubclass(cls, ValidationError))
                self.assertFalse(issubclass(cls, InfrastructureError))

    def test_repository_errors_are_configuration_errors(self) -> None:
        from asf.repositories import RepositoryConfigError

        self.assertTrue(issubclass(RepositoryConfigError, ConfigurationError))
        self.assertTrue(issubclass(RepositoryConfigError, ValidationError))
        self.assertFalse(issubclass(RepositoryConfigError, InfrastructureError))

    def test_process_errors_are_infrastructure_errors(self) -> None:
        from asf.process import (
            CommandError,
            CommandFailedError,
            CommandNotFoundError,
            CommandStartError,
            CommandTimeoutError,
        )

        for cls in (
            CommandError,
            CommandFailedError,
            CommandNotFoundError,
            CommandStartError,
            CommandTimeoutError,
        ):
            with self.subTest(cls.__name__):
                self.assertTrue(issubclass(cls, InfrastructureError))
                self.assertFalse(issubclass(cls, ValidationError))


    def test_podman_and_session_errors_use_shared_categories(self) -> None:
        from asf.podman import (
            PodmanCommandError,
            PodmanError,
            PodmanOutputError,
            PodmanValidationError,
        )
        from asf.session import (
            AmbiguousSessionError,
            NoRunningSessionError,
            RuntimeCatalogError,
            UnknownRuntimeError,
        )

        for cls in (PodmanError, PodmanCommandError, PodmanOutputError):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, InfrastructureError))
        self.assertTrue(issubclass(PodmanValidationError, ValidationError))
        for cls in (AmbiguousSessionError, NoRunningSessionError):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, InfrastructureError))
        self.assertTrue(issubclass(RuntimeCatalogError, ConfigurationError))
        self.assertTrue(issubclass(UnknownRuntimeError, ValidationError))

    def test_session_lock_errors_are_infrastructure_errors(self) -> None:
        from asf.session_lock import (
            SessionAlreadyRunningError,
            SessionLockAcquireError,
            SessionLockError,
            SessionLockOwnershipError,
        )

        for cls in (
            SessionLockError,
            SessionAlreadyRunningError,
            SessionLockAcquireError,
            SessionLockOwnershipError,
        ):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, InfrastructureError))
                self.assertFalse(issubclass(cls, ValidationError))

    def test_cleanup_errors_are_infrastructure_errors(self) -> None:
        from asf.cleanup import CleanupError, CleanupFailedError

        for cls in (CleanupError, CleanupFailedError):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, InfrastructureError))
                self.assertFalse(issubclass(cls, ValidationError))

    def test_diagnostic_errors_use_shared_categories(self) -> None:
        from asf.diagnostics import DiagnosticsError, DiagnosticsUsageError

        self.assertTrue(issubclass(DiagnosticsError, InfrastructureError))
        self.assertTrue(issubclass(DiagnosticsUsageError, UsageError))


    def test_stop_errors_use_shared_categories(self) -> None:
        from asf.stop import StopError, StopUsageError

        self.assertTrue(issubclass(StopError, InfrastructureError))
        self.assertTrue(issubclass(StopUsageError, UsageError))


    def test_reset_errors_use_shared_categories(self) -> None:
        from asf.reset import ResetError, ResetUsageError

        self.assertTrue(issubclass(ResetError, InfrastructureError))
        self.assertTrue(issubclass(ResetUsageError, UsageError))



    def test_network_errors_are_infrastructure_errors(self) -> None:
        from asf.networks import NetworkCreationError

        self.assertTrue(issubclass(NetworkCreationError, InfrastructureError))
        self.assertFalse(issubclass(NetworkCreationError, ValidationError))

    def test_runtime_plan_errors_are_configuration_errors(self) -> None:
        from asf.runtime_plan import RuntimePlanError

        self.assertTrue(issubclass(RuntimePlanError, ConfigurationError))
        self.assertTrue(issubclass(RuntimePlanError, ValidationError))
        self.assertFalse(issubclass(RuntimePlanError, InfrastructureError))

    def test_devcontainer_errors_are_configuration_errors(self) -> None:
        from asf.devcontainer import DevcontainerError

        self.assertTrue(issubclass(DevcontainerError, ConfigurationError))
        self.assertTrue(issubclass(DevcontainerError, ValidationError))
        self.assertFalse(issubclass(DevcontainerError, InfrastructureError))

    def test_proxy_errors_use_shared_categories(self) -> None:
        from asf.proxy import ProxyError, ProxyLifecycleError

        self.assertTrue(issubclass(ProxyError, ConfigurationError))
        self.assertTrue(issubclass(ProxyError, ValidationError))
        self.assertFalse(issubclass(ProxyError, InfrastructureError))
        self.assertTrue(issubclass(ProxyLifecycleError, InfrastructureError))
        self.assertFalse(issubclass(ProxyLifecycleError, ValidationError))

    def test_broker_errors_use_shared_categories(self) -> None:
        from asf.broker import BrokerError, BrokerLifecycleError

        self.assertTrue(issubclass(BrokerError, ConfigurationError))
        self.assertTrue(issubclass(BrokerError, ValidationError))
        self.assertFalse(issubclass(BrokerError, InfrastructureError))
        self.assertTrue(issubclass(BrokerLifecycleError, InfrastructureError))
        self.assertFalse(issubclass(BrokerLifecycleError, ValidationError))

    def test_verification_errors_use_shared_categories(self) -> None:
        from asf.verification import ProbeValidationError

        self.assertTrue(issubclass(ProbeValidationError, ValidationError))
        self.assertFalse(
            issubclass(ProbeValidationError, InfrastructureError)
        )

    def test_no_parallel_exception_hierarchy_exists(self) -> None:
        from asf import (
            broker,
            cleanup,
            devcontainer,
            diagnostics,
            identity,
            manifest,
            networks,
            paths,
            podman,
            process,
            proxy,
            repositories,
            reset,
            runtime_plan,
            session,
            session_lock,
            stop,
            verification,
        )

        for module in (
            broker,
            cleanup,
            devcontainer,
            diagnostics,
            identity,
            manifest,
            networks,
            paths,
            podman,
            process,
            proxy,
            repositories,
            reset,
            runtime_plan,
            session,
            session_lock,
            stop,
            verification,
        ):
            for name in dir(module):
                attribute = getattr(module, name)
                if (
                    isinstance(attribute, type)
                    and issubclass(attribute, Exception)
                    and attribute.__module__.startswith("asf.")
                ):
                    with self.subTest(module=module.__name__, error=name):
                        self.assertTrue(issubclass(attribute, AsfError))

    def test_one_cli_boundary_can_catch_every_subsystem(self) -> None:
        from asf.identity import ResourceIdentity
        from asf.paths import RepoPaths
        from asf.process import run

        raisers = (
            lambda: ResourceIdentity.from_physical_path("relative/path"),
            lambda: RepoPaths.for_root("/definitely/missing"),
            lambda: RepoPaths.discover().child("/etc/passwd"),
            lambda: run(["asf-command-that-does-not-exist"], timeout=5),
        )
        for index, raiser in enumerate(raisers):
            with self.subTest(index=index), self.assertRaises(AsfError) as caught:
                raiser()
            self.assertEqual(caught.exception.exit_code, 1)


class ModuleSurfaceTests(unittest.TestCase):
    def test_all_lists_every_public_error_class(self) -> None:
        exported = {
            name
            for name in dir(errors)
            if not name.startswith("_")
            and isinstance(getattr(errors, name), type)
            and issubclass(getattr(errors, name), Exception)
        }
        self.assertEqual(exported, set(errors.__all__))


if __name__ == "__main__":
    unittest.main()
