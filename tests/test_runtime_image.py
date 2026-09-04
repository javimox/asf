#!/usr/bin/env python3
"""Shared-base and thin runtime image build-vector tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from asf.config import AsfConfig
from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.runtime_image import build_base_image_argv, build_runtime_image_argv

ROOT = Path(__file__).resolve().parents[1]


def build_arg_names(argv: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        argv[index + 1].partition("=")[0]
        for index, item in enumerate(argv[:-1])
        if item == "--build-arg"
    )


class RuntimeImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.paths = RepoPaths.for_root(ROOT)
        cls.config = AsfConfig.load(cls.paths.config_file)
        cls.pins = cls.config.build_arguments()

    def test_base_build_receives_only_base_arguments(self) -> None:
        manifest = load_model(ROOT / "agents" / "claude" / "runtime.yml")
        argv = build_base_image_argv(
            self.paths, manifest, build_arguments=self.pins
        )
        self.assertEqual(
            set(build_arg_names(argv)),
            {
                "FZF_SHA256_AMD64",
                "FZF_SHA256_ARM64",
                "FZF_VERSION",
                "GIT_DELTA_VERSION",
                "NODE_IMAGE",
                "SEMGREP_VERSION",
                "TZ",
                "UV_IMAGE",
                "ZSH_IN_DOCKER_VERSION",
            },
        )
        self.assertNotIn("CLAUDE_CODE_VERSION", build_arg_names(argv))
        self.assertNotIn("TIRITH_VERSION", build_arg_names(argv))

    def test_claude_build_receives_only_its_pin_and_base_image(self) -> None:
        manifest = load_model(ROOT / "agents" / "claude" / "runtime.yml")
        argv = build_runtime_image_argv(
            self.paths, manifest, build_arguments=self.pins
        )
        self.assertEqual(
            set(build_arg_names(argv)),
            {"ASF_BASE_IMAGE", "CLAUDE_CODE_VERSION"},
        )

    def test_hermes_build_receives_only_hermes_pins_and_base_image(self) -> None:
        manifest = load_model(ROOT / "agents" / "hermes" / "runtime.yml")
        argv = build_runtime_image_argv(
            self.paths, manifest, build_arguments=self.pins
        )
        self.assertEqual(
            set(build_arg_names(argv)),
            {
                "ASF_BASE_IMAGE",
                "HERMES_AGENT_COMMIT",
                "TIRITH_SHA256_AMD64",
                "TIRITH_SHA256_ARM64",
                "TIRITH_VERSION",
            },
        )

    def test_generic_build_receives_only_base_image(self) -> None:
        manifest = load_model(ROOT / "agents" / "crewai" / "runtime.yml")
        argv = build_runtime_image_argv(
            self.paths, manifest, build_arguments=self.pins
        )
        self.assertEqual(set(build_arg_names(argv)), {"ASF_BASE_IMAGE"})


if __name__ == "__main__":
    unittest.main()
