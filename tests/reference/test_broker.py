#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path

from asf.broker import BrokerRequest, BrokerSettings, describe_lines
from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.runtime_plan import build_runtime_plan

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name("broker_vectors.json")
IMAGE = "ghcr.io/berriai/litellm:v1.93.0"


class BrokerConfigurationReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.paths = RepoPaths.for_root(ROOT)

    def test_every_accepted_runtime_vector(self) -> None:
        owner_pid = self.fixture["owner_pid"]
        for runtime, expected in self.fixture["runtimes"].items():
            with self.subTest(runtime=runtime):
                manifest = load_model(self.paths.identity.runtime_manifest(runtime))
                plan = build_runtime_plan(
                    manifest,
                    paths=self.paths,
                    owner_pid=owner_pid,
                    broker_globally_enabled=True,
                )
                request = BrokerRequest(
                    self.paths,
                    manifest,
                    plan,
                    BrokerSettings(IMAGE),
                )
                actual = {
                    "provider": request.provider,
                    "protocol": request.protocol,
                    "api_key_name": request.api_key_name,
                    "direct_domain": request.direct_domain,
                    "model_mode": request.models.mode,
                    "default_model": request.models.default_model,
                    "models": list(request.models.models),
                    "route": request.models.route,
                }
                self.assertEqual(actual, expected)

    def test_description_preserves_the_accepted_field_order(self) -> None:
        owner_pid = self.fixture["owner_pid"]
        for runtime, expected in self.fixture["runtimes"].items():
            with self.subTest(runtime=runtime):
                manifest = load_model(self.paths.identity.runtime_manifest(runtime))
                plan = build_runtime_plan(
                    manifest,
                    paths=self.paths,
                    owner_pid=owner_pid,
                    broker_globally_enabled=True,
                )
                request = BrokerRequest(
                    self.paths,
                    manifest,
                    plan,
                    BrokerSettings(IMAGE),
                )
                fields = describe_lines(request)
                self.assertEqual(len(fields), 10)
                self.assertEqual(fields[0], request.container.name)
                self.assertEqual(fields[1], request.secret_name)
                self.assertEqual(
                    fields[2:],
                    (
                        expected["provider"],
                        expected["protocol"],
                        expected["api_key_name"],
                        expected["direct_domain"],
                        expected["model_mode"],
                        expected["default_model"],
                        " ".join(expected["models"]),
                        expected["route"],
                    ),
                )



if __name__ == "__main__":
    unittest.main()
