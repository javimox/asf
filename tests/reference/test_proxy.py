#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest
from pathlib import Path

from asf.proxy import PROXY_PORT, caddy_image_tag, render_caddyfile, render_containerfile

FIXTURE = Path(__file__).with_name("proxy_vectors.json")


def _dockerfile_instructions(text: str) -> tuple[str, ...]:
    instructions: list[str] = []
    current = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        if continued:
            line = line[:-1]
        current = f"{current} {line}".strip()
        if not continued:
            instructions.append(" ".join(current.split()))
            current = ""
    if current:
        instructions.append(" ".join(current.split()))
    return tuple(instructions)


class ProxyReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_image_inputs_match_the_accepted_bash_generator(self) -> None:
        self.assertEqual(
            _dockerfile_instructions(render_containerfile()),
            _dockerfile_instructions(self.vectors["containerfile"]),
        )
        self.assertEqual(caddy_image_tag(), self.vectors["image_tag"])

    def test_every_policy_matches_the_accepted_bash_generator(self) -> None:
        for vector in self.vectors["policies"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    render_caddyfile(
                        tuple(vector["effective_domains"]),
                        access_logs=vector["access_logs"],
                        port=vector.get("port", PROXY_PORT),
                    ),
                    vector["expected"],
                )


if __name__ == "__main__":
    unittest.main()
