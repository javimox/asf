#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "tools" / "litellm_entrypoint.py"


def import_module():
    spec = importlib.util.spec_from_file_location("litellm_entrypoint", ENTRYPOINT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LiteLLMEntrypointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = import_module()

    def test_empty_list_means_wildcard_all_models(self) -> None:
        models, mode = self.module.resolve_models("openai", "")
        self.assertEqual(mode, "wildcard")
        self.assertEqual(models, [])
        config = self.module.render_config("openai", [], agent="hermes")
        # Both request shapes route onto the provider wildcard.
        self.assertIn('model_name: "openai/*"', config)
        self.assertIn('model_name: "*"', config)
        self.assertIn('model: "openai/*"', config)

    def test_explicit_allowlist_restricts_models(self) -> None:
        models, mode = self.module.resolve_models(
            "anthropic", "claude-sonnet-4-6 anthropic/claude-opus-4-6"
        )
        self.assertEqual(mode, "allowlist")
        self.assertEqual(models, ["claude-opus-4-6", "claude-sonnet-4-6"])
        config = self.module.render_config("anthropic", models, agent="claude")
        self.assertNotIn('model_name: "*"', config)

    def test_invalid_explicit_list_fails_clearly(self) -> None:
        with self.assertRaises(RuntimeError):
            self.module.resolve_models("openai", "*** ///")

    def test_hermes_config_has_concrete_routes_and_drops_temperature(self) -> None:
        config = self.module.render_config("openai", ["gpt-5.5", "gpt-5-nano"], agent="hermes")
        self.assertIn('model_name: "gpt-5.5"', config)
        self.assertIn('model: "openai/gpt-5.5"', config)
        self.assertIn("additional_drop_params:", config)
        self.assertIn("- temperature", config)
        self.assertNotIn("openai/*", config)
        self.assertNotIn("provider-secret", config)

    def test_claude_config_does_not_drop_temperature(self) -> None:
        config = self.module.render_config("anthropic", ["claude-sonnet-4-6"], agent="claude")
        self.assertIn('model: "anthropic/claude-sonnet-4-6"', config)
        self.assertNotIn("additional_drop_params", config)

    def test_config_omits_enterprise_only_allowed_routes(self) -> None:
        # allowed_routes is a LiteLLM Enterprise feature; the OSS image errors
        # at request time if it is present. It must not be emitted.
        for agent, provider, model in (
            ("claude", "anthropic", "claude-sonnet-4-6"),
            ("hermes", "openai", "gpt-5.5"),
        ):
            config = self.module.render_config(provider, [model], agent=agent)
            self.assertNotIn("allowed_routes", config)
            self.assertIn("master_key:", config)
            self.assertIn("disable_spend_logs: true", config)
            self.assertIn("litellm_observer.proxy_handler_instance", config)
            self.assertIn("turn_off_message_logging: true", config)

    def test_provider_key_is_read_from_mounted_secret_file(self) -> None:
        import os, tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".secret", delete=False) as fh:
            fh.write("file-secret\n")
            key_file = fh.name
        env = {
            "ASF_LITELLM_PROVIDER": "openai",
            "ASF_LITELLM_MODELS": "gpt-5.5",
            "ASF_PROVIDER_KEY_FILE": key_file,
        }
        saved_keys = list(env) + ["LITELLM_PROVIDER_API_KEY", "OPENAI_API_KEY"]
        saved = {key: os.environ.get(key) for key in saved_keys}
        os.environ.pop("LITELLM_PROVIDER_API_KEY", None)
        try:
            os.environ.update(env)
            # Patch execvp so main() stops before starting litellm.
            calls = []
            self.module.os.execvp = lambda *a: calls.append(a)
            status = self.module.main()
            self.assertEqual(status, 127)  # falls through after patched execvp
            self.assertEqual(os.environ["OPENAI_API_KEY"], "file-secret")
            self.assertEqual(os.environ["LITELLM_PROVIDER_API_KEY"], "file-secret")
            self.assertTrue(calls and calls[0][0] == "litellm")
        finally:
            os.unlink(key_file)
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_any_provider_slug_with_agent_shaped_routes(self) -> None:
        # Upstream provider changes; the agent's wire protocol (routes) does not.
        config = self.module.render_config("openrouter", ["some-model"], agent="hermes")
        self.assertIn('model: "openrouter/some-model"', config)
        self.assertEqual(self.module.provider_key_env("openrouter"), "OPENROUTER_API_KEY")
        self.assertEqual(self.module.provider_key_env("gemini"), "GEMINI_API_KEY")


if __name__ == "__main__":
    unittest.main()
