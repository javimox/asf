#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OBSERVER = ROOT / "tools" / "litellm_observer.py"


class FakeCustomLogger:
    pass


def import_observer(log_path: Path, *, prompt_path: Path | None = None, prompts: bool = False):
    litellm = types.ModuleType("litellm")
    integrations = types.ModuleType("litellm.integrations")
    custom_logger = types.ModuleType("litellm.integrations.custom_logger")
    custom_logger.CustomLogger = FakeCustomLogger
    saved = {
        name: sys.modules.get(name)
        for name in ("litellm", "litellm.integrations", "litellm.integrations.custom_logger")
    }
    env_saved = {
        key: os.environ.get(key)
        for key in (
            "ASF_BROKER_REQUEST_LOG",
            "ASF_LLM_PROMPT_LOG",
            "ASF_LLM_PROMPTS",
            "LITELLM_AGENT",
            "ASF_OBSERVATION_SESSION_ID",
            "ASF_LITELLM_PROVIDER",
        )
    }
    os.environ["ASF_BROKER_REQUEST_LOG"] = str(log_path)
    os.environ["ASF_LLM_PROMPTS"] = "true" if prompts else "false"
    if prompt_path is not None:
        os.environ["ASF_LLM_PROMPT_LOG"] = str(prompt_path)
    else:
        os.environ.pop("ASF_LLM_PROMPT_LOG", None)
    os.environ["LITELLM_AGENT"] = "hermes"
    os.environ["ASF_OBSERVATION_SESSION_ID"] = "20260821T225127Z-deadbeef"
    os.environ["ASF_LITELLM_PROVIDER"] = "openai"
    sys.modules["litellm"] = litellm
    sys.modules["litellm.integrations"] = integrations
    sys.modules["litellm.integrations.custom_logger"] = custom_logger
    try:
        spec = importlib.util.spec_from_file_location("asf_test_litellm_observer", OBSERVER)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, value in saved.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
        for key, value in env_saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class LiteLLMObserverTests(unittest.TestCase):
    def test_success_metadata_excludes_prompts_and_response_bodies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_path = Path(temporary) / "requests.jsonl"
            module = import_observer(log_path)
            start = datetime.now(timezone.utc)
            end = start + timedelta(seconds=1.234)
            kwargs = {
                "model": "gpt-5.5",
                "call_type": "completion",
                "messages": [{"role": "user", "content": "SECRET-PROMPT"}],
                "response_cost": 0.0123,
                "stream": False,
            }
            response = {
                "id": "response-id",
                "choices": [{"message": {"content": "SECRET-RESPONSE"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
            }
            asyncio.run(
                module.proxy_handler_instance.async_log_success_event(
                    kwargs, response, start, end
                )
            )
            text = log_path.read_text(encoding="utf-8")
            self.assertNotIn("SECRET-PROMPT", text)
            self.assertNotIn("SECRET-RESPONSE", text)
            row = json.loads(text)
            self.assertEqual(row["event"], "llm_request_complete")
            self.assertEqual(row["runtime"], "hermes")
            self.assertEqual(row["session_id"], "20260821T225127Z-deadbeef")
            self.assertEqual(row["provider"], "openai")
            self.assertEqual(row["model"], "gpt-5.5")
            self.assertEqual(row["latency_ms"], 1234)
            self.assertEqual(row["input_tokens"], 10)
            self.assertEqual(row["output_tokens"], 4)
            self.assertEqual(row["total_tokens"], 14)
            self.assertEqual(row["cost_usd"], 0.0123)

    def test_prompt_capture_is_explicit_and_separate_from_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            request_path = Path(temporary) / "requests.jsonl"
            prompt_path = Path(temporary) / "prompts.jsonl"
            module = import_observer(
                request_path, prompt_path=prompt_path, prompts=True
            )
            messages = [
                {"role": "system", "content": "SYSTEM-PROMPT"},
                {"role": "user", "content": "USER-PROMPT"},
            ]
            module.proxy_handler_instance.log_pre_api_call(
                "gpt-5.5", messages, {"call_type": "completion"}
            )

            row = json.loads(prompt_path.read_text(encoding="utf-8"))
            self.assertEqual(row["event"], "llm_prompt")
            self.assertEqual(row["runtime"], "hermes")
            self.assertEqual(row["session_id"], "20260821T225127Z-deadbeef")
            self.assertEqual(row["provider"], "openai")
            self.assertEqual(row["model"], "gpt-5.5")
            self.assertEqual(row["messages"], messages)
            self.assertFalse(request_path.exists())

    def test_prompt_capture_disabled_writes_no_prompt_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            request_path = Path(temporary) / "requests.jsonl"
            prompt_path = Path(temporary) / "prompts.jsonl"
            module = import_observer(
                request_path, prompt_path=prompt_path, prompts=False
            )
            module.proxy_handler_instance.log_pre_api_call(
                "gpt-5.5", [{"role": "user", "content": "SECRET-PROMPT"}], {}
            )
            self.assertFalse(prompt_path.exists())

    def test_failure_records_type_not_error_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            log_path = Path(temporary) / "requests.jsonl"
            module = import_observer(log_path)
            start = datetime.now(timezone.utc)
            error = RuntimeError("SECRET-ERROR-TEXT")
            asyncio.run(
                module.proxy_handler_instance.async_log_failure_event(
                    {"model": "gpt-5.5"}, error, start, start
                )
            )
            text = log_path.read_text(encoding="utf-8")
            self.assertNotIn("SECRET-ERROR-TEXT", text)
            row = json.loads(text)
            self.assertEqual(row["event"], "llm_request_failed")
            self.assertEqual(row["error_type"], "RuntimeError")


if __name__ == "__main__":
    unittest.main()
