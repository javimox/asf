#!/usr/bin/env python3
"""LiteLLM callback for ASF request metadata and optional prompt capture."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

_REQUEST_LOG_PATH = Path(
    os.environ.get("ASF_BROKER_REQUEST_LOG", "/tmp/asf-broker-requests.jsonl")
)
_PROMPT_LOG_PATH = Path(
    os.environ.get("ASF_LLM_PROMPT_LOG", "/tmp/asf-llm-prompts.jsonl")
)
_PROMPTS_ENABLED = os.environ.get("ASF_LLM_PROMPTS", "false") == "true"
_RUNTIME = os.environ.get("LITELLM_AGENT", "")
_SESSION_ID = os.environ.get("ASF_OBSERVATION_SESSION_ID", "")
_PROVIDER = os.environ.get("ASF_LITELLM_PROVIDER", "")


def _get(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        return value.get(key)
    return getattr(value, key, None)


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _duration_ms(start_time: Any, end_time: Any) -> int | None:
    try:
        seconds = (end_time - start_time).total_seconds()
    except (AttributeError, TypeError):
        try:
            seconds = float(end_time) - float(start_time)
        except (TypeError, ValueError):
            return None
    if seconds < 0:
        return None
    return round(seconds * 1000)


def _usage(response_obj: Any) -> tuple[int | None, int | None, int | None]:
    usage = _get(response_obj, "usage")
    if usage is None:
        return None, None, None
    input_tokens = _number(_get(usage, "prompt_tokens"))
    if input_tokens is None:
        input_tokens = _number(_get(usage, "input_tokens"))
    output_tokens = _number(_get(usage, "completion_tokens"))
    if output_tokens is None:
        output_tokens = _number(_get(usage, "output_tokens"))
    total_tokens = _number(_get(usage, "total_tokens"))
    return (
        int(input_tokens) if input_tokens is not None else None,
        int(output_tokens) if output_tokens is not None else None,
        int(total_tokens) if total_tokens is not None else None,
    )


def _write(path: Path, payload: dict[str, Any]) -> None:
    """Append one private JSON record; observability must never affect requests."""

    try:
        data = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n"
        ).encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            while data:
                written = os.write(fd, data)
                data = data[written:]
        finally:
            os.close(fd)
    except (OSError, TypeError, ValueError):
        return


def _append_metadata(
    event: str,
    kwargs: dict[str, Any],
    response_obj: Any,
    start_time: Any,
    end_time: Any,
) -> None:
    try:
        input_tokens, output_tokens, total_tokens = _usage(response_obj)
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "runtime": _RUNTIME,
            "session_id": _SESSION_ID,
            "provider": _PROVIDER,
        }
        model = kwargs.get("model")
        if isinstance(model, str) and model:
            payload["model"] = model
        call_type = kwargs.get("call_type")
        if isinstance(call_type, str) and call_type:
            payload["call_type"] = call_type
        latency_ms = _duration_ms(start_time, end_time)
        if latency_ms is not None:
            payload["latency_ms"] = latency_ms
        for key, value in (
            ("input_tokens", input_tokens),
            ("output_tokens", output_tokens),
            ("total_tokens", total_tokens),
        ):
            if value is not None:
                payload[key] = value
        response_cost = _number(kwargs.get("response_cost"))
        if response_cost is not None:
            payload["cost_usd"] = float(response_cost)
        stream = kwargs.get("stream")
        if isinstance(stream, bool):
            payload["stream"] = stream
        cache_hit = kwargs.get("cache_hit")
        if isinstance(cache_hit, bool):
            payload["cache_hit"] = cache_hit
        if event == "llm_request_failed" and response_obj is not None:
            payload["error_type"] = type(response_obj).__name__
        _write(_REQUEST_LOG_PATH, payload)
    except (TypeError, ValueError):
        return


def _append_prompt(model: Any, messages: Any, kwargs: dict[str, Any]) -> None:
    if not _PROMPTS_ENABLED:
        return
    payload: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": "llm_prompt",
        "runtime": _RUNTIME,
        "session_id": _SESSION_ID,
        "provider": _PROVIDER,
        "messages": messages,
    }
    if isinstance(model, str) and model:
        payload["model"] = model
    call_type = kwargs.get("call_type")
    if isinstance(call_type, str) and call_type:
        payload["call_type"] = call_type
    _write(_PROMPT_LOG_PATH, payload)


class ASFRequestObserver(CustomLogger):
    """Record broker metadata and, when opted in, request prompts."""

    def log_pre_api_call(self, model, messages, kwargs):  # noqa: ANN001
        _append_prompt(model, messages, kwargs)

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):  # noqa: ANN001
        _append_metadata("llm_request_complete", kwargs, response_obj, start_time, end_time)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):  # noqa: ANN001
        _append_metadata("llm_request_failed", kwargs, response_obj, start_time, end_time)


proxy_handler_instance = ASFRequestObserver()
