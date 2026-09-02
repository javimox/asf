#!/usr/bin/env python3
"""Compact host-side renderer for structured Codex/Claude review streams."""

from __future__ import annotations

import argparse
import json
import os
import select
import shlex
import sys
import time
from pathlib import Path
from typing import Any


CODEX_EVENTS = {
    "thread.started",
    "turn.started",
    "turn.completed",
    "turn.failed",
    "item.started",
    "item.updated",
    "item.completed",
    "error",
}
CLAUDE_EVENTS = {
    "system",
    "assistant",
    "user",
    "result",
    "stream_event",
    "rate_limit_event",
}


def _short(text: str, limit: int = 180) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _event_for(agent: str, obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    event_type = obj.get("type")
    if agent == "codex":
        return event_type in CODEX_EVENTS
    return event_type in CLAUDE_EVENTS


def _claude_text(obj: dict[str, Any]) -> str:
    message = obj.get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if not isinstance(content, list):
        return ""
    parts = [
        block.get("text", "")
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    return "".join(part for part in parts if isinstance(part, str))


def _claude_tool_progress(obj: dict[str, Any]) -> list[str]:
    message = obj.get("message")
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if not isinstance(content, list):
        return []

    progress: list[str] = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        name = str(block.get("name") or "tool")
        tool_input = block.get("input")
        tool_input = tool_input if isinstance(tool_input, dict) else {}

        if name == "Bash":
            detail = tool_input.get("command")
        elif name in {"Read", "Write", "Edit"}:
            detail = tool_input.get("file_path")
        elif name == "Grep":
            pattern = tool_input.get("pattern")
            path = tool_input.get("path")
            if pattern and path:
                detail = f'{pattern!r} in {path}'
            else:
                detail = pattern or path
        elif name == "Glob":
            pattern = tool_input.get("pattern")
            path = tool_input.get("path")
            if pattern and path:
                detail = f'{pattern} in {path}'
            else:
                detail = pattern or path
        else:
            detail = None

        if detail:
            progress.append(f"→ {name}: {_short(str(detail))}")
        else:
            progress.append(f"→ {name}")
    return progress


def _codex_command(command: Any) -> str:
    text = str(command or "")
    try:
        parts = shlex.split(text)
    except ValueError:
        return text
    if len(parts) >= 3 and parts[0] in {"bash", "/bin/bash"} and parts[1] == "-lc":
        return parts[2]
    return text


def _number(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) else 0


def _float(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None


def _write_answer(path: Path, text: str) -> None:
    text = text.strip()
    if not text:
        return
    path.write_text(text + "\n", encoding="utf-8")


def _append_usage(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def _codex_progress(obj: dict[str, Any]) -> str | None:
    event_type = obj.get("type")
    if event_type in {"error", "turn.failed"}:
        error = obj.get("message") or obj.get("error") or "unknown error"
        if isinstance(error, dict):
            error = error.get("message", error)
        return f"! { _short(str(error)) }"
    if event_type not in {"item.started", "item.completed"}:
        return None

    item = obj.get("item")
    if not isinstance(item, dict):
        return None
    item_type = item.get("type")
    if item_type == "command_execution" and event_type == "item.started":
        return f"→ Bash: {_short(_codex_command(item.get('command')))}"
    if item_type == "file_change" and event_type == "item.completed":
        changes = item.get("changes")
        if isinstance(changes, list):
            paths = [
                str(change.get("path"))
                for change in changes
                if isinstance(change, dict) and change.get("path")
            ]
            if paths:
                return f"→ changed: {_short(', '.join(paths))}"
        return "→ file change completed"
    if item_type == "mcp_tool_call" and event_type == "item.started":
        return f"→ tool: {_short(str(item.get('tool', 'MCP')))}"
    if item_type == "web_search" and event_type == "item.started":
        return f"→ web search: {_short(str(item.get('query', '')))}"
    if item_type == "error" and event_type == "item.completed":
        return f"! {_short(str(item.get('message', 'agent warning')))}"
    return None


def _claude_progress(obj: dict[str, Any]) -> list[str]:
    if obj.get("type") != "assistant":
        return []
    return _claude_tool_progress(obj)


def stream(args: argparse.Namespace) -> int:
    jsonl = Path(args.jsonl)
    runtime_log = Path(args.runtime_log)
    answer_path = Path(args.answer)
    usage_path = Path(args.usage)
    for path in (jsonl, runtime_log, answer_path, usage_path):
        path.parent.mkdir(parents=True, exist_ok=True)

    started = time.monotonic()
    agent_started: float | None = None
    last_agent_event = started
    last_heartbeat = started
    final_answer = ""
    claude_message_id: str | None = None
    claude_message_text = ""
    final_usage: dict[str, Any] = {}
    result_metadata: dict[str, Any] = {}
    completed = False
    outcome = "no-completion-event"

    print("      preparing sandbox…", flush=True)

    with jsonl.open("w", encoding="utf-8") as events, runtime_log.open(
        "w", encoding="utf-8"
    ) as runtime:
        input_fd = sys.stdin.fileno()
        pending = b""
        eof = False
        while not eof:
            ready, _, _ = select.select([input_fd], [], [], 1.0)
            now = time.monotonic()
            if not ready:
                if now - last_heartbeat >= args.heartbeat:
                    if agent_started is None:
                        print(
                            f"      … sandbox still preparing ({int(now - started)}s)",
                            flush=True,
                        )
                    elif completed:
                        print(
                            "      … model completed; waiting for CLI/sandbox cleanup "
                            f"({int(now - last_agent_event)}s)",
                            flush=True,
                        )
                    else:
                        print(
                            "      … agent still running; "
                            f"no structured event for {int(now - last_agent_event)}s",
                            flush=True,
                        )
                    last_heartbeat = now
                continue

            chunk = os.read(input_fd, 65536)
            if chunk:
                pending += chunk
                parts = pending.split(b"\n")
                pending = parts.pop()
            else:
                eof = True
                parts = [pending] if pending else []
                pending = b""

            for raw_line in parts:
                line = raw_line.decode("utf-8", errors="replace") + "\n"
                now = time.monotonic()
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    runtime.write(line)
                    runtime.flush()
                    continue

                if not _event_for(args.agent, obj):
                    runtime.write(line)
                    runtime.flush()
                    continue

                events.write(line)
                events.flush()
                last_agent_event = now
                last_heartbeat = now

                if agent_started is None:
                    agent_started = now
                    print(
                        f"      ✓ agent started ({agent_started - started:.1f}s)",
                        flush=True,
                    )

                if args.agent == "codex":
                    progress = _codex_progress(obj)
                    if progress:
                        print(f"      {progress}", flush=True)

                    if obj.get("type") == "item.completed":
                        item = obj.get("item")
                        if isinstance(item, dict) and item.get("type") == "agent_message":
                            text = item.get("text")
                            if isinstance(text, str) and text.strip():
                                final_answer = text.strip()
                    elif obj.get("type") == "turn.completed":
                        usage = obj.get("usage")
                        if isinstance(usage, dict):
                            final_usage = usage
                        completed = True
                        outcome = "success"
                    elif obj.get("type") == "turn.failed":
                        outcome = "turn-failed"
                else:
                    for progress in _claude_progress(obj):
                        print(f"      {progress}", flush=True)

                    if obj.get("type") == "assistant":
                        text = _claude_text(obj)
                        message = obj.get("message")
                        message_id = (
                            message.get("id") if isinstance(message, dict) else None
                        )
                        if text:
                            if isinstance(message_id, str) and message_id == claude_message_id:
                                claude_message_text += text
                            else:
                                claude_message_id = (
                                    message_id if isinstance(message_id, str) else None
                                )
                                claude_message_text = text
                            final_answer = claude_message_text
                    elif obj.get("type") == "result":
                        result_text = obj.get("result")
                        if (
                            not final_answer
                            and isinstance(result_text, str)
                            and result_text.strip()
                        ):
                            final_answer = result_text.strip()
                        usage = obj.get("usage")
                        if isinstance(usage, dict):
                            final_usage = usage
                        result_metadata = obj
                        # A truncated review is not a review. When present,
                        # Claude's subtype is authoritative: error_max_turns can
                        # arrive with is_error false. Keep the fallback for older
                        # CLI output that may omit subtype.
                        subtype = obj.get("subtype")
                        if isinstance(subtype, str) and subtype:
                            outcome = subtype
                        elif obj.get("is_error") is True:
                            outcome = "error"
                        else:
                            outcome = "success"
                        completed = outcome == "success"

    ended = time.monotonic()
    _write_answer(answer_path, final_answer)

    if agent_started is not None:
        duration_ms = int((ended - agent_started) * 1000)
    else:
        duration_ms = int((ended - started) * 1000)
    if args.agent == "claude" and isinstance(result_metadata.get("duration_ms"), (int, float)):
        duration_ms = int(result_metadata["duration_ms"])

    if args.agent == "codex":
        record = {
            "round": args.round,
            "agent": "codex",
            "outcome": outcome,
            "duration_ms": duration_ms,
            "input_tokens": _number(final_usage.get("input_tokens")),
            "cached_input_tokens": _number(final_usage.get("cached_input_tokens")),
            "cache_write_input_tokens": _number(final_usage.get("cache_write_input_tokens")),
            "output_tokens": _number(final_usage.get("output_tokens")),
            "reasoning_output_tokens": _number(final_usage.get("reasoning_output_tokens")),
        }
    else:
        record = {
            "round": args.round,
            "agent": "claude",
            "outcome": outcome,
            "duration_ms": duration_ms,
            "input_tokens": _number(final_usage.get("input_tokens")),
            "cache_read_input_tokens": _number(final_usage.get("cache_read_input_tokens")),
            "cache_creation_input_tokens": _number(
                final_usage.get("cache_creation_input_tokens")
            ),
            "output_tokens": _number(final_usage.get("output_tokens")),
            "num_turns": _number(result_metadata.get("num_turns")),
            "provider_cost_usd": _float(result_metadata.get("total_cost_usd")),
        }
    _append_usage(usage_path, record)

    if not completed:
        if outcome == "error_max_turns":
            turns = _number(result_metadata.get("num_turns"))
            print(
                f"      ! round hit the turn cap after {turns} turns; "
                "raise ASF_REVIEW_CLAUDE_MAX_TURNS or narrow the task",
                flush=True,
            )
        elif outcome == "no-completion-event":
            print("      ! structured completion event was not observed", flush=True)
        else:
            print(f"      ! round ended as {outcome}", flush=True)
        return 3
    return 0


def _tokens(value: int) -> str:
    return f"{value:,}"


def _duration(milliseconds: int) -> str:
    seconds = max(0, milliseconds // 1000)
    minutes, seconds = divmod(seconds, 60)
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


def summarize(args: argparse.Namespace) -> int:
    records: list[dict[str, Any]] = []
    path = Path(args.usage)
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))

    codex_input = codex_cached = codex_output = 0
    claude_input = claude_cache_read = claude_cache_write = claude_output = 0
    claude_cost = 0.0
    claude_cost_seen = False
    for record in records:
        agent = record.get("agent", "unknown")
        round_number = record.get("round", "?")
        duration = _duration(_number(record.get("duration_ms")))
        if agent == "codex":
            input_tokens = _number(record.get("input_tokens"))
            cached = _number(record.get("cached_input_tokens"))
            output = _number(record.get("output_tokens"))
            reasoning = _number(record.get("reasoning_output_tokens"))
            codex_input += input_tokens
            codex_cached += cached
            codex_output += output
            new_input = max(0, input_tokens - cached)
            details = (
                f"input {_tokens(new_input)} new + {_tokens(cached)} cached · "
                f"out {_tokens(output)}"
            )
            if reasoning:
                details += f" · reasoning {_tokens(reasoning)}"
        else:
            input_tokens = _number(record.get("input_tokens"))
            cache_read = _number(record.get("cache_read_input_tokens"))
            cache_write = _number(record.get("cache_creation_input_tokens"))
            output = _number(record.get("output_tokens"))
            turns = _number(record.get("num_turns"))
            claude_input += input_tokens
            claude_cache_read += cache_read
            claude_cache_write += cache_write
            claude_output += output
            new_input = input_tokens + cache_write
            details = (
                f"input {_tokens(new_input)} new + {_tokens(cache_read)} cached · "
                f"out {_tokens(output)}"
            )
            if turns:
                details += f" · {turns} turns"
            cost = record.get("provider_cost_usd")
            if isinstance(cost, (int, float)):
                claude_cost += float(cost)
                claude_cost_seen = True
                details += f" · provider-reported ${cost:.4f}"
        result = record.get("outcome")
        if isinstance(result, str) and result not in ("", "success"):
            details += f" · {result}"
        print(f"round {round_number} · {agent} · {duration} · {details}")

    if codex_input or codex_output:
        codex_new = max(0, codex_input - codex_cached)
        print(
            "codex total · "
            f"input {_tokens(codex_new)} new + {_tokens(codex_cached)} cached · "
            f"out {_tokens(codex_output)}"
        )
    if claude_input or claude_cache_read or claude_cache_write or claude_output:
        claude_new = claude_input + claude_cache_write
        details = (
            "claude total · "
            f"input {_tokens(claude_new)} new + {_tokens(claude_cache_read)} cached · "
            f"out {_tokens(claude_output)}"
        )
        if claude_cost_seen:
            details += f" · provider-reported ${claude_cost:.4f}"
        print(details)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    stream_parser = sub.add_parser("stream")
    stream_parser.add_argument("--agent", choices=("codex", "claude"), required=True)
    stream_parser.add_argument("--round", type=int, required=True)
    stream_parser.add_argument("--jsonl", required=True)
    stream_parser.add_argument("--runtime-log", required=True)
    stream_parser.add_argument("--answer", required=True)
    stream_parser.add_argument("--usage", required=True)
    stream_parser.add_argument("--heartbeat", type=int, default=30)
    stream_parser.set_defaults(func=stream)

    summary_parser = sub.add_parser("summarize")
    summary_parser.add_argument("--usage", required=True)
    summary_parser.set_defaults(func=summarize)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
