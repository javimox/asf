#!/usr/bin/env python3
"""Send a minimal diagnostic request from inside the LiteLLM container."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request


def request_payload(agent: str, model: str) -> tuple[str, dict[str, object]]:
    if agent == "hermes":
        return "/v1/chat/completions", {
            "model": model,
            "max_completion_tokens": 128,
            "reasoning_effort": "none",
            "messages": [{"role": "user", "content": "Reply exactly with OK."}],
        }
    return "/v1/messages", {
        "model": model,
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply exactly with OK."}],
    }


def main() -> int:
    agent = os.environ.get("LITELLM_AGENT", "claude")
    model = os.environ["LITELLM_TEST_MODEL"]
    endpoint, payload = request_payload(agent, model)
    request = urllib.request.Request(
        f"http://127.0.0.1:4000{endpoint}",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {os.environ['LITELLM_MASTER_KEY']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            print(f"HTTP {response.status}")
            print(response.read().decode(errors="replace"))
    except urllib.error.HTTPError as error:
        print(f"HTTP {error.code}", file=sys.stderr)
        print(error.read().decode(errors="replace"), file=sys.stderr)
        return 1
    except Exception as error:  # Network diagnostics should report the original failure.
        print(f"Request failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
