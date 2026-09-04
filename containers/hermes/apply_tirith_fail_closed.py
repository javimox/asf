#!/usr/bin/env python3
"""Apply ASF's narrow fail-closed compatibility fix to Hermes Tirith handling."""

from pathlib import Path
import sys


UNSAFE_BLOCK = '''    if _circuit_open:\n        return {"action": "allow", "findings": [], "summary": "tirith disabled (circuit breaker)"}\n'''

FAIL_CLOSED_BLOCK = '''    if _circuit_open:\n        if cfg["tirith_fail_open"]:\n            return {"action": "allow", "findings": [], "summary": "tirith disabled (circuit breaker)"}\n        return {\n            "action": "block",\n            "findings": [],\n            "summary": "tirith unavailable, circuit breaker open (fail-closed)",\n        }\n'''


def apply(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    matches = text.count(UNSAFE_BLOCK)
    if matches != 1:
        raise ValueError(
            "expected exactly one Hermes Tirith circuit-breaker block, "
            f"found {matches}"
        )

    updated = text.replace(UNSAFE_BLOCK, FAIL_CLOSED_BLOCK, 1)
    compile(updated, str(path), "exec")
    path.write_text(updated, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} PATH", file=sys.stderr)
        return 2

    try:
        apply(Path(sys.argv[1]))
    except (OSError, ValueError, SyntaxError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
