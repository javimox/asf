#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 - <<'PY'
from pathlib import Path

from asf.routed import RoutedService, _HOLDER
from asf.routed_allocation import RoutedAllocator
from asf.runtime import RuntimeService

root = Path.cwd()
assert RoutedService is not None
assert RoutedAllocator is not None
assert RuntimeService is not None
assert "trap 'exit 0' TERM INT HUP" in _HOLDER
assert "--stop-timeout=2" in (root / "asf" / "routed.py").read_text()
PY

echo 'test_routed_shell.sh: all assertions passed'
