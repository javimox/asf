#!/usr/bin/env bash
# Agent Sandboxing Framework — thin user-facing launcher.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 not found." >&2
    echo "  Install package: python (Arch), python3 (Debian/Ubuntu/Fedora)." >&2
    exit 1
fi

export PYTHONPATH="${SCRIPT_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
# Keep progress and failure diagnostics visible when callers redirect output,
# especially the real-host harness during first-time image builds.
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
exec python3 -m asf "$@"
