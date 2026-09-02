#!/usr/bin/env bash
# OpenAI Codex CLI setup.
# ASF does not overwrite Codex config/model/session state on restart.
set -euo pipefail

CODEX_HOME="${CODEX_HOME:-${HOME}/.codex}"

install -d -m 0700 "$CODEX_HOME"

if ! command -v codex >/dev/null 2>&1; then
    echo "  ✗ Codex CLI is missing from the image" >&2
    exit 1
fi

echo "  ✓ Codex CLI: $(codex --version)"
if codex login status >/dev/null 2>&1; then
    echo "  ✓ Codex authentication: cached login available"
else
    echo "  ○ Codex authentication: not logged in"
    echo "    Run: codex login --device-auth"
fi
echo "  ✓ Start with: codex"
