#!/usr/bin/env bash
# Claude Code agent setup.
# Called by on-start.sh on every container start.
# Overwrites ~/.claude/ policy files so Claude cannot weaken its own guardrails
# between sessions. Claude state (memory, history, todos) is untouched.
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "${HOME}/.claude/hooks"

cp "${AGENT_DIR}/.claude/settings.json"                 "${HOME}/.claude/settings.json"
cp "${AGENT_DIR}/.claude/hooks/pretooluse-guard.sh"     "${HOME}/.claude/hooks/pretooluse-guard.sh"
chmod +x "${HOME}/.claude/hooks/pretooluse-guard.sh"
cp "${AGENT_DIR}/CLAUDE.md"                             "${HOME}/.claude/CLAUDE.md"

echo "  ✓ Claude Code policy injected (settings.json, hooks, CLAUDE.md)"
echo "  ✓ Start with: claude"
