#!/usr/bin/env bash
# smolagents adapter setup — runs on every container start.
#
# Thin by design: installs smolagents into a venv held on a persistent volume, so
# only the first start pays the download. Adds NO security policy.
set -euo pipefail

VENV=/home/node/.venv
REQUIREMENTS=/workspace/sandbox/agents/smolagents/requirements.txt

if [[ ! -x "$VENV/bin/python" ]]; then
    echo "  → Creating venv for smolagents (first start only)"
    uv venv "$VENV" >/dev/null
fi

# `uv pip install` is a no-op when everything is already satisfied, so this
# stays fast on later starts and picks up requirements.txt edits.
if ! VIRTUAL_ENV="$VENV" uv pip install -r "$REQUIREMENTS" >/tmp/smolagents-install.log 2>&1; then
    echo "  ✗ smolagents install failed — see /tmp/smolagents-install.log" >&2
    echo "    Is pypi.org in network.allow_domains in agents/smolagents/runtime.yml?" >&2
    exit 1
fi

echo "  ✓ smolagents ready  (venv: $VENV)"
echo ""
echo "  Activate:  source $VENV/bin/activate"
echo "  Broker:    \$OPENAI_BASE_URL -> the local LiteLLM proxy"
echo "  Run:       python -m my_agent.main   (from /workspace/repos/<your-repo>)"
