#!/usr/bin/env bash
# Hermes agent setup — run by on-start.sh on every container start.
#
# Re-injects config.yaml and SOUL.md each start so Hermes cannot weaken its
# own guardrails between sessions. Memory, skills, sessions, and credentials
# in the volume are never touched. command_allowlist resets to [] each start,
# so "Always Approve" choices do not persist.
#
# Active layers: container boundary, firewall (hermes allowlist section),
# approvals.mode=manual, redact_secrets, skill guards, allow_private_urls=false,
# SOUL.md. Tirith is image-provided and mandatory; setup aborts if the pinned
# binary is missing or broken. Claude Code's pretooluse guard does not apply.
set -euo pipefail

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "${HOME}/.hermes"

# Overwrite config and identity on every start.
# Hermes reads config.yaml at startup; SOUL.md is loaded as slot #1 in the
# system prompt (primary agent identity — equivalent to Claude's CLAUDE.md).
cp "${AGENT_DIR}/config.yaml" "${HOME}/.hermes/config.yaml"
cp "${AGENT_DIR}/SOUL.md"     "${HOME}/.hermes/SOUL.md"

# ASF may override the session default when broker configuration requires it.
# Only the container-side copy changes; the tracked direct-mode configuration
# remains unchanged.
if [[ "${ASF_BROKER_ENABLED:-false}" == "true" && -n "${ASF_DEFAULT_MODEL:-}" ]]; then
    python3 - "${HOME}/.hermes/config.yaml" "${ASF_DEFAULT_MODEL}" <<'PYEOF'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
selected = sys.argv[2]
text = path.read_text()
pattern = re.compile(r"^(\s*default:\s*)(['\"]?)([^#\s'\"]+)(\2)(\s*(?:#.*)?)$", re.MULTILINE)
match = pattern.search(text)
if not match:
    raise SystemExit("Hermes config has no model.default entry")
replacement = f"{match.group(1)}{match.group(2)}{selected}{match.group(4)}{match.group(5)}"
path.write_text(text[:match.start()] + replacement + text[match.end():])
PYEOF
fi

echo "  ✓ Hermes config injected (config.yaml, SOUL.md)"

# Report the immutable Tirith scanner selected in config.yaml. It is installed
# during the image build and must be runnable before Hermes starts.
TIRITH_BIN="/usr/local/bin/tirith"
if [[ -x "$TIRITH_BIN" ]] && "$TIRITH_BIN" --version &>/dev/null; then
    echo "  ✓ Tirith scanner: present and runnable ($TIRITH_BIN)"
else
    echo "  ✗ Tirith scanner: missing or not runnable at $TIRITH_BIN"
    echo "    Rebuild the Hermes image: ./sandbox.sh build hermes"
    exit 1
fi

echo "  ✓ Run: hermes"
echo ""
echo "  Secrets are injected from the HOST into the Hermes process — do NOT write"
echo "  API keys into ~/.hermes/.env inside the container."
echo "  Put them on the host in:  secrets/common.env  or  secrets/hermes.env"
echo "  e.g.  echo 'OPENAI_API_KEY=sk-...' >> secrets/hermes.env  (on host)"
echo "  then: chmod 600 secrets/hermes.env && ./sandbox.sh open hermes"
echo ""
echo "  For Nous Portal OAuth (no key needed): run 'hermes setup --portal'"
