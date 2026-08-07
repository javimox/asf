#!/usr/bin/env bash
# The shipped/default path has both BROKER_ENABLED=true and llm.broker=true.
# Keep a focused regression around that path: an undefined network variable in
# hardening once made every brokered runtime fail only after policy setup.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp -a "$ROOT/." "$TMP/asf"
mkdir -p "$TMP/bin"
MOCK_LOG="$TMP/commands.log"
export MOCK_LOG TERM=xterm
export ASF_FAKE_PODMAN_SCRIPT="$TMP/asf/tests/fake_podman_open.sh"
export ASF_FAKE_PODMAN_STATE="$TMP/podman-state"
mkdir -p "$ASF_FAKE_PODMAN_STATE"
export ASF_STOP_VERIFY_ATTEMPTS=1 ASF_STOP_VERIFY_DELAY=0

cat > "$TMP/bin/podman" <<'PODMAN'
#!/usr/bin/env bash
exec "${ASF_FAKE_PODMAN_SCRIPT:?}" "$@"
PODMAN

cat > "$TMP/bin/devcontainer" <<'DEVCONTAINER'
#!/usr/bin/env bash
set -euo pipefail
printf 'devcontainer %s\n' "$*" >> "${MOCK_LOG:?}"
if [[ "${1:-}" == up ]]; then
    session_label=""
    previous=""
    for argument in "$@"; do
        if [[ "$previous" == "--id-label" && "$argument" == asf.session=* ]]; then
            session_label="${argument#asf.session=}"
        fi
        previous="$argument"
    done
    [[ -z "$session_label" ]] || "${ASF_FAKE_PODMAN_SCRIPT:?}" __add-runtime "$session_label" >/dev/null
fi
exit 0
DEVCONTAINER

chmod 755 "$TMP/bin/podman" "$TMP/bin/devcontainer"

cat > "$TMP/asf/secrets/claude.env" <<'ENV'
ANTHROPIC_API_KEY=test-provider-key
ENV
chmod 600 "$TMP/asf/secrets/claude.env"

output=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open claude 2>&1)
grep -q 'Broker container started' <<<"$output"
grep -q 'LiteLLM broker ready' <<<"$output"
grep -q 'Starting container' <<<"$output"
! grep -q 'BROKER_NETWORK' <<<"$output"
grep -qE 'podman run .*--network .*claude-internal:alias=asf-broker .*--network .*claude-provider' "$MOCK_LOG"
grep -q 'devcontainer up ' "$MOCK_LOG"

python3 - "$TMP/asf/.devcontainer/sessions/claude/devcontainer.json" <<'PY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
data = json.loads("\n".join(line for line in p.read_text().splitlines() if not line.startswith("//")))
networks = [x for x in data.get("runArgs", []) if x.startswith("--network=")]
assert len(networks) == 1 and networks[0].endswith("-claude-internal"), networks
assert data["containerEnv"]["ASF_BROKER_ENABLED"] == "true"
PY

echo "test_broker_enabled_open.sh: all assertions passed"
