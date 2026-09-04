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

chmod 755 "$TMP/bin/podman"

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
grep -qE '^podman run .*--label=asf\.session=.*-claude' "$MOCK_LOG"

python3 - "$TMP/asf" <<'PY'
import sys
from asf.paths import RepoPaths
from asf.runtime_plan import load_runtime_plan, runtime_plan_path

paths = RepoPaths.for_root(sys.argv[1])
plan = load_runtime_plan(runtime_plan_path(paths, "claude"))
assert plan.broker_enabled is True
attachments = plan.runtime_container.attachments
assert len(attachments) == 1 and attachments[0].network.endswith("-claude-internal"), attachments
PY

echo "test_broker_enabled_open.sh: all assertions passed"
