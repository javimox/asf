#!/usr/bin/env bash
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "requires bash >= 4 (macOS: brew install bash)." >&2
    exit 1
fi
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export XDG_STATE_HOME="$TMP/state"
cp -a "$ROOT/." "$TMP/asf"
mkdir -p "$TMP/bin" "$TMP/podman-state"

# Keep this test deterministic: no provider is needed for the lifecycle checks.
grep -v '^BROKER_ENABLED=' "$TMP/asf/asf.conf" > "$TMP/asf/asf.conf.new"
echo 'BROKER_ENABLED=false' >> "$TMP/asf/asf.conf.new"
mv "$TMP/asf/asf.conf.new" "$TMP/asf/asf.conf"

cat > "$TMP/bin/podman" <<'PODMAN'
#!/usr/bin/env bash
exec "${ASF_FAKE_PODMAN_SCRIPT:?}" "$@"
PODMAN
chmod 755 "$TMP/bin/podman"

export MOCK_LOG="$TMP/commands.log"
export ASF_FAKE_PODMAN_SCRIPT="$TMP/asf/tests/fake_podman_open.sh"
export ASF_FAKE_PODMAN_STATE="$TMP/podman-state"
export ASF_STOP_VERIFY_ATTEMPTS=1 ASF_STOP_VERIFY_DELAY=0

# Direct Podman container lifecycle: shared base, thin agent image, hardened run,
# bootstrap, then the interactive workload.
: > "$MOCK_LOG"
output=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open claude 2>&1)
grep -q 'Starting container' <<< "$output"
grep -q 'Container ready' <<< "$output"
grep -q 'ASF session cleanup complete' <<< "$output"
grep -qE '^podman build .*containers/base/Containerfile' "$MOCK_LOG"
grep -qE '^podman build .*containers/claude/Containerfile' "$MOCK_LOG"
grep -q 'ASF_BASE_IMAGE=localhost/' "$MOCK_LOG"
grep -qE '^podman run .*--detach .*--label=asf\.session=.*-claude .*--userns=keep-id:uid=1000,gid=1000' "$MOCK_LOG"
grep -qE '^podman run .*--network=.*-claude-internal' "$MOCK_LOG"
grep -qE '^podman run .*--cap-drop=ALL' "$MOCK_LOG"
grep -qE '^podman exec .* bash /workspace/sandbox/containers/on-start\.sh$' "$MOCK_LOG"
grep -qE '^podman exec --interactive --tty .* zsh$' "$MOCK_LOG"

# Persisted state is the runtime/security plan only; it must not depend on an
# a second generated orchestration configuration.
python3 - "$TMP/asf" <<'PY'
import sys
from asf.paths import RepoPaths
from asf.runtime_plan import load_runtime_plan, runtime_plan_path

paths = RepoPaths.for_root(sys.argv[1])
plan = load_runtime_plan(runtime_plan_path(paths, "claude"))
assert plan.runtime == "claude"
assert plan.runtime_isolation == "container"
assert {item.kind.value for item in plan.generated_files} == {"runtime-plan", "proxy-policy"}
PY

# `build` uses the same two-image pipeline without creating a runtime.
: > "$MOCK_LOG"
(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh build hermes >/dev/null 2>&1)
[[ $(grep -c '^podman build ' "$MOCK_LOG") -eq 2 ]]
grep -qE '^podman build .*containers/base/Containerfile' "$MOCK_LOG"
grep -qE '^podman build .*containers/hermes/Containerfile' "$MOCK_LOG"
if grep -qE '^podman run .*--label=asf\.session=' "$MOCK_LOG"; then
    echo "build started a runtime container" >&2
    exit 1
fi

# Missing build pins fail before a runtime can start.
cp "$TMP/asf/asf.conf" "$TMP/asf/asf.conf.orig"
grep -v '^SEMGREP_VERSION=' "$TMP/asf/asf.conf.orig" > "$TMP/asf/asf.conf"
: > "$MOCK_LOG"
set +e
pin_output=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open claude 2>&1)
pin_status=$?
set -e
mv "$TMP/asf/asf.conf.orig" "$TMP/asf/asf.conf"
[[ "$pin_status" -ne 0 ]]
grep -q 'Missing required value in asf.conf (build section): SEMGREP_VERSION' <<< "$pin_output"
if grep -qE '^podman run .*--label=asf\.session=' "$MOCK_LOG"; then
    echo "missing build pin still started a runtime" >&2
    exit 1
fi

# Probe infrastructure failure must fail closed before the runtime starts.
: > "$MOCK_LOG"
set +e
infra=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" MOCK_PROBE_INFRA_FAIL=true ./sandbox.sh open claude 2>&1)
infra_status=$?
set -e
[[ "$infra_status" -ne 0 ]]
grep -q 'probe infrastructure failed (125)' <<< "$infra"
if grep -qE '^podman run .*--label=asf\.session=' "$MOCK_LOG"; then
    echo "runtime started after verification infrastructure failure" >&2
    exit 1
fi

# Isolated mode gets one internal network and no proxy service.
mkdir -p "$TMP/asf/agents/isolated-test"
cat > "$TMP/asf/agents/isolated-test/runtime.yml" <<'YML'
name: isolated-test
adapter: generic
network:
  mode: isolated
llm:
  broker: false
YML
: > "$MOCK_LOG"
iso_out=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open isolated-test 2>&1)
grep -q 'Isolation verified' <<< "$iso_out"
if grep -qE '^podman run .*--label=asf\.role=proxy' "$MOCK_LOG"; then
    echo "isolated runtime started a proxy" >&2
    exit 1
fi
grep -qE '^podman run .*--label=asf\.session=.*-isolated-test .*--network=.*-isolated-test-internal' "$MOCK_LOG"
if grep -qE '^podman network create .*-isolated-test-(egress|provider)' "$MOCK_LOG"; then
    echo "isolated runtime created an external network" >&2
    exit 1
fi

echo "test_cli.sh: all assertions passed"
