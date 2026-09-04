#!/usr/bin/env bash
# Real-host stop, cleanup, and stale-recovery acceptance.
set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
    echo "test_stop_host.sh: requires bash >= 4" >&2
    exit 1
fi

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1090
source "$SOURCE_ROOT/tests/lib/host-fixture.sh"
AGENT="${1:-claude}"
OPEN_TIMEOUT="${ASF_HOST_OPEN_TIMEOUT:-900}"

if [[ "${ASF_INTEGRATION:-0}" != 1 ]]; then
    echo "test_stop_host.sh: skipped (set ASF_INTEGRATION=1)"
    exit 0
fi
command -v podman >/dev/null || { echo "podman not found." >&2; exit 1; }

OPEN_TIMEOUT=$(host_fixture_positive_integer "$OPEN_TIMEOUT" ASF_HOST_OPEN_TIMEOUT)
host_fixture_select_provider "$AGENT" "test_stop_host.sh"
host_fixture_init "$SOURCE_ROOT" "$AGENT" "asf-host-stop"

OPEN_PID=""
OPEN_COUNTER=0
OUTPUT_DIR="$WORK_ROOT/output"
mkdir -p "$OUTPUT_DIR"

container_id() {
    (
        cd "$ROOT"
        PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 - "$ROOT" "$AGENT" <<'PY_ID'
import sys
from asf.paths import RepoPaths
from asf.session import SessionDiscovery
paths = RepoPaths.for_root(sys.argv[1])
print("\n".join(SessionDiscovery.from_paths(paths).runtime_container_ids(sys.argv[2])))
PY_ID
    )
}

session_state() {
    (
        cd "$ROOT"
        PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 - "$ROOT" "$AGENT" <<'PY_STATE'
import sys
from asf.paths import RepoPaths
from asf.session import SessionDiscovery

paths = RepoPaths.for_root(sys.argv[1])
session = SessionDiscovery.from_paths(paths).session(sys.argv[2])
container = session.container
print(
    f"running={session.is_running} stale={session.is_stale} "
    f"ambiguous={session.is_ambiguous} "
    f"state={container.state.value if container else 'none'}"
)
PY_STATE
    )
}

residue_status() {
    (
        cd "$ROOT"
        PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 - "$ROOT" "$AGENT" <<'PY'
import sys
from asf.paths import RepoPaths
from asf.residue import ResidueScanner
from asf.session import SessionDiscovery

paths = RepoPaths.for_root(sys.argv[1])
residue = ResidueScanner(SessionDiscovery.from_paths(paths)).scan(sys.argv[2])
print(
    f"empty={residue.empty} inconclusive={residue.inconclusive} "
    f"resources={len(residue.resources())}"
)
PY
    )
}

persistent_volumes() {
    (
        cd "$ROOT"
        PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 - "$ROOT" "$AGENT" <<'PY'
import sys
from asf.manifest import load_model
from asf.paths import RepoPaths

paths = RepoPaths.for_root(sys.argv[1])
runtime = sys.argv[2]
manifest = load_model(paths.identity.runtime_manifest(runtime))
for state in manifest.state_volumes:
    print(paths.identity.state_volume(runtime, state.key))
print(paths.identity.shell_history_volume(runtime))
PY
    )
}

show_open_log() {
    local prefix="$1"
    for stream in out err; do
        local path="${prefix}.${stream}"
        [[ -s "$path" ]] || continue
        echo "  startup ${stream}:" >&2
        sed 's/^/    /' "$path" >&2
    done
}

wait_process_exit() {
    local pid="$1"
    for _ in $(seq 1 40); do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            wait "$pid" >/dev/null 2>&1 || true
            return 0
        fi
        sleep 0.25
    done
    return 1
}

wait_stable() {
    local prefix="$1"
    local started_at elapsed state
    local stable_polls=0
    local required_stable_polls=3
    started_at=$(date +%s)

    while (( stable_polls < required_stable_polls )); do
        if ! kill -0 "$OPEN_PID" >/dev/null 2>&1; then
            set +e
            wait "$OPEN_PID"
            local status=$?
            set -e
            OPEN_PID=""
            echo "open exited before ${AGENT} became stable (status ${status})" >&2
            show_open_log "$prefix"
            return 1
        fi

        state=$(session_state)
        if [[ -n "$(container_id)" && \
              "$state" == "running=True stale=False ambiguous=False state=running" ]]; then
            stable_polls=$((stable_polls + 1))
        else
            stable_polls=0
        fi

        elapsed=$(( $(date +%s) - started_at ))
        if (( elapsed >= OPEN_TIMEOUT )); then
            echo "timed out after ${OPEN_TIMEOUT}s waiting for stable ${AGENT}" >&2
            show_open_log "$prefix"
            return 1
        fi
        (( stable_polls >= required_stable_polls )) || sleep 2
    done
}

assert_clean() {
    local status
    status=$(residue_status)
    [[ "$status" == "empty=True inconclusive=False resources=0" ]] || {
        echo "ASF residue remains after cleanup: $status" >&2
        return 1
    }
}

open_session() {
    local output_prefix="${1:-}"
    if [[ -z "$output_prefix" ]]; then
        OPEN_COUNTER=$((OPEN_COUNTER + 1))
        output_prefix="$OUTPUT_DIR/open-${OPEN_COUNTER}"
    fi

    echo "  → Starting ${AGENT} test containers"
    (
        cd "$ROOT"
        export PYTHONUNBUFFERED=1
        exec ./sandbox.sh open "$AGENT"
    ) >"${output_prefix}.out" 2>"${output_prefix}.err" &
    OPEN_PID=$!

    wait_stable "$output_prefix" || {
        echo "could not start ${AGENT} for stop and recovery test" >&2
        return 1
    }
    echo "  ✓ ${AGENT} test containers ready"
}

stop_and_reap() {
    local output="$1"
    local action="${2:-Stopping and removing ${AGENT} test containers}"
    echo "  → ${action}"
    sandbox_in_fixture stop "$AGENT" >"$output.out" 2>"$output.err"
    if [[ -n "$OPEN_PID" ]]; then
        wait_process_exit "$OPEN_PID" || {
            echo "open process did not exit after stop" >&2
            return 1
        }
        OPEN_PID=""
    fi
    assert_clean
    echo "  ✓ ${AGENT} test containers stopped and cleanup verified"
}

teardown_fixture() {
    host_fixture_stop_runtime_quietly
    host_fixture_stop_open_process 0
    if [[ -d "$ROOT" ]]; then
        mapfile -t fixture_volumes < <(persistent_volumes 2>/dev/null || true)
        for volume in "${fixture_volumes[@]}"; do
            [[ -n "$volume" ]] || continue
            podman volume rm -f "$volume" >/dev/null 2>&1 || true
        done
    fi
    host_fixture_remove_work_root
}
trap teardown_fixture EXIT

# Use a clean, self-contained checkout from the shared host fixture.
host_fixture_prepare_checkout "host-stop-hold.sh" "ASF host-stop test session ready"

fixture_root=$(
    cd "$ROOT"
    PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 - "$ROOT" <<'PY_ROOT'
import sys
from asf.paths import RepoPaths
print(RepoPaths.for_root(sys.argv[1]).root)
PY_ROOT
)
[[ "$fixture_root" == "$ROOT" ]] || {
    echo "test_stop_host.sh: fixture imported a different checkout" >&2
    exit 1
}

(
    cd "$ROOT"
    PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 - "$ROOT" "$AGENT" <<'PY_VALIDATE'
import sys
from asf.paths import RepoPaths
from asf.session import SessionDiscovery
SessionDiscovery.from_paths(RepoPaths.for_root(sys.argv[1])).validate_runtime(sys.argv[2])
PY_VALIDATE
)

if [[ -n "$(container_id)" ]]; then
    echo "test_stop_host.sh: ${AGENT} is already running in fixture; refusing to touch it" >&2
    exit 1
fi

echo "Live stop and idempotent cleanup (${AGENT})"
open_session
mapfile -t volumes < <(persistent_volumes)
stop_and_reap "$OUTPUT_DIR/live"
grep -q 'ASF session cleanup complete' "$OUTPUT_DIR/live.out"
for volume in "${volumes[@]}"; do
    podman volume inspect "$volume" >/dev/null 2>&1 || {
        echo "persistent volume was removed: $volume" >&2
        exit 1
    }
done
echo "  → Repeating stop to verify idempotency"
sandbox_in_fixture stop "$AGENT" >/dev/null
assert_clean
echo "  ✓ live stop, verification, idempotency, and volumes"

echo "Signal-triggered cleanup (${AGENT})"
open_session "$OUTPUT_DIR/signal"
lock_pid_file="$ROOT/.asf/.open-lock-${AGENT}/pid"
[[ -f "$lock_pid_file" && "$(tr -d '\n' < "$lock_pid_file")" == "$OPEN_PID" ]] || {
    echo "open lock PID did not survive the session-supervisor handoff" >&2
    exit 1
}
echo "  → Sending TERM to the ${AGENT} session supervisor"
kill -TERM "$OPEN_PID"
for _ in $(seq 1 80); do
    kill -0 "$OPEN_PID" >/dev/null 2>&1 || break
    sleep 0.25
done
if kill -0 "$OPEN_PID" >/dev/null 2>&1; then
    echo "open supervisor did not exit after TERM" >&2
    exit 1
fi
set +e
wait "$OPEN_PID"
signal_status=$?
set -e
OPEN_PID=""
[[ "$signal_status" -eq 143 ]] || {
    echo "TERM returned ${signal_status}, expected 143" >&2
    cat "$OUTPUT_DIR/signal.out" "$OUTPUT_DIR/signal.err" >&2
    exit 1
}
grep -q 'ASF session cleanup complete' "$OUTPUT_DIR/signal.out"
if grep -q 'Agent session exited with status' "$OUTPUT_DIR/signal.err"; then
    echo "signal exit was misreported as an agent failure" >&2
    exit 1
fi
assert_clean
for volume in "${volumes[@]}"; do
    podman volume inspect "$volume" >/dev/null 2>&1 || {
        echo "signal cleanup removed persistent volume: $volume" >&2
        exit 1
    }
done
echo "  ✓ TERM status, supervisor cleanup, lock release, and volumes"

echo "SIGKILL stale-session recovery (${AGENT})"
open_session
echo "  → Sending SIGKILL to the ${AGENT} session supervisor"
kill -9 "$OPEN_PID" >/dev/null 2>&1 || true
wait "$OPEN_PID" >/dev/null 2>&1 || true
OPEN_PID=""
[[ "$(residue_status)" != "empty=True inconclusive=False resources=0" ]] || {
    echo "expected residue after SIGKILL" >&2
    exit 1
}
stop_and_reap "$OUTPUT_DIR/stale" "Recovering and removing stale ${AGENT} test containers"
grep -q 'ASF session cleanup complete' "$OUTPUT_DIR/stale.out"
echo "  ✓ stale lock and resources recovered after SIGKILL"

echo "Partial-resource recovery (${AGENT})"
open_session
proxy=$(podman ps -q \
    --filter "label=asf.sandbox=$ROOT" \
    --filter "label=asf.role=proxy" \
    --filter "label=asf.agent=$AGENT" | head -n1)
[[ -n "$proxy" ]] || {
    echo "expected a support proxy container for partial-resource recovery" >&2
    exit 1
}
echo "  → Removing one support container to simulate partial cleanup"
podman rm -f "$proxy" >/dev/null 2>&1
stop_and_reap "$OUTPUT_DIR/partial"
echo "  ✓ an already-removed support container is tolerated"

echo "  → Verifying an unknown runtime fails cleanly"
set +e
unknown_output=$(sandbox_in_fixture stop definitely-not-an-agent 2>&1)
unknown_status=$?
set -e
[[ "$unknown_status" -eq 1 ]] || {
    echo "unknown runtime exited $unknown_status" >&2
    exit 1
}
[[ "$unknown_output" != *"Traceback (most recent call last)"* ]] || {
    echo "unknown runtime leaked a traceback" >&2
    exit 1
}
echo "  ✓ unknown runtime is a clean CLI failure"

trap - EXIT
teardown_fixture

echo "test_stop_host.sh: all assertions passed"
