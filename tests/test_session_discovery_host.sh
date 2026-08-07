#!/usr/bin/env bash
# Real-host session discovery and diagnostics acceptance.
set -euo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1090
source "$SOURCE_ROOT/tests/lib/host-fixture.sh"
AGENT="${1:-claude}"

if [[ "${ASF_INTEGRATION:-0}" != 1 ]]; then
    echo "test_session_discovery_host.sh: set ASF_INTEGRATION=1 to run" >&2
    exit 0
fi
command -v podman >/dev/null || { echo "podman not found." >&2; exit 1; }

host_fixture_select_provider "$AGENT" "test_session_discovery_host.sh"
OPEN_TIMEOUT=$(host_fixture_positive_integer "${ASF_HOST_OPEN_TIMEOUT:-900}" ASF_HOST_OPEN_TIMEOUT)
host_fixture_init "$SOURCE_ROOT" "$AGENT" "asf-host-session"

OPENED=false
OPEN_PID=""
OPEN_LOG=""

show_open_log() {
    [[ -n "$OPEN_LOG" && -f "$OPEN_LOG" ]] || return 0
    if [[ -s "$OPEN_LOG" ]]; then
        echo "  startup log:" >&2
        sed 's/^/    /' "$OPEN_LOG" >&2
    else
        echo "  startup produced no output." >&2
    fi
}

cleanup() {
    if [[ "$OPENED" == true ]]; then
        host_fixture_stop_runtime_quietly
        host_fixture_stop_open_process
    fi
    host_fixture_remove_work_root
}
trap cleanup EXIT

# Exercise a clean, self-contained checkout using the shared host fixture.
host_fixture_prepare_checkout "host-session-hold.sh" "ASF host-test session ready"

query() {
    (
        cd "$ROOT"
        PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 - "$ROOT" "$@" <<'PY'
import sys
from asf.paths import RepoPaths
from asf.session import SessionDiscovery, SessionDiscoveryError
paths = RepoPaths.for_root(sys.argv[1])
discovery = SessionDiscovery.from_paths(paths)
question = sys.argv[2]
runtime = sys.argv[3] if len(sys.argv) > 3 else ""
if question == "ids":
    print(",".join(discovery.runtime_container_ids(runtime)))
elif question == "running":
    print(",".join(discovery.running_runtimes()))
elif question == "resolve":
    try:
        print(discovery.resolve_runtime(runtime or None))
    except SessionDiscoveryError:
        print("<error>")
elif question == "root":
    print(paths.root)
elif question == "state":
    session = discovery.session(runtime)
    container = session.container
    print(
        f"running={session.is_running} stale={session.is_stale} "
        f"ambiguous={session.is_ambiguous} "
        f"state={container.state.value if container else 'none'}"
    )
PY
    )
}

[[ "$(query root)" == "$ROOT" ]] || {
    echo "test_session_discovery_host.sh: fixture imported a different checkout" >&2
    exit 1
}
[[ -z "$(query ids "$AGENT")" ]] || {
    echo "test_session_discovery_host.sh: ${AGENT} already running in fixture" >&2
    exit 1
}
[[ "$(query resolve "$AGENT")" == "$AGENT" ]]
[[ "$(query resolve)" == "<error>" ]]

set +e
report=$(sandbox_in_fixture test "$AGENT" 2>&1)
status=$?
set -e
[[ "$status" -eq 1 && "$report" == *"No running ${AGENT} container."* ]]
[[ "$report" != *"Traceback (most recent call last)"* ]]

echo "  → Starting ${AGENT} session-discovery test containers"
OPEN_LOG="$WORK_ROOT/open.log"
(
    cd "$ROOT"
    export PYTHONUNBUFFERED=1
    exec ./sandbox.sh open "$AGENT"
) >"$OPEN_LOG" 2>&1 &
OPEN_PID=$!
OPENED=true
started_at=$(date +%s)
next_update=10
stable_polls=0
required_stable_polls=3

while (( stable_polls < required_stable_polls )); do
    if ! kill -0 "$OPEN_PID" 2>/dev/null; then
        set +e
        wait "$OPEN_PID"
        open_status=$?
        set -e
        echo "test_session_discovery_host.sh: open exited before the runtime became stable (status $open_status)." >&2
        show_open_log
        exit 1
    fi

    state=$(query state "$AGENT")
    if [[ -n "$(query ids "$AGENT")" && \
          "$state" == "running=True stale=False ambiguous=False state=running" ]]; then
        stable_polls=$((stable_polls + 1))
    else
        stable_polls=0
    fi

    elapsed=$(( $(date +%s) - started_at ))
    if (( elapsed >= OPEN_TIMEOUT )); then
        echo "test_session_discovery_host.sh: timed out after ${OPEN_TIMEOUT}s waiting for a stable $AGENT runtime." >&2
        show_open_log
        exit 1
    fi
    if (( elapsed >= next_update )); then
        last_line=$(tail -n 1 "$OPEN_LOG" 2>/dev/null || true)
        if [[ -n "$last_line" ]]; then
            printf '  still opening after %ss: %s\n' "$elapsed" "$last_line"
        else
            printf '  still opening after %ss (no startup output yet)\n' "$elapsed"
        fi
        next_update=$((next_update + 10))
    fi
    (( stable_polls >= required_stable_polls )) || sleep 2
done

elapsed=$(( $(date +%s) - started_at ))
echo "  ✓ ${AGENT} test containers remained stable for ${required_stable_polls} polls after ${elapsed}s"
[[ "$(query running)" == *"$AGENT"* ]]
[[ "$(query resolve)" == "$AGENT" ]]
[[ "$(query state "$AGENT")" == "running=True stale=False ambiguous=False state=running" ]]

# The provider key and ephemeral broker token must never appear in startup logs.
! grep -Fq "$DUMMY_KEY" "$OPEN_LOG"
! grep -Eq '(ASF_BROKER_TOKEN|ANTHROPIC_AUTH_TOKEN|OPENAI_API_KEY)=[0-9a-f]{64}' "$OPEN_LOG"

sandbox_in_fixture proxy status "$AGENT" >/dev/null
sandbox_in_fixture proxy config "$AGENT" >/dev/null
sandbox_in_fixture test "$AGENT" >/dev/null

# Prove the service workload did not disappear while the security checks ran.
kill -0 "$OPEN_PID" 2>/dev/null
[[ "$(query state "$AGENT")" == "running=True stale=False ambiguous=False state=running" ]]

echo "  → Stopping and removing ${AGENT} session-discovery test containers"
sandbox_in_fixture stop "$AGENT" >/dev/null
host_fixture_stop_open_process
OPENED=false
[[ -z "$(query ids "$AGENT")" ]] || {
    echo "test_session_discovery_host.sh: test containers remain after cleanup" >&2
    exit 1
}
echo "  ✓ ${AGENT} session-discovery test containers stopped and cleanup verified"

trap - EXIT
cleanup
echo "test_session_discovery_host.sh: all assertions passed"
