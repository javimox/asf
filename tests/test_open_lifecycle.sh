#!/usr/bin/env bash
# Fast shell-boundary test for the open-session supervisor.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
OPEN_PID=""
cleanup() {
    if [[ -n "$OPEN_PID" ]]; then
        kill -KILL "$OPEN_PID" >/dev/null 2>&1 || true
        wait "$OPEN_PID" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

cp -a "$ROOT/." "$TMP/asf"
mkdir -p "$TMP/bin" "$TMP/podman-state"
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
export SESSION_STARTED="$TMP/session-started"
export ASF_FAKE_RUNTIME_BLOCK=true
export ASF_STOP_VERIFY_ATTEMPTS=1 ASF_STOP_VERIFY_DELAY=0 ASF_SHUTDOWN_TIMEOUT=0
export ASF_EXPECT_RUNTIME_PLAN="$TMP/asf/.asf/sessions/claude/runtime-plan.json"
: > "$MOCK_LOG"

(
    cd "$TMP/asf"
    exec env PATH="$TMP/bin:$PATH" ./sandbox.sh open claude \
        >"$TMP/open.out" 2>"$TMP/open.err"
) &
OPEN_PID=$!

for _ in $(seq 1 500); do
    [[ -f "$SESSION_STARTED" ]] && break
    kill -0 "$OPEN_PID" >/dev/null 2>&1 || {
        cat "$TMP/open.out" "$TMP/open.err" >&2
        echo "open supervisor exited before the session started" >&2
        exit 1
    }
    sleep 0.02
done
[[ -f "$SESSION_STARTED" ]] || {
    echo "timed out waiting for the supervised session" >&2
    exit 1
}

python3 - "$ASF_EXPECT_RUNTIME_PLAN" "$OPEN_PID" <<'PY'
import json, sys
plan = json.load(open(sys.argv[1], encoding="utf-8"))
assert plan["runtime"] == "claude"
assert plan["owner_pid"] == int(sys.argv[2])
assert plan["network_mode"] == "proxy"
assert plan["broker_enabled"] is False
assert [item["role"] for item in plan["networks"]] == ["internal", "egress"]
assert [item["role"] for item in plan["support_containers"]] == ["proxy"]
assert plan["runtime_container"]["name"].endswith("-claude")
PY

lock="$TMP/asf/.asf/.open-lock-claude/pid"
[[ -f "$lock" ]]
[[ "$(tr -d '\n' < "$lock")" == "$OPEN_PID" ]] || {
    echo "open lock PID changed across the Bash-to-Python exec" >&2
    exit 1
}

kill -TERM "$OPEN_PID"
set +e
wait "$OPEN_PID"
status=$?
set -e
OPEN_PID=""
[[ "$status" -eq 143 ]] || {
    echo "TERM returned $status instead of 143" >&2
    cat "$TMP/open.out" "$TMP/open.err" >&2
    exit 1
}

grep -q 'ASF session cleanup complete' "$TMP/open.out"
if grep -q 'Agent session exited with status' "$TMP/open.err"; then
    echo "signal exit was misreported as an agent failure" >&2
    exit 1
fi
[[ ! -e "$TMP/asf/.asf/.open-lock-claude" ]]
[[ ! -f "$ASF_FAKE_PODMAN_STATE/runtime_exists" ]]
for role in proxy broker routed-gateway routed-init; do
    [[ ! -f "$ASF_FAKE_PODMAN_STATE/${role}_exists" ]]
done
if [[ -s "$ASF_FAKE_PODMAN_STATE/networks" ]]; then
    echo "signal cleanup left networks behind" >&2
    cat "$ASF_FAKE_PODMAN_STATE/networks" >&2
    exit 1
fi

echo "test_open_lifecycle.sh: all assertions passed"
