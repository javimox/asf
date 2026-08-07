#!/usr/bin/env bash
# Shared real-host test fixture for isolated ASF checkouts.
# OPEN_PID is owned by the sourcing harness.
# shellcheck disable=SC2154

host_fixture_positive_integer() {
    local value="$1"
    local name="${2:-value}"
    case "$value" in
        ""|*[!0-9]*|0)
            echo "$name must be a positive integer (seconds)." >&2
            return 1
            ;;
    esac
    printf '%d\n' "$((10#$value))"
}

host_fixture_select_provider() {
    local agent="$1"
    local caller="$2"
    case "$agent" in
        claude)
            PROVIDER_KEY=ANTHROPIC_API_KEY
            MODEL_SETTING=LITELLM_CLAUDE_MODELS
            ;;
        hermes)
            PROVIDER_KEY=OPENAI_API_KEY
            MODEL_SETTING=LITELLM_HERMES_MODELS
            ;;
        *)
            echo "${caller}: supported agents: claude, hermes" >&2
            return 1
            ;;
    esac
}

host_fixture_init() {
    local source_root="$1"
    local agent="$2"
    local work_prefix="$3"

    SOURCE_ROOT="$source_root"
    AGENT="$agent"
    WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/${work_prefix}.XXXXXX")
    ROOT="$WORK_ROOT/asf"
    DUMMY_KEY="asf-host-fixture-dummy-key-$$"
}

sandbox_in_fixture() {
    (
        cd "$ROOT"
        exec ./sandbox.sh "$@"
    )
}

host_fixture_prepare_checkout() {
    local hold_script="$1"
    local ready_message="$2"

    # Never read or modify the operator's credentials, manifests, locks, or
    # persistent session state. Every host test receives a private checkout.
    cp -a "$SOURCE_ROOT/." "$ROOT"
    rm -rf "$ROOT/.devcontainer/sessions"
    find "$ROOT/.devcontainer" -maxdepth 1 -name '.open-lock-*' -exec rm -rf {} +

    python3 - "$ROOT/asf.conf" "$MODEL_SETTING" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
model_setting = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
lines = [
    line for line in lines
    if not line.startswith("BROKER_ENABLED=")
    and not line.startswith(f"{model_setting}=")
]
lines.extend(("BROKER_ENABLED=true", f'{model_setting}="asf-host-test-model"'))
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

    printf '%s=%s\n' "$PROVIDER_KEY" "$DUMMY_KEY" > "$ROOT/secrets/$AGENT.env"
    chmod 600 "$ROOT/secrets/$AGENT.env"

    {
        printf '%s\n' '#!/usr/bin/env bash'
        printf '%s\n' 'set -euo pipefail'
        printf '%s\n' "trap 'exit 0' TERM INT HUP"
        printf '%s\n' "printf '%s\\n' $(printf '%q' "$ready_message")"
        printf '%s\n' 'while sleep 1; do :; done'
    } > "$ROOT/tests/$hold_script"
    chmod 0755 "$ROOT/tests/$hold_script"

    python3 - "$ROOT/agents/$AGENT/runtime.yml" "$hold_script" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
hold_script = sys.argv[2]
text = path.read_text(encoding="utf-8")
old = "runtime:\n  mode: interactive\n"
new = (
    "runtime:\n"
    "  mode: service\n"
    f"  command: [bash, /workspace/sandbox/tests/{hold_script}]\n"
)
if text.count(old) != 1:
    raise SystemExit(f"could not patch {path} to a test-only service runtime")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
}

host_fixture_stop_open_process() {
    local grace_polls="${1:-20}"
    [[ -n "${OPEN_PID:-}" ]] || return 0

    local _
    for ((_=0; _<grace_polls; _++)); do
        kill -0 "$OPEN_PID" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$OPEN_PID" 2>/dev/null; then
        kill -TERM "$OPEN_PID" 2>/dev/null || true
        for _ in $(seq 1 5); do
            kill -0 "$OPEN_PID" 2>/dev/null || break
            sleep 1
        done
    fi
    if kill -0 "$OPEN_PID" 2>/dev/null; then
        kill -KILL "$OPEN_PID" 2>/dev/null || true
    fi
    wait "$OPEN_PID" >/dev/null 2>&1 || true
    OPEN_PID=""
}

host_fixture_stop_runtime_quietly() {
    if [[ -x "${ROOT:-}/sandbox.sh" ]]; then
        sandbox_in_fixture stop "$AGENT" >/dev/null 2>&1 || true
    fi
}

host_fixture_remove_work_root() {
    [[ -n "${WORK_ROOT:-}" ]] || return 0
    rm -rf "$WORK_ROOT"
}
