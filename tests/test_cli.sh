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
mkdir -p "$TMP/bin"

# Keep this integration test deterministic and independent of network access.
# (Portable: BSD/macOS sed -i needs a suffix argument, so avoid sed -i.)
grep -v '^BROKER_ENABLED=' "$TMP/asf/asf.conf" > "$TMP/asf/asf.conf.new"
echo 'BROKER_ENABLED=false' >> "$TMP/asf/asf.conf.new"
mv "$TMP/asf/asf.conf.new" "$TMP/asf/asf.conf"

cat > "$TMP/bin/podman" <<'EOF_PODMAN'
#!/usr/bin/env bash
exec "${ASF_FAKE_PODMAN_SCRIPT:?}" "$@"
EOF_PODMAN

cat > "$TMP/bin/devcontainer" <<'EOF_DEVCONTAINER'
#!/usr/bin/env bash
set -euo pipefail
printf 'devcontainer %s\n' "$*" >> "${MOCK_LOG:?}"
# The real CLI enforces two constraints this mock reproduces:
#   1. `build` has no --id-label option (it creates no container)
#   2. --config must be NAMED devcontainer.json or .devcontainer.json
config=""
prev=""
for arg in "$@"; do
    [[ "$prev" == "--config" ]] && config="$arg"
    prev="$arg"
done
if [[ -n "$config" ]]; then
    case "$(basename "$config")" in
        devcontainer.json|.devcontainer.json) ;;
        *) echo "Error: Filename must be devcontainer.json or .devcontainer.json ($config)." >&2; exit 1 ;;
    esac
    [[ -f "$config" ]] || { echo "Error: config not found: $config" >&2; exit 1; }
fi

case "${1:-}" in
    build)
        case "$*" in
            *--id-label*) echo "Unknown arguments: id-label, idLabel" >&2; exit 1 ;;
        esac
        ;;
    up)
        session_label=""
        previous=""
        for argument in "$@"; do
            if [[ "$previous" == "--id-label" && "$argument" == asf.session=* ]]; then
                session_label="${argument#asf.session=}"
            fi
            previous="$argument"
        done
        [[ -z "$session_label" ]] || "${ASF_FAKE_PODMAN_SCRIPT:?}" __add-runtime "$session_label" >/dev/null
        ;;
    exec) exit "${DEVCONTAINER_EXEC_STATUS:-0}" ;;
    *) exit 2 ;;
esac
EOF_DEVCONTAINER
chmod 755 "$TMP/bin/podman" "$TMP/bin/devcontainer"

# The brokered provider key must be omitted from agent runtime flags.
PYTHONPATH="$TMP/asf" python3 - "$TMP/asf" <<'PY_SECRET'
import io, sys
from asf.manifest import load_model
from asf.paths import RepoPaths
from asf.runtime import load_runtime_environment
from asf.runtime_plan import build_runtime_plan

paths = RepoPaths.for_root(sys.argv[1])
(paths.secrets_dir / "hermes.env").write_text(
    "OPENAI_API_KEY=provider-secret\nVISIBLE_SETTING=enabled\n", encoding="utf-8"
)
(paths.secrets_dir / "not-declared.env").write_text(
    "UNDECLARED_SECRET=must-not-leak\n", encoding="utf-8"
)
manifest = load_model(paths.identity.runtime_manifest("hermes"))
plan = build_runtime_plan(
    manifest, paths=paths, owner_pid=4242, broker_globally_enabled=True
)
values = dict(load_runtime_environment(
    plan, excluded_key="OPENAI_API_KEY", output=io.StringIO(), error=io.StringIO()
))
assert values["VISIBLE_SETTING"] == "enabled"
assert "OPENAI_API_KEY" not in values
assert "UNDECLARED_SECRET" not in values
PY_SECRET

MOCK_LOG="$TMP/commands.log"
export MOCK_LOG
export ASF_FAKE_PODMAN_SCRIPT="$TMP/asf/tests/fake_podman_open.sh"
export ASF_FAKE_PODMAN_STATE="$TMP/podman-state"
mkdir -p "$ASF_FAKE_PODMAN_STATE"
session_label=$(PYTHONPATH="$TMP/asf" python3 - "$TMP/asf" <<'PY_STATE'
import sys
from asf.paths import RepoPaths
print(RepoPaths.for_root(sys.argv[1]).identity.session_key("claude"))
PY_STATE
)
printf '%s' "$session_label" > "$ASF_FAKE_PODMAN_STATE/runtime_session"
: > "$ASF_FAKE_PODMAN_STATE/runtime_exists"
export ASF_STOP_VERIFY_ATTEMPTS=1 ASF_STOP_VERIFY_DELAY=0
: > "$MOCK_LOG"
output=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open claude 2>&1)

grep -q 'Starting container' <<< "$output"
grep -q 'Agent container removed' <<< "$output"
grep -q 'ASF session cleanup complete' <<< "$output"

# Stale resources are removed before any new network is created. A killed
# launcher must not leave the next session building on old policy state.
first_rm=$(grep -n '^podman rm ' "$MOCK_LOG" | head -n1 | cut -d: -f1)
first_create=$(grep -n '^podman network create ' "$MOCK_LOG" | head -n1 | cut -d: -f1)
[[ -n "$first_rm" && -n "$first_create" && "$first_rm" -lt "$first_create" ]]

# Per-agent session identity must reach the devcontainer CLI, or two agents
# would share one container.
grep -q 'devcontainer up .*--config .*sessions/claude/devcontainer\.json' "$MOCK_LOG"
grep -q 'devcontainer up .*--id-label asf\.session=.*-claude' "$MOCK_LOG"
grep -q 'devcontainer exec .*--id-label asf\.session=.*-claude' "$MOCK_LOG"

python3 - "$TMP/asf/.devcontainer/sessions/claude/devcontainer.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
config = json.loads("\n".join(line for line in path.read_text().splitlines() if not line.startswith("//")))
assert config["build"]["args"]["AGENT"] == "claude"
assert config["containerEnv"]["ASF_AGENT"] == "claude"
# The container must be self-labelled so `podman ps --filter label=` finds it
# regardless of how the devcontainer CLI treats --id-label.
assert any(arg.startswith("--label=asf.session=") and arg.endswith("-claude")
           for arg in config["runArgs"]), config["runArgs"]
# Named container, so `podman ps` shows which agent is which.
assert any(arg.startswith("--name=") and arg.endswith("-claude")
           for arg in config["runArgs"]), config["runArgs"]
assert config["build"]["args"]["SEMGREP_VERSION"] == "1.171.0"
assert any("/workspace/sandbox/secrets" in arg for arg in config["runArgs"])
volume_sources = [mount.split(",", 1)[0] for mount in config["mounts"] if "type=volume" in mount]
assert all("-" in source.removeprefix("source=") for source in volume_sources)
PY

# A real devcontainer exec failure must be reported after cleanup, not swallowed.
: > "$MOCK_LOG"
set +e
failure_output=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" DEVCONTAINER_EXEC_STATUS=42 ./sandbox.sh open claude 2>&1)
failure_status=$?
set -e

[[ "$failure_status" -eq 42 ]]
grep -q 'Agent session exited with status 42' <<< "$failure_output"
grep -q 'Agent container removed' <<< "$failure_output"
grep -q 'ASF session cleanup complete' <<< "$failure_output"
grep -q '^podman rm ' "$MOCK_LOG"

# A missing dependency pin must ABORT the run — previously the error was
# swallowed by process substitution and the build fell back to Dockerfile
# ARG defaults, silently defeating the pinning contract.
cp "$TMP/asf/asf.conf" "$TMP/asf/asf.conf.orig"
grep -v '^SEMGREP_VERSION=' "$TMP/asf/asf.conf.orig" > "$TMP/asf/asf.conf"
set +e
pin_output=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open claude 2>&1)
pin_status=$?
set -e
mv "$TMP/asf/asf.conf.orig" "$TMP/asf/asf.conf"

[[ "$pin_status" -ne 0 ]]
grep -q 'Missing required value in asf.conf (build section): SEMGREP_VERSION' <<< "$pin_output"
if grep -q 'Starting container' <<< "$pin_output"; then
    echo "missing pin did not abort before container start" >&2
    exit 1
fi

# Build paths in the generated config must resolve from ITS OWN directory.
python3 - "$TMP/asf/.devcontainer/sessions/claude/devcontainer.json" <<'BUILDPATHS'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads("\n".join(l for l in path.read_text().splitlines() if not l.startswith("//")))
build = cfg["build"]
dockerfile = (path.parent / build["dockerfile"]).resolve()
context = (path.parent / build["context"]).resolve()
assert dockerfile.is_file(), f"dockerfile does not resolve: {dockerfile}"
assert (context / "sandbox.sh").is_file(), f"context is not the project root: {context}"
BUILDPATHS

# Egress enforcement replaced the in-container firewall. `open` must create the
# three networks, put the agent on the INTERNAL one only, start the proxy, and
# verify policy BEFORE the agent container starts.
: > "$MOCK_LOG"
open_output=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open claude 2>&1)

grep -q 'Networks ready'          <<< "$open_output"
grep -q 'Egress proxy ready'      <<< "$open_output"
grep -q 'Egress policy verified'  <<< "$open_output"

# Verification must come BEFORE the container starts: a failed check has to
# stop the session, not report on one already running.
verify_line=$(grep -n 'Egress policy verified' <<< "$open_output" | head -1 | cut -d: -f1)
start_line=$(grep -n 'Starting container'      <<< "$open_output" | head -1 | cut -d: -f1)
if [[ -n "$verify_line" && -n "$start_line" && "$verify_line" -ge "$start_line" ]]; then
    echo "egress was verified AFTER the agent container started" >&2
    exit 1
fi

# The agent must join the INTERNAL network only, and carry no capabilities.
# These are runArgs in the generated config, not flags on the CLI command line.
python3 - "$TMP/asf/.devcontainer/sessions/claude/devcontainer.json" <<'NETCHECK'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads("\n".join(l for l in path.read_text().splitlines()
                           if not l.startswith("//")))
run_args = cfg.get("runArgs", [])
nets = [a.split("=", 1)[1] for a in run_args if a.startswith("--network=")]
assert len(nets) == 1, f"expected exactly one network, got {nets}"
assert nets[0].endswith("-internal"), f"agent must be on the internal network, got {nets[0]}"

# The whole point of the refactor: no capabilities, no privileged helper.
banned = ("--cap-add", "NET_ADMIN", "NET_RAW", "--privileged")
for arg in run_args:
    for bad in banned:
        assert bad not in arg, f"capability flag survived the refactor: {arg}"

env = cfg.get("containerEnv", {})
assert env.get("HTTP_PROXY"), "agent has no HTTP_PROXY: it would have no egress at all"
if env.get("ASF_BROKER_ENABLED") == "true":
    assert "4000" in env.get("OPENAI_BASE_URL", "") + env.get("ANTHROPIC_BASE_URL", "")
NETCHECK

# ./sandbox.sh build <agent> uses the same build flags.
: > "$MOCK_LOG"
(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh build hermes >/dev/null 2>&1)
grep -q 'devcontainer build .*--config .*sessions/hermes/devcontainer\.json' "$MOCK_LOG"
if grep -q 'devcontainer build .*--id-label' "$MOCK_LOG"; then
    echo "sandbox.sh build passed --id-label" >&2
    exit 1
fi

# Two agents coexist: separate configs, separate locks, separate session labels.
: > "$MOCK_LOG"
(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open hermes >/dev/null 2>&1) || true
[[ -f "$TMP/asf/.devcontainer/sessions/hermes/devcontainer.json" ]]
[[ -f "$TMP/asf/.devcontainer/sessions/claude/devcontainer.json" ]]
grep -q 'devcontainer up .*--id-label asf\.session=.*-hermes' "$MOCK_LOG"

# A live claude lock must not block hermes, and must block a second claude.
mkdir -p "$TMP/asf/.devcontainer/.open-lock-claude"
echo $$ > "$TMP/asf/.devcontainer/.open-lock-claude/pid"
set +e
blocked=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open claude 2>&1)
blocked_status=$?
(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open hermes >/dev/null 2>&1)
hermes_status=$?
set -e
rm -rf "$TMP/asf/.devcontainer/.open-lock-claude"

[[ "$blocked_status" -ne 0 ]]
grep -q 'claude session .* is already running' <<< "$blocked"
[[ "$hermes_status" -eq 0 ]]

# Proxy/isolated probes are fixed Python vectors after Phase 4E. The behavioral
# failure checks below remain the production regression for the old pipeline
# masking bug; source-level shell extraction is no longer applicable.
[[ ! -d "$ROOT/lib" ]]

# ── the positive control must actually be able to fail ──────────────────────
# Regression for a real bug: the probe was `nc ... | head -c 1`, and a pipeline
# returns HEAD's status — 0 even when nc could not reach the proxy. The
# "positive control" therefore always passed, which is the exact false positive
# it exists to prevent. Reserved probe exit codes keep that property: an
# unreachable upstream is reported as an inconclusive infrastructure failure,
# never as REACHED.
#
# Since the advisory-control change, an *inconclusive* positive control is an
# availability warning: the session starts, the transcript says so explicitly,
# and every deny check stays fatal. An explicit proxy DENIAL of an allowlisted
# host remains blocking; that policy-failure branch is covered by the
# deterministic unit tests in tests/test_verification_engine.py.
: > "$MOCK_LOG"
set +e
broken=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" MOCK_CONNECT_OK=false \
         ./sandbox.sh open claude 2>&1)
broken_status=$?
set -e

[[ "$broken_status" -eq 0 ]] \
    || { echo "inconclusive positive control aborted the session instead of degrading to a warning" >&2; exit 1; }
grep -q 'availability control unavailable' <<< "$broken" \
    || { echo "no advisory warning was printed for the unreachable positive control" >&2; exit 1; }
grep -q 'positive control unavailable' <<< "$broken" \
    || { echo "success line still claimed a proven allow path" >&2; exit 1; }
if grep -q 'Egress policy verified.*(allow,' <<< "$broken"; then
    echo "claimed a verified allow path while the positive control failed" >&2
    exit 1
fi
grep -q 'devcontainer up' "$MOCK_LOG" \
    || { echo "agent container did not start after the advisory degradation" >&2; exit 1; }
runs=$(cd "$TMP/asf" && python3 - <<'PY_RUNS'
from asf.paths import RepoPaths
from asf.runs import runs_root

print(runs_root(RepoPaths.for_root("."), "claude"))
PY_RUNS
)
report="$runs/$(cat "$runs/current")/verification-report.json"
[[ -f "$report" ]] \
    || { echo "verification report was not persisted to the session directory" >&2; exit 1; }
grep -q '"advisory": true' "$report" \
    || { echo "persisted report does not record the advisory control" >&2; exit 1; }

# Podman/timeout failures are infrastructure failures, not successful deny
# verdicts. A fail-closed verifier must abort rather than treating rc=125 as
# evidence that the policy blocked a request.
: > "$MOCK_LOG"
set +e
infra=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" MOCK_PROBE_INFRA_FAIL=true \
        ./sandbox.sh open claude 2>&1)
infra_status=$?
set -e
[[ "$infra_status" -ne 0 ]] \
    || { echo "session started after probe infrastructure failure" >&2; exit 1; }
grep -q 'probe infrastructure failed (125)' <<< "$infra" \
    || { echo "probe infrastructure failure was not identified" >&2; exit 1; }
grep -q 'devcontainer up' "$MOCK_LOG" \
    && { echo "agent started after probe infrastructure failure" >&2; exit 1; }

# ── the port check must be able to fail ─────────────────────────────────────
# Simulates a proxy that allows any port on an allowlisted host (tinyproxy's
# plain-HTTP behaviour). The session must refuse to start.
: > "$MOCK_LOG"
set +e
leaky=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" MOCK_PORT_ENFORCED=false \
        ./sandbox.sh open claude 2>&1)
leaky_status=$?
set -e

[[ "$leaky_status" -ne 0 ]] \
    || { echo "session started although a non-443 port was reachable" >&2; exit 1; }
grep -q 'did not reject plain HTTP to a forbidden port' <<< "$leaky" \
    || { echo "the port check did not report the failure" >&2; exit 1; }
grep -q 'devcontainer up' "$MOCK_LOG" \
    && { echo "agent started despite the port check failing" >&2; exit 1; }

# ── isolated mode actually isolates ─────────────────────────────────────────
# The dangerous failure is the opposite of fail-closed: a runtime that declares
# `isolated` but is quietly given proxy egress. Assert the topology instead of
# trusting the branch.
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

grep -q 'Isolation verified' <<< "$iso_out" \
    || { echo "isolated mode did not verify isolation:" >&2; echo "$iso_out" >&2; exit 1; }

# No proxy may be built or started.
if grep -qE 'podman (run|build) .*proxy' "$MOCK_LOG"; then
    echo "isolated mode started or built a proxy" >&2; exit 1
fi
# No egress network may exist for this runtime.
if grep -qE 'network create .*-isolated-test-egress' "$MOCK_LOG"; then
    echo "isolated mode created an egress network" >&2; exit 1
fi
if grep -qE 'network create .*-isolated-test-provider' "$MOCK_LOG"; then
    echo "isolated mode without a broker created a provider network" >&2; exit 1
fi
grep -qE 'network create .*--internal .*-isolated-test-internal' "$MOCK_LOG" \
    || { echo "isolated mode did not create the internal network" >&2; exit 1; }

# The generated config must carry no proxy environment and one network.
python3 - "$TMP/asf/.devcontainer/sessions/isolated-test/devcontainer.json" <<'ISOCHECK'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
cfg = json.loads("\n".join(l for l in path.read_text().splitlines()
                           if not l.startswith("//")))
env = cfg.get("containerEnv", {})
leaked = [k for k in env if "proxy" in k.lower()]
assert not leaked, f"isolated runtime received proxy env: {leaked}"
nets = [a for a in cfg.get("runArgs", []) if a.startswith("--network=")]
assert len(nets) == 1, f"expected one network, got {nets}"
assert nets[0].endswith("-internal"), f"not the internal network: {nets[0]}"
ISOCHECK
rm -rf "$TMP/asf/agents/isolated-test"

# ── routed lifecycle fails closed before the agent ─────────────────────────
mkdir -p "$TMP/asf/agents/routed-test"
cat > "$TMP/asf/agents/routed-test/runtime.yml" <<'YML'
name: routed-test
adapter: generic
network:
  mode: routed
  allow:
    - cidr: 192.168.50.0/24
      protocol: tcp
      ports: [8080]
  verify:
    address: 192.168.50.9
    protocol: tcp
    port: 8080
    blocked_port: 8081
llm:
  broker: false
YML
(cd "$TMP/asf" && python3 -m asf.manifest agents/routed-test/runtime.yml >/dev/null) \
    || { echo "the routed manifest should be valid" >&2; exit 1; }

# A bad allocation pool must abort before a gateway or agent is started.
echo 'ASF_SUBNET_POOL=not-a-cidr' >> "$TMP/asf/asf.conf"
: > "$MOCK_LOG"
set +e
routed_out=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh open routed-test 2>&1)
routed_status=$?
set -e
[[ "$routed_status" -ne 0 ]] \
    || { echo "routed mode started with an invalid allocation pool" >&2; exit 1; }
# The abort must be explained, but WHICH abort depends on the host: a machine
# without iproute2 correctly fails earlier in _require_routed_host. Accept
# either explanation; a silent failure is what must not happen.
if ! grep -qE 'subnet allocation failed|Required command not found' <<< "$routed_out"; then
    echo "routed abort printed no explanation:" >&2
    printf '%s\n' "$routed_out" >&2
    exit 1
fi
if grep -q 'devcontainer up' "$MOCK_LOG"; then
    echo "routed allocation failure still started the agent" >&2; exit 1
fi
if grep -qE '^podman run .*asf.role=routed-gateway' "$MOCK_LOG"; then
    echo "routed allocation failure still started a gateway" >&2; exit 1
fi
rm -rf "$TMP/asf/agents/routed-test"

echo "test_cli.sh: all assertions passed"
