#!/usr/bin/env bash
# Integration test — real Podman, network required, Linux only.
#
# Gated: runs only when ASF_INTEGRATION=1 and Podman exist;
# skips (exit 0) otherwise, so ./tests/run.sh stays fast by default.
#
# Uses a DUMMY provider key: asf.conf gets an explicit model list, so the
# broker skips provider discovery and never contacts the provider. No real
# credentials, no provider quota.
#
# Asserts, from inside a live agent container:
#   1. a non-allowlisted host is refused; an allowlisted one works via the proxy;
#      no route bypasses the proxy; the agent has no sudo
#   2. /workspace/sandbox/secrets is an empty tmpfs
#   3. the provider key value is absent from the agent environment
#   4. the direct provider domain (api.anthropic.com) is blocked
# And from the host afterwards: containers, secret, and network cleaned up.
set -euo pipefail

if [[ "${ASF_INTEGRATION:-0}" != "1" ]]; then
    echo "test_integration.sh: skipped (set ASF_INTEGRATION=1 to run)" >&2
    exit 0
fi
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "test_integration.sh: skipped (Linux only)" >&2
    exit 0
fi
for tool in podman python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "test_integration.sh: skipped ($tool not found)" >&2
        exit 0
    fi
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
DUMMY_KEY="asf-integration-dummy-key-$$"

cleanup() {
    ( cd "$TMP/asf" 2>/dev/null && ./sandbox.sh stop claude >/dev/null 2>&1 ) || true
    rm -rf "$TMP"
}
trap cleanup EXIT

cp -a "$ROOT/." "$TMP/asf"
cd "$TMP/asf"
rm -rf .asf/.open-lock-*
RESOURCE_PREFIX=$(PYTHONPATH="$PWD" python3 -c 'from asf.paths import RepoPaths; print(RepoPaths.for_root(".").identity.prefix, end="")')

# Broker on, explicit model list (no discovery), dummy key.
grep -v '^BROKER_ENABLED=' asf.conf > asf.conf.new
{
    echo 'BROKER_ENABLED=true'
    echo 'LITELLM_CLAUDE_MODELS="claude-integration-test"'
} >> asf.conf.new
mv asf.conf.new asf.conf
printf 'ANTHROPIC_API_KEY=%s\n' "$DUMMY_KEY" > secrets/claude.env
chmod 600 secrets/claude.env

# Test the manifest's explicit positive-control domain rather than assuming a
# hidden/global GitHub allowance. The provider domain may be removed when the
# broker is active, so verify_domain must name an effective non-provider host.
ALLOW_TEST_DOMAIN=$(PYTHONPATH="$PWD" python3 - <<'PYDOMAIN'
from asf.manifest import load_model
value = load_model("agents/claude/runtime.yml").network.verify_domain
if not value:
    raise SystemExit("claude runtime must declare network.verify_domain")
print(value)
PYDOMAIN
)

# Exercise the real ASF service-runtime path: write a test-only command into
# the copied checkout, switch only the copied Claude manifest to service mode,
# and capture its normal stdout.
CHECK_SCRIPT="$TMP/asf/tests/integration-session-checks.sh"
cat > "$CHECK_SCRIPT" <<CHECKS
#!/usr/bin/env bash
set -euo pipefail

echo "MARK:session-started"

# Not allowlisted: the proxy must refuse it.
if curl --connect-timeout 8 -s -o /dev/null https://example.com; then
    echo "MARK:FAIL example.com reachable"
else
    echo "MARK:denied-host-blocked"
fi

# Allowlisted: must work THROUGH the proxy. Without this the deny checks
# would pass trivially on a proxy that blocks everything.
if curl --connect-timeout 15 -s -o /dev/null "https://${ALLOW_TEST_DOMAIN}"; then
    echo "MARK:allowed-host-reachable"
else
    echo "MARK:FAIL allowlisted host unreachable"
fi

# No route may bypass the proxy: the agent's network has no gateway.
if env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
        curl --connect-timeout 8 -s -o /dev/null "https://${ALLOW_TEST_DOMAIN}"; then
    echo "MARK:FAIL reached the internet bypassing the proxy"
else
    echo "MARK:no-bypass"
fi

# The agent must have no sudo helper.
if command -v sudo >/dev/null 2>&1; then
    echo "MARK:FAIL sudo is present in the agent container"
else
    echo "MARK:no-sudo"
fi

fstype=\$(stat -f -c '%T' /workspace/sandbox/secrets)
entries=\$(find /workspace/sandbox/secrets -mindepth 1 | wc -l)
if [ "\$fstype" = "tmpfs" ] && [ "\$entries" -eq 0 ]; then
    echo "MARK:secrets-masked"
else
    echo "MARK:FAIL secrets not masked (fstype=\$fstype entries=\$entries)"
fi

if env | grep -qF '${DUMMY_KEY}'; then
    echo "MARK:FAIL provider key present in agent env"
else
    echo "MARK:key-absent"
fi

if curl --connect-timeout 5 -s -o /dev/null https://api.anthropic.com; then
    echo "MARK:FAIL direct provider domain reachable"
else
    echo "MARK:provider-blocked"
fi
CHECKS
chmod 0755 "$CHECK_SCRIPT"

python3 - <<'PYMANIFEST'
from pathlib import Path

path = Path("agents/claude/runtime.yml")
text = path.read_text()
old = "runtime:\n  mode: interactive\n"
new = (
    "runtime:\n"
    "  mode: service\n"
    "  command: [bash, /workspace/sandbox/tests/integration-session-checks.sh]\n"
)
if text.count(old) != 1:
    raise SystemExit("could not patch the copied Claude runtime for integration")
path.write_text(text.replace(old, new, 1))
PYMANIFEST

# Validate the modified manifest before spending time on a real image/session.
python3 -m asf.manifest agents/claude/runtime.yml >/dev/null

echo "test_integration.sh: opening a real claude session (this builds the image)..."

set +e
session_output=$(./sandbox.sh open claude 2>&1)
open_status=$?
set -e

if (( open_status != 0 )); then
    echo "test_integration.sh: sandbox.sh open exited with status ${open_status}" >&2
fi

fail=0
if (( open_status != 0 )); then
    fail=1
fi
for mark in session-started denied-host-blocked allowed-host-reachable no-bypass \
            no-sudo secrets-masked key-absent provider-blocked; do
    if ! grep -q "MARK:${mark}" <<< "$session_output"; then
        echo "test_integration.sh: missing MARK:${mark}" >&2
        fail=1
    fi
done
if grep -q "MARK:FAIL" <<< "$session_output"; then
    grep "MARK:FAIL" <<< "$session_output" >&2
    fail=1
fi

# Teardown must retain and parse the real Caddy JSON shape. The agent's
# requests count; ASF startup probes are tagged and excluded.
if ! evidence_output=$(PYTHONPATH="$PWD" python3 - "$ALLOW_TEST_DOMAIN" <<'PYEVIDENCE'
import json
import sys
from pathlib import Path

from asf.egress_evidence import load_evidence_history
from asf.paths import RepoPaths

allowed = sys.argv[1]
paths = RepoPaths.for_root(".")
history = load_evidence_history(paths, "claude")
if len(history) != 1:
    raise SystemExit(f"expected one egress history record, found {len(history)}")
evidence = history[0]
if evidence.allowlisted_connects.get(allowed, 0) < 1:
    raise SystemExit(f"agent allowlisted CONNECT missing for {allowed}")
if evidence.denied_connects.get("example.com", 0) < 1:
    raise SystemExit("agent denied CONNECT missing for example.com")
if evidence.denied_connects.get("api.anthropic.com", 0) < 1:
    raise SystemExit("agent denied CONNECT missing for api.anthropic.com")
if evidence.ignored_probe_connects < 1:
    raise SystemExit("startup verification CONNECTs were not identified")
directory = paths.session_artifact("claude", "evidence", evidence.session_id)
if not (directory / "summary.json").is_file():
    raise SystemExit("egress summary.json was not retained")
if not any(path.name.startswith("caddy-access") for path in directory.iterdir()):
    raise SystemExit("raw Caddy access log was not retained")
print(json.dumps(evidence.to_json_dict(), sort_keys=True))
PYEVIDENCE
); then
    echo "test_integration.sh: egress evidence assertion failed" >&2
    fail=1
fi

if ! advice=$(./sandbox.sh advise claude 2>&1); then
    echo "test_integration.sh: advise command failed" >&2
    printf '%s\n' "$advice" >&2
    fail=1
elif ! grep -q "1 recorded session; window 12" <<< "$advice"; then
    echo "test_integration.sh: advise did not consume retained evidence" >&2
    printf '%s\n' "$advice" >&2
    fail=1
fi

# Host-side: session exit must have removed all ephemeral resources.
if [[ -n "$(podman ps -aq --filter "label=asf.sandbox=$TMP/asf" 2>/dev/null)" ]]; then
    echo "test_integration.sh: broker container not cleaned up" >&2
    fail=1
fi
if podman secret ls --format '{{.Name}}' 2>/dev/null \
        | grep -q "^${RESOURCE_PREFIX}-claude-provider-"; then
    echo "test_integration.sh: provider secret not cleaned up" >&2
    fail=1
fi
for network in \
    "${RESOURCE_PREFIX}-claude-internal" \
    "${RESOURCE_PREFIX}-claude-egress" \
    "${RESOURCE_PREFIX}-claude-provider"; do
    if podman network inspect "$network" >/dev/null 2>&1; then
        echo "test_integration.sh: network not cleaned up: $network" >&2
        fail=1
    fi
done

if (( fail )); then
    echo "test_integration.sh: FAILED — full session output follows" >&2
    [[ -n "${evidence_output:-}" ]] && printf 'evidence: %s\n' "$evidence_output" >&2
    printf '%s\n' "$session_output" >&2
    exit 1
fi
echo "test_integration.sh: all assertions passed"
