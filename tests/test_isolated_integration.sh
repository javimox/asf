#!/usr/bin/env bash
# Real isolated-mode lifecycle test.
set -euo pipefail

if [[ "${ASF_INTEGRATION:-0}" != 1 ]]; then
    echo "test_isolated_integration.sh: skipped (set ASF_INTEGRATION=1)"
    exit 0
fi
if [[ "$(uname -s)" != Linux ]]; then
    echo "test_isolated_integration.sh: skipped (Linux only)"
    exit 0
fi
for tool in podman python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "test_isolated_integration.sh: skipped ($tool not found)"
        exit 0
    }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
cleanup() {
    (cd "$TMP/asf" 2>/dev/null && ./sandbox.sh stop isolated-integration >/dev/null 2>&1) || true
    rm -rf "$TMP"
}
trap cleanup EXIT
cp -a "$ROOT/." "$TMP/asf"
RESOURCE_PREFIX=$(cd "$TMP/asf" && PYTHONPATH="$PWD" python3 -c 'from asf.paths import RepoPaths; print(RepoPaths.for_root(".").identity.prefix, end="")')

cat >> "$TMP/asf/asf.conf" <<'EOF_CONF'
BROKER_ENABLED=false
EOF_CONF
mkdir -p "$TMP/asf/agents/isolated-integration"
cat > "$TMP/asf/agents/isolated-integration/runtime.yml" <<'EOF_MANIFEST'
name: isolated-integration
adapter: generic
runtime:
  mode: service
  command: ["bash", "/workspace/sandbox/tests/runtime-isolated-checks.sh"]
network:
  mode: isolated
llm:
  broker: false
EOF_MANIFEST

cat > "$TMP/asf/tests/runtime-isolated-checks.sh" <<'EOF_CHECKS'
#!/usr/bin/env bash
set -euo pipefail

echo MARK:isolated-session-started
test -z "$(ip -4 route show default)"
echo MARK:isolated-no-ipv4-default
test -z "$(ip -6 route show default)"
echo MARK:isolated-no-ipv6-default
if ip -4 route get 1.1.1.1 >/dev/null 2>&1; then
    echo 'MARK:FAIL isolated public route exists'
    exit 1
fi
echo MARK:isolated-no-public-route
if getent ahostsv4 example.com >/dev/null 2>&1; then
    echo 'MARK:FAIL isolated external DNS works'
    exit 1
fi
echo MARK:isolated-no-external-dns
python3 - <<'PY'
values = {
    line.split()[0].rstrip(':'): int(line.split()[1], 16)
    for line in open('/proc/self/status')
    if line.startswith(('CapEff:', 'CapBnd:'))
}
raise SystemExit(0 if values == {'CapEff': 0, 'CapBnd': 0} else 1)
PY
echo MARK:isolated-no-capabilities
test "$(stat -f -c %T /workspace/sandbox/secrets)" = tmpfs
test -z "$(find /workspace/sandbox/secrets -mindepth 1 -print -quit)"
echo MARK:isolated-secrets-masked
EOF_CHECKS
chmod 0755 "$TMP/asf/tests/runtime-isolated-checks.sh"

set +e
output=$(cd "$TMP/asf" && ./sandbox.sh open isolated-integration 2>&1)
status=$?
set -e
if (( status != 0 )); then
    echo "test_isolated_integration.sh: FAILED" >&2
    printf '%s\n' "$output" >&2
    exit "$status"
fi
for marker in \
    isolated-session-started isolated-no-ipv4-default isolated-no-ipv6-default \
    isolated-no-public-route isolated-no-external-dns isolated-no-capabilities \
    isolated-secrets-masked; do
    grep -q "MARK:${marker}" <<< "$output" || {
        echo "test_isolated_integration.sh: missing MARK:${marker}" >&2
        printf '%s\n' "$output" >&2
        exit 1
    }
done
if grep -q 'MARK:FAIL' <<< "$output"; then
    grep 'MARK:FAIL' <<< "$output" >&2
    exit 1
fi
if [[ -n "$(podman ps -aq --filter "label=asf.sandbox=$TMP/asf" 2>/dev/null)" ]]; then
    echo "test_isolated_integration.sh: containers not cleaned up" >&2
    exit 1
fi
network="${RESOURCE_PREFIX}-isolated-integration-internal"
if podman network inspect "$network" >/dev/null 2>&1; then
    echo "test_isolated_integration.sh: network not cleaned up: $network" >&2
    exit 1
fi

echo "test_isolated_integration.sh: all assertions passed"
