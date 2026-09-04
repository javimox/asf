#!/usr/bin/env bash
# Live krun smoke test. Opt-in because it requires KVM/libkrun and a
# networked image build on the host running the suite.
set -euo pipefail

if [[ "${ASF_KRUN_INTEGRATION:-0}" != "1" ]]; then
    echo "test_krun_integration.sh: skipped (set ASF_KRUN_INTEGRATION=1)"
    exit 0
fi
if [[ "$(uname -s)" != Linux ]]; then
    echo "test_krun_integration.sh: skipped (Linux only)"
    exit 0
fi
for tool in podman krun python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "test_krun_integration.sh: skipped ($tool not found)"
        exit 0
    }
done
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    echo "test_krun_integration.sh: skipped (/dev/kvm is not usable)"
    exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
RUNTIME=krun-integration
REPO="$TMP/repo"

cleanup() {
    (cd "$TMP/asf" 2>/dev/null && ./sandbox.sh stop "$RUNTIME" >/dev/null 2>&1) || true
    rm -rf "$TMP"
}
trap cleanup EXIT

cp -a "$ROOT/." "$TMP/asf"
mkdir -p "$REPO" "$TMP/asf/agents/$RUNTIME"

cat >> "$TMP/asf/asf.conf" <<'EOF_CONF'
BROKER_ENABLED=false
EOF_CONF

cat > "$TMP/asf/agents/$RUNTIME/runtime.yml" <<'EOF_MANIFEST'
name: krun-integration
adapter: generic
runtime:
  mode: service
  isolation: microvm
  command: ["bash", "/workspace/sandbox/tests/runtime-krun-checks.sh"]
network:
  mode: isolated
llm:
  broker: false
EOF_MANIFEST

cat > "$TMP/asf/agents/$RUNTIME/repos.yml" <<EOF_REPOS
repos:
  - path: $REPO
    mode: rw
EOF_REPOS

cat > "$TMP/asf/tests/runtime-krun-checks.sh" <<'EOF_CHECKS'
#!/usr/bin/env bash
set -euo pipefail

test "${ASF_ISOLATION:-}" = microvm
echo MARK:krun-runtime

printf 'krun guest identity: uid=%s gid=%s\n' "$(id -u)" "$(id -g)"
grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/self/status

test "$(id -u)" -eq 1000
test "$(id -g)" -eq 1000
python3 - <<'PY'
expected_caps = {
    'CapInh': 0,
    'CapPrm': 0,
    'CapEff': 0,
    'CapBnd': 0,
    'CapAmb': 0,
}
actual_caps = {}
no_new_privs = None
for line in open('/proc/self/status'):
    key, _, value = line.partition(':')
    if key in expected_caps:
        actual_caps[key] = int(value.strip(), 16)
    elif key == 'NoNewPrivs':
        no_new_privs = int(value.strip())
raise SystemExit(
    0 if actual_caps == expected_caps and no_new_privs == 1 else 1
)
PY
echo MARK:krun-unprivileged

test -z "$(find /workspace/sandbox/secrets -mindepth 1 -print -quit)"
echo MARK:krun-secrets-masked

if curl --noproxy '*' --connect-timeout 3 -fsS https://example.com >/dev/null 2>&1; then
    echo 'MARK:FAIL isolated krun runtime reached the public internet' >&2
    exit 1
fi
echo MARK:krun-direct-egress-denied

printf 'written by krun\n' > /workspace/repos/repo/krun-write.txt
echo MARK:krun-repo-write
EOF_CHECKS
chmod 0755 "$TMP/asf/tests/runtime-krun-checks.sh"

set +e
output=$(cd "$TMP/asf" && ./sandbox.sh open "$RUNTIME" 2>&1)
status=$?
set -e
if (( status != 0 )); then
    echo "test_krun_integration.sh: FAILED" >&2
    printf '%s\n' "$output" >&2
    exit "$status"
fi

for marker in \
    krun-runtime krun-unprivileged krun-secrets-masked \
    krun-direct-egress-denied krun-repo-write; do
    grep -q "MARK:${marker}" <<< "$output" || {
        echo "test_krun_integration.sh: missing MARK:${marker}" >&2
        printf '%s\n' "$output" >&2
        exit 1
    }
done
if grep -q 'MARK:FAIL' <<< "$output"; then
    grep 'MARK:FAIL' <<< "$output" >&2
    exit 1
fi

test -f "$REPO/krun-write.txt"
[[ "$(stat -c %u "$REPO/krun-write.txt")" == "$(id -u)" ]]
[[ "$(stat -c %g "$REPO/krun-write.txt")" == "$(id -g)" ]]

echo "test_krun_integration.sh: all assertions passed"
