#!/usr/bin/env bash
# Real routed-mode integration test against a reachable external target.
set -euo pipefail

if [[ "${ASF_INTEGRATION:-0}" != 1 ]]; then
    echo "test_routed_integration.sh: skipped (set ASF_INTEGRATION=1)"
    exit 0
fi
if [[ "$(uname -s)" != Linux ]]; then
    echo "test_routed_integration.sh: skipped (Linux only)"
    exit 0
fi
for tool in podman python3 flock; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "test_routed_integration.sh: skipped ($tool not found)"
        exit 0
    }
done
if [[ -z "${ASF_ROUTED_TARGET_IP:-}" || -z "${ASF_ROUTED_ALLOWED_PORT:-}" || \
      -z "${ASF_ROUTED_BLOCKED_PORT:-}" ]]; then
    echo "test_routed_integration.sh: skipped"
    echo "  Set ASF_ROUTED_TARGET_IP, ASF_ROUTED_ALLOWED_PORT, and ASF_ROUTED_BLOCKED_PORT."
    exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
cleanup() {
    (cd "$TMP/asf" 2>/dev/null && ./sandbox.sh stop routed-integration >/dev/null 2>&1) || true
    rm -rf "$TMP"
}
trap cleanup EXIT
cp -a "$ROOT/." "$TMP/asf"
RESOURCE_PREFIX=$(cd "$TMP/asf" && PYTHONPATH="$PWD" python3 -c 'from asf.paths import RepoPaths; print(RepoPaths.for_root(".").identity.prefix, end="")')

TARGET_CIDR="${ASF_ROUTED_TARGET_CIDR:-${ASF_ROUTED_TARGET_IP}/32}"
cat >> "$TMP/asf/asf.conf" <<'EOF'
BROKER_ENABLED=false
EOF
mkdir -p "$TMP/asf/agents/routed-integration"
cat > "$TMP/asf/agents/routed-integration/runtime.yml" <<EOF
name: routed-integration
adapter: generic
runtime:
  mode: service
  command: ["bash", "/workspace/sandbox/tests/runtime-routed-checks.sh"]
network:
  mode: routed
  allow:
    - cidr: ${TARGET_CIDR}
      protocol: tcp
      ports: [${ASF_ROUTED_ALLOWED_PORT}]
  verify:
    address: ${ASF_ROUTED_TARGET_IP}
    protocol: tcp
    port: ${ASF_ROUTED_ALLOWED_PORT}
    blocked_port: ${ASF_ROUTED_BLOCKED_PORT}
llm:
  broker: false
EOF

cat > "$TMP/asf/tests/runtime-routed-checks.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
echo MARK:routed-session-started
nc -z -w 8 ${ASF_ROUTED_TARGET_IP} ${ASF_ROUTED_ALLOWED_PORT}
echo MARK:routed-allowed-reachable
if nc -z -w 8 ${ASF_ROUTED_TARGET_IP} ${ASF_ROUTED_BLOCKED_PORT}; then
    echo "blocked port was reachable" >&2
    exit 1
fi
echo MARK:routed-blocked-denied
test -z "\$(ip -4 route show default)"
echo MARK:routed-no-default
python3 - <<'PY'
values = {
    line.split()[0].rstrip(':'): int(line.split()[1], 16)
    for line in open('/proc/self/status')
    if line.startswith(('CapEff:', 'CapBnd:'))
}
raise SystemExit(0 if values == {'CapEff': 0, 'CapBnd': 0} else 1)
PY
echo MARK:routed-no-capabilities
EOF
chmod 755 "$TMP/asf/tests/runtime-routed-checks.sh"

set +e
output=$(cd "$TMP/asf" && ./sandbox.sh open routed-integration 2>&1)
status=$?
set -e
if (( status != 0 )); then
    echo "test_routed_integration.sh: FAILED" >&2
    printf '%s\n' "$output" >&2
    exit "$status"
fi
for marker in \
    routed-session-started routed-allowed-reachable routed-blocked-denied \
    routed-no-default routed-no-capabilities; do
    grep -q "MARK:${marker}" <<< "$output" || {
        echo "test_routed_integration.sh: missing MARK:${marker}" >&2
        printf '%s\n' "$output" >&2
        exit 1
    }
done
for lifecycle_mark in \
    "Routed gateway ready" \
    "NET_ADMIN initializer exited" \
    "Routed policy verified"; do
    grep -q "$lifecycle_mark" <<< "$output" || {
        echo "test_routed_integration.sh: missing lifecycle evidence: $lifecycle_mark" >&2
        printf '%s\n' "$output" >&2
        exit 1
    }
done

if [[ -n "$(podman ps -aq --filter "label=asf.sandbox=$TMP/asf" 2>/dev/null)" ]]; then
    echo "test_routed_integration.sh: containers not cleaned up" >&2
    exit 1
fi
for network in \
    "${RESOURCE_PREFIX}-routed-integration-internal" \
    "${RESOURCE_PREFIX}-routed-integration-scan" \
    "${RESOURCE_PREFIX}-routed-integration-routed-egress"; do
    if podman network inspect "$network" >/dev/null 2>&1; then
        echo "test_routed_integration.sh: network not cleaned up: $network" >&2
        exit 1
    fi
done

if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
    reservation_dir="${XDG_RUNTIME_DIR}/asf-subnets"
else
    reservation_dir="/tmp/asf-subnets-$(id -u)"
fi
reservation_file=$(python3 - "$reservation_dir" \
    "${RESOURCE_PREFIX}-routed-integration" <<'PY_RESERVATION'
import hashlib
import sys
from pathlib import Path

directory = Path(sys.argv[1])
digest = hashlib.sha256(sys.argv[2].encode()).hexdigest()[:24]
print(directory / f"{digest}.json")
PY_RESERVATION
)
if [[ -e "$reservation_file" ]]; then
    echo "test_routed_integration.sh: subnet reservation not released" >&2
    exit 1
fi

printf '\n── External routed lifecycle ─────────────────────────────────────\n'
printf '  target: %s (%s)\n' "$ASF_ROUTED_TARGET_IP" "$TARGET_CIDR"
printf '  ✓ allowed TCP %s reached\n' "$ASF_ROUTED_ALLOWED_PORT"
printf '  ✓ known-open TCP %s denied by routed policy\n' "$ASF_ROUTED_BLOCKED_PORT"
printf '  ✓ runtime has no IPv4 default route\n'
printf '  ✓ runtime effective and bounding capabilities are zero\n'
printf '  ✓ capability-less gateway ready; NET_ADMIN initializer exited\n'
printf '  ✓ containers, networks, and subnet reservation cleaned up\n'

echo "test_routed_integration.sh: all assertions passed"
