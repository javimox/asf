#!/usr/bin/env bash
# Live krun + Caddy proxy integration test. Opt-in because it requires
# KVM/libkrun, Podman, and external HTTPS connectivity on the host.
set -euo pipefail

if [[ "${ASF_KRUN_PROXY_INTEGRATION:-0}" != "1" ]]; then
    echo "test_krun_proxy_integration.sh: skipped (set ASF_KRUN_PROXY_INTEGRATION=1)"
    exit 0
fi
if [[ "$(uname -s)" != Linux ]]; then
    echo "test_krun_proxy_integration.sh: skipped (Linux only)"
    exit 0
fi
for tool in podman krun python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "test_krun_proxy_integration.sh: skipped ($tool not found)"
        exit 0
    }
done
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    echo "test_krun_proxy_integration.sh: skipped (/dev/kvm is not usable)"
    exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
RUNTIME=krun-proxy-integration
ALLOWED=example.com
BLOCKED=example.org

cleanup() {
    (cd "$TMP/asf" 2>/dev/null && ./sandbox.sh stop "$RUNTIME" >/dev/null 2>&1) || true
    rm -rf "$TMP"
}
trap cleanup EXIT

cp -a "$ROOT/." "$TMP/asf"
mkdir -p "$TMP/asf/agents/$RUNTIME"

cat >> "$TMP/asf/asf.conf" <<'EOF_CONF'
BROKER_ENABLED=false
EOF_CONF

cat > "$TMP/asf/agents/$RUNTIME/runtime.yml" <<EOF_MANIFEST
name: $RUNTIME
adapter: generic
runtime:
  mode: service
  isolation: microvm
  command: ["bash", "/workspace/sandbox/tests/runtime-krun-proxy-checks.sh"]
network:
  mode: proxy
  verify_domain: $ALLOWED
  allow_domains:
    - $ALLOWED
llm:
  broker: false
EOF_MANIFEST

cat > "$TMP/asf/agents/$RUNTIME/repos.yml" <<'EOF_REPOS'
repos: []
EOF_REPOS

cat > "$TMP/asf/tests/runtime-krun-proxy-checks.sh" <<EOF_CHECKS
#!/usr/bin/env bash
set -euo pipefail

test "\${ASF_ISOLATION:-}" = microvm
test -z "\${DEVCONTAINER+x}"
test "\$(id -u)" -eq 1000
test "\$(id -g)" -eq 1000
test -n "\${ASF_PROXY:-}"
test "\${HTTP_PROXY:-}" = "\${ASF_PROXY}"
test "\${HTTPS_PROXY:-}" = "\${ASF_PROXY}"
echo MARK:krun-proxy-runtime

# Positive control: the allowlisted HTTPS destination must work through Caddy.
if curl --connect-timeout 10 --max-time 20 -fsS "https://$ALLOWED" >/dev/null; then
    echo MARK:krun-proxy-allowed
else
    echo 'MARK:FAIL allowlisted HTTPS failed through Caddy' >&2
    exit 1
fi

# The same destination must not be reachable when all proxy variables are
# removed. --noproxy is included explicitly so curl cannot use an inherited
# proxy configuration from elsewhere.
if env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
       -u ALL_PROXY -u all_proxy \
       curl --noproxy '*' --connect-timeout 3 --max-time 5 \
       -fsS "https://$ALLOWED" >/dev/null 2>&1; then
    echo 'MARK:FAIL direct HTTPS bypassed Caddy' >&2
    exit 1
fi
echo MARK:krun-proxy-no-bypass

# A destination outside the manifest allowlist must be rejected by Caddy.
if curl --connect-timeout 8 --max-time 12 -fsS "https://$BLOCKED" >/dev/null 2>&1; then
    echo 'MARK:FAIL non-allowlisted HTTPS passed through Caddy' >&2
    exit 1
fi
echo MARK:krun-proxy-blocked
EOF_CHECKS
chmod 0755 "$TMP/asf/tests/runtime-krun-proxy-checks.sh"

set +e
output=$(cd "$TMP/asf" && ./sandbox.sh open "$RUNTIME" 2>&1)
status=$?
set -e
if (( status != 0 )); then
    echo "test_krun_proxy_integration.sh: FAILED" >&2
    printf '%s\n' "$output" >&2
    exit "$status"
fi

for marker in \
    krun-proxy-runtime krun-proxy-allowed krun-proxy-no-bypass \
    krun-proxy-blocked; do
    grep -q "MARK:${marker}" <<< "$output" || {
        echo "test_krun_proxy_integration.sh: missing MARK:${marker}" >&2
        printf '%s\n' "$output" >&2
        exit 1
    }
done
if grep -q 'MARK:FAIL' <<< "$output"; then
    grep 'MARK:FAIL' <<< "$output" >&2
    exit 1
fi

# Teardown retains Caddy evidence. Require the successful guest request to have
# traversed Caddy, require the blocked request to have reached and been denied
# by Caddy, and make sure ASF's startup verification is classified separately.
if ! evidence_output=$(cd "$TMP/asf" && PYTHONPATH="$TMP/asf" python3 - "$RUNTIME" "$ALLOWED" "$BLOCKED" <<'PY'
import json
import sys

from asf.egress_evidence import load_evidence_history
from asf.paths import RepoPaths

runtime, allowed, blocked = sys.argv[1:]
paths = RepoPaths.for_root('.')
history = load_evidence_history(paths, runtime)
if len(history) != 1:
    raise SystemExit(f"expected one egress history record, found {len(history)}")
evidence = history[0]
if evidence.allowlisted_connects.get(allowed, 0) < 1:
    raise SystemExit(f"agent allowlisted CONNECT missing for {allowed}")
if evidence.denied_connects.get(blocked, 0) < 1:
    raise SystemExit(f"agent denied CONNECT missing for {blocked}")
if evidence.ignored_probe_connects < 1:
    raise SystemExit("startup verification CONNECTs were not identified")
print(json.dumps(evidence.to_json_dict(), sort_keys=True))
PY
); then
    echo "test_krun_proxy_integration.sh: Caddy evidence assertion failed" >&2
    printf '%s\n' "${evidence_output:-}" >&2
    printf '%s\n' "$output" >&2
    exit 1
fi

# All ephemeral proxy/runtime/network resources must be gone when the service
# command exits and ASF completes teardown.
if [[ -n "$(podman ps -aq --filter "label=asf.sandbox=$TMP/asf" 2>/dev/null)" ]]; then
    echo "test_krun_proxy_integration.sh: session containers were not cleaned up" >&2
    exit 1
fi

printf 'test_krun_proxy_integration.sh: all assertions passed\n'
