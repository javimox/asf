#!/usr/bin/env bash
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "tests require bash >= 4 (macOS: brew install bash)." >&2
    exit 1
fi
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_STATE_HOME=$(mktemp -d)
trap 'rm -rf "$TEST_STATE_HOME"' EXIT
export XDG_STATE_HOME="$TEST_STATE_HOME"
export ASF_TEST_STATE_GUARD="$TEST_STATE_HOME"

bash -n \
    "$ROOT/sandbox.sh" \
    "$ROOT"/containers/*.sh \
    "$ROOT"/agents/*/setup.sh \
    "$ROOT"/tests/*.sh \
    "$ROOT"/tests/lib/*.sh \
    "$ROOT"/tools/krun-runtime/*.sh

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck --severity=warning --external-sources \
        "$ROOT/sandbox.sh" \
        "$ROOT"/containers/*.sh \
        "$ROOT"/agents/*/setup.sh \
        "$ROOT"/tests/*.sh \
        "$ROOT"/tests/lib/*.sh \
        "$ROOT"/tools/krun-runtime/*.sh
else
    echo "shellcheck not found; skipping local static shell analysis" >&2
fi

python3 -m unittest discover -s "$ROOT/tests" -p 'test_*.py' -v
bash "$ROOT/tests/run_reference.sh"
python3 -m compileall -q "$ROOT/asf" "$ROOT/tools" "$ROOT/tests"
# Run each shell suite explicitly so a failure names the file that failed
# (bare `[[ ]]` assertions exit silently under set -e).
for suite in \
    test_cli test_open_lifecycle test_broker_cli test_proxy_config \
    test_proxy_cli test_security_cli test_routed_shell test_guard \
    test_broker_enabled_open test_runtime_state \
    test_integration test_isolated_integration test_routed_integration \
    test_krun_integration test_krun_proxy_integration; do
    if "$ROOT/tests/${suite}.sh"; then
        echo "✓ ${suite}.sh"
    else
        echo "✗ ${suite}.sh FAILED (exit $?)" >&2
        exit 1
    fi
done

echo "→ Verifying the SBOM matches the tree"
python3 "$ROOT/tools/generate_sbom.py" --check || {
    echo "✗ SBOM is stale — run: python3 tools/generate_sbom.py" >&2
    exit 1
}

echo "All test suites passed."
