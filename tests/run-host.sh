#!/usr/bin/env bash
# Real Podman security tests for the current host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export ASF_INTEGRATION=1

bash "$ROOT/tests/test_session_discovery_host.sh"
bash "$ROOT/tests/test_stop_host.sh"
bash "$ROOT/tests/test_reset_host.sh"
bash "$ROOT/tests/test_integration.sh"
bash "$ROOT/tests/test_isolated_integration.sh"
bash "$ROOT/tests/test_caddy_proxy_paths.sh"
bash "$ROOT/tests/test_caddy_private_resolution.sh"

if [[ -n "${ASF_ROUTED_TARGET_IP:-}" && \
      -n "${ASF_ROUTED_ALLOWED_PORT:-}" && \
      -n "${ASF_ROUTED_BLOCKED_PORT:-}" ]]; then
    bash "$ROOT/tests/test_routed_integration.sh"
else
    echo "run-host.sh: external routed test skipped"
    echo "  Start tests/helpers/routed_test_target.py on the target and set:"
    echo "  ASF_ROUTED_TARGET_IP, ASF_ROUTED_ALLOWED_PORT, ASF_ROUTED_BLOCKED_PORT"
fi

echo "run-host.sh: all requested host tests passed"
