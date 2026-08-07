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
bash "$ROOT/tests/spike-caddy-private-resolution.sh"
bash "$ROOT/tests/spike-gateway-caps.sh"

if [[ "${ASF_RUN_DESIGN_SPIKES:-0}" == 1 ]]; then
    bash "$ROOT/tests/experiments/spike-gateway.sh"
fi

if [[ -n "${ASF_ROUTED_TARGET_IP:-}" && \
      -n "${ASF_ROUTED_ALLOWED_PORT:-}" && \
      -n "${ASF_ROUTED_BLOCKED_PORT:-}" ]]; then
    bash "$ROOT/tests/test_routed_integration.sh"
else
    echo "run-host.sh: external routed test skipped"
    echo "  Start tools/routed_test_target.py on the target and set:"
    echo "  ASF_ROUTED_TARGET_IP, ASF_ROUTED_ALLOWED_PORT, ASF_ROUTED_BLOCKED_PORT"
fi

if [[ "${ASF_RUN_LEGACY_ROUTED_SPIKES:-0}" == 1 ]]; then
    : "${ASF_ROUTED_TARGET_IP:?set ASF_ROUTED_TARGET_IP}"
    : "${ASF_ROUTED_TARGET_CIDR:?set ASF_ROUTED_TARGET_CIDR}"
    : "${ASF_ROUTED_ALLOWED_PORT:?set ASF_ROUTED_ALLOWED_PORT}"
    : "${ASF_ROUTED_BLOCKED_PORT:?set ASF_ROUTED_BLOCKED_PORT}"
    : "${ASF_ROUTED_ALLOWED_UDP:?set ASF_ROUTED_ALLOWED_UDP}"
    : "${ASF_ROUTED_BLOCKED_UDP:?set ASF_ROUTED_BLOCKED_UDP}"
    TARGET_IP="$ASF_ROUTED_TARGET_IP" \
    TARGET_ROUTE="$ASF_ROUTED_TARGET_CIDR" \
    ALLOWED_TCP="$ASF_ROUTED_ALLOWED_PORT" \
    BLOCKED_TCP="$ASF_ROUTED_BLOCKED_PORT" \
    ALLOWED_UDP="$ASF_ROUTED_ALLOWED_UDP" \
    BLOCKED_UDP="$ASF_ROUTED_BLOCKED_UDP" \
        bash "$ROOT/tests/experiments/spike-rootless-gateway-stage2.sh"
    TARGET_IP="$ASF_ROUTED_TARGET_IP" \
    TARGET_ROUTE="$ASF_ROUTED_TARGET_CIDR" \
    ALLOWED_TCP="$ASF_ROUTED_ALLOWED_PORT" \
    BLOCKED_TCP="$ASF_ROUTED_BLOCKED_PORT" \
    ALLOWED_UDP="$ASF_ROUTED_ALLOWED_UDP" \
    BLOCKED_UDP="$ASF_ROUTED_BLOCKED_UDP" \
        bash "$ROOT/tests/experiments/spike-combined-internal-routed-v2.sh"
fi

echo "run-host.sh: all requested host tests passed"
