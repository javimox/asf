#!/usr/bin/env bash
# Convenience entry point for the real-host stop and recovery test.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec bash "$ROOT/tests/test_stop_host.sh" "$@"
