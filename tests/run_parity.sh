#!/usr/bin/env bash
# Run independent parity files concurrently without interleaving their output.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
pids=()
names=()
cleanup() {
    local pid
    for pid in "${pids[@]}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    for pid in "${pids[@]}"; do
        wait "$pid" >/dev/null 2>&1 || true
    done
    rm -rf "$TMP"
}
trap cleanup EXIT

for path in "$ROOT"/tests/parity/test_*.py; do
    name=$(basename "$path" .py)
    names+=("$name")
    (
        cd "$ROOT"
        PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v "tests.parity.${name}"
    ) >"$TMP/${name}.log" 2>&1 &
    pids+=("$!")
done

failed=0
for index in "${!pids[@]}"; do
    name=${names[$index]}
    if ! wait "${pids[$index]}"; then
        failed=1
    fi
    cat "$TMP/${name}.log"
done

exit "$failed"
