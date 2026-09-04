#!/usr/bin/env bash
# Real-host Phase 3D reset acceptance using a checkout copy and test-only volumes.
set -euo pipefail

if [[ "${ASF_INTEGRATION:-0}" != 1 ]]; then
    echo "test_reset_host.sh: skipped (set ASF_INTEGRATION=1)"
    exit 0
fi
for tool in podman python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "test_reset_host.sh: skipped ($tool not found)"
        exit 0
    }
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
TARGET_RUNTIME="${1:-claude}"
OTHER_RUNTIME="hermes"
TARGET_VOLUMES=()
OTHER_VOLUME=""

cleanup() {
    (cd "$TMP/asf" 2>/dev/null && ./sandbox.sh stop "$TARGET_RUNTIME" >/dev/null 2>&1) || true
    (( ${#TARGET_VOLUMES[@]} == 0 )) || podman volume rm -f "${TARGET_VOLUMES[@]}" >/dev/null 2>&1 || true
    [[ -z "$OTHER_VOLUME" ]] || podman volume rm -f "$OTHER_VOLUME" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT

cp -a "$ROOT/." "$TMP/asf"
rm -rf "$TMP/asf/.asf/.open-lock-"*

mapfile -t TARGET_VOLUMES < <(
    PYTHONPATH="$TMP/asf" python3 - "$TMP/asf" "$TARGET_RUNTIME" <<'PY'
import sys
from asf.manifest import load_model
from asf.paths import RepoPaths

paths = RepoPaths.for_root(sys.argv[1])
runtime = sys.argv[2]
manifest = load_model(paths.identity.runtime_manifest(runtime))
for state in manifest.state_volumes:
    print(paths.identity.state_volume(runtime, state.key))
print(paths.identity.shell_history_volume(runtime))
PY
)
OTHER_VOLUME=$(
    PYTHONPATH="$TMP/asf" python3 - "$TMP/asf" "$OTHER_RUNTIME" <<'PY'
import sys
from asf.paths import RepoPaths
print(RepoPaths.for_root(sys.argv[1]).identity.shell_history_volume(sys.argv[2]))
PY
)

for volume in "${TARGET_VOLUMES[@]}" "$OTHER_VOLUME"; do
    podman volume create "$volume" >/dev/null
done

output=$(cd "$TMP/asf" && ./sandbox.sh reset "$TARGET_RUNTIME")
grep -q "Cleared all ${TARGET_RUNTIME} state" <<<"$output"
for volume in "${TARGET_VOLUMES[@]}"; do
    if podman volume inspect "$volume" >/dev/null 2>&1; then
        echo "reset left target volume behind: $volume" >&2
        exit 1
    fi
done
podman volume inspect "$OTHER_VOLUME" >/dev/null 2>&1 || {
    echo "reset removed another runtime's volume: $OTHER_VOLUME" >&2
    exit 1
}

repeat=$(cd "$TMP/asf" && ./sandbox.sh reset "$TARGET_RUNTIME")
grep -q "No persistent volumes found for ${TARGET_RUNTIME}" <<<"$repeat"

status=$(PYTHONPATH="$TMP/asf" python3 - "$TMP/asf" "$TARGET_RUNTIME" <<'PY'
import sys
from asf.paths import RepoPaths
from asf.residue import ResidueScanner
from asf.session import SessionDiscovery

paths = RepoPaths.for_root(sys.argv[1])
residue = ResidueScanner(SessionDiscovery.from_paths(paths)).scan(sys.argv[2])
print(f"{residue.empty}:{residue.inconclusive}:{len(residue.resources())}")
PY
)
[[ "$status" == "True:False:0" ]] || {
    echo "reset left session residue: $status" >&2
    exit 1
}

echo "test_reset_host.sh: all assertions passed"
