#!/usr/bin/env bash
set -euo pipefail

# Verify the locally installed TAP-capable crun against ASF's pinned release.
#
# The repository ships only source and provenance (VERSION, COMMIT); the
# executable is built locally by build.sh into tools/krun-runtime/bin/. This
# check fails closed when that install is missing, stale relative to the pin,
# or inconsistent with its own recorded checksum.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME_DIR="$ROOT/tools/krun-runtime"
INSTALL=${1:-"$RUNTIME_DIR/bin"}

pinned_version=$(<"$RUNTIME_DIR/VERSION")
pinned_commit=$(<"$RUNTIME_DIR/COMMIT")

for file in VERSION COMMIT SHA256SUMS crun; do
    [[ -f "$INSTALL/$file" ]] || {
        cat >&2 <<MSG
local TAP-capable crun install is missing $file: $INSTALL
Build it with: tools/krun-runtime/build.sh
MSG
        exit 1
    }
done

local_version=$(<"$INSTALL/VERSION")
local_commit=$(<"$INSTALL/COMMIT")

if [[ $local_version != "$pinned_version" || $local_commit != "$pinned_commit" ]]; then
    cat >&2 <<MSG
local TAP-capable crun does not match ASF's pinned release.
  pinned:  $pinned_version ($pinned_commit)
  local:   $local_version ($local_commit)
If upstream published a new release, review it, update
tools/krun-runtime/{VERSION,COMMIT} together, then rebuild.
Otherwise rebuild the pin: tools/krun-runtime/build.sh
MSG
    exit 1
fi

[[ -x "$INSTALL/crun" ]] || {
    printf 'local crun is not executable: %s/crun\n' "$INSTALL" >&2
    exit 1
}

(
    cd "$INSTALL"
    sha256sum --check --strict --quiet SHA256SUMS
)

version_output=$("$INSTALL/crun" --version)
printf '%s\n' "$version_output" | grep -F "commit: $pinned_commit" >/dev/null || {
    printf 'local crun does not report expected commit %s\n' "$pinned_commit" >&2
    exit 1
}

printf '✓ local TAP-capable crun matches pinned release %s (%s)\n' \
    "$pinned_version" "$pinned_commit"
