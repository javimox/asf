#!/usr/bin/env bash
set -euo pipefail

# Build ASF's TAP-capable crun from an upstream release.
#
# Usage:
#   tools/krun-runtime/build.sh [VERSION|latest] [OUTPUT_DIR]
#
# The output directory receives:
#   crun          built executable
#   VERSION       resolved upstream release tag
#   COMMIT        exact upstream source commit
#   SHA256SUMS    checksum for the executable
#
# The source edit is intentionally tiny and guarded. If upstream changes the
# krun networking code, the build fails instead of guessing how to patch it.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME_DIR="$ROOT/tools/krun-runtime"
PINNED_VERSION=$(<"$RUNTIME_DIR/VERSION")
PINNED_COMMIT=$(<"$RUNTIME_DIR/COMMIT")
SELECTOR=${1:-$PINNED_VERSION}
# Default install target is the path ASF resolves for routed sessions. It is
# git-ignored: the repository ships source and provenance, never the binary.
OUTPUT=${2:-"$RUNTIME_DIR/bin"}

need() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'missing build dependency: %s\n' "$1" >&2
        exit 1
    }
}

for cmd in git curl autoconf automake libtoolize pkg-config make gcc python3 strip sha256sum; do
    need "$cmd"
done

if [[ $SELECTOR == latest ]]; then
    printf 'Resolving latest upstream crun release...\n'
    auth=()
    [[ -n ${GITHUB_TOKEN:-} ]] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
    release_json=$(curl -fsSL \
        -H 'Accept: application/vnd.github+json' \
        "${auth[@]}" \
        https://api.github.com/repos/containers/crun/releases/latest)
    VERSION=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' \
        <<<"$release_json")
else
    VERSION=$SELECTOR
fi

[[ $VERSION =~ ^[0-9]+\.[0-9]+([.][0-9]+)?$ ]] || {
    printf 'unexpected crun release tag: %s\n' "$VERSION" >&2
    exit 1
}

if ! pkg-config --exists libkrun 2>/dev/null && [[ ! -r /usr/include/libkrun.h && ! -r /usr/local/include/libkrun.h ]]; then
    cat >&2 <<'MSG'
libkrun development headers were not found.
Install a libkrun 1.x development build with virtio-net enabled, then retry.
MSG
    exit 1
fi

libkrun_so=$(ldconfig -p 2>/dev/null | awk '!found && /libkrun\.so\.1/{print $NF; found=1}')
if [[ -n ${libkrun_so:-} ]] && command -v nm >/dev/null 2>&1; then
    if ! nm -D "$libkrun_so" 2>/dev/null | grep ' krun_add_net_tap$' >/dev/null; then
        printf 'installed %s does not export krun_add_net_tap\n' "$libkrun_so" >&2
        exit 1
    fi
fi

if [[ -n ${CRUN_TAP_WORK:-} ]]; then
    WORK=$CRUN_TAP_WORK
    rm -rf "$WORK"
    mkdir -p "$WORK"
else
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT
fi
SRC="$WORK/crun"
PREFIX="$WORK/prefix"

printf 'Fetching crun %s...\n' "$VERSION"
git init -q "$SRC"
git -C "$SRC" remote add origin https://github.com/containers/crun.git
git -C "$SRC" fetch --quiet --depth 1 origin \
    "refs/tags/$VERSION:refs/tags/$VERSION"
git -C "$SRC" checkout --quiet --detach "$VERSION"
git -C "$SRC" submodule update --init --recursive --depth 1

COMMIT=$(git -C "$SRC" rev-parse HEAD)
EXPECTED_COMMIT=${CRUN_EXPECT_COMMIT:-}
if [[ -z $EXPECTED_COMMIT && $SELECTOR != latest && $VERSION == "$PINNED_VERSION" ]]; then
    EXPECTED_COMMIT=$PINNED_COMMIT
fi
if [[ -n $EXPECTED_COMMIT && $COMMIT != "$EXPECTED_COMMIT" ]]; then
    printf 'unexpected crun commit for %s: %s (expected %s)\n' \
        "$VERSION" "$COMMIT" "$EXPECTED_COMMIT" >&2
    exit 1
fi

python3 - "$SRC/src/libcrun/handlers/krun.c" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()

declaration = (
    "  int32_t (*krun_add_net_unixstream) (uint32_t ctx_id, const char *c_path, int fd, "
    "uint8_t *const c_mac, uint32_t features, uint32_t flags);\n"
)
if source.count(declaration) != 1:
    raise SystemExit(
        "crun source layout changed: libkrun network declaration not found exactly once"
    )
source = source.replace(
    declaration,
    declaration
    + "  int32_t (*krun_add_net_tap) (uint32_t ctx_id, const char *c_tap_name, "
      "const uint8_t *c_mac, uint32_t features, uint32_t flags);\n"
    + "  const char *tap_name;\n",
    1,
)

configure_start = source.find("static int\nlibkrun_configure_vm ")
configure_end = source.find("static int\nlibkrun_configure_flavor ", configure_start)
if configure_start < 0 or configure_end < 0:
    raise SystemExit("crun source layout changed: libkrun_configure_vm not found")

configure_vm = source[configure_start:configure_end]
passt = "  if (kconf->use_passt)\n    {\n"
if configure_vm.count(passt) != 1:
    raise SystemExit(
        "crun source layout changed: passt branch not found exactly once in libkrun_configure_vm"
    )

tap = """  tap_name = find_annotation (container, \"krun.tap_name\");
  if (tap_name != NULL)
    {
      if (tap_name[0] == '\\0')
        return crun_make_error (err, EINVAL, \"krun.tap_name cannot be empty\");
      if (kconf->use_passt)
        return crun_make_error (err, EINVAL, \"krun.tap_name and krun.use_passt are mutually exclusive\");

      krun_add_net_tap = dlsym (handle, \"krun_add_net_tap\");
      if (krun_add_net_tap == NULL)
        return crun_make_error (err, 0, \"could not find symbol `krun_add_net_tap` in the krun library\");

      uint8_t mac[] = { 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee };
      ret = krun_add_net_tap (ctx_id, tap_name, &mac[0], COMPAT_NET_FEATURES, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, -ret, \"could not add krun TAP interface `%s`\", tap_name);
    }
  else if (kconf->use_passt)
    {
"""
configure_vm = configure_vm.replace(passt, tap, 1)
source = source[:configure_start] + configure_vm + source[configure_end:]
path.write_text(source)
PY

git -C "$SRC" --no-pager diff --check

# Keep the build tied to the source commit rather than wall-clock time. The
# output checksum records the local build; CI also tests the executable itself.
SOURCE_DATE_EPOCH=$(git -C "$SRC" show -s --format=%ct HEAD)
export SOURCE_DATE_EPOCH

cd "$SRC"
./autogen.sh >/dev/null
./configure \
    --prefix="$PREFIX" \
    --with-libkrun \
    >/dev/null

grep -qx '#define HAVE_LIBKRUN 1' config.h || {
    echo 'crun was built without libkrun support' >&2
    exit 1
}

make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >/dev/null
make install >/dev/null

rm -rf "$OUTPUT"
mkdir -p "$OUTPUT"
cp "$PREFIX/bin/crun" "$OUTPUT/crun"
strip --strip-unneeded "$OUTPUT/crun"
chmod 0755 "$OUTPUT/crun"
printf '%s\n' "$VERSION" > "$OUTPUT/VERSION"
printf '%s\n' "$COMMIT" > "$OUTPUT/COMMIT"
(
    cd "$OUTPUT"
    sha256sum crun > SHA256SUMS
)

version_output=$("$OUTPUT/crun" --version)
printf '%s\n' "$version_output"
printf '%s\n' "$version_output" | grep -F "commit: $COMMIT" >/dev/null || {
    printf 'built crun does not report expected commit %s\n' "$COMMIT" >&2
    exit 1
}

printf '\nASF TAP-capable crun candidate:\n'
printf '  version: %s\n' "$VERSION"
printf '  commit:  %s\n' "$COMMIT"
printf '  binary:  %s/crun\n' "$OUTPUT"
printf '  sha256:  %s\n' "$(cut -d' ' -f1 "$OUTPUT/SHA256SUMS")"
