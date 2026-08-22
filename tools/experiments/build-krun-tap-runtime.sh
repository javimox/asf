#!/usr/bin/env bash
set -euo pipefail

# Build a private crun binary that exposes libkrun's TAP backend through one
# experimental OCI annotation:
#
#   krun.tap_name=<tap-device>
#
# Nothing is installed system-wide. The resulting binary lives below
# tools/experiments/.krun-tap-runtime/. ASF's routed microVM path uses this
# private runtime; isolated/proxy krun sessions keep using the normal runtime.

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CRUN_VERSION=1.29.1
CRUN_COMMIT=f0d911de5587342cfeb16473bf32ecdfeaf25957
WORK=${CRUN_TAP_WORK:-"$ROOT/tools/experiments/.krun-tap-build"}
PREFIX=${CRUN_TAP_PREFIX:-"$ROOT/tools/experiments/.krun-tap-runtime"}
SRC="$WORK/crun"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'missing build dependency: %s\n' "$1" >&2
        exit 1
    }
}

for cmd in git autoconf automake libtoolize pkg-config make gcc python3; do
    need "$cmd"
done

if ! pkg-config --exists libkrun 2>/dev/null && [[ ! -r /usr/include/libkrun.h ]]; then
    cat >&2 <<'MSG'
libkrun development headers were not found.
Install the development files matching the libkrun used by your krun runtime,
then rerun this script. The installed libkrun must export krun_add_net_tap().
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

rm -rf "$WORK"
mkdir -p "$WORK"
git init -q "$SRC"
git -C "$SRC" remote add origin https://github.com/containers/crun.git
git -C "$SRC" fetch --quiet --depth 1 origin \
    "refs/tags/$CRUN_VERSION:refs/tags/$CRUN_VERSION"
git -C "$SRC" checkout --quiet --detach "$CRUN_VERSION"
git -C "$SRC" submodule update --init --recursive --depth 1

commit=$(git -C "$SRC" rev-parse HEAD)
if [[ $commit != "$CRUN_COMMIT" ]]; then
    printf 'unexpected crun commit: %s\n' "$commit" >&2
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
    raise SystemExit("crun source layout changed: libkrun network declaration not found exactly once")
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
    raise SystemExit("crun source layout changed: passt branch not found exactly once in libkrun_configure_vm")

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

make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
rm -rf "$PREFIX"
make install >/dev/null

printf '\nprivate TAP-capable crun built at:\n  %s/bin/crun\n' "$PREFIX"
version_output=$("$PREFIX/bin/crun" --version)
printf '%s\n' "$version_output"
printf '%s\n' "$version_output" | grep -F "crun version $CRUN_VERSION" >/dev/null || {
    printf 'unexpected crun version output; expected %s\n' "$CRUN_VERSION" >&2
    exit 1
}
