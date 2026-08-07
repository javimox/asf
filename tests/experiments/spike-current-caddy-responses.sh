#!/usr/bin/env bash
# Diagnostic spike: exercise the exact Caddy and probe images selected by this
# checkout. Unlike ad-hoc image discovery, this cannot accidentally test a
# stale localhost/asf-proxy-caddy tag left by an older ASF candidate.
set -euo pipefail

ENGINE="${ENGINE:-podman}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
NET="asf-current-caddy-spike-$$"
CADDY="asf-current-caddy-spike-$$"
DIR="$(mktemp -d)"

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
CADDY_IMAGE="$(python3 -c 'from asf.proxy import caddy_image_tag; print(caddy_image_tag())')"
PROBE_IMAGE="$(python3 - "$ROOT" <<'PY'
import sys
from asf.paths import RepoPaths
print(RepoPaths.for_root(sys.argv[1]).identity.probe_image("v2"))
PY
)"

cleanup() {
    "$ENGINE" rm -f "$CADDY" >/dev/null 2>&1 || true
    "$ENGINE" network rm -f "$NET" >/dev/null 2>&1 || true
    rm -rf "$DIR"
}
trap cleanup EXIT

for image in "$CADDY_IMAGE" "$PROBE_IMAGE"; do
    if ! "$ENGINE" image exists "$image"; then
        echo "required image is absent: $image" >&2
        echo "run ./sandbox.sh open claude once from this checkout first" >&2
        exit 1
    fi
done

python3 - "$DIR/Caddyfile" <<'PY'
import sys
from pathlib import Path
from asf.proxy import render_caddyfile
Path(sys.argv[1]).write_text(render_caddyfile(("statsig.com",)), encoding="utf-8")
PY

"$ENGINE" network create --internal "$NET" >/dev/null
"$ENGINE" run -d --name "$CADDY" --network "$NET" \
    --network-alias asf-proxy \
    --mount "type=bind,src=$DIR/Caddyfile,dst=/etc/caddy/Caddyfile,ro=true" \
    "$CADDY_IMAGE" >/dev/null
sleep 2

if ! "$ENGINE" container exists "$CADDY"; then
    echo "Caddy container was not created" >&2
    exit 1
fi
if ! "$ENGINE" ps --format '{{.Names}}' | grep -qx "$CADDY"; then
    echo "Caddy failed to stay running:" >&2
    "$ENGINE" logs "$CADDY" 2>&1 | tail -30 >&2
    exit 1
fi

printf 'podman: %s\n' \
    "$("$ENGINE" version --format '{{.Client.Version}} / server {{.Server.Version}}' 2>/dev/null || "$ENGINE" --version)"
echo "caddy image: $CADDY_IMAGE"
echo "probe image: $PROBE_IMAGE"

probe() {
    local request="$1"
    printf '%s' "$request" | timeout 40 "$ENGINE" run --rm --network "$NET" \
        --read-only --tmpfs /tmp:rw,nosuid,nodev,size=4m \
        --cap-drop=ALL --security-opt=no-new-privileges \
        --pids-limit=32 --memory=64m -i \
        "$PROBE_IMAGE" nc -q 1 -w 6 asf-proxy 3128 2>/dev/null \
        | tr -d '\r'
}

status() {
    probe "$1" | awk '/^HTTP\/[0-9.]+ [0-9][0-9][0-9]/{print $2; exit}'
}

PLAIN_FORBIDDEN=$'GET http://statsig.com:9000/ HTTP/1.1\r\nHost: statsig.com:9000\r\nConnection: close\r\n\r\n'
PLAIN_ALLOWED=$'GET http://statsig.com:443/ HTTP/1.1\r\nHost: statsig.com:443\r\nConnection: close\r\n\r\n'
CONNECT_ALLOWED=$'CONNECT statsig.com:443 HTTP/1.1\r\nHost: statsig.com:443\r\nConnection: close\r\n\r\n'
CONNECT_DENIED=$'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nConnection: close\r\n\r\n'

plain_forbidden="$(status "$PLAIN_FORBIDDEN" || true)"
plain_allowed="$(status "$PLAIN_ALLOWED" || true)"
connect_allowed="$(status "$CONNECT_ALLOWED" || true)"
connect_denied="$(status "$CONNECT_DENIED" || true)"

printf '%-38s %s\n' 'plain HTTP, forbidden port:' "${plain_forbidden:-<none>}"
printf '%-38s %s\n' 'plain HTTP, allowed host:443:' "${plain_allowed:-<none>}"
printf '%-38s %s\n' 'CONNECT, allowed host:' "${connect_allowed:-<none>}"
printf '%-38s %s\n' 'CONNECT, denied host:' "${connect_denied:-<none>}"

[[ "$plain_forbidden" == 403 ]]
[[ "$plain_allowed" == 403 ]]
[[ "$connect_allowed" == 200 ]]
if [[ "$connect_denied" != 403 && "$connect_denied" != 407 ]]; then
    echo "CONNECT denial is not explicit; HTTP ${connect_denied:-<none>} is not accepted as proof of policy denial." >&2
    exit 2
fi
