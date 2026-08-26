#!/usr/bin/env bash
# Prove that an allowlisted hostname cannot turn proxy mode into LAN access.
# The target name is explicitly allowed but resolves to a private Podman IP;
# production ACL ordering must reject it on CONNECT and plain HTTP before the
# request reaches the target. A public CONNECT positive control prevents a
# deny-everything proxy from looking secure.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
P=asf-caddy-private-spike
PASS=0; FAIL=0; TMP=""
ok(){ echo "  ✓ $*"; PASS=$((PASS+1)); }
bad(){ echo "  ✗ $*"; FAIL=$((FAIL+1)); }
hdr(){ echo; echo "── $* ─────────────────────────────────────"; }
cleanup(){
  podman rm -f "$P-proxy" "$P-target" >/dev/null 2>&1 || true
  podman network rm -f "$P-internal" "$P-egress" >/dev/null 2>&1 || true
  [[ -z "$TMP" ]] || rm -rf "$TMP"
}
trap cleanup EXIT INT TERM
command -v podman >/dev/null || { echo "podman not found"; exit 1; }

ALPINE_RUNTIME_IMAGE=$(PYTHONPATH="$ROOT" python3 -m asf.proxy image-info --field alpine) || exit 1
TMP=$(mktemp -d)
mkdir -p "$TMP/caddy" "$TMP/target"
PYTHONPATH="$ROOT" python3 -m asf.proxy write-image-files --directory "$TMP/caddy"
PYTHONPATH="$ROOT" python3 - "$TMP/caddy/Caddyfile" <<'PY_CADDY'
from pathlib import Path
import sys

from asf.proxy import render_caddyfile

Path(sys.argv[1]).write_text(
    render_caddyfile(("allowed-private.test", "example.com")),
    encoding="utf-8",
)
PY_CADDY

cat > "$TMP/target/Containerfile" <<'EOF'
FROM __ALPINE_RUNTIME_IMAGE__
RUN apk add --no-cache netcat-openbsd
CMD ["sh", "-c", "touch /tmp/hits; while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok' | nc -l -p 443 >/dev/null 2>&1; echo HIT >>/tmp/hits; done"]
EOF
sed -i "s|__ALPINE_RUNTIME_IMAGE__|${ALPINE_RUNTIME_IMAGE}|" \
  "$TMP/target/Containerfile"

hdr "Build"
podman build -q -t "$P-caddy" "$TMP/caddy" >/dev/null 2>&1 \
  && ok "built pinned Caddy+forwardproxy image" || { bad "Caddy build failed"; exit 1; }
PYTHONPATH="$ROOT" python3 -m asf.proxy format-file --directory "$TMP/caddy" --image "$P-caddy"
podman build -q -t "$P-target-image" "$TMP/target" >/dev/null 2>&1 \
  && ok "built controlled private target" || { bad "target build failed"; exit 1; }
podman run --rm --network none --read-only \
  --mount type=tmpfs,dst=/config,tmpfs-size=4194304,tmpfs-mode=0700,U=true --mount type=tmpfs,dst=/data,tmpfs-size=4194304,tmpfs-mode=0700,U=true \
  --mount "type=bind,src=$TMP/caddy/Caddyfile,dst=/etc/caddy/Caddyfile,ro=true" \
  "$P-caddy" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
  >/dev/null 2>&1 \
  && ok "generated Caddy policy validates" || { bad "Caddy policy invalid"; exit 1; }

hdr "Topology"
podman network create --internal "$P-internal" >/dev/null \
  && ok "internal client network" || { bad "internal network failed"; exit 1; }
podman network create "$P-egress" >/dev/null \
  && ok "proxy egress network" || { bad "egress network failed"; exit 1; }
podman run -d --name "$P-target" --network "$P-egress:alias=allowed-private.test" \
  "$P-target-image" >/dev/null \
  && ok "private target started with an allowlisted DNS alias" || { bad "target failed"; exit 1; }
podman run -d --name "$P-proxy" --network "$P-internal" --network "$P-egress" \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=16m --mount type=tmpfs,dst=/config,tmpfs-size=4194304,tmpfs-mode=0700,U=true \
  --mount type=tmpfs,dst=/data,tmpfs-size=4194304,tmpfs-mode=0700,U=true \
  --mount "type=bind,src=$TMP/caddy/Caddyfile,dst=/etc/caddy/Caddyfile,ro=true" \
  "$P-caddy" >/dev/null \
  && ok "Caddy started with the production ACL template" || { bad "Caddy failed"; exit 1; }

for _ in $(seq 1 30); do
  podman exec "$P-proxy" sh -c 'nc -z 127.0.0.1 3128' >/dev/null 2>&1 && break
  sleep 1
done

run_client(){
  timeout 30 podman run --rm --network "$P-internal" "$P-target-image" sh -c "$1" 2>&1
}

hdr "Positive control"
if run_client "printf '' | nc -w 10 -q 1 -X connect -x $P-proxy:3128 example.com 443 >/dev/null"; then
  ok "public allowlisted CONNECT succeeds"
else
  bad "public positive control failed; deny verdict would be inconclusive"
fi

hdr "Private-resolution enforcement"
connect_out=$(run_client "printf '' | nc -w 8 -q 1 -X connect -x $P-proxy:3128 allowed-private.test 443" || true)
if grep -q '403' <<<"$connect_out"; then
  ok "CONNECT to allowlisted private-resolving name was explicitly denied"
else
  bad "CONNECT did not return an explicit proxy denial"
fi
plain_out=$(run_client "printf 'GET http://allowed-private.test:443/ HTTP/1.1\\r\\nHost: allowed-private.test:443\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 8 $P-proxy 3128" || true)
if grep -q '403' <<<"$plain_out"; then
  ok "plain HTTP to allowlisted private-resolving name was explicitly denied"
else
  bad "plain HTTP did not return an explicit proxy denial"
fi
sleep 0.5
if podman exec "$P-target" test ! -s /tmp/hits; then
  ok "private target observed no request"
else
  bad "private target was reached"
fi

hdr "Verdict"
echo "  passed: $PASS   failed: $FAIL"
(( FAIL == 0 ))
