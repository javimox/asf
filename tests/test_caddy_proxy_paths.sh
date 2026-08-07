#!/usr/bin/env bash
# Verify Caddy hostname and port policy on CONNECT and plain-HTTP paths.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ALPINE_RUNTIME_IMAGE=$(PYTHONPATH="$ROOT" python3 -m asf.proxy image-info --field alpine) || exit 1
P="asf-caddy-paths-$$"
TARGET_IMAGE="asf-caddy-paths/target:v1"
CADDY_IMAGE=$(PYTHONPATH="$ROOT" python3 -m asf.proxy image-info --field tag) \
    || exit 1
TMP=$(mktemp -d)
PASS=0
FAIL=0
CLIENT_RC=0
CLIENT_OUT=""

ok() { echo "  ✓ $*"; PASS=$((PASS + 1)); }
bad() { echo "  ✗ $*"; FAIL=$((FAIL + 1)); }
hdr() { echo; echo "── $* ─────────────────────────────────────"; }

cleanup() {
    podman rm -f "${P}-proxy" "${P}-allowed" "${P}-denied" >/dev/null 2>&1 || true
    podman network rm -f "${P}-internal" "${P}-egress" >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

command -v podman >/dev/null || { echo "podman not found"; exit 1; }

build_target() {
    if podman image exists "$TARGET_IMAGE"; then
        ok "using cached target/client image"
        return 0
    fi

    mkdir -p "$TMP/target"
    cat > "$TMP/target/Containerfile" <<'TARGET'
FROM __ALPINE_RUNTIME_IMAGE__
RUN apk add --no-cache curl netcat-openbsd
RUN printf '%s\n' '#!/bin/sh' \
    'touch /tmp/hits' \
    'for p in 443 9000; do' \
    '  ( while true; do' \
    '      printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok" | nc -l -p "$p" >/dev/null 2>&1' \
    '      echo "HIT:$p" >> /tmp/hits' \
    '    done ) &' \
    'done' \
    'wait' > /run.sh && chmod +x /run.sh
CMD ["/run.sh"]
TARGET
    sed -i "s|__ALPINE_RUNTIME_IMAGE__|${ALPINE_RUNTIME_IMAGE}|" "$TMP/target/Containerfile"
    if timeout 300 podman build -q -t "$TARGET_IMAGE" "$TMP/target" >/dev/null 2>&1; then
        ok "built target/client image"
    else
        bad "target/client image build failed"
        return 1
    fi
}

prepare_caddy() {
    mkdir -p "$TMP/caddy"
    cat > "$TMP/caddy/Caddyfile" <<EOF_CADDY
{
    admin off
    servers {
        protocols h1
    }
}

:3128 {
    route {
        forward_proxy {
            ports 443
            acl {
                allow ${P}-allowed
                deny all
            }
        }
    }
}
EOF_CADDY

    if ! podman image exists "$CADDY_IMAGE"; then
        PYTHONPATH="$ROOT" python3 -m asf.proxy write-image-files --directory "$TMP/caddy"
        echo "  … building Caddy with forwardproxy"
        if ! timeout 900 podman build -q -t "$CADDY_IMAGE" "$TMP/caddy" \
                >"$TMP/caddy-build.log" 2>&1; then
            bad "Caddy build failed"
            tail -20 "$TMP/caddy-build.log" | sed 's/^/      /'
            return 1
        fi
        ok "built production Caddy image"
    else
        ok "using production Caddy image"
    fi

    PYTHONPATH="$ROOT" python3 -m asf.proxy format-file --directory "$TMP/caddy" --image "$CADDY_IMAGE" || return 1
    if ! podman run --rm --network none --read-only \
        --mount "type=bind,src=$TMP/caddy/Caddyfile,dst=/etc/caddy/Caddyfile,ro=true" \
        --tmpfs /tmp:rw,nosuid,nodev,size=16m \
        --mount type=tmpfs,dst=/config,tmpfs-size=4194304,tmpfs-mode=0700,U=true \
        --mount type=tmpfs,dst=/data,tmpfs-size=4194304,tmpfs-mode=0700,U=true \
        "$CADDY_IMAGE" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
        >"$TMP/caddy-validate.log" 2>&1; then
        bad "generated Caddy policy did not validate"
        tail -20 "$TMP/caddy-validate.log" | sed 's/^/      /'
        return 1
    fi
}

start_topology() {
    podman network create --internal "${P}-internal" >/dev/null || return 1
    podman network create "${P}-egress" >/dev/null || return 1
    podman run -d --name "${P}-allowed" --network "${P}-egress" "$TARGET_IMAGE" >/dev/null || return 1
    podman run -d --name "${P}-denied" --network "${P}-egress" "$TARGET_IMAGE" >/dev/null || return 1
    podman run -d --name "${P}-proxy" \
        --network "${P}-internal" \
        --network "${P}-egress" \
        --read-only --cap-drop=ALL --security-opt=no-new-privileges \
        --tmpfs /tmp:rw,nosuid,nodev,size=16m \
        --mount type=tmpfs,dst=/config,tmpfs-size=4194304,tmpfs-mode=0700,U=true \
        --mount type=tmpfs,dst=/data,tmpfs-size=4194304,tmpfs-mode=0700,U=true \
        --mount "type=bind,src=$TMP/caddy/Caddyfile,dst=/etc/caddy/Caddyfile,ro=true" \
        "$CADDY_IMAGE" >/dev/null || return 1

    local i
    for ((i = 0; i < 30; i++)); do
        if podman exec "${P}-proxy" caddy version >/dev/null 2>&1 && \
           podman run --rm --network "${P}-internal" "$TARGET_IMAGE" \
               nc -z -w 1 "${P}-proxy" 3128 >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

reset_hits() {
    podman exec "${P}-allowed" sh -c ': > /tmp/hits' >/dev/null 2>&1 || return 1
    podman exec "${P}-denied" sh -c ': > /tmp/hits' >/dev/null 2>&1 || return 1
}

reached() {
    local target="$1" port="$2"
    podman exec "${P}-${target}" cat /tmp/hits 2>/dev/null | grep -q "^HIT:${port}$"
}

wait_for_hit() {
    local target="$1" port="$2" i
    for ((i = 0; i < 30; i++)); do
        reached "$target" "$port" && return 0
        sleep 0.1
    done
    return 1
}

run_client() {
    local command="$1"
    CLIENT_OUT=$(timeout 20 podman run --rm --network "${P}-internal" \
        "$TARGET_IMAGE" sh -c "$command" 2>&1)
    CLIENT_RC=$?
}

curl_connect() {
    local host="$1" port="$2"
    run_client "curl --silent --show-error --max-time 6 \
        --proxy http://${P}-proxy:3128 --proxytunnel \
        --output /dev/null --write-out 'HTTP_CODE:%{http_code}\\n' \
        http://${host}:${port}/ 2>&1"
}

curl_plain() {
    local host="$1" port="$2"
    run_client "curl --silent --show-error --max-time 6 \
        --proxy http://${P}-proxy:3128 \
        --output /dev/null --write-out 'HTTP_CODE:%{http_code}\\n' \
        http://${host}:${port}/ 2>&1"
}

http_code() {
    sed -n 's/.*HTTP_CODE:\([0-9][0-9][0-9]\).*/\1/p' <<<"$CLIENT_OUT" | tail -n1
}

explicit_403() {
    [[ "$(http_code)" == 403 ]] || grep -Eqi \
        'CONNECT tunnel failed, response 403|403 Forbidden|proxy[^[:alnum:]]+403' \
        <<<"$CLIENT_OUT"
}

show_failure() {
    echo "      client rc: $CLIENT_RC"
    [[ -n "$CLIENT_OUT" ]] && sed 's/^/      /' <<<"$CLIENT_OUT"
}

expect_allowed() {
    local path="$1" target="$2" port="$3" description="$4"
    reset_hits || return 1
    if [[ "$path" == connect ]]; then
        curl_connect "${P}-${target}" "$port"
    else
        curl_plain "${P}-${target}" "$port"
    fi
    if wait_for_hit "$target" "$port" && [[ "$CLIENT_RC" -eq 0 ]] && [[ "$(http_code)" == 200 ]]; then
        ok "$description"
    else
        bad "$description"
        show_failure
    fi
}

expect_denied() {
    local path="$1" target="$2" port="$3" description="$4"
    reset_hits || return 1
    if [[ "$path" == connect ]]; then
        curl_connect "${P}-${target}" "$port"
    else
        curl_plain "${P}-${target}" "$port"
    fi
    sleep 0.4
    if reached "$target" "$port"; then
        bad "$description reached the target"
    elif ! explicit_403; then
        bad "$description did not return explicit proxy 403"
        show_failure
    else
        ok "$description"
    fi
}

hdr "Build"
build_target || exit 1
prepare_caddy || exit 1

hdr "Topology"
if start_topology; then
    ok "Caddy and controlled targets started"
else
    bad "could not start Caddy test topology"
    podman logs --tail 30 "${P}-proxy" 2>&1 | sed 's/^/      /' || true
    exit 1
fi

hdr "CONNECT path"
expect_allowed connect allowed 443 "allowlisted host on port 443 reached"
expect_denied connect allowed 9000 "allowlisted host on port 9000 denied"
expect_denied connect denied 443 "undeclared host on port 443 denied"

hdr "Plain-HTTP path"
expect_allowed plain allowed 443 "allowlisted host on port 443 reached"
expect_denied plain allowed 9000 "allowlisted host on port 9000 denied"
expect_denied plain denied 443 "undeclared host on port 443 denied"

hdr "Verdict"
echo "  passed: $PASS"
echo "  failed: $FAIL"
(( FAIL == 0 )) || exit 1
echo "  RESULT: CADDY PATH POLICY PROVEN"
