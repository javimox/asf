#!/usr/bin/env bash
# Comparative evidence only. Tinyproxy is not supported by ASF.
#
# Verify whether a forward proxy enforces hostname and destination-port policy
# on BOTH HTTP proxy paths:
#   1. CONNECT tunnelling
#   2. ordinary plain-HTTP forwarding
#
# The suite uses local target containers and records factual target-side hits.
# Tinyproxy is a mandatory positive control in the default "both" mode: its
# known plain-HTTP port bypass must be detected before the Caddy verdict is
# considered trustworthy.
#
# Usage:
#   bash tests/experiments/compare-tinyproxy-caddy.sh
#   PROXY=caddy bash tests/experiments/compare-tinyproxy-caddy.sh
#   PROXY=tinyproxy bash tests/experiments/compare-tinyproxy-caddy.sh
#   bash tests/experiments/compare-tinyproxy-caddy.sh --clean

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SCRIPT_DIR="$ROOT"
# Reuse the exact production Caddy build inputs. The policy itself remains a
# controlled test policy because the local target deliberately has a private
# address; private-address rejection is covered separately by
# spike-caddy-private-resolution.sh.
ALPINE_RUNTIME_IMAGE=$(PYTHONPATH="$ROOT" python3 -m asf.proxy image-info --field alpine) || exit 1

P=asf-pathspike
IMAGE_REV=v2
TARGET_IMAGE="${P}/target:${IMAGE_REV}"
TINY_IMAGE="${P}/tiny:${IMAGE_REV}"
CADDY_IMAGE=$(PYTHONPATH="$ROOT" python3 -m asf.proxy image-info --field tag) \
    || exit 1
PROXY_SEL="${PROXY:-both}"

PASS=0
FAIL=0
SKIP=0
CONTROL_OK=unknown
SUITE_VALID=1
TMP=""

ok()   { echo "  ✓ $*"; PASS=$((PASS + 1)); }
bad()  { echo "  ✗ $*"; FAIL=$((FAIL + 1)); }
skip() { echo "  – $*"; SKIP=$((SKIP + 1)); }
hdr()  { echo; echo "── $* ─────────────────────────────────────"; }

cleanup_runtime() {
    podman rm -f "${P}-proxy" "${P}-allowed" "${P}-denied" >/dev/null 2>&1 || true
    podman network rm -f "${P}-internal" "${P}-egress" >/dev/null 2>&1 || true
    [[ -n "${TMP:-}" ]] && rm -rf "$TMP"
}

clean_all() {
    cleanup_runtime
    # The Caddy image is shared with the production lifecycle and is kept.
    podman rmi -f \
        "$TINY_IMAGE" "$TARGET_IMAGE" \
        "${P}/tiny:latest" "${P}/target:latest" \
        >/dev/null 2>&1 || true
}

trap cleanup_runtime EXIT INT TERM

command -v podman >/dev/null || { echo "podman not found"; exit 1; }

if [[ "${1:-}" == "--clean" ]]; then
    clean_all
    echo "cleaned containers, networks, and spike images"
    exit 0
fi

case "$PROXY_SEL" in
    caddy|tinyproxy|both) ;;
    *) echo "PROXY must be caddy|tinyproxy|both"; exit 1 ;;
esac

TMP=$(mktemp -d)
echo "podman: $(podman --version)"

# ── target/client image ─────────────────────────────────────────────────────
# The same image is used as:
#   * target: listeners on 80/443/9000 that append HIT:<port>
#   * client: command override with full curl and OpenBSD nc
build_target() {
    if podman image exists "$TARGET_IMAGE"; then
        ok "using cached target/client image"
        return 0
    fi

    mkdir -p "$TMP/target"
    cat > "$TMP/target/Containerfile" <<'EOF_TARGET'
FROM __ALPINE_RUNTIME_IMAGE__
RUN apk add --no-cache curl netcat-openbsd
RUN printf '%s\n' '#!/bin/sh' \
    'touch /tmp/hits' \
    'for p in 80 443 9000; do' \
    '  ( while true; do' \
    '      printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok" | nc -l -p "$p" >/dev/null 2>&1' \
    '      echo "HIT:$p" >> /tmp/hits' \
    '    done ) &' \
    'done' \
    'wait' > /run.sh && chmod +x /run.sh
CMD ["/run.sh"]
EOF_TARGET
    sed -i "s|__ALPINE_RUNTIME_IMAGE__|${ALPINE_RUNTIME_IMAGE}|" \
        "$TMP/target/Containerfile"

    if timeout 300 podman build -q -t "$TARGET_IMAGE" "$TMP/target" >/dev/null 2>&1; then
        ok "built target/client image (curl, nc; listeners on 80/443/9000)"
    else
        bad "target/client image build failed"
        return 1
    fi
}

# ── Caddy + forwardproxy ────────────────────────────────────────────────────
build_caddy() {
    mkdir -p "$TMP/caddy"
    cat > "$TMP/caddy/Caddyfile" <<EOF_CADDYFILE
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
                # Test-only: the controlled target uses a private address.
                allow ${P}-allowed
                deny all
            }
        }
    }
}
EOF_CADDYFILE

    if podman image exists "$CADDY_IMAGE"; then
        ok "using production caddy+forwardproxy image"
        return 0
    fi

    PYTHONPATH="$ROOT" python3 -m asf.proxy write-image-files --directory "$TMP/caddy"
    echo "  … building caddy with forwardproxy (xcaddy; first run may take a few minutes)"
    if timeout 900 podman build -q -t "$CADDY_IMAGE" "$TMP/caddy" >"$TMP/caddy-build.log" 2>&1; then
        ok "built production caddy+forwardproxy image"
    else
        bad "caddy build failed — last lines:"
        tail -20 "$TMP/caddy-build.log" | sed 's/^/      /'
        return 1
    fi
}

# ── Tinyproxy positive control ──────────────────────────────────────────────
build_tiny() {
    if podman image exists "$TINY_IMAGE"; then
        ok "using cached tinyproxy control image"
        return 0
    fi

    mkdir -p "$TMP/tiny"
    cat > "$TMP/tiny/Containerfile" <<'EOF_TINY_IMAGE'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache tinyproxy netcat-openbsd
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY filter /etc/tinyproxy/filter
ENTRYPOINT []
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
EOF_TINY_IMAGE

    cat > "$TMP/tiny/tinyproxy.conf" <<'EOF_TINY_CONF'
Port 3128
Listen 0.0.0.0
Timeout 60
Filter "/etc/tinyproxy/filter"
FilterDefaultDeny Yes
FilterExtended On
ConnectPort 443
Allow 10.0.0.0/8
Allow 172.16.0.0/12
Allow 192.168.0.0/16
LogLevel Info
EOF_TINY_CONF

    printf '^%s$\n' "${P}-allowed" > "$TMP/tiny/filter"

    if timeout 300 podman build -q -t "$TINY_IMAGE" "$TMP/tiny" >/dev/null 2>&1; then
        ok "built tinyproxy image (positive control)"
    else
        bad "tinyproxy build failed"
        return 1
    fi
}

# ── observation helpers ─────────────────────────────────────────────────────
hits_for() {
    local who="$1"
    podman exec "${P}-${who}" cat /tmp/hits 2>/dev/null || true
}

reset_hits() {
    podman exec "${P}-allowed" sh -c ': > /tmp/hits' >/dev/null 2>&1 || return 1
    podman exec "${P}-denied"  sh -c ': > /tmp/hits' >/dev/null 2>&1 || return 1
}

reached() {
    local who="$1" port="$2"
    hits_for "$who" | grep -q "^HIT:${port}$"
}

wait_for_hit() {
    local who="$1" port="$2" i
    for ((i = 0; i < 30; i++)); do
        reached "$who" "$port" && return 0
        sleep 0.1
    done
    return 1
}

proxy_running() {
    [[ "$(podman inspect -f '{{.State.Running}}' "${P}-proxy" 2>/dev/null || true)" == "true" ]]
}

# Run a command in a throwaway client container. Results are stored globally.
CLIENT_RC=0
CLIENT_OUT=""
run_client() {
    local command="$1"
    CLIENT_OUT=$(timeout 20 podman run --rm \
        --network "${P}-internal" \
        "$TARGET_IMAGE" sh -c "$command" 2>&1)
    CLIENT_RC=$?
}

curl_connect() {
    local proxy="$1" host="$2" port="$3"
    run_client "curl --silent --show-error --max-time 6 \
        --proxy http://${proxy} --proxytunnel \
        --output /dev/null --write-out 'HTTP_CODE:%{http_code}\\n' \
        http://${host}:${port}/ 2>&1"
}

curl_plain() {
    local proxy="$1" host="$2" port="$3"
    run_client "curl --silent --show-error --max-time 6 \
        --proxy http://${proxy} \
        --output /dev/null --write-out 'HTTP_CODE:%{http_code}\\n' \
        http://${host}:${port}/ 2>&1"
}

client_http_code() {
    sed -n 's/.*HTTP_CODE:\([0-9][0-9][0-9]\).*/\1/p' <<<"$CLIENT_OUT" | tail -n1
}

explicit_proxy_denial() {
    local code
    code=$(client_http_code)
    [[ "$code" == "403" ]] || grep -Eqi \
        'CONNECT tunnel failed, response 403|403 Forbidden|proxy[^[:alnum:]]+403|proxying refused' \
        <<<"$CLIENT_OUT"
}

show_client_failure() {
    echo "      client rc: $CLIENT_RC"
    if [[ -n "$CLIENT_OUT" ]]; then
        sed 's/^/      /' <<<"$CLIENT_OUT"
    else
        echo "      client output: <empty>"
    fi
}

verify_denied() {
    local who="$1" port="$2" description="$3"

    sleep 0.4
    if reached "$who" "$port"; then
        bad "$description REACHED the target"
        return 1  # policy bypass
    fi
    if ! proxy_running; then
        bad "$description did not reach the target, but the proxy crashed"
        return 2  # infrastructure failure
    fi
    if ! explicit_proxy_denial; then
        bad "$description produced no target hit, but no explicit proxy 403"
        show_client_failure
        return 3  # inconclusive client/proxy outcome
    fi

    ok "$description blocked with explicit proxy denial"
    return 0
}

start_proxy() {
    local impl="$1" image="$2" i
    local -a mounts=() tmpfs=(--tmpfs /tmp:rw,nosuid,nodev,size=16m)

    if [[ "$impl" == caddy ]]; then
        _format_caddy_config "$TMP/caddy" "$image"
        mounts+=(--mount "type=bind,src=$TMP/caddy/Caddyfile,dst=/etc/caddy/Caddyfile,ro=true")
        tmpfs+=(--mount type=tmpfs,dst=/config,tmpfs-size=4194304,tmpfs-mode=0700,U=true --mount type=tmpfs,dst=/data,tmpfs-size=4194304,tmpfs-mode=0700,U=true)
        if ! podman run --rm --network none --read-only \
            "${mounts[@]}" "${tmpfs[@]}" \
            "$image" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
            >"$TMP/caddy-validate.log" 2>&1; then
            bad "$impl generated policy did not validate"
            tail -20 "$TMP/caddy-validate.log" | sed 's/^/      /'
            return 1
        fi
    else
        tmpfs+=(--tmpfs /var/log/tinyproxy:rw,nosuid,nodev,size=16m)
    fi

    podman rm -f "${P}-proxy" >/dev/null 2>&1 || true
    if ! podman run -d --name "${P}-proxy" \
        --network "${P}-internal" \
        --network "${P}-egress" \
        --read-only \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        "${tmpfs[@]}" \
        "${mounts[@]}" \
        "$image" >/dev/null 2>&1; then
        bad "$impl failed to start"
        return 1
    fi

    for ((i = 0; i < 30; i++)); do
        if timeout 5 podman exec "${P}-proxy" sh -c 'nc -z 127.0.0.1 3128' >/dev/null 2>&1; then
            ok "$impl listening on :3128"
            return 0
        fi
        if ! proxy_running; then
            break
        fi
        sleep 1
    done

    bad "$impl never listened — its log:"
    podman logs --tail 30 "${P}-proxy" 2>&1 | sed 's/^/      /'
    return 1
}

# ── identical request matrix per proxy ──────────────────────────────────────
declare -A RESULT_HOSTS RESULT_PORTS RESULT_PLAIN

run_matrix() {
    local impl="$1"
    local proxy="${P}-proxy:3128"
    local allowed="${P}-allowed"
    local denied="${P}-denied"

    hdr "[$impl] A. CONNECT allowed host :443 (baseline)"
    reset_hits || { bad "could not reset target hit records"; return 1; }
    curl_connect "$proxy" "$allowed" 443
    if wait_for_hit allowed 443 && [[ "$CLIENT_RC" -eq 0 ]] && [[ "$(client_http_code)" == "200" ]]; then
        ok "CONNECT :443 reached the allowed target and returned HTTP 200"
    else
        bad "CONNECT :443 baseline failed — later results are not trustworthy"
        show_client_failure
        RESULT_HOSTS[$impl]=inconclusive
        RESULT_PORTS[$impl]=inconclusive
        if [[ "$impl" == "tinyproxy" ]]; then
            CONTROL_OK=no
            SUITE_VALID=0
        fi
        return 1
    fi

    hdr "[$impl] B. CONNECT allowed host :9000 (CONNECT port ACL)"
    reset_hits
    curl_connect "$proxy" "$allowed" 9000
    verify_denied allowed 9000 "CONNECT :9000"
    case $? in
        0) : ;;
        1) RESULT_PORTS[$impl]=bypassable ;;
        *) RESULT_PORTS[$impl]=inconclusive ;;
    esac

    hdr "[$impl] C. plain HTTP allowed host :443 (path capability)"
    reset_hits
    curl_plain "$proxy" "$allowed" 443
    if wait_for_hit allowed 443 && [[ "$CLIENT_RC" -eq 0 ]] && [[ "$(client_http_code)" == "200" ]]; then
        ok "plain HTTP forwarding is supported on an allowed port"
        RESULT_PLAIN[$impl]=supported
    else
        verify_denied allowed 443 "plain HTTP :443"
        case $? in
            0)
                ok "proxy is CONNECT-only by construction"
                RESULT_PLAIN[$impl]=refused
                ;;
            *)
                RESULT_PLAIN[$impl]=inconclusive
                ;;
        esac
    fi

    hdr "[$impl] D. plain HTTP allowed host :9000 (port bypass check)"
    reset_hits
    curl_plain "$proxy" "$allowed" 9000
    if wait_for_hit allowed 9000; then
        if [[ "$impl" == "tinyproxy" ]]; then
            ok "positive control detected: tinyproxy allowed plain HTTP :9000"
            RESULT_PORTS[$impl]=bypassable
            CONTROL_OK=yes
        else
            bad "plain HTTP :9000 REACHED the target — port policy bypassed"
            RESULT_PORTS[$impl]=bypassable
        fi
    else
        if [[ "$impl" == "tinyproxy" ]]; then
            bad "positive control FAILED: tinyproxy's known plain-HTTP bypass was not detected"
            show_client_failure
            RESULT_PORTS[$impl]=unexpectedly-enforced
            CONTROL_OK=no
            SUITE_VALID=0
        else
            verify_denied allowed 9000 "plain HTTP :9000"
            case $? in
                0) RESULT_PORTS[$impl]=enforced ;;
                1) RESULT_PORTS[$impl]=bypassable ;;
                *) RESULT_PORTS[$impl]=inconclusive ;;
            esac
        fi
    fi

    hdr "[$impl] E. CONNECT denied host :443 (host ACL, CONNECT path)"
    reset_hits
    curl_connect "$proxy" "$denied" 443
    if verify_denied denied 443 "CONNECT to denied host :443"; then
        RESULT_HOSTS[$impl]=enforced
    else
        RESULT_HOSTS[$impl]=leaky-or-inconclusive
    fi

    hdr "[$impl] F. plain HTTP denied host :443 (host ACL, plain path)"
    reset_hits
    curl_plain "$proxy" "$denied" 443
    if verify_denied denied 443 "plain HTTP to denied host :443"; then
        [[ "${RESULT_HOSTS[$impl]:-}" == "enforced" ]] || RESULT_HOSTS[$impl]=leaky-or-inconclusive
    else
        RESULT_HOSTS[$impl]=leaky-or-inconclusive
    fi

    echo
    echo "  [$impl] proxy log tail:"
    timeout 10 podman logs --tail 12 "${P}-proxy" 2>&1 | sed 's/^/      /'
}

# ── build and run ────────────────────────────────────────────────────────────
hdr "Build images"
build_target || exit 1

impls=()
case "$PROXY_SEL" in
    caddy)
        build_caddy && impls=(caddy)
        ;;
    tinyproxy)
        build_tiny && impls=(tinyproxy)
        ;;
    both)
        # Build both, but run the positive control first.
        build_tiny  && impls+=(tinyproxy)
        build_caddy && impls+=(caddy)
        ;;
esac

(( ${#impls[@]} > 0 )) || { bad "no proxy image built"; exit 1; }

hdr "Networks and targets"
podman network rm -f "${P}-internal" "${P}-egress" >/dev/null 2>&1 || true
podman network create --internal "${P}-internal" >/dev/null && ok "internal network (no gateway)"
podman network create "${P}-egress" >/dev/null && ok "egress network"

podman run -d --name "${P}-allowed" --network "${P}-egress" "$TARGET_IMAGE" >/dev/null \
    && ok "allowed target started" || { bad "allowed target failed"; exit 1; }
podman run -d --name "${P}-denied" --network "${P}-egress" "$TARGET_IMAGE" >/dev/null \
    && ok "denied target started" || { bad "denied target failed"; exit 1; }
sleep 1

for impl in "${impls[@]}"; do
    if [[ "$impl" == "caddy" && "$PROXY_SEL" == "both" && "$CONTROL_OK" != "yes" ]]; then
        skip "Caddy matrix skipped because the Tinyproxy positive control was not valid"
        RESULT_HOSTS[$impl]=untested
        RESULT_PORTS[$impl]=untested
        continue
    fi

    hdr "═══ $impl ═══"
    case "$impl" in
        caddy)
            start_proxy caddy "$CADDY_IMAGE" || continue
            ;;
        tinyproxy)
            if ! start_proxy tinyproxy "$TINY_IMAGE"; then
                CONTROL_OK=no
                SUITE_VALID=0
                continue
            fi
            ;;
    esac
    run_matrix "$impl" || true
done

hdr "Summary"
printf "  %-12s %-18s %-18s %s\n" "proxy" "plain HTTP" "host ACL" "port restriction"
for impl in "${impls[@]}"; do
    printf "  %-12s %-18s %-18s %s\n" \
        "$impl" \
        "${RESULT_PLAIN[$impl]:-untested}" \
        "${RESULT_HOSTS[$impl]:-untested}" \
        "${RESULT_PORTS[$impl]:-untested}"
done

echo
if [[ "$PROXY_SEL" == "both" || "$PROXY_SEL" == "tinyproxy" ]]; then
    case "$CONTROL_OK" in
        yes) echo "  Positive control: VALID — Tinyproxy's known bypass was detected." ;;
        no)  echo "  Positive control: FAILED — all other proxy verdicts are inconclusive." ;;
        *)   echo "  Positive control: NOT COMPLETED." ;;
    esac
else
    echo "  Positive control: not run; the Caddy-only verdict is provisional."
fi

echo
echo "  passed: $PASS   failed: $FAIL   skipped: $SKIP"

if (( FAIL > 0 )) || (( SUITE_VALID == 0 )); then
    exit 1
fi
