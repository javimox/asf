#!/usr/bin/env bash
# SUPERSEDED — kept as comparative evidence, not part of any test run.
#
# This is the original design-validation spike. Every question it asks has since
# been answered and is now covered by production tests:
#   Q1/Q2 (internal network has no egress, devcontainer accepts --network)
#         → asserted by tests/test_cli.sh and every real session
#   Q3/Q4 (netns sharing, capability-less container cannot alter rules)
#         → tests/spike-gateway-caps.sh
#   Phase 2 topology and both request paths
#         → tests/test_caddy_proxy_paths.sh, tests/test_*_integration.sh
#
# It also still references tinyproxy, which is no longer a production proxy.
# Run it only to reproduce the original design validation.
#
# verify-egress-topology.sh — verify the ASF egress design against real Podman.
#
# PHASE 1  mechanisms in isolation (fast, no images built)
#   Q1  devcontainer CLI accepts a network in runArgs
#   Q2  an --internal network really has no egress
#   Q3  a container can join another container's netns
#   Q4  a container WITHOUT NET_ADMIN cannot alter rules a sidecar applied
#
# PHASE 2  the full three-network topology (builds two small images)
#   T1  container-name DNS works on an --internal network
#   T2  agent has NO direct egress (no gateway)
#   T3  agent CAN reach the proxy and the broker stand-in
#   T4  allowlisted host succeeds THROUGH the proxy
#   T5  non-allowlisted host is REFUSED by the proxy
#   T6  provider API is unreachable from the agent
#   T7  SSH over CONNECT to github.com:22 works
#   T8  the broker stand-in CAN reach the internet directly
#   T9  per-port ACL on an allowlisted domain  ← decides squid vs smokescreen
#
# Phase 2 runs the identical suite against each proxy implementation:
#   PROXY=squid ./spike-network.sh --phase2
#   PROXY=smokescreen ./spike-network.sh --phase2
#   PROXY=both ./spike-network.sh --phase2        (default)
#
# Phase 2 needs working internet (builds images, contacts pypi/github).
# Everything is prefixed "asf-spike-" and removed on exit.
#
# Usage:  ./spike-network.sh            # both phases
#         ./spike-network.sh --phase1   # mechanisms only
#         ./spike-network.sh --phase2   # topology only
#         SKIP_Q1=1 ./spike-network.sh   # skip the devcontainer check
#         ./spike-network.sh --clean    # remove leftovers from a killed run
#         ./spike-network.sh --g3-help  # read g3proxy's own usage
#
# Every external call is timeboxed: nothing here can hang the script.
set -uo pipefail

P=asf-spike
BASE=docker.io/library/alpine:3.20
PASS=0; FAIL=0; SKIP=0
PHASE="${1:---all}"

ok()   { echo "  ✓ $*"; PASS=$((PASS+1)); }
bad()  { echo "  ✗ $*"; FAIL=$((FAIL+1)); }
skip() { echo "  – $*"; SKIP=$((SKIP+1)); }
hdr()  { echo; echo "── $* ─────────────────────────────────────────"; }

cleanup() {
    podman rm -f "${P}-a" "${P}-b" "${P}-netns" "${P}-proxy" "${P}-broker" \
        >/dev/null 2>&1
    # The devcontainer CLI names its containers randomly; find them by label.
    if [[ -n "${TMP:-}" ]]; then
        podman ps -aq --filter "label=devcontainer.local_folder=$TMP/dc" \
            | xargs -r podman rm -f >/dev/null 2>&1
    fi
    podman network rm -f "${P}-internal" "${P}-normal" \
        "${P}-net-internal" "${P}-net-egress" "${P}-net-provider" >/dev/null 2>&1
    podman rmi -f "${P}/agent" "${P}/squid" "${P}/smoke" "${P}/tiny" "${P}/g3" "${P}/proxy" >/dev/null 2>&1
    rm -rf "${TMP:-/nonexistent}"
}
trap cleanup EXIT INT TERM

command -v podman >/dev/null || { echo "podman not found"; exit 1; }
echo "podman: $(podman --version)"
TMP=$(mktemp -d)

# Remove then create, so a leftover network from a killed run is not reported
# as a failure. `network create` errors with "already exists", which previously
# printed ✗ even though the topology was fine.
ensure_network() {
    local name="$1"; shift
    podman network rm -f "$name" >/dev/null 2>&1
    if podman network create "$@" "$name" >/dev/null 2>&1; then
        ok "network $name"
    else
        bad "could not create network $name"
        podman network create "$@" "$name" 2>&1 | sed 's/^/      /'
    fi
}

# --clean: remove leftovers from an interrupted run and exit.
if [[ "${1:-}" == "--clean" ]]; then
    cleanup
    echo "removed any leftover asf-spike resources"
    exit 0
fi

# --g3-help: build g3proxy and print its usage, so its config schema can be
# read from the binary instead of guessed at.
if [[ "${1:-}" == "--g3-help" ]]; then
    mkdir -p "$TMP/g3h"
    cat > "$TMP/g3h/Containerfile" <<'EOF'
FROM docker.io/library/rust:1-alpine AS build
# NOTE: python3 is NOT needed once --features excludes the Python binding
# (that is what pulled in PyO3). Kept only for the --g3-help variant that
# builds with default features.
RUN apk add --no-cache git musl-dev openssl-dev openssl-libs-static pkgconfig cmake make g++ capnproto capnproto-dev c-ares-dev
# Verify every build tool BEFORE the long cargo compile: each missing
# dependency otherwise costs a full build to discover the next one.
RUN set -e; for tool in capnp cmake g++ pkg-config; do \
      command -v "$tool" >/dev/null || { echo "MISSING BUILD TOOL: $tool" >&2; exit 1; }; \
    done; capnp --version
WORKDIR /src
RUN git clone --depth 1 https://github.com/bytedance/g3.git .
# Select the required features explicitly. The final fallback previously used
# --no-default-features without a rustls provider, which always triggers the
# compile_error! in g3proxy/src/main.rs. Disabling Lua, Python and QUIC also
# makes this spike build substantially smaller and faster.
RUN cargo build --release -p g3proxy \
    --no-default-features \
    --features "rustls-ring,c-ares"
FROM docker.io/library/alpine:3.20
# g3proxy links dynamically against the Alpine OpenSSL and c-ares libraries.
RUN apk add --no-cache ca-certificates libgcc openssl c-ares
COPY --from=build /src/target/release/g3proxy /usr/local/bin/g3proxy
EOF
    echo "building g3proxy (Rust, slow) …"
    timeout 1800 podman build -t "${P}/g3-help" "$TMP/g3h" 2>&1 | tail -20 || exit 1
    echo
    echo "════ g3proxy --help ════"
    timeout 30 podman run --rm "${P}/g3-help" g3proxy --help 2>&1
    podman rmi -f "${P}/g3-help" >/dev/null 2>&1
    exit 0
fi

# --smoke-help: print smokescreen's own flags and ACL expectations. Faster than
# guessing at its config format from the outside.
if [[ "${1:-}" == "--smoke-help" ]]; then
    mkdir -p "$TMP/smoke"
    cat > "$TMP/smoke/Containerfile" <<'EOF'
FROM docker.io/library/golang:1.23-alpine AS build
RUN apk add --no-cache git
RUN go install github.com/stripe/smokescreen@latest
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/smokescreen /usr/local/bin/smokescreen
EOF
    echo "building smokescreen (no ACL) …"
    timeout 420 podman build -q -t "${P}/smoke-help" "$TMP/smoke" >/dev/null 2>&1         || { echo "build failed"; exit 1; }
    echo
    echo "════ smokescreen --help ════"
    timeout 30 podman run --rm "${P}/smoke-help" smokescreen --help 2>&1
    echo
    echo "════ flags mentioning role / acl / tls ════"
    timeout 30 podman run --rm "${P}/smoke-help" smokescreen --help 2>&1 | grep -iE 'role|acl|tls|cert|missing|deny|allow' || echo "(none matched)"
    podman rmi -f "${P}/smoke-help" >/dev/null 2>&1
    exit 0
fi

# ═════════════════════════ PHASE 1 ═════════════════════════════════════════
run_phase1() {
podman image exists "$BASE" || podman pull -q "$BASE" >/dev/null

hdr "Q2  --internal network egress"
ensure_network "${P}-internal" --internal
ensure_network "${P}-normal"

if timeout 30 podman run --rm --network "${P}-internal" "$BASE" \
        timeout 5 ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
    bad "internal network HAS egress (topology would not enforce)"
else
    ok "internal network has NO egress"
fi
if timeout 30 podman run --rm --network "${P}-normal" "$BASE" \
        timeout 5 ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
    ok "normal network has egress (control case)"
else
    skip "normal network has no egress either — host may block ICMP"
fi

hdr "Q3  join another container's netns"
podman run -d --name "${P}-netns" --network "${P}-normal" \
    "$BASE" sleep 300 >/dev/null 2>&1 \
    && ok "started netns-holder" || bad "could not start netns holder"
if timeout 30 podman run --rm --network "container:${P}-netns" "$BASE" ip addr >/dev/null 2>&1; then
    ok "second container joined the first's netns"
else
    bad "--network container:<name> not supported here"
fi

hdr "Q4  NET_ADMIN-less container cannot alter shared-netns rules"
if timeout 60 podman run --rm --network "container:${P}-netns" --cap-add=NET_ADMIN "$BASE" \
        sh -c 'apk add -q iptables >/dev/null 2>&1;
               iptables -A OUTPUT -d 192.0.2.1 -j DROP' >/dev/null 2>&1; then
    ok "sidecar WITH NET_ADMIN applied a rule"
    if timeout 60 podman run --rm --network "container:${P}-netns" --cap-drop=ALL "$BASE" \
            sh -c 'apk add -q iptables >/dev/null 2>&1;
                   iptables -F OUTPUT' >/dev/null 2>&1; then
        bad "SECURITY: container without NET_ADMIN CHANGED the rules"
    else
        ok "container without NET_ADMIN could NOT change the rules"
    fi
else
    skip "could not apply sidecar rule (offline?)"
fi

hdr "Q1  devcontainer CLI accepts a network in runArgs"
if [[ "${SKIP_Q1:-0}" == "1" ]]; then
    skip "Q1 skipped (SKIP_Q1=1)"
elif ! command -v devcontainer >/dev/null; then
    skip "devcontainer CLI not installed"
else
    mkdir -p "$TMP/dc/.devcontainer"
    cat > "$TMP/dc/.devcontainer/devcontainer.json" <<JSON
{ "name": "asf-spike", "image": "${BASE}",
  "runArgs": ["--network=${P}-internal"], "overrideCommand": true }
JSON
    # timeout: `devcontainer up` may keep streaming the container's stdout,
    # which never ends when overrideCommand runs `sleep infinity`.
    timeout 90 devcontainer up --docker-path podman \
        --workspace-folder "$TMP/dc" >"$TMP/up.log" 2>&1
    up_status=$?

    if [[ $up_status -eq 124 ]]; then
        # The container is what matters, not whether the CLI returned.
        if podman ps -q --filter "label=devcontainer.local_folder=$TMP/dc" | grep -q .; then
            ok "devcontainer accepted --network (CLI did not return; container IS running)"
        else
            bad "devcontainer up timed out and no container is running"
        fi
    elif [[ $up_status -eq 0 ]]; then
        ok "devcontainer up accepted --network in runArgs"
    fi

    if [[ $up_status -eq 0 || $up_status -eq 124 ]]; then
        if timeout 30 devcontainer exec --docker-path podman \
                --workspace-folder "$TMP/dc" \
                -- timeout 5 ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
            bad "devcontainer reached the internet on an internal network"
        else
            ok "devcontainer on internal network has NO egress"
        fi
        podman ps -aq --filter "label=devcontainer.local_folder=$TMP/dc" \
            | xargs -r podman rm -f >/dev/null 2>&1
    else
        bad "devcontainer up REJECTED the arrangement (exit $up_status)"
        tail -5 "$TMP/up.log" | sed 's/^/      /'
    fi
fi
}

# ═════════════════════════ PHASE 2 ═════════════════════════════════════════
# ═════════════════════════ PHASE 2 ═════════════════════════════════════════
# Parameterised by proxy implementation so squid and smokescreen run the
# IDENTICAL test suite and can be compared directly.
#
#   PROXY=squid|smokescreen|both   (default: both)

PROXY_IMPL="${PROXY:-both}"
declare -A RESULT_PORT_ACL     # impl -> yes|no|unknown

build_agent_image() {
    mkdir -p "$TMP/agent"
    cat > "$TMP/agent/Containerfile" <<'EOF'
FROM docker.io/library/alpine:3.20
# The agent cannot install anything at runtime: it has no route out.
# netcat-openbsd provides `nc -X connect`, used for SSH over CONNECT.
RUN apk add --no-cache curl netcat-openbsd bind-tools openssh-client
EOF
    timeout 300 podman build -q -t "${P}/agent" "$TMP/agent" >/dev/null 2>&1 \
        && ok "built agent image (curl, nc -X, ssh)" \
        || { bad "agent image build failed"; return 1; }
}

# ── squid ───────────────────────────────────────────────────────────────────
build_squid() {
    mkdir -p "$TMP/squid"
    cat > "$TMP/squid/Containerfile" <<'EOF'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache squid
COPY squid.conf /etc/squid/squid.conf
RUN mkdir -p /var/cache/squid && chown -R squid:squid /var/cache/squid
CMD ["squid", "-N", "-f", "/etc/squid/squid.conf"]
EOF
    cat > "$TMP/squid/squid.conf" <<'EOF'
http_port 3128

acl allowed       dstdomain pypi.org files.pythonhosted.org github.com ssh.github.com
acl connect_ports port 443
acl CONNECT       method CONNECT

# ORDER MATTERS. Deny CONNECT outside connect_ports BEFORE the domain allow:
# squid applies the first matching rule, so a domain-only allow placed first
# would re-permit every port and make this an open TCP relay.
http_access deny CONNECT !connect_ports
http_access allow allowed
http_access deny all

cache deny all
cache_log /dev/null
access_log stdio:/dev/stdout
pid_filename none
dns_v4_first on
EOF
    timeout 300 podman build -q -t "${P}/squid" "$TMP/squid" >/dev/null 2>&1 \
        && ok "built squid image" || { bad "squid image build failed"; return 1; }
}

# ── smokescreen ─────────────────────────────────────────────────────────────
# Stripe's Go egress proxy. Built from source; no official image is assumed.
build_smokescreen() {
    mkdir -p "$TMP/smoke"
    cat > "$TMP/smoke/Containerfile" <<'EOF'
FROM docker.io/library/golang:1.23-alpine AS build
RUN apk add --no-cache git
RUN go install github.com/stripe/smokescreen@latest

FROM docker.io/library/alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/smokescreen /usr/local/bin/smokescreen
COPY acl.yaml /etc/smokescreen/acl.yaml
COPY config.yaml /etc/smokescreen/config.yaml
# The config file holds ONLY settings its yamlConfig type accepts; listen
# address and ACL path are CLI flags (the loader rejects them in the file).
CMD ["smokescreen", "--config-file", "/etc/smokescreen/config.yaml", \
     "--listen-ip", "0.0.0.0", "--listen-port", "4750", \
     "--egress-acl-file", "/etc/smokescreen/acl.yaml"]
EOF

    # `smokescreen --help` shows NO --allow-missing-role flag, but it does show
    # --config-file, which is SEPARATE from --egress-acl-file. The setting
    # belongs here, not in the ACL: putting it in the ACL is silently ignored
    # (the logs keep reporting "allow_missing_role":false).
    # Verified by elimination: smokescreen's config loader rejected
    # listen_ip / listen_port / egress_acl_file as unknown fields but accepted
    # allow_missing_role, so this file holds that setting alone.
    cat > "$TMP/smoke/config.yaml" <<'EOF'
---
# Without mTLS a client has no role and smokescreen denies every request
# ("defaultRoleFromRequest requires TLS"). This makes the ACL's `default`
# policy apply instead.
allow_missing_role: true
EOF
    # Smokescreen's ACL is domain-based. Without mTLS client certs every
    # connection falls to `default`. Whether it can ALSO restrict ports is
    # exactly what T9 below measures.
    cat > "$TMP/smoke/acl.yaml" <<'EOF'
version: v1

# Domain policy only. `allow_missing_role` lives in config.yaml, NOT here.
#
# NOTE for ASF: smokescreen identifies clients by ROLE from a TLS client
# certificate. With mTLS, ONE smokescreen can enforce a DIFFERENT allowlist per
# runtime instead of one proxy per runtime — cert management traded for fewer
# containers.
services: []

default:
  name: default
  project: asf
  action: enforce
  allowed_domains:
    - pypi.org
    - files.pythonhosted.org
    - github.com
    - ssh.github.com
EOF
    if timeout 420 podman build -q -t "${P}/smoke" "$TMP/smoke" >"$TMP/smoke-build.log" 2>&1; then
        ok "built smokescreen image"
    else
        bad "smokescreen image build failed — last lines:"
        tail -12 "$TMP/smoke-build.log" | sed 's/^/      /'
        return 1
    fi
}

# ── tinyproxy ───────────────────────────────────────────────────────────────
# ~5k lines of C (vs squid's ~200k). Its ConnectPort allowlist is GLOBAL rather
# than per-domain — sufficient here, since ASF only ever needs 443.
build_tinyproxy() {
    mkdir -p "$TMP/tiny"
    cat > "$TMP/tiny/Containerfile" <<'EOF'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache tinyproxy
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY filter         /etc/tinyproxy/filter
CMD ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
EOF
    cat > "$TMP/tiny/tinyproxy.conf" <<'EOF'
Port 8888
Listen 0.0.0.0
Timeout 60

# Domain allowlist: FilterDefaultDeny means anything not matched is refused.
Filter "/etc/tinyproxy/filter"
FilterDefaultDeny Yes
FilterExtended On

# CONNECT port allowlist — GLOBAL, not per-domain. 443 only: no port-22
# exception is needed because SSH goes to ssh.github.com:443.
ConnectPort 443

# Who may USE the proxy (the agent's internal network).
Allow 10.0.0.0/8
Allow 172.16.0.0/12
Allow 192.168.0.0/16

LogLevel Info
EOF
    # Extended regex, anchored: match whole hostnames, not substrings.
    cat > "$TMP/tiny/filter" <<'EOF'
^pypi\.org$
^files\.pythonhosted\.org$
^github\.com$
^ssh\.github\.com$
EOF
    timeout 300 podman build -q -t "${P}/tiny" "$TMP/tiny" >"$TMP/tiny-build.log" 2>&1 \
        && ok "built tinyproxy image" \
        || { bad "tinyproxy image build failed:"; tail -8 "$TMP/tiny-build.log" | sed 's/^/      /'; return 1; }
}

# ── g3proxy (ByteDance g3 suite) ────────────────────────────────────────────
# Rust: removes the memory-safety CVE class that affects squid and tinyproxy.
# Built from source — a cargo build of a large workspace, so expect 10+ minutes
# on the first run. The config schema below is a best effort; if g3proxy rejects
# it, start_proxy prints the error and `--g3-help` dumps its own usage.
build_g3proxy() {
    mkdir -p "$TMP/g3"
    cat > "$TMP/g3/Containerfile" <<'EOF'
FROM docker.io/library/rust:1-alpine AS build
# NOTE: python3 is NOT needed once --features excludes the Python binding
# (that is what pulled in PyO3). Kept only for the --g3-help variant that
# builds with default features.
RUN apk add --no-cache git musl-dev openssl-dev openssl-libs-static pkgconfig cmake make g++ capnproto capnproto-dev c-ares-dev
# Verify every build tool BEFORE the long cargo compile: each missing
# dependency otherwise costs a full build to discover the next one.
RUN set -e; for tool in capnp cmake g++ pkg-config; do \
      command -v "$tool" >/dev/null || { echo "MISSING BUILD TOOL: $tool" >&2; exit 1; }; \
    done; capnp --version
WORKDIR /src
RUN git clone --depth 1 https://github.com/bytedance/g3.git .
# Build only the proxy binary, not the whole suite.
# Select the required features explicitly. The final fallback previously used
# --no-default-features without a rustls provider, which always triggers the
# compile_error! in g3proxy/src/main.rs. Disabling Lua, Python and QUIC also
# makes this spike build substantially smaller and faster.
RUN cargo build --release -p g3proxy \
    --no-default-features \
    --features "rustls-ring,c-ares"

FROM docker.io/library/alpine:3.20
# g3proxy links dynamically against the Alpine OpenSSL and c-ares libraries.
RUN apk add --no-cache ca-certificates libgcc openssl c-ares
COPY --from=build /src/target/release/g3proxy /usr/local/bin/g3proxy
COPY g3proxy.yaml /etc/g3proxy/g3proxy.yaml
CMD ["g3proxy", "-c", "/etc/g3proxy/g3proxy.yaml", "-v"]
EOF

    cat > "$TMP/g3/g3proxy.yaml" <<'EOF'
---
# Minimal forward proxy: listen, filter destinations, go direct.
log: stdout

resolver:
  - name: default
    type: c-ares
    server:
      - 1.1.1.1
      - 8.8.8.8

escaper:
  - name: direct
    type: direct_fixed
    resolver: default
    resolve_strategy: IPv4First

server:
  - name: http
    type: http_proxy
    listen:
      address: "0.0.0.0:3130"
    escaper: direct
    # g3proxy's ACL types are allowlists when configured. The host filter uses
    # exact/child/regex keys; the exact-port ACL is a plain list.
    dst_host_filter_set:
      exact:
        - pypi.org
        - files.pythonhosted.org
        - github.com
        - ssh.github.com
    dst_port_filter:
      - 443
EOF
    # Try a published image first — a source build of this workspace is long
    # and pulls in capnp, PyO3 and cmake toolchains.
    local candidate
    for candidate in \
        docker.io/bytedance/g3proxy:latest \
        ghcr.io/bytedance/g3proxy:latest \
        docker.io/bytedance/g3:latest
    do
        if timeout 180 podman pull -q "$candidate" >/dev/null 2>&1; then
            ok "pulled prebuilt g3proxy image ($candidate)"
            # Re-tag with our config layered on top.
            cat > "$TMP/g3/Containerfile.image" <<EOF
FROM ${candidate}
COPY g3proxy.yaml /etc/g3proxy/g3proxy.yaml
EOF
            if timeout 120 podman build -q -t "${P}/g3" -f "$TMP/g3/Containerfile.image" \
                    "$TMP/g3" >/dev/null 2>&1; then
                return 0
            fi
            echo "  … could not layer config onto $candidate; falling back to source"
        fi
    done

    echo "  … no prebuilt image found; building from source (Rust, 10+ min)"
    if timeout 1800 podman build -q -t "${P}/g3" "$TMP/g3" >"$TMP/g3-build.log" 2>&1; then
        ok "built g3proxy image from source"
    else
        bad "g3proxy build failed — last lines:"
        tail -15 "$TMP/g3-build.log" | sed 's/^/      /'
        echo "      (a MISSING BUILD TOOL line above names the dependency)"
        return 1
    fi
}

# ── lifecycle ───────────────────────────────────────────────────────────────
start_proxy() {   # impl
    local impl="$1"
    podman rm -f "${P}-proxy" >/dev/null 2>&1
    case "$impl" in
        squid)       PROXY_IMAGE="${P}/squid"; PROXY_PORT=3128 ;;
        # PROXY_KIND drives log parsing in proxy_verdict.
        smokescreen) PROXY_IMAGE="${P}/smoke"; PROXY_PORT=4750 ;;
        tinyproxy)   PROXY_IMAGE="${P}/tiny";  PROXY_PORT=8888 ;;
        g3proxy)     PROXY_IMAGE="${P}/g3";    PROXY_PORT=3130 ;;
    esac
    PROXY_KIND="$impl"
    podman run -d --name "${P}-proxy" \
        --network "${P}-net-internal" --network "${P}-net-egress" \
        "$PROXY_IMAGE" >/dev/null 2>&1 \
        && ok "$impl started on internal + egress" \
        || { bad "$impl failed to start"; return 1; }

    local up=0
    for _ in $(seq 1 25); do
        if timeout 5 podman exec "${P}-proxy" \
                sh -c "nc -z 127.0.0.1 $PROXY_PORT" >/dev/null 2>&1; then
            up=1; break
        fi
        sleep 1
    done
    if (( up )); then
        ok "$impl is accepting connections on :$PROXY_PORT"
    else
        bad "$impl never listened on :$PROXY_PORT — its log:"
        timeout 15 podman logs --tail 20 "${P}-proxy" 2>&1 | sed 's/^/      /'
        return 1
    fi
}

# Run a command in a throwaway AGENT container (internal network only).
agent() {   # command [outer-timeout-seconds]
    timeout "${2:-60}" podman run --rm --network "${P}-net-internal" \
        -e http_proxy="http://${P}-proxy:${PROXY_PORT}" \
        -e https_proxy="http://${P}-proxy:${PROXY_PORT}" \
        "${P}/agent" sh -c "$1" 2>&1
}

# Did the proxy allow or deny this destination? Judged from the PROXY's own
# log, never from client output — a client-side check gave a false pass before,
# reporting "refused" when the port was in fact allowed.
proxy_verdict() {   # host port -> allowed|denied|unknown
    local host="$1" port="$2" logs decision
    logs=$(timeout 15 podman logs "${P}-proxy" 2>&1)

    # Each proxy states its verdict differently, and tinyproxy states it on a
    # separate line from the request — so match per implementation rather than
    # grepping for the host and hoping the verdict is on the same line.
    case "$PROXY_KIND" in
        squid)
            decision=$(grep -F "${host}:${port}" <<<"$logs" \
                        | grep -E 'TCP_DENIED|TCP_TUNNEL|TCP_MISS' | tail -1)
            if   grep -q 'TCP_DENIED' <<<"$decision"; then echo denied
            elif grep -qE 'TCP_TUNNEL|TCP_MISS' <<<"$decision"; then echo allowed
            else echo unknown; fi
            ;;
        smokescreen)
            decision=$(grep -F "${host}:${port}" <<<"$logs" \
                        | grep 'CANONICAL-PROXY-DECISION' | tail -1)
            if   grep -q '"allow":false' <<<"$decision"; then echo denied
            elif grep -q '"allow":true'  <<<"$decision"; then echo allowed
            else echo unknown; fi
            ;;
        tinyproxy)
            # "Refused CONNECT method on port 22" — port only, no host.
            if grep -qE "Refused CONNECT method on port ${port}\b" <<<"$logs"; then
                echo denied
            elif grep -qE "Established connection to host \"${host}\"" <<<"$logs"; then
                echo allowed
            else
                echo unknown
            fi
            ;;
        *)
            # Unknown implementation: fall back to generic patterns.
            decision=$(grep -F "${host}:${port}" <<<"$logs" | tail -1)
            if   grep -qiE 'denied|refused|forbidden|"allow":false' <<<"$decision"; then echo denied
            elif grep -qiE 'tunnel|established|"allow":true' <<<"$decision"; then echo allowed
            else echo unknown; fi
            ;;
    esac
}

# ── the suite, run identically per implementation ───────────────────────────
run_topology_tests() {   # impl
    local impl="$1"

    hdr "[$impl] T1  container-name DNS on an internal network"
    if agent "getent hosts ${P}-proxy" | grep -q .; then
        ok "agent resolved the proxy by container name"
    else
        bad "container-name DNS FAILED on internal network"
    fi

    hdr "[$impl] T2  agent has no direct egress"
    if agent 'timeout 6 curl -s --noproxy "*" -o /dev/null https://pypi.org' >/dev/null 2>&1; then
        bad "agent reached the internet DIRECTLY"
    else
        ok "agent cannot reach the internet directly"
    fi
    if agent 'timeout 5 nslookup pypi.org' | grep -qiE 'address: *[0-9]'; then
        skip "agent CAN resolve external DNS (tunnelling gap remains)"
    else
        ok "agent cannot resolve external names (DNS gap closed)"
    fi

    hdr "[$impl] T3  agent can reach the controlled services"
    agent "nc -z ${P}-proxy ${PROXY_PORT}" >/dev/null 2>&1 \
        && ok "agent → proxy:${PROXY_PORT} reachable" || bad "agent cannot reach the proxy"
    agent "nc -z ${P}-broker 4000" >/dev/null 2>&1 \
        && ok "agent → broker:4000 reachable" || bad "agent cannot reach the broker"

    hdr "[$impl] T4  allowlisted host succeeds through the proxy"
    echo "  … fetching a small page from pypi.org"
    local code allow_path_works=0
    code=$(agent 'timeout 25 curl -s -o /dev/null -w "%{http_code}" https://pypi.org/simple/pip/')
    if grep -qE '^(200|30[0-9])$' <<<"$code"; then
        ok "pypi.org reachable via proxy (HTTP $code)"
        allow_path_works=1
    else
        bad "allowlisted host FAILED through the proxy (got: ${code:-no response})"
        echo "      ⚠ the ALLOW path is broken, so every deny-test below would"
        echo "        pass trivially. They are reported as inconclusive."
        timeout 15 podman logs --tail 4 "${P}-proxy" 2>&1 | sed 's/^/        /'
        if [[ "$impl" == smokescreen ]]; then
            echo
            echo "      smokescreen flags mentioning role/acl/tls (its own help):"
            timeout 30 podman run --rm "${P}/smoke" smokescreen --help 2>&1 \
                | grep -iE 'role|acl|tls|cert|missing' | sed 's/^/        /' \
                || echo "        (could not read help)"
        fi
    fi

    hdr "[$impl] T5  non-allowlisted host is refused"
    code=$(agent 'timeout 20 curl -s -o /dev/null -w "%{http_code}" https://example.com')
    if [[ "$code" == "200" ]]; then
        bad "non-allowlisted host was ALLOWED"
    elif (( allow_path_works )); then
        ok "non-allowlisted host refused (curl: ${code:-connection failed})"
    else
        skip "refused, but inconclusive — this proxy is refusing everything"
    fi

    hdr "[$impl] T6  provider API unreachable from the agent"
    code=$(agent 'timeout 20 curl -s -o /dev/null -w "%{http_code}" https://api.openai.com/v1/models')
    if grep -qE '^[23]' <<<"$code"; then
        bad "agent reached the provider API"
    elif (( allow_path_works )); then
        ok "agent cannot reach api.openai.com (got: ${code:-connection failed})"
    else
        skip "unreachable, but inconclusive — this proxy is refusing everything"
    fi

    hdr "[$impl] T7  SSH over CONNECT"
    echo "  … opening a CONNECT tunnel to ssh.github.com:443"
    local banner
    # No -q here: stdin is EOF immediately, and -q would quit before the SSH
# banner arrives. `head -1` closes the pipe and kills nc as soon as a line
# is read, so this stays fast without needing -q.
banner=$(agent "timeout 12 nc -w 8 -X connect -x ${P}-proxy:${PROXY_PORT} ssh.github.com 443 < /dev/null | head -1" 30)
    if grep -q 'SSH-2' <<<"$banner"; then
        ok "CONNECT ssh.github.com:443 tunnelled (SSH banner received)"
    else
        bad "SSH over 443 failed — got: $(head -c 90 <<<"$banner")"
    fi

    echo "  … running a real ssh handshake through the proxy (~10s)"
    local ssh_opts ssh_out
    ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10"
    ssh_out=$(agent "timeout 30 ssh $ssh_opts -o 'ProxyCommand nc -X connect -x ${P}-proxy:${PROXY_PORT} %h %p' -p 443 -T git@ssh.github.com")
    if grep -qiE 'successfully authenticated|permission denied|publickey' <<<"$ssh_out"; then
        ok "ssh reached GitHub through the proxy (auth stage reached)"
    else
        bad "ssh through proxy failed — got: $(head -c 90 <<<"$ssh_out")"
    fi

    # ── T9: THE decision criterion for swapping proxies ────────────────────
    # An allowlisted DOMAIN on a NON-allowlisted PORT. If this is allowed, the
    # proxy is an open TCP relay to every allowed host, and port restriction
    # must come from a second layer (netfilter on the proxy's egress).
    hdr "[$impl] T9  per-port ACL on an allowlisted domain"
    if (( ! allow_path_works )); then
        skip "cannot measure port ACLs while the proxy denies everything"
        RESULT_PORT_ACL[$impl]=inconclusive
        return
    fi
    # Fire both probes in the BACKGROUND. Only the ACL decision matters, and
    # the proxy logs it the moment the request arrives. If the proxy ALLOWS the
    # request it then dials a port that may drop packets for ~135s — waiting
    # for that tells us nothing and stalls the suite.
    local probe="nc -w 3 -q 1 -X connect -x ${P}-proxy:${PROXY_PORT}"
    echo "  … probing CONNECT github.com:22 and :8080 (decision only)"
    agent "timeout 5 $probe github.com 22   < /dev/null" 20 >/dev/null 2>&1 &
    local pid22=$!
    agent "timeout 5 $probe github.com 8080 < /dev/null" 20 >/dev/null 2>&1 &
    local pid8080=$!
    sleep 6                                   # enough for both decisions to log
    kill "$pid22" "$pid8080" 2>/dev/null || true
    wait "$pid22" "$pid8080" 2>/dev/null || true
    echo "  … reading the proxy's verdict"
    local v22 v8080
    v22=$(proxy_verdict github.com 22)
    v8080=$(proxy_verdict github.com 8080)
    echo "      proxy verdict for github.com:22   → $v22"
    echo "      proxy verdict for github.com:8080 → $v8080"

    if [[ "$v22" == denied && "$v8080" == denied ]]; then
        ok "per-port ACL ENFORCED (443-only)"
        RESULT_PORT_ACL[$impl]=yes
    elif [[ "$v22" == allowed || "$v8080" == allowed ]]; then
        bad "per-port ACL NOT enforced — open TCP relay to allowlisted hosts"
        echo "      → port restriction must come from another layer."
        if [[ "$impl" == smokescreen ]]; then
            echo "        smokescreen has --deny-address IP[:PORT], but that is"
            echo "        IP-scoped, not per-domain: it cannot express"
            echo "        'this domain, 443 only' when the IP is a shared CDN."
            echo "        The alternative is netfilter on the proxy egress."
        fi
        RESULT_PORT_ACL[$impl]=no
    else
        skip "no clear proxy verdict — inspect the log below"
        RESULT_PORT_ACL[$impl]=unknown
    fi

    echo
    echo "  [$impl] proxy log tail:"
    timeout 15 podman logs --tail 10 "${P}-proxy" 2>&1 | sed 's/^/      /'
}

run_phase2() {
hdr "Build images (agent tools must be baked in — the agent has no egress)"
build_agent_image || return

local impls=()
case "$PROXY_IMPL" in
    squid)       impls=(squid) ;;
    smokescreen) impls=(smokescreen) ;;
    tinyproxy)   impls=(tinyproxy) ;;
    g3proxy)     impls=(g3proxy) ;;
    both)        impls=(squid smokescreen) ;;
    all)         impls=(squid smokescreen tinyproxy g3proxy) ;;
    *)           echo "PROXY must be squid|smokescreen|tinyproxy|g3proxy|both|all"; return 1 ;;
esac

for impl in "${impls[@]}"; do
    case "$impl" in
        squid)       build_squid       || { bad "skipping squid tests"; continue; } ;;
        smokescreen) build_smokescreen || { bad "skipping smokescreen tests"; continue; } ;;
        tinyproxy)   build_tinyproxy   || { bad "skipping tinyproxy tests"; continue; } ;;
        g3proxy)     build_g3proxy     || { bad "skipping g3proxy tests"; continue; } ;;
    esac
done

hdr "Create the three networks"
ensure_network "${P}-net-internal" --internal
ensure_network "${P}-net-egress"
ensure_network "${P}-net-provider"

hdr "Start the broker stand-in (shared by both proxy runs)"
podman rm -f "${P}-broker" >/dev/null 2>&1
podman run -d --name "${P}-broker" \
    --network "${P}-net-internal" --network "${P}-net-provider" \
    "${P}/agent" sh -c 'while true; do
        printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" | nc -l -p 4000
    done' >/dev/null 2>&1 \
    && ok "broker stand-in started on internal + provider" || bad "broker failed to start"

for impl in "${impls[@]}"; do
    hdr "═══ proxy implementation: $impl ═══"
    local img
    case "$impl" in
        squid) img="${P}/squid" ;; smokescreen) img="${P}/smoke" ;;
        tinyproxy) img="${P}/tiny" ;; g3proxy) img="${P}/g3" ;;
    esac
    if ! podman image exists "$img"; then
        skip "$impl image unavailable — skipping its tests"
        continue
    fi
    start_proxy "$impl" || { skip "$impl did not start — skipping its tests"; continue; }
    run_topology_tests "$impl"
done

hdr "T8  broker stand-in reaches the internet directly"
if timeout 40 podman exec "${P}-broker" sh -c \
        'timeout 20 curl -s -o /dev/null -w "%{http_code}" https://api.openai.com/v1/models' \
        2>/dev/null | grep -qE '^[0-9]{3}$'; then
    ok "broker can reach the provider API directly"
else
    bad "broker cannot reach the internet"
fi

# ── comparison ──────────────────────────────────────────────────────────────
if (( ${#impls[@]} > 1 )); then
    hdr "Proxy comparison"
    printf "  %-14s %s\n" "implementation" "per-port ACL (the deciding criterion)"
    for impl in "${impls[@]}"; do
        printf "  %-14s %s\n" "$impl" "${RESULT_PORT_ACL[$impl]:-not tested}"
    done
    echo
    echo "  A proxy that cannot restrict ports is still usable, but then port"
    echo "  restriction must come from netfilter on the PROXY's egress network —"
    echo "  the defence-in-depth layer already described in EGRESS-DESIGN.md."
fi
}

# ═════════════════════════ run ═════════════════════════════════════════════
case "$PHASE" in
    --phase1) run_phase1 ;;
    --phase2) run_phase2 ;;
    *)        run_phase1; run_phase2 ;;
esac

hdr "Result"
echo "  passed: $PASS   failed: $FAIL   skipped: $SKIP"
echo
echo "Phase 1 → the mechanisms work in isolation."
echo "Phase 2 → the full topology holds: agent isolated, proxy the only way out,"
echo "          broker independently connected, SSH tunnelled over CONNECT."
echo
echo "T1 (DNS) or T7 (SSH) failing is design-blocking."
echo "T7 uses ssh.github.com:443, so no port-22 exception is needed."
echo "T9 decides proxy choice: a proxy that cannot restrict ports needs a"
echo "    netfilter layer on its egress to avoid being an open relay."
echo "A skip on T2's DNS check means the agent can still resolve external names:"
echo "not fatal, but the DNS-tunnelling gap stays on the limitations list."
[[ "$FAIL" -eq 0 ]]
