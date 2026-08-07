#!/usr/bin/env bash
# DESIGN ARTIFACT — the decision it made is implemented; not a production test.
#
# This spike chose between two routed architectures:
#   A  routed gateway with a Podman-injected static route   → CHOSEN, shipped
#   B  shared network namespace + sidecar                    → REJECTED
#
# Architecture B is not implemented anywhere, so its checks (G6A/G6B) test code
# that does not exist. The properties still relevant to production are covered by:
#   forwarding sysctl / capability-less holder → tests/spike-gateway-caps.sh
#   enforced allow-deny matrix                 → historical pre-v50 routed verifier
#                                                tests/test_routed_integration.sh
#
# Kept as evidence for how the architecture was selected.
# spike-gateway-merged.sh — which rootless ASF routed-network design is viable?
#
# This spike evaluates three variants in dependency order:
#
#   A1. ROUTED + PODMAN ROUTE
#       scanner namespace -> routed gateway -> target network
#       Podman injects the scanner's static route with `network create --route`.
#
#   A2. ROUTED + ROUTE-INIT SIDECAR
#       same topology as A1, but a short-lived trusted sidecar joins the
#       scanner namespace, adds the route with NET_ADMIN, then exits. The
#       scanner itself never receives NET_ADMIN and cannot alter the route.
#
#   B.  FILTER-INIT SIDECAR
#       scanner namespace is attached directly to the target network. A
#       short-lived trusted sidecar writes default-deny OUTPUT rules, then
#       exits. The scanner has no NET_ADMIN and cannot alter the rules.
#
# The test uses controlled target containers and target-side hit records.
# A permissive positive control runs before every enforcement verdict; a
# blocked-path result is INCONCLUSIVE if the same path was not first proven
# reachable while policy was permissive.
#
# This is Stage 1 only: controlled rootless bridge networks. It does not yet
# prove fidelity through pasta/rootless user-mode egress to a real LAN.
#
# Usage:
#   chmod +x spike-gateway-merged.sh
#   ./spike-gateway-merged.sh
#   ./spike-gateway-merged.sh --clean

set -uo pipefail

P="asf-gwmerge"
IMAGE="${P}/tools"
BASE_IMAGE="docker.io/library/alpine:3.20"

TARGET_NET="${P}-target"
G3_NET="${P}-g3"
G4_NET="${P}-g4"
A_SCAN_NET="${P}-a-scan"

ALLOWED="${P}-allowed"
DENIED="${P}-denied"
G3_GW="${P}-g3-gateway"
A_GW="${P}-a-gateway"
A_NS="${P}-a-netns"
B_NS="${P}-b-netns"

SCAN_SUBNET="10.77.0.0/24"
SCAN_NET_GW="10.77.0.1"
GW_SCAN_IP="10.77.0.2"
SCANNER_IP="10.77.0.10"

TARGET_SUBNET="10.78.0.0/24"
TARGET_NET_GW="10.78.0.1"
GW_TARGET_IP="10.78.0.2"
ALLOWED_IP="10.78.0.10"
DENIED_IP="10.78.0.11"
B_NS_IP="10.78.0.20"

ALLOWED_TCP=8080
BLOCKED_TCP=9999
ALLOWED_UDP=161
BLOCKED_UDP=9999

PASS=0
FAIL=0
SKIP=0
WARN=0

ok()   { printf '  ✓ %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  ✗ %s\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '  – %s\n' "$*"; SKIP=$((SKIP+1)); }
warn() { printf '  ! %s\n' "$*"; WARN=$((WARN+1)); }
note() { printf '      %s\n' "$*"; }
hdr()  { printf '\n── %s ─────────────────────────────────────\n' "$*"; }

runtime_cleanup() {
    podman rm -f \
        "$ALLOWED" "$DENIED" "$G3_GW" "$A_GW" "$A_NS" "$B_NS" \
        >/dev/null 2>&1 || true
    podman network rm -f \
        "$G3_NET" "$G4_NET" "$A_SCAN_NET" "$TARGET_NET" \
        >/dev/null 2>&1 || true
}

full_cleanup() {
    runtime_cleanup
    podman rmi -f "$IMAGE" >/dev/null 2>&1 || true
}

trap runtime_cleanup EXIT INT TERM

command -v podman >/dev/null 2>&1 || { echo "podman not found"; exit 1; }

if [[ "${1:-}" == "--clean" ]]; then
    full_cleanup
    echo "cleaned"
    exit 0
fi

ROOTLESS=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || echo unknown)
NET_BACKEND=$(podman info --format '{{.Host.NetworkBackend}}' 2>/dev/null || echo unknown)
echo "podman: $(podman --version)"
echo "rootless: $ROOTLESS"
echo "network backend: $NET_BACKEND"
if [[ "$ROOTLESS" != "true" ]]; then
    warn "Podman does not report rootless=true; results do not answer the rootless question"
fi

build_image() {
    local tmp
    tmp=$(mktemp -d)
    cat >"$tmp/Containerfile" <<'EOF_IMAGE'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache \
      curl iproute2 iputils netcat-openbsd nftables nmap socat tcpdump

RUN cat > /target.sh <<'EOS' && chmod +x /target.sh
#!/bin/sh
set -eu
: > /tmp/hits

listen_tcp() {
    p="$1"
    while true; do
        printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok' \
          | nc -l -p "$p" >/dev/null 2>&1 || true
        echo "TCP:$p" >> /tmp/hits
    done
}

listen_udp() {
    p="$1"
    socat -u "UDP4-RECVFROM:${p},reuseaddr,fork" OPEN:/tmp/hits,creat,append
}

listen_tcp 8080 &
listen_tcp 9999 &
listen_udp 161 &
listen_udp 9999 &
wait
EOS

CMD ["sleep", "infinity"]
EOF_IMAGE

    if podman image exists "$IMAGE"; then
        ok "tools image already present"
    elif timeout 600 podman build -q -t "$IMAGE" "$tmp" >/dev/null 2>&1; then
        ok "built tools image (nftables, iproute2, curl, nc, nmap, socat)"
    else
        bad "tools image build failed"
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$tmp"
}

container_running() {
    [[ "$(podman inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == "true" ]]
}

reset_hits() {
    podman exec "$ALLOWED" sh -c ': > /tmp/hits' >/dev/null 2>&1 || true
    podman exec "$DENIED" sh -c ': > /tmp/hits' >/dev/null 2>&1 || true
}

hit_exists() {
    local who="$1" token="$2"
    podman exec "$who" grep -Fxq "$token" /tmp/hits 2>/dev/null
}

wait_for_hit() {
    local who="$1" token="$2" i
    for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        hit_exists "$who" "$token" && return 0
        sleep 0.2
    done
    return 1
}

# Run a capability-less process in architecture A's scanner namespace.
a_client() {
    timeout 12 podman run --rm \
        --network "container:${A_NS}" \
        --cap-drop ALL --security-opt no-new-privileges \
        "$IMAGE" sh -c "$1" 2>&1
}

a_client_raw() {
    timeout 12 podman run --rm \
        --network "container:${A_NS}" \
        --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges \
        "$IMAGE" sh -c "$1" 2>&1
}

# Run a capability-less process in architecture B's scanner namespace.
b_client() {
    timeout 12 podman run --rm \
        --network "container:${B_NS}" \
        --cap-drop ALL --security-opt no-new-privileges \
        "$IMAGE" sh -c "$1" 2>&1
}

b_client_raw() {
    timeout 12 podman run --rm \
        --network "container:${B_NS}" \
        --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges \
        "$IMAGE" sh -c "$1" 2>&1
}

# ── G1/G2: primitive capabilities ──────────────────────────────────────────

test_gateway_primitives() {
    hdr "G1  IPv4 forwarding inside a rootless NET_ADMIN container"
    FORWARD_OK=0
    if timeout 30 podman run --rm \
          --cap-drop ALL --cap-add NET_ADMIN \
          --sysctl net.ipv4.ip_forward=1 \
          "$IMAGE" sh -c 'test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1' \
          >/dev/null 2>&1; then
        ok "ip_forward can be enabled with podman --sysctl"
        FORWARD_OK=1
    elif timeout 30 podman run --rm \
          --cap-drop ALL --cap-add NET_ADMIN \
          "$IMAGE" sh -c 'sysctl -w net.ipv4.ip_forward=1 >/dev/null && test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1' \
          >/dev/null 2>&1; then
        ok "ip_forward can be enabled from inside the container"
        note "Prefer --sysctl in ASF so the setting is declarative at startup"
        FORWARD_OK=1
    else
        bad "ip_forward cannot be enabled; routed gateway architecture is blocked"
    fi

    hdr "G2  nftables forwarding and NAT primitives with NET_ADMIN"
    NFT_OK=0
    if timeout 40 podman run --rm \
          --cap-drop ALL --cap-add NET_ADMIN \
          "$IMAGE" sh -c 'nft -f - <<"NFT"
flush ruleset
table inet asf_test_filter {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ip daddr 192.0.2.0/24 tcp dport 8080 counter accept
  }
}
table ip asf_test_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.0.0.0/8 masquerade
  }
}
NFT
nft list table inet asf_test_filter | grep -q 8080 &&
nft list table ip asf_test_nat | grep -q masquerade' >/dev/null 2>&1; then
        ok "nftables filter and masquerade rules can be installed"
        NFT_OK=1
    else
        bad "nftables forwarding/NAT primitives are unavailable"
    fi
}

# ── Controlled networks and targets ────────────────────────────────────────

start_targets() {
    hdr "Controlled target network"
    runtime_cleanup

    if podman network create --internal \
          --subnet "$TARGET_SUBNET" --gateway "$TARGET_NET_GW" \
          "$TARGET_NET" >/dev/null; then
        ok "created internal target network $TARGET_SUBNET"
    else
        bad "failed to create target network"
        return 1
    fi

    podman run -d --name "$ALLOWED" \
        --network "$TARGET_NET:ip=$ALLOWED_IP" \
        "$IMAGE" /target.sh >/dev/null \
        && ok "allowed target started at $ALLOWED_IP" \
        || { bad "allowed target failed"; return 1; }

    podman run -d --name "$DENIED" \
        --network "$TARGET_NET:ip=$DENIED_IP" \
        "$IMAGE" /target.sh >/dev/null \
        && ok "denied target started at $DENIED_IP" \
        || { bad "denied target failed"; return 1; }

    sleep 1
}

# ── G3/G4: route ownership ─────────────────────────────────────────────────

test_route_ownership() {
    hdr "G3  capability-less scanner cannot add a route"
    podman network rm -f "$G3_NET" >/dev/null 2>&1 || true
    if ! podman network create --internal \
          --subnet "$SCAN_SUBNET" --gateway "$SCAN_NET_GW" \
          "$G3_NET" >/dev/null; then
        bad "failed to create route-capability test network"
        return 1
    fi

    podman run -d --name "$G3_GW" \
        --network "$G3_NET:ip=$GW_SCAN_IP" \
        --cap-drop ALL --security-opt no-new-privileges \
        "$IMAGE" sleep infinity >/dev/null 2>&1 || true

    if timeout 30 podman run --rm \
          --network "$G3_NET:ip=$SCANNER_IP" \
          --cap-drop ALL --security-opt no-new-privileges \
          "$IMAGE" sh -c "ip route add $TARGET_SUBNET via $GW_SCAN_IP" \
          >/dev/null 2>&1; then
        bad "a capability-less container added a route"
    else
        ok "a capability-less container cannot add a valid next-hop route"
    fi
    podman rm -f "$G3_GW" >/dev/null 2>&1 || true
    podman network rm -f "$G3_NET" >/dev/null 2>&1 || true

    hdr "G4  Podman static-route injection (functional test)"
    ROUTE_VIA_PODMAN=0
    podman network rm -f "$G4_NET" >/dev/null 2>&1 || true

    if podman network create --help 2>&1 | grep -q -- '--route'; then
        note "podman exposes network create --route; testing actual injection"
    else
        note "podman help does not advertise --route; testing it once anyway"
    fi

    if podman network create --internal \
          --subnet "$SCAN_SUBNET" --gateway "$SCAN_NET_GW" \
          --route "$TARGET_SUBNET,$GW_SCAN_IP" \
          "$G4_NET" >/dev/null 2>&1 \
       && timeout 30 podman run --rm \
          --network "$G4_NET:ip=$SCANNER_IP" \
          --cap-drop ALL --security-opt no-new-privileges \
          "$IMAGE" sh -c "ip route show $TARGET_SUBNET | grep -q 'via $GW_SCAN_IP'" \
          >/dev/null 2>&1; then
        ROUTE_VIA_PODMAN=1
        ok "Podman injected the static route into a capability-less container"
    else
        skip "Podman could not inject the requested route on this host/version"
        note "Architecture A will use a short-lived route-init sidecar instead"
    fi
    podman network rm -f "$G4_NET" >/dev/null 2>&1 || true
}

# ── Architecture A: separate routed gateway ────────────────────────────────

load_a_permissive_policy() {
    podman exec -i "$A_GW" nft -f - <<EOF_NFT
flush ruleset
table inet asf_gateway_filter {
  chain forward {
    type filter hook forward priority filter; policy accept;
    counter
  }
}
table ip asf_gateway_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $SCANNER_IP ip daddr $TARGET_SUBNET counter masquerade
  }
}
EOF_NFT
}

load_a_enforced_policy() {
    podman exec -i "$A_GW" nft -f - <<EOF_NFT
flush ruleset
table inet asf_gateway_filter {
  chain forward {
    type filter hook forward priority filter; policy drop;

    ct state established,related counter accept

    ip saddr $SCANNER_IP ip daddr $ALLOWED_IP tcp dport $ALLOWED_TCP counter accept
    ip saddr $SCANNER_IP ip daddr $ALLOWED_IP udp dport $ALLOWED_UDP counter accept
    ip saddr $SCANNER_IP ip daddr $ALLOWED_IP icmp type echo-request counter accept

    counter drop
  }
}
table ip asf_gateway_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $SCANNER_IP ip daddr $TARGET_SUBNET counter masquerade
  }
}
EOF_NFT
}

start_architecture_a() {
    hdr "G5  Architecture A — routed gateway"
    A_ROUTE_METHOD="none"
    A_CONTROL_VALID=0
    A_ENFORCED_OK=0

    if (( FORWARD_OK == 0 || NFT_OK == 0 )); then
        skip "Architecture A skipped: G1/G2 prerequisite failed"
        return 1
    fi

    podman rm -f "$A_GW" "$A_NS" >/dev/null 2>&1 || true
    podman network rm -f "$A_SCAN_NET" >/dev/null 2>&1 || true

    if (( ROUTE_VIA_PODMAN == 1 )); then
        if podman network create --internal \
              --subnet "$SCAN_SUBNET" --gateway "$SCAN_NET_GW" \
              --route "$TARGET_SUBNET,$GW_SCAN_IP" \
              "$A_SCAN_NET" >/dev/null; then
            A_ROUTE_METHOD="podman"
            ok "created scanner network with a Podman-injected route"
        else
            warn "Podman route worked in G4 but failed for Architecture A"
        fi
    fi

    if [[ "$A_ROUTE_METHOD" == "none" ]]; then
        if podman network create --internal \
              --subnet "$SCAN_SUBNET" --gateway "$SCAN_NET_GW" \
              "$A_SCAN_NET" >/dev/null; then
            A_ROUTE_METHOD="sidecar"
            ok "created scanner network; route will be installed by init sidecar"
        else
            bad "failed to create Architecture A scanner network"
            return 1
        fi
    fi

    podman run -d --name "$A_GW" \
        --cap-drop ALL --cap-add NET_ADMIN \
        --sysctl net.ipv4.ip_forward=1 \
        --network "$A_SCAN_NET:ip=$GW_SCAN_IP" \
        --network "$TARGET_NET:ip=$GW_TARGET_IP" \
        "$IMAGE" sleep infinity >/dev/null \
        && ok "gateway started on scanner and target networks" \
        || { bad "gateway failed to start"; return 1; }

    # A network-level route is injected into every member, including the
    # dual-homed gateway. Remove the gateway's self-referential copy so its
    # directly connected target route wins unambiguously.
    if [[ "$A_ROUTE_METHOD" == "podman" ]]; then
        podman exec "$A_GW" ip route del "$TARGET_SUBNET" via "$GW_SCAN_IP" \
            >/dev/null 2>&1 || true
    fi

    podman run -d --name "$A_NS" \
        --network "$A_SCAN_NET:ip=$SCANNER_IP" \
        --cap-drop ALL --security-opt no-new-privileges \
        "$IMAGE" sleep infinity >/dev/null \
        && ok "capability-less scanner namespace started" \
        || { bad "scanner namespace failed to start"; return 1; }

    if [[ "$A_ROUTE_METHOD" == "sidecar" ]]; then
        if timeout 30 podman run --rm \
              --network "container:${A_NS}" \
              --cap-drop ALL --cap-add NET_ADMIN \
              "$IMAGE" sh -c "ip route replace $TARGET_SUBNET via $GW_SCAN_IP" \
              >/dev/null 2>&1; then
            ok "route-init sidecar installed the route and exited"
        else
            bad "route-init sidecar could not install the route"
            return 1
        fi
    fi

    echo "  scanner routes:"
    podman exec "$A_NS" ip -4 route | sed 's/^/    /'
    echo "  gateway routes:"
    podman exec "$A_GW" ip -4 route | sed 's/^/    /'

    if podman exec "$A_NS" ip route show "$TARGET_SUBNET" | grep -q "via $GW_SCAN_IP"; then
        ok "scanner namespace contains the expected route via the gateway"
    else
        bad "scanner namespace lacks the expected target route"
        return 1
    fi

    if a_client "ip route del $TARGET_SUBNET" >/dev/null 2>&1; then
        bad "capability-less scanner altered its route table"
    else
        ok "scanner cannot alter the route installed by Podman/init sidecar"
    fi
}

a_positive_control() {
    hdr "G5A  Architecture A positive control"
    if ! load_a_permissive_policy || ! container_running "$A_GW"; then
        bad "could not load permissive Architecture A policy"
        return 1
    fi
    ok "loaded permissive forwarding + NAT policy"

    reset_hits
    a_client "curl -fsS --max-time 3 http://$ALLOWED_IP:$BLOCKED_TCP/ >/dev/null" >/dev/null || true
    if wait_for_hit "$ALLOWED" "TCP:$BLOCKED_TCP"; then
        ok "control reached otherwise-blocked TCP port"
    else
        bad "control could not reach otherwise-blocked TCP port"
        return 1
    fi

    reset_hits
    a_client "curl -fsS --max-time 3 http://$DENIED_IP:$ALLOWED_TCP/ >/dev/null" >/dev/null || true
    if wait_for_hit "$DENIED" "TCP:$ALLOWED_TCP"; then
        ok "control reached otherwise-denied target"
    else
        bad "control could not reach otherwise-denied target"
        return 1
    fi

    reset_hits
    a_client "printf 'UDP:$BLOCKED_UDP\\n' | nc -u -w 1 $ALLOWED_IP $BLOCKED_UDP" >/dev/null || true
    if wait_for_hit "$ALLOWED" "UDP:$BLOCKED_UDP"; then
        ok "control forwarded otherwise-blocked UDP port"
    else
        bad "control could not forward otherwise-blocked UDP port"
        return 1
    fi

    if a_client_raw "ping -c 1 -W 2 $DENIED_IP >/dev/null" >/dev/null 2>&1; then
        ok "control forwarded ICMP to otherwise-denied target"
    else
        bad "control could not forward ICMP"
        return 1
    fi

    A_CONTROL_VALID=1
}

a_enforcement_matrix() {
    hdr "G5B  Architecture A enforced matrix"
    if (( A_CONTROL_VALID == 0 )); then
        skip "inconclusive: Architecture A positive control failed"
        return 1
    fi

    if ! load_a_enforced_policy || ! container_running "$A_GW"; then
        bad "could not load Architecture A enforced policy"
        return 1
    fi
    ok "loaded default-deny gateway policy"

    local local_fail=0

    reset_hits
    if a_client "curl -fsS --max-time 3 http://$ALLOWED_IP:$ALLOWED_TCP/ >/dev/null" >/dev/null \
       && wait_for_hit "$ALLOWED" "TCP:$ALLOWED_TCP"; then
        ok "allowed TCP target/port reached"
    else
        bad "allowed TCP target/port failed"; local_fail=1
    fi

    reset_hits
    a_client "curl -fsS --max-time 2 http://$ALLOWED_IP:$BLOCKED_TCP/ >/dev/null" >/dev/null || true
    if ! wait_for_hit "$ALLOWED" "TCP:$BLOCKED_TCP" && container_running "$A_GW"; then
        ok "undeclared TCP port blocked"
    else
        bad "undeclared TCP port reached target or gateway died"; local_fail=1
    fi

    reset_hits
    a_client "curl -fsS --max-time 2 http://$DENIED_IP:$ALLOWED_TCP/ >/dev/null" >/dev/null || true
    if ! wait_for_hit "$DENIED" "TCP:$ALLOWED_TCP" && container_running "$A_GW"; then
        ok "undeclared destination blocked"
    else
        bad "undeclared destination reached or gateway died"; local_fail=1
    fi

    reset_hits
    a_client "printf 'UDP:$ALLOWED_UDP\\n' | nc -u -w 1 $ALLOWED_IP $ALLOWED_UDP" >/dev/null || true
    if wait_for_hit "$ALLOWED" "UDP:$ALLOWED_UDP"; then
        ok "allowed UDP target/port reached"
    else
        bad "allowed UDP target/port failed"; local_fail=1
    fi

    reset_hits
    a_client "printf 'UDP:$BLOCKED_UDP\\n' | nc -u -w 1 $ALLOWED_IP $BLOCKED_UDP" >/dev/null || true
    if ! wait_for_hit "$ALLOWED" "UDP:$BLOCKED_UDP" && container_running "$A_GW"; then
        ok "undeclared UDP port blocked"
    else
        bad "undeclared UDP port reached or gateway died"; local_fail=1
    fi

    if a_client_raw "ping -c 1 -W 2 $ALLOWED_IP >/dev/null" >/dev/null 2>&1; then
        ok "allowed ICMP echo reached target"
    else
        bad "allowed ICMP echo failed"; local_fail=1
    fi

    if ! a_client_raw "ping -c 1 -W 2 $DENIED_IP >/dev/null" >/dev/null 2>&1 \
       && container_running "$A_GW"; then
        ok "ICMP to undeclared destination blocked"
    else
        bad "ICMP to undeclared destination was not blocked"; local_fail=1
    fi

    if ! a_client "ip route get 1.1.1.1 >/dev/null" >/dev/null 2>&1; then
        ok "scanner has no direct external route"
    else
        bad "scanner unexpectedly has a route outside the declared target subnet"; local_fail=1
    fi

    hdr "Architecture A nftables counters"
    podman exec "$A_GW" nft -a list table inet asf_gateway_filter | sed 's/^/  /'
    podman exec "$A_GW" nft -a list table ip asf_gateway_nat | sed 's/^/  /'

    if (( local_fail == 0 )); then
        A_ENFORCED_OK=1
    fi
}

# ── Architecture B: filter-init sidecar in shared scanner namespace ────────

start_architecture_b() {
    hdr "G6  Architecture B — shared namespace + filter-init sidecar"
    B_CONTROL_VALID=0
    B_ENFORCED_OK=0

    podman rm -f "$B_NS" >/dev/null 2>&1 || true
    podman run -d --name "$B_NS" \
        --network "$TARGET_NET:ip=$B_NS_IP" \
        --cap-drop ALL --security-opt no-new-privileges \
        "$IMAGE" sleep infinity >/dev/null \
        && ok "capability-less scanner namespace attached directly to target network" \
        || { bad "Architecture B namespace failed to start"; return 1; }
}

b_positive_control() {
    hdr "G6A  Architecture B positive control"
    reset_hits
    b_client "curl -fsS --max-time 3 http://$ALLOWED_IP:$BLOCKED_TCP/ >/dev/null" >/dev/null || true
    if wait_for_hit "$ALLOWED" "TCP:$BLOCKED_TCP"; then
        ok "control reached otherwise-blocked TCP port"
    else
        bad "control could not reach otherwise-blocked TCP port"
        return 1
    fi

    reset_hits
    b_client "curl -fsS --max-time 3 http://$DENIED_IP:$ALLOWED_TCP/ >/dev/null" >/dev/null || true
    if wait_for_hit "$DENIED" "TCP:$ALLOWED_TCP"; then
        ok "control reached otherwise-denied target"
    else
        bad "control could not reach otherwise-denied target"
        return 1
    fi

    reset_hits
    b_client "printf 'UDP:$BLOCKED_UDP\\n' | nc -u -w 1 $ALLOWED_IP $BLOCKED_UDP" >/dev/null || true
    if wait_for_hit "$ALLOWED" "UDP:$BLOCKED_UDP"; then
        ok "control reached otherwise-blocked UDP port"
    else
        bad "control could not reach otherwise-blocked UDP port"
        return 1
    fi

    if b_client_raw "ping -c 1 -W 2 $DENIED_IP >/dev/null" >/dev/null 2>&1; then
        ok "control reached otherwise-denied target with ICMP"
    else
        bad "control could not reach otherwise-denied target with ICMP"
        return 1
    fi

    B_CONTROL_VALID=1
}

b_apply_policy() {
    timeout 40 podman run --rm \
        --network "container:${B_NS}" \
        --cap-drop ALL --cap-add NET_ADMIN \
        "$IMAGE" sh -c "nft -f - <<'NFT'
flush ruleset
table inet asf_runtime_output {
  chain output {
    type filter hook output priority filter; policy drop;

    oifname \"lo\" counter accept
    ct state established,related counter accept

    ip daddr $ALLOWED_IP tcp dport $ALLOWED_TCP counter accept
    ip daddr $ALLOWED_IP udp dport $ALLOWED_UDP counter accept
    ip daddr $ALLOWED_IP icmp type echo-request counter accept

    counter drop
  }
}
NFT" >/dev/null 2>&1
}

b_enforcement_matrix() {
    hdr "G6B  Architecture B enforced matrix"
    if (( B_CONTROL_VALID == 0 )); then
        skip "inconclusive: Architecture B positive control failed"
        return 1
    fi

    if b_apply_policy; then
        ok "filter-init sidecar applied default-deny OUTPUT policy and exited"
    else
        bad "filter-init sidecar could not apply policy"
        return 1
    fi

    local local_fail=0

    reset_hits
    if b_client "curl -fsS --max-time 3 http://$ALLOWED_IP:$ALLOWED_TCP/ >/dev/null" >/dev/null \
       && wait_for_hit "$ALLOWED" "TCP:$ALLOWED_TCP"; then
        ok "allowed TCP target/port reached"
    else
        bad "allowed TCP target/port failed"; local_fail=1
    fi

    reset_hits
    b_client "curl -fsS --max-time 2 http://$ALLOWED_IP:$BLOCKED_TCP/ >/dev/null" >/dev/null || true
    if ! wait_for_hit "$ALLOWED" "TCP:$BLOCKED_TCP" && container_running "$B_NS"; then
        ok "undeclared TCP port blocked"
    else
        bad "undeclared TCP port reached or namespace holder died"; local_fail=1
    fi

    reset_hits
    b_client "curl -fsS --max-time 2 http://$DENIED_IP:$ALLOWED_TCP/ >/dev/null" >/dev/null || true
    if ! wait_for_hit "$DENIED" "TCP:$ALLOWED_TCP" && container_running "$B_NS"; then
        ok "undeclared destination blocked"
    else
        bad "undeclared destination reached or namespace holder died"; local_fail=1
    fi

    reset_hits
    b_client "printf 'UDP:$ALLOWED_UDP\\n' | nc -u -w 1 $ALLOWED_IP $ALLOWED_UDP" >/dev/null || true
    if wait_for_hit "$ALLOWED" "UDP:$ALLOWED_UDP"; then
        ok "allowed UDP target/port reached"
    else
        bad "allowed UDP target/port failed"; local_fail=1
    fi

    reset_hits
    b_client "printf 'UDP:$BLOCKED_UDP\\n' | nc -u -w 1 $ALLOWED_IP $BLOCKED_UDP" >/dev/null || true
    if ! wait_for_hit "$ALLOWED" "UDP:$BLOCKED_UDP" && container_running "$B_NS"; then
        ok "undeclared UDP port blocked"
    else
        bad "undeclared UDP port reached or namespace holder died"; local_fail=1
    fi

    if b_client_raw "ping -c 1 -W 2 $ALLOWED_IP >/dev/null" >/dev/null 2>&1; then
        ok "allowed ICMP echo reached target"
    else
        bad "allowed ICMP echo failed"; local_fail=1
    fi

    if ! b_client_raw "ping -c 1 -W 2 $DENIED_IP >/dev/null" >/dev/null 2>&1 \
       && container_running "$B_NS"; then
        ok "ICMP to undeclared destination blocked"
    else
        bad "ICMP to undeclared destination was not blocked"; local_fail=1
    fi

    if ! b_client "ip route get 1.1.1.1 >/dev/null" >/dev/null 2>&1; then
        ok "shared namespace has no direct external route"
    else
        bad "shared namespace unexpectedly has an external route"; local_fail=1
    fi

    if b_client "nft flush ruleset" >/dev/null 2>&1; then
        bad "capability-less scanner flushed its namespace policy"; local_fail=1
    else
        ok "capability-less scanner cannot flush the sidecar-installed policy"
    fi

    # Re-check an enforced denial after the attempted flush.
    reset_hits
    b_client "curl -fsS --max-time 2 http://$ALLOWED_IP:$BLOCKED_TCP/ >/dev/null" >/dev/null || true
    if ! wait_for_hit "$ALLOWED" "TCP:$BLOCKED_TCP"; then
        ok "blocked port remains blocked after attempted policy modification"
    else
        bad "policy no longer blocks the undeclared port"; local_fail=1
    fi

    hdr "Architecture B nftables counters"
    timeout 20 podman run --rm \
        --network "container:${B_NS}" \
        --cap-drop ALL --cap-add NET_ADMIN \
        "$IMAGE" nft -a list table inet asf_runtime_output 2>/dev/null \
        | sed 's/^/  /' || true

    if (( local_fail == 0 )); then
        B_ENFORCED_OK=1
    fi
}

# ── G7: capability semantics and scanner fidelity preview ──────────────────

test_icmp_and_nmap_semantics() {
    hdr "G7  ICMP and raw-scan capability semantics"

    if container_running "$A_NS"; then
        if a_client "ping -c 1 -W 2 $ALLOWED_IP >/dev/null" >/dev/null 2>&1; then
            ok "ICMP echo works in Architecture A without NET_RAW on this host"
            note "Do not make protocol=icmp automatically imply NET_RAW"
        elif a_client_raw "ping -c 1 -W 2 $ALLOWED_IP >/dev/null" >/dev/null 2>&1; then
            ok "ICMP echo works only when NET_RAW is explicitly granted"
            note "On this host, the manifest must request the capability for ping"
        else
            skip "ICMP echo unavailable even with NET_RAW"
        fi

        local st_out ss_out
        st_out=$(mktemp)
        ss_out=$(mktemp)
        if a_client "nmap -n -Pn -sT -p $ALLOWED_TCP,$BLOCKED_TCP --host-timeout 8s $ALLOWED_IP" \
             >"$st_out" 2>&1; then
            if grep -q "${ALLOWED_TCP}/tcp.*open" "$st_out"; then
                ok "Nmap TCP-connect scan sees allowed port $ALLOWED_TCP"
            else
                bad "Nmap TCP-connect scan did not see allowed port $ALLOWED_TCP"
            fi
            if grep -q "${BLOCKED_TCP}/tcp.*open" "$st_out"; then
                bad "Nmap TCP-connect scan saw blocked port $BLOCKED_TCP as open"
            else
                ok "Nmap TCP-connect scan does not see blocked port as open"
            fi
        else
            skip "Nmap TCP-connect scan did not complete"
        fi

        if a_client_raw "nmap -n -Pn -sS -p $ALLOWED_TCP --host-timeout 8s $ALLOWED_IP" \
             >"$ss_out" 2>&1; then
            if grep -q "${ALLOWED_TCP}/tcp.*open" "$ss_out"; then
                ok "Nmap SYN scan works in the controlled bridge topology with NET_RAW"
            else
                skip "Nmap SYN scan ran but did not classify the allowed port as open"
            fi
        else
            skip "Nmap SYN scan unavailable with the tested rootless capability set"
        fi
        rm -f "$st_out" "$ss_out"
    else
        skip "Architecture A namespace unavailable; capability tests skipped"
    fi
}

# ── G8 is embedded in both A route immutability and B firewall immutability ─

print_verdict() {
    hdr "Verdict"
    printf '  route supplied by Podman: %s\n' "$([[ ${ROUTE_VIA_PODMAN:-0} == 1 ]] && echo yes || echo no)"
    printf '  Architecture A route method: %s\n' "${A_ROUTE_METHOD:-untested}"
    printf '  Architecture A enforced matrix: %s\n' "$([[ ${A_ENFORCED_OK:-0} == 1 ]] && echo passed || echo failed/inconclusive)"
    printf '  Architecture B enforced matrix: %s\n' "$([[ ${B_ENFORCED_OK:-0} == 1 ]] && echo passed || echo failed/inconclusive)"
    echo

    if (( ${A_ENFORCED_OK:-0} == 1 )); then
        if [[ "${A_ROUTE_METHOD:-}" == "podman" ]]; then
            echo "  RESULT: A1 VIABLE — Podman injects the route; the scanner needs no NET_ADMIN."
            echo "  This is the preferred design: routing and enforcement remain outside the runtime."
        else
            echo "  RESULT: A2 VIABLE — a trusted route-init sidecar adds the route and exits."
            echo "  The scanner itself has no NET_ADMIN, while enforcement remains in a separate gateway."
        fi
    elif (( ${B_ENFORCED_OK:-0} == 1 )); then
        echo "  RESULT: B VIABLE AS FALLBACK — filter-init sidecar enforcement works."
        echo "  Caveat: the scanner is directly attached to the target-facing network namespace."
    else
        echo "  RESULT: CONTROLLED ROOTLESS ROUTED MODE NOT PROVEN."
        echo "  Inspect G1/G2, route setup, positive controls and nftables counters."
    fi

    echo
    echo "  Stage 1 does not prove real-LAN or pasta fidelity. A separate Stage 2 should"
    echo "  use a controlled listener on the host/LAN and test TCP-connect, UDP, ICMP,"
    echo "  SYN scans and bypass behavior independently."
    echo
    echo "  passed: $PASS   failed: $FAIL   skipped: $SKIP   warnings: $WARN"
}

# ── Main ────────────────────────────────────────────────────────────────────

hdr "Build"
build_image || exit 1

test_gateway_primitives
start_targets || exit 1
test_route_ownership

if start_architecture_a; then
    a_positive_control || true
    a_enforcement_matrix || true
else
    skip "Architecture A setup did not complete"
fi

start_architecture_b || true
if container_running "$B_NS"; then
    b_positive_control || true
    b_enforcement_matrix || true
fi

test_icmp_and_nmap_semantics
print_verdict
