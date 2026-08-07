#!/usr/bin/env bash
# LEGACY VALIDATION — superseded for CI by tests/test_routed_integration.sh.
#
# Retained because it covers one thing the production test does not: scanner
# fidelity across a rootless user-mode egress path (nmap TCP-connect, SYN and
# UDP scans, traceroute, OS-detection limits). That provides comparative evidence about
# what scanning genuinely works through the gateway.
#
# Everything else here — topology, enforced matrix, bypass check — is asserted
# by the production routed lifecycle on every session.
# spike-rootless-gateway-stage2.sh
#
# Stage 2 for ASF routed mode: can a capability-less scanner reach a real
# host/LAN target through a rootless Podman gateway while nftables enforces
# exact destination/protocol/port policy?
#
# Default lab topology:
#   host / libvirt bridge: <your bridge address>
#   QEMU target VM:        <your target address>
#
# The VM must already run listeners that reply on:
#   TCP 18080  (allowed)     TCP 19999  (positive-control only; later blocked)
#   UDP 18161  (allowed)     UDP 19998  (positive-control only; later blocked)
# and must answer ICMP echo.
#
# The script optionally starts listeners on the host bridge address as a
# controlled *undeclared destination*. Failure to reach those host listeners
# does not invalidate the VM tests; it makes only the destination-ACL row
# inconclusive.
#
# Usage:
#   chmod +x spike-rootless-gateway-stage2.sh
#   ./spike-rootless-gateway-stage2.sh
#
# Overrides:
#   TARGET_IP=<address> TARGET_ROUTE=<address>/32 ./spike-...
#   START_HOST_CONTROL=0 ./spike-...       # do not start host listeners
#   ./spike-rootless-gateway-stage2.sh --clean

set -uo pipefail

P="asf-gwstage2"
IMAGE="${P}/tools"

SCAN_NET="${P}-scan"
EGRESS_NET="${P}-egress"
GW="${P}-gateway"
SCANNER_NS="${P}-scanner-ns"

SCAN_SUBNET="${SCAN_SUBNET:-10.77.20.0/24}"
SCAN_NET_GW="${SCAN_NET_GW:-10.77.20.1}"
GW_SCAN_IP="${GW_SCAN_IP:-10.77.20.2}"
SCANNER_IP="${SCANNER_IP:-10.77.20.10}"

EGRESS_SUBNET="${EGRESS_SUBNET:-10.79.20.0/24}"
EGRESS_NET_GW="${EGRESS_NET_GW:-10.79.20.1}"
GW_EGRESS_IP="${GW_EGRESS_IP:-10.79.20.2}"

# No default target. A hardcoded LAN address would silently probe whichever
# host now owns it — possibly not yours, and possibly not one you may scan.
if [[ -z "${TARGET_IP:-}" ]]; then
    cat >&2 <<'USAGE'
TARGET_IP is required.

Point this spike at a host you are authorised to scan. It needs two OPEN TCP
ports: one to allow, and one to leave undeclared (the negative control must be
open, or "unreachable" proves nothing).

A ready-made target, run on the target host:
    python3 tools/routed_test_target.py --allowed-port 18080 --blocked-port 19999

Then:
    TARGET_IP=<address> TARGET_ROUTE=<address>/32 <this-script>
USAGE
    exit 2
fi
TARGET_IP="$TARGET_IP"
TARGET_ROUTE="${TARGET_ROUTE:-${TARGET_IP}/32}"
HOST_CONTROL_IP="${HOST_CONTROL_IP:-}"
START_HOST_CONTROL="${START_HOST_CONTROL:-1}"

ALLOWED_TCP="${ALLOWED_TCP:-18080}"
BLOCKED_TCP="${BLOCKED_TCP:-19999}"
ALLOWED_UDP="${ALLOWED_UDP:-18161}"
BLOCKED_UDP="${BLOCKED_UDP:-19998}"
CLOSED_TCP="${CLOSED_TCP:-19000}"
CLOSED_UDP="${CLOSED_UDP:-19001}"

HOST_TCP="${HOST_TCP:-18081}"
HOST_UDP="${HOST_UDP:-18162}"

PASS=0
FAIL=0
SKIP=0
WARN=0
HOST_SERVER_PID=""
TMP=""

ok()   { printf '  ✓ %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  ✗ %s\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '  – %s\n' "$*"; SKIP=$((SKIP+1)); }
warn() { printf '  ! %s\n' "$*"; WARN=$((WARN+1)); }
note() { printf '      %s\n' "$*"; }
hdr()  { printf '\n── %s ─────────────────────────────────────\n' "$*"; }

runtime_cleanup() {
    podman rm -f "$SCANNER_NS" "$GW" >/dev/null 2>&1 || true
    podman network rm -f "$SCAN_NET" "$EGRESS_NET" >/dev/null 2>&1 || true
    if [[ -n "$HOST_SERVER_PID" ]]; then
        kill "$HOST_SERVER_PID" >/dev/null 2>&1 || true
        wait "$HOST_SERVER_PID" >/dev/null 2>&1 || true
    fi
    [[ -n "$TMP" ]] && rm -rf "$TMP"
}

full_cleanup() {
    runtime_cleanup
    podman rmi -f "$IMAGE" >/dev/null 2>&1 || true
}

trap runtime_cleanup EXIT INT TERM

command -v podman >/dev/null 2>&1 || { echo "podman not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found"; exit 1; }

if [[ "${1:-}" == "--clean" ]]; then
    full_cleanup
    echo "cleaned"
    exit 0
fi

TMP=$(mktemp -d)
ROOTLESS=$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || echo unknown)
NET_BACKEND=$(podman info --format '{{.Host.NetworkBackend}}' 2>/dev/null || echo unknown)

printf 'podman: %s\n' "$(podman --version)"
printf 'rootless: %s\n' "$ROOTLESS"
printf 'network backend: %s\n' "$NET_BACKEND"
printf 'target: %s (route %s)\n' "$TARGET_IP" "$TARGET_ROUTE"

if [[ "$ROOTLESS" != "true" ]]; then
    warn "Podman does not report rootless=true; results do not answer the rootless question"
fi

build_image() {
    hdr "Build"
    mkdir -p "$TMP/image"
    cat >"$TMP/image/Containerfile" <<'EOF_IMAGE'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache \
      curl iproute2 iputils netcat-openbsd nftables nmap socat tcpdump traceroute
CMD ["sleep", "infinity"]
EOF_IMAGE

    if podman image exists "$IMAGE"; then
        ok "tools image already present"
    elif timeout 600 podman build -q -t "$IMAGE" "$TMP/image" >/dev/null 2>&1; then
        ok "built tools image (nftables, routing, curl, nc, nmap, socat)"
    else
        bad "tools image build failed"
        return 1
    fi
}

host_tcp() {
    local ip="$1" port="$2"
    curl --noproxy '*' --connect-timeout 3 --max-time 5 -fsS "http://${ip}:${port}/" 2>/dev/null
}

host_udp() {
    local ip="$1" port="$2" out
    out=$(printf 'asf-stage2-host\n' | nc -u -w 3 "$ip" "$port" 2>/dev/null || true)
    grep -q 'ok' <<<"$out"
}

start_host_control() {
    hdr "Optional host-side denied target"
    HOST_CONTROL_READY=0

    if [[ "$START_HOST_CONTROL" != "1" ]]; then
        skip "host-side control disabled (START_HOST_CONTROL=$START_HOST_CONTROL)"
        return 0
    fi

    cat >"$TMP/host-control.py" <<'EOF_PY'
#!/usr/bin/env python3
import socket
import sys
import threading

bind_ip = sys.argv[1]
tcp_port = int(sys.argv[2])
udp_port = int(sys.argv[3])
log_path = sys.argv[4]
lock = threading.Lock()


def log(line: str) -> None:
    with lock:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def tcp() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind_ip, tcp_port))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(4096)
                log(f"TCP:{tcp_port} source={addr[0]}:{addr[1]} bytes={len(data)}")
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


def udp() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((bind_ip, udp_port))
        while True:
            data, addr = s.recvfrom(65535)
            log(f"UDP:{udp_port} source={addr[0]}:{addr[1]} bytes={len(data)}")
            s.sendto(b"ok", addr)


open(log_path, "w", encoding="utf-8").close()
threading.Thread(target=tcp, daemon=True).start()
threading.Thread(target=udp, daemon=True).start()
threading.Event().wait()
EOF_PY

    python3 "$TMP/host-control.py" "$HOST_CONTROL_IP" "$HOST_TCP" "$HOST_UDP" \
        "$TMP/host-control.log" >"$TMP/host-control.out" 2>&1 &
    HOST_SERVER_PID=$!
    sleep 1

    if ! kill -0 "$HOST_SERVER_PID" >/dev/null 2>&1; then
        warn "could not start host listeners on ${HOST_CONTROL_IP}; destination-ACL control will be skipped"
        sed 's/^/      /' "$TMP/host-control.out" 2>/dev/null || true
        HOST_SERVER_PID=""
        return 0
    fi

    if host_tcp "$HOST_CONTROL_IP" "$HOST_TCP" >/dev/null && host_udp "$HOST_CONTROL_IP" "$HOST_UDP"; then
        HOST_CONTROL_READY=1
        ok "host listeners ready at ${HOST_CONTROL_IP}:${HOST_TCP}/tcp and :${HOST_UDP}/udp"
    else
        warn "host listeners started but host baseline failed; destination-ACL control will be skipped"
    fi
}

host_baseline() {
    hdr "L0  Host-to-VM baseline"
    BASELINE_OK=1

    if host_tcp "$TARGET_IP" "$ALLOWED_TCP" >/dev/null; then
        ok "host reached target TCP $ALLOWED_TCP"
    else
        bad "host could not reach target TCP $ALLOWED_TCP"
        BASELINE_OK=0
    fi

    if host_tcp "$TARGET_IP" "$BLOCKED_TCP" >/dev/null; then
        ok "host reached target TCP $BLOCKED_TCP (future blocked-port control)"
    else
        bad "host could not reach target TCP $BLOCKED_TCP"
        BASELINE_OK=0
    fi

    if host_udp "$TARGET_IP" "$ALLOWED_UDP"; then
        ok "host reached target UDP $ALLOWED_UDP"
    else
        bad "host could not reach target UDP $ALLOWED_UDP"
        BASELINE_OK=0
    fi

    if host_udp "$TARGET_IP" "$BLOCKED_UDP"; then
        ok "host reached target UDP $BLOCKED_UDP (future blocked-port control)"
    else
        bad "host could not reach target UDP $BLOCKED_UDP"
        BASELINE_OK=0
    fi

    HOST_ICMP_OK=0
    if command -v ping >/dev/null 2>&1 && ping -c 1 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
        HOST_ICMP_OK=1
        ok "host reached target with ICMP echo"
    else
        warn "host ICMP echo failed or ping is unavailable; ICMP rows will be conditional"
    fi
}

create_topology() {
    hdr "L1  Rootless routed topology"
    podman rm -f "$SCANNER_NS" "$GW" >/dev/null 2>&1 || true
    podman network rm -f "$SCAN_NET" "$EGRESS_NET" >/dev/null 2>&1 || true

    if podman network create --internal \
          --subnet "$SCAN_SUBNET" --gateway "$SCAN_NET_GW" \
          --route "$TARGET_ROUTE,$GW_SCAN_IP" \
          "$SCAN_NET" >/dev/null; then
        ok "created internal scanner network with route $TARGET_ROUTE via $GW_SCAN_IP"
    else
        bad "failed to create scanner network with static route"
        return 1
    fi

    if podman network create \
          --subnet "$EGRESS_SUBNET" --gateway "$EGRESS_NET_GW" \
          "$EGRESS_NET" >/dev/null; then
        ok "created rootless egress network $EGRESS_SUBNET"
    else
        bad "failed to create egress network"
        return 1
    fi

    if podman run -d --name "$GW" \
          --cap-drop ALL --cap-add NET_ADMIN \
          --sysctl net.ipv4.ip_forward=1 \
          --network "$SCAN_NET:ip=$GW_SCAN_IP" \
          --network "$EGRESS_NET:ip=$GW_EGRESS_IP" \
          "$IMAGE" sleep infinity >/dev/null; then
        ok "gateway started with NET_ADMIN on scanner + egress networks"
    else
        bad "gateway failed to start"
        return 1
    fi

    # The network route is injected into every scan-network member, including
    # the gateway. Remove its self-referential copy so the egress default route
    # is used for TARGET_ROUTE.
    podman exec "$GW" ip route del "$TARGET_ROUTE" via "$GW_SCAN_IP" >/dev/null 2>&1 || true

    if podman run -d --name "$SCANNER_NS" \
          --network "$SCAN_NET:ip=$SCANNER_IP" \
          --cap-drop ALL --security-opt no-new-privileges \
          "$IMAGE" sleep infinity >/dev/null; then
        ok "capability-less scanner namespace started"
    else
        bad "scanner namespace failed to start"
        return 1
    fi

    note "scanner routes:"
    podman exec "$SCANNER_NS" ip route | sed 's/^/        /'
    note "gateway routes:"
    podman exec "$GW" ip route | sed 's/^/        /'

    if podman exec "$SCANNER_NS" sh -c \
          "ip route show '$TARGET_ROUTE' | grep -q 'via $GW_SCAN_IP'"; then
        ok "scanner has the expected Podman-injected route"
    else
        bad "scanner route is missing or points elsewhere"
        return 1
    fi

    if podman exec "$SCANNER_NS" ip route | grep -q '^default '; then
        bad "scanner unexpectedly has a default route"
    else
        ok "scanner has no direct default route"
    fi

    if podman run --rm --network "container:${SCANNER_NS}" \
          --cap-drop ALL --security-opt no-new-privileges \
          "$IMAGE" sh -c "ip route replace '$TARGET_ROUTE' via '$SCAN_NET_GW'" \
          >/dev/null 2>&1; then
        bad "capability-less scanner altered its route"
    else
        ok "capability-less scanner cannot alter its route"
    fi
}

gw_cmd() {
    timeout 20 podman exec "$GW" sh -c "$1" 2>&1
}

scanner_cmd() {
    timeout 20 podman run --rm \
        --network "container:${SCANNER_NS}" \
        --cap-drop ALL --security-opt no-new-privileges \
        "$IMAGE" sh -c "$1" 2>&1
}

scanner_raw_cmd() {
    timeout 120 podman run --rm \
        --network "container:${SCANNER_NS}" \
        --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges \
        "$IMAGE" sh -c "$1" 2>&1
}

scanner_long_cmd() {
    timeout 120 podman run --rm \
        --network "container:${SCANNER_NS}" \
        --cap-drop ALL --security-opt no-new-privileges \
        "$IMAGE" sh -c "$1" 2>&1
}

tcp_probe_cmd() {
    local ip="$1" port="$2"
    printf "curl --noproxy '*' --connect-timeout 3 --max-time 5 -fsS 'http://%s:%s/' >/dev/null" "$ip" "$port"
}

udp_probe_cmd() {
    local ip="$1" port="$2"
    printf "out=\$(printf 'asf-stage2\\n' | nc -u -w 3 '%s' '%s' 2>/dev/null || true); printf '%%s' \"\$out\" | grep -q ok" "$ip" "$port"
}

load_permissive_policy() {
    podman exec -i "$GW" nft -f - <<EOF_NFT
flush ruleset
table inet asf_stage2_filter {
  chain forward {
    type filter hook forward priority filter; policy accept;
    counter
  }
}
table ip asf_stage2_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $SCANNER_IP ip daddr $TARGET_ROUTE counter masquerade
  }
}
EOF_NFT
}

load_enforced_policy() {
    podman exec -i "$GW" nft -f - <<EOF_NFT
flush ruleset
table inet asf_stage2_filter {
  chain forward {
    type filter hook forward priority filter; policy drop;

    ct state established,related counter accept

    ip saddr $SCANNER_IP ip daddr $TARGET_IP tcp dport $ALLOWED_TCP counter accept
    ip saddr $SCANNER_IP ip daddr $TARGET_IP udp dport $ALLOWED_UDP counter accept
    ip saddr $SCANNER_IP ip daddr $TARGET_IP icmp type echo-request counter accept

    counter drop
  }
}
table ip asf_stage2_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $SCANNER_IP ip daddr $TARGET_ROUTE counter masquerade
  }
}
EOF_NFT
}

load_fidelity_policy() {
    podman exec -i "$GW" nft -f - <<EOF_NFT
flush ruleset
table inet asf_stage2_filter {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related counter accept
    ip saddr $SCANNER_IP ip daddr $TARGET_IP counter accept
    counter drop
  }
}
table ip asf_stage2_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $SCANNER_IP ip daddr $TARGET_ROUTE counter masquerade
  }
}
EOF_NFT
}

gateway_direct_baseline() {
    hdr "L2  Gateway direct reachability across rootless egress"
    GW_DIRECT_OK=1

    if gw_cmd "$(tcp_probe_cmd "$TARGET_IP" "$ALLOWED_TCP")" >/dev/null; then
        ok "gateway reached VM TCP $ALLOWED_TCP"
    else
        bad "gateway could not reach VM TCP $ALLOWED_TCP"
        GW_DIRECT_OK=0
    fi

    if gw_cmd "$(tcp_probe_cmd "$TARGET_IP" "$BLOCKED_TCP")" >/dev/null; then
        ok "gateway reached VM TCP $BLOCKED_TCP"
    else
        bad "gateway could not reach VM TCP $BLOCKED_TCP"
        GW_DIRECT_OK=0
    fi

    if gw_cmd "$(udp_probe_cmd "$TARGET_IP" "$ALLOWED_UDP")" >/dev/null; then
        ok "gateway reached VM UDP $ALLOWED_UDP"
    else
        bad "gateway could not reach VM UDP $ALLOWED_UDP"
        GW_DIRECT_OK=0
    fi

    if gw_cmd "$(udp_probe_cmd "$TARGET_IP" "$BLOCKED_UDP")" >/dev/null; then
        ok "gateway reached VM UDP $BLOCKED_UDP"
    else
        bad "gateway could not reach VM UDP $BLOCKED_UDP"
        GW_DIRECT_OK=0
    fi

    GW_ICMP_OK=0
    if gw_cmd "ping -c 1 -W 2 '$TARGET_IP'" >/dev/null; then
        GW_ICMP_OK=1
        ok "gateway reached VM with ICMP echo"
    else
        warn "gateway ICMP echo failed; ICMP forwarding may be unavailable"
    fi

    HOST_DEST_CONTROL=0
    if (( HOST_CONTROL_READY == 1 )); then
        if gw_cmd "$(tcp_probe_cmd "$HOST_CONTROL_IP" "$HOST_TCP")" >/dev/null \
           && gw_cmd "$(udp_probe_cmd "$HOST_CONTROL_IP" "$HOST_UDP")" >/dev/null; then
            HOST_DEST_CONTROL=1
            ok "gateway reached host-side undeclared-destination listeners"
        else
            warn "gateway cannot reach host-side listeners; destination-ACL row will be inconclusive"
        fi
    fi
}

positive_control() {
    hdr "L3  Permissive forwarding positive control"
    CONTROL_OK=1

    if load_permissive_policy; then
        ok "loaded permissive forwarding + NAT policy"
    else
        bad "failed to load permissive policy"
        CONTROL_OK=0
        return 1
    fi

    if scanner_cmd "$(tcp_probe_cmd "$TARGET_IP" "$ALLOWED_TCP")" >/dev/null; then
        ok "control reached VM TCP $ALLOWED_TCP"
    else
        bad "control could not reach VM TCP $ALLOWED_TCP"
        CONTROL_OK=0
    fi

    if scanner_cmd "$(tcp_probe_cmd "$TARGET_IP" "$BLOCKED_TCP")" >/dev/null; then
        ok "control reached future-blocked VM TCP $BLOCKED_TCP"
    else
        bad "control could not reach future-blocked VM TCP $BLOCKED_TCP"
        CONTROL_OK=0
    fi

    if scanner_cmd "$(udp_probe_cmd "$TARGET_IP" "$ALLOWED_UDP")" >/dev/null; then
        ok "control reached VM UDP $ALLOWED_UDP"
    else
        bad "control could not reach VM UDP $ALLOWED_UDP"
        CONTROL_OK=0
    fi

    if scanner_cmd "$(udp_probe_cmd "$TARGET_IP" "$BLOCKED_UDP")" >/dev/null; then
        ok "control reached future-blocked VM UDP $BLOCKED_UDP"
    else
        bad "control could not reach future-blocked VM UDP $BLOCKED_UDP"
        CONTROL_OK=0
    fi

    ICMP_CONTROL_OK=0
    if (( HOST_ICMP_OK == 1 && GW_ICMP_OK == 1 )) \
       && scanner_cmd "ping -c 1 -W 2 '$TARGET_IP'" >/dev/null; then
        ICMP_CONTROL_OK=1
        ok "control forwarded ICMP echo to VM"
    else
        warn "ICMP positive control unavailable; ICMP enforcement row will be skipped"
    fi

    DEST_CONTROL_OK=0
    if (( HOST_DEST_CONTROL == 1 )); then
        if scanner_cmd "$(tcp_probe_cmd "$HOST_CONTROL_IP" "$HOST_TCP")" >/dev/null \
           && scanner_cmd "$(udp_probe_cmd "$HOST_CONTROL_IP" "$HOST_UDP")" >/dev/null; then
            DEST_CONTROL_OK=1
            ok "control reached future-denied host destination"
        else
            warn "scanner could not reach host-side control through permissive gateway"
        fi
    fi
}

enforced_matrix() {
    hdr "L4  Enforced VM policy matrix"
    ENFORCED_OK=1

    if (( CONTROL_OK == 0 )); then
        skip "enforcement matrix inconclusive: permissive control failed"
        ENFORCED_OK=0
        return 1
    fi

    if load_enforced_policy; then
        ok "loaded default-deny policy for exact VM/protocol/ports"
    else
        bad "failed to load enforced policy"
        ENFORCED_OK=0
        return 1
    fi

    if scanner_cmd "$(tcp_probe_cmd "$TARGET_IP" "$ALLOWED_TCP")" >/dev/null; then
        ok "allowed VM TCP $ALLOWED_TCP reached"
    else
        bad "allowed VM TCP $ALLOWED_TCP failed"
        ENFORCED_OK=0
    fi

    if scanner_cmd "$(tcp_probe_cmd "$TARGET_IP" "$BLOCKED_TCP")" >/dev/null; then
        bad "undeclared VM TCP $BLOCKED_TCP reached"
        ENFORCED_OK=0
    else
        ok "undeclared VM TCP $BLOCKED_TCP blocked"
    fi

    if scanner_cmd "$(udp_probe_cmd "$TARGET_IP" "$ALLOWED_UDP")" >/dev/null; then
        ok "allowed VM UDP $ALLOWED_UDP reached"
    else
        bad "allowed VM UDP $ALLOWED_UDP failed"
        ENFORCED_OK=0
    fi

    if scanner_cmd "$(udp_probe_cmd "$TARGET_IP" "$BLOCKED_UDP")" >/dev/null; then
        bad "undeclared VM UDP $BLOCKED_UDP reached"
        ENFORCED_OK=0
    else
        ok "undeclared VM UDP $BLOCKED_UDP blocked"
    fi

    if (( ICMP_CONTROL_OK == 1 )); then
        if scanner_cmd "ping -c 1 -W 2 '$TARGET_IP'" >/dev/null; then
            ok "allowed ICMP echo reached VM"
        else
            bad "allowed ICMP echo failed after a valid positive control"
            ENFORCED_OK=0
        fi
    else
        skip "ICMP enforcement row inconclusive: positive control unavailable"
    fi

    if (( DEST_CONTROL_OK == 1 )); then
        if scanner_cmd "$(tcp_probe_cmd "$HOST_CONTROL_IP" "$HOST_TCP")" >/dev/null; then
            bad "undeclared host destination reached over TCP"
            ENFORCED_OK=0
        else
            ok "undeclared host destination blocked over TCP"
        fi

        if scanner_cmd "$(udp_probe_cmd "$HOST_CONTROL_IP" "$HOST_UDP")" >/dev/null; then
            bad "undeclared host destination reached over UDP"
            ENFORCED_OK=0
        else
            ok "undeclared host destination blocked over UDP"
        fi
    else
        skip "destination-IP ACL row inconclusive: host destination positive control unavailable"
    fi

    if scanner_cmd "curl --connect-timeout 2 --max-time 3 -fsS http://1.1.1.1/" >/dev/null; then
        bad "scanner reached an external IPv4 destination outside TARGET_ROUTE"
        ENFORCED_OK=0
    else
        ok "scanner has no IPv4 bypass outside the injected route"
    fi

    if scanner_cmd "ip -6 route | grep -q '^default '" >/dev/null; then
        bad "scanner has an IPv6 default route"
        ENFORCED_OK=0
    else
        ok "scanner has no IPv6 default route"
    fi

    if scanner_cmd "curl -g --connect-timeout 2 --max-time 3 -fsS 'http://[2606:4700:4700::1111]/'" >/dev/null; then
        bad "scanner reached external IPv6"
        ENFORCED_OK=0
    else
        ok "scanner has no IPv6 egress bypass"
    fi

    if scanner_cmd "nft flush ruleset" >/dev/null; then
        bad "capability-less scanner altered nftables"
        ENFORCED_OK=0
    else
        ok "capability-less scanner cannot alter gateway policy"
    fi

    hdr "Gateway nftables counters"
    podman exec "$GW" nft list ruleset | sed 's/^/  /'
}

fidelity_matrix() {
    hdr "L5  Scanner fidelity across rootless user-mode egress"

    if (( CONTROL_OK == 0 )); then
        skip "scanner-fidelity tests skipped: transitive forwarding was not proven"
        return 0
    fi

    if load_fidelity_policy; then
        ok "loaded target-only fidelity policy (all protocols/ports to VM only)"
    else
        bad "failed to load fidelity policy"
        return 1
    fi

    local out

    out=$(scanner_long_cmd "nmap -n -Pn -sT -p ${ALLOWED_TCP},${CLOSED_TCP} '$TARGET_IP'" || true)
    printf '%s\n' "$out" | sed 's/^/      /'
    if grep -Eq "^${ALLOWED_TCP}/tcp[[:space:]]+open" <<<"$out"; then
        ok "Nmap TCP-connect scan sees TCP $ALLOWED_TCP open"
    else
        bad "Nmap TCP-connect scan did not see TCP $ALLOWED_TCP open"
    fi

    out=$(scanner_raw_cmd "nmap -n -Pn -sS -p ${ALLOWED_TCP},${CLOSED_TCP} '$TARGET_IP'" || true)
    printf '%s\n' "$out" | sed 's/^/      /'
    if grep -Eq "^${ALLOWED_TCP}/tcp[[:space:]]+open" <<<"$out"; then
        ok "Nmap SYN scan sees TCP $ALLOWED_TCP open"
        SYN_FIDELITY="works"
    else
        warn "Nmap SYN scan did not identify TCP $ALLOWED_TCP as open"
        SYN_FIDELITY="degraded"
    fi

    out=$(scanner_raw_cmd "nmap -n -Pn -sU --max-retries 1 --host-timeout 45s -p ${ALLOWED_UDP},${CLOSED_UDP} '$TARGET_IP'" || true)
    printf '%s\n' "$out" | sed 's/^/      /'
    if grep -Eq "^${ALLOWED_UDP}/udp[[:space:]]+open" <<<"$out"; then
        ok "Nmap UDP scan sees UDP $ALLOWED_UDP open"
        UDP_FIDELITY="works"
    else
        warn "Nmap UDP scan did not conclusively identify UDP $ALLOWED_UDP as open"
        UDP_FIDELITY="degraded-or-inconclusive"
    fi

    out=$(scanner_long_cmd "nmap -n -Pn -sT -sV --version-light -p ${ALLOWED_TCP} '$TARGET_IP'" || true)
    printf '%s\n' "$out" | sed 's/^/      /'
    if grep -Eq "^${ALLOWED_TCP}/tcp[[:space:]]+open" <<<"$out"; then
        ok "Nmap service detection reached TCP $ALLOWED_TCP"
    else
        warn "Nmap service detection did not complete successfully"
    fi

    out=$(scanner_raw_cmd "nmap -n -Pn -O --osscan-limit --max-os-tries 1 -p ${ALLOWED_TCP},${CLOSED_TCP} '$TARGET_IP'" || true)
    printf '%s\n' "$out" | sed 's/^/      /'
    if grep -Eq 'OS details:|Running:|Aggressive OS guesses:' <<<"$out"; then
        ok "Nmap OS detection produced an OS result"
        OS_FIDELITY="result-produced"
    else
        warn "Nmap OS detection produced no conclusive OS result"
        OS_FIDELITY="inconclusive"
    fi

    out=$(scanner_raw_cmd "traceroute -n -m 6 -w 2 '$TARGET_IP'" || true)
    printf '%s\n' "$out" | sed 's/^/      /'
    if grep -q "$TARGET_IP" <<<"$out"; then
        ok "traceroute reached the VM"
    else
        warn "traceroute did not reach the VM conclusively"
    fi
}

bypass_by_gateway_removal() {
    hdr "L6  Enforcement-point removal / bypass check"

    if (( CONTROL_OK == 0 )); then
        skip "gateway-removal test skipped: forwarding baseline was not valid"
        return 0
    fi

    podman stop -t 1 "$GW" >/dev/null 2>&1 || true
    if scanner_cmd "$(tcp_probe_cmd "$TARGET_IP" "$ALLOWED_TCP")" >/dev/null; then
        bad "scanner still reached VM after gateway stopped — hidden bypass exists"
    else
        ok "scanner cannot reach VM when the gateway enforcement point is absent"
    fi
}

verdict() {
    hdr "Verdict"
    printf '  host baseline:              %s\n' "$([[ ${BASELINE_OK:-0} == 1 ]] && echo passed || echo failed)"
    printf '  gateway direct LAN egress: %s\n' "$([[ ${GW_DIRECT_OK:-0} == 1 ]] && echo passed || echo failed)"
    printf '  permissive forwarding:     %s\n' "$([[ ${CONTROL_OK:-0} == 1 ]] && echo passed || echo failed)"
    printf '  enforced policy matrix:    %s\n' "$([[ ${ENFORCED_OK:-0} == 1 ]] && echo passed || echo failed)"
    printf '  SYN-scan fidelity:         %s\n' "${SYN_FIDELITY:-untested}"
    printf '  UDP-scan fidelity:         %s\n' "${UDP_FIDELITY:-untested}"
    printf '  OS-detection fidelity:     %s\n' "${OS_FIDELITY:-untested}"
    echo

    if [[ ${BASELINE_OK:-0} == 1 && ${GW_DIRECT_OK:-0} == 1 && ${CONTROL_OK:-0} == 1 && ${ENFORCED_OK:-0} == 1 ]]; then
        cat <<'TXT'
  RESULT: STAGE 2 CORE VIABLE

  A capability-less scanner reached the real VM only through the rootless
  routed gateway, and the gateway enforced exact destination/protocol/port
  rules. Classify raw-scanner support separately using the fidelity rows.
TXT
    elif [[ ${BASELINE_OK:-0} == 1 && ${GW_DIRECT_OK:-0} != 1 ]]; then
        cat <<'TXT'
  RESULT: ROOTLESS EGRESS BLOCKER

  The host can reach the VM, but the gateway cannot. The unresolved boundary
  is the gateway container's rootless egress path; transitive forwarding and
  policy results are not meaningful until this is fixed.
TXT
    elif [[ ${GW_DIRECT_OK:-0} == 1 && ${CONTROL_OK:-0} != 1 ]]; then
        cat <<'TXT'
  RESULT: TRANSITIVE FORWARDING BLOCKER

  The gateway itself reaches the VM, but scanner traffic does not traverse it
  under a permissive policy. Investigate rootless forwarding/NAT interaction.
TXT
    else
        cat <<'TXT'
  RESULT: STAGE 2 NOT PROVEN

  Review the first failed dependency above. Later blocked-path observations
  must not be treated as enforcement evidence when their positive control
  failed.
TXT
    fi

    echo
    printf '  passed: %d   failed: %d   skipped: %d   warnings: %d\n' \
        "$PASS" "$FAIL" "$SKIP" "$WARN"
    echo
    echo "  Check the VM log around this run. Expected successful probes should"
    echo "  appear with a host-side translated source address, not the runtime IP."
    if [[ -f "$TMP/host-control.log" ]]; then
        echo
        echo "  Host-side denied-target hit log:"
        sed 's/^/      /' "$TMP/host-control.log" || true
    fi
}

main() {
    build_image || exit 1
    start_host_control
    host_baseline

    if [[ ${BASELINE_OK:-0} != 1 ]]; then
        verdict
        exit 1
    fi

    create_topology || { verdict; exit 1; }
    gateway_direct_baseline

    if [[ ${GW_DIRECT_OK:-0} == 1 ]]; then
        positive_control
        enforced_matrix
        fidelity_matrix
        bypass_by_gateway_removal
    else
        skip "L3-L6 skipped because gateway direct egress failed"
    fi

    verdict
}

main "$@"
