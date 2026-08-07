#!/usr/bin/env bash
# LEGACY VALIDATION — covers internal + routed attachment together.
#
# Unique value: bidirectional agent-to-agent traffic on the internal network
# while routed policy is enforced (C3), and the parser/orchestrator invariants
# around it. The production lifecycle asserts the routed half of this on every
# session; the collaboration half has no production equivalent yet.
# spike-combined-internal-routed.sh
#
# Final ASF network-design spike:
#   Can one capability-limited scanner runtime participate in an ASF internal
#   agent network AND use a separately enforced routed gateway, without either
#   network creating a bypass?
#
# Proven topology under test:
#
#   parser/orchestrator ───── ASF internal network ───── scanner runtime
#                                                        │
#                                                        │ Podman static route
#                                                        ▼
#                                               routed gateway (NET_ADMIN)
#                                                        │
#                                                        ▼
#                                                declared external target
#
# The scanner joins two --internal networks:
#   1. ASF internal network: agent-to-agent communication and container DNS.
#   2. Scan network: only a static TARGET_ROUTE via the gateway; no default.
#
# The gateway alone joins the scan network and a rootless egress network.
# The scanner never receives NET_ADMIN. NET_RAW is optional and explicit.
# IPv4/IPv6 forwarding is explicitly disabled on ordinary runtimes and IPv4
# forwarding is explicitly enabled only on the routed gateway.
#
# The external target must already reply on:
#   TCP ALLOWED_TCP / BLOCKED_TCP
#   UDP ALLOWED_UDP / BLOCKED_UDP
#   ICMP echo (optional but recommended)
#
# Defaults match the earlier QEMU Stage 2 target. For a remote machine:
#   TARGET_IP=192.168.20.6 TARGET_ROUTE=192.168.20.6/32 ./spike-...
#
# Usage:
#   chmod +x spike-combined-internal-routed.sh
#   ./spike-combined-internal-routed.sh
#   ./spike-combined-internal-routed.sh --clean

set -uo pipefail

P="asf-combospike"
IMAGE="${P}/tools"

INTERNAL_NET="${P}-internal"
SCAN_NET="${P}-scan"
EGRESS_NET="${P}-egress"

PARSER="${P}-parser"
SCANNER="${P}-scanner"
GW="${P}-gateway"

INTERNAL_SUBNET="${INTERNAL_SUBNET:-10.76.30.0/24}"
INTERNAL_GW="${INTERNAL_GW:-10.76.30.1}"
SCANNER_INTERNAL_IP="${SCANNER_INTERNAL_IP:-10.76.30.10}"
PARSER_IP="${PARSER_IP:-10.76.30.20}"

SCAN_SUBNET="${SCAN_SUBNET:-10.77.30.0/24}"
SCAN_NET_GW="${SCAN_NET_GW:-10.77.30.1}"
GW_SCAN_IP="${GW_SCAN_IP:-10.77.30.2}"
SCANNER_SCAN_IP="${SCANNER_SCAN_IP:-10.77.30.10}"

EGRESS_SUBNET="${EGRESS_SUBNET:-10.79.30.0/24}"
EGRESS_NET_GW="${EGRESS_NET_GW:-10.79.30.1}"
GW_EGRESS_IP="${GW_EGRESS_IP:-10.79.30.2}"

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
ALLOWED_TCP="${ALLOWED_TCP:-18080}"
BLOCKED_TCP="${BLOCKED_TCP:-19999}"
ALLOWED_UDP="${ALLOWED_UDP:-18161}"
BLOCKED_UDP="${BLOCKED_UDP:-19998}"

PARSER_TCP="${PARSER_TCP:-8088}"
PARSER_UDP="${PARSER_UDP:-8089}"
SCANNER_SERVICE_TCP="${SCANNER_SERVICE_TCP:-8090}"
SCANNER_NET_RAW="${SCANNER_NET_RAW:-1}"

PASS=0
FAIL=0
SKIP=0
WARN=0
TMP=""

ok()   { printf '  ✓ %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  ✗ %s\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '  – %s\n' "$*"; SKIP=$((SKIP+1)); }
warn() { printf '  ! %s\n' "$*"; WARN=$((WARN+1)); }
note() { printf '      %s\n' "$*"; }
hdr()  { printf '\n── %s ─────────────────────────────────────\n' "$*"; }

runtime_cleanup() {
    podman rm -f "$PARSER" "$SCANNER" "$GW" >/dev/null 2>&1 || true
    podman network rm -f "$INTERNAL_NET" "$SCAN_NET" "$EGRESS_NET" >/dev/null 2>&1 || true
    [[ -n "$TMP" ]] && rm -rf "$TMP"
}

full_cleanup() {
    runtime_cleanup
    podman rmi -f "$IMAGE" >/dev/null 2>&1 || true
}

trap runtime_cleanup EXIT INT TERM

command -v podman >/dev/null 2>&1 || { echo "podman not found"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "host curl not found"; exit 1; }
command -v nc >/dev/null 2>&1 || { echo "host nc not found"; exit 1; }

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
printf 'scanner NET_RAW: %s\n' "$SCANNER_NET_RAW"

if [[ "$ROOTLESS" != "true" ]]; then
    warn "Podman does not report rootless=true; results do not answer the rootless question"
fi

build_image() {
    hdr "Build"
    mkdir -p "$TMP/image"
    cat >"$TMP/image/Containerfile" <<'EOF_IMAGE'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache \
      bind-tools curl iproute2 iputils netcat-openbsd nftables python3 socat

COPY internal-service.py /usr/local/bin/internal-service.py
CMD ["sleep", "infinity"]
EOF_IMAGE

    cat >"$TMP/image/internal-service.py" <<'EOF_PY'
#!/usr/bin/env python3
import socket
import sys
import threading
from pathlib import Path

name = sys.argv[1]
tcp_port = int(sys.argv[2])
udp_port = int(sys.argv[3])
log_path = Path("/tmp/hits")
lock = threading.Lock()


def log(message: str) -> None:
    line = f"{name} {message}\n"
    with lock:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line)
    print(line, end="", flush=True)


def tcp_listener() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", tcp_port))
        server.listen()
        log(f"TCP:{tcp_port} listening")
        while True:
            connection, address = server.accept()
            with connection:
                try:
                    payload = connection.recv(4096)
                    log(f"TCP:{tcp_port} HIT source={address[0]}:{address[1]} bytes={len(payload)}")
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Length: 2\r\n"
                        b"Connection: close\r\n\r\n"
                        b"ok"
                    )
                except OSError as error:
                    log(f"TCP:{tcp_port} error={error}")


def udp_listener() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", udp_port))
        log(f"UDP:{udp_port} listening")
        while True:
            payload, address = server.recvfrom(65535)
            log(f"UDP:{udp_port} HIT source={address[0]}:{address[1]} bytes={len(payload)}")
            server.sendto(b"ok", address)


log_path.write_text("", encoding="utf-8")
threads = [threading.Thread(target=tcp_listener, daemon=True)]
if udp_port > 0:
    threads.append(threading.Thread(target=udp_listener, daemon=True))
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
EOF_PY

    if podman image exists "$IMAGE"; then
        ok "tools image already present"
    elif timeout 600 podman build -q -t "$IMAGE" "$TMP/image" >/dev/null 2>&1; then
        ok "built tools image (DNS, routing, nftables, TCP/UDP services)"
    else
        bad "tools image build failed"
        return 1
    fi
}

host_tcp() {
    curl --noproxy '*' --connect-timeout 3 --max-time 5 -fsS \
        "http://$1:$2/" >/dev/null 2>&1
}

host_udp() {
    local out
    out=$(printf 'asf-combo-host\n' | nc -u -w 3 "$1" "$2" 2>/dev/null || true)
    grep -q 'ok' <<<"$out"
}

container_tcp() {
    local container="$1" ip="$2" port="$3"
    timeout 10 podman exec "$container" sh -c \
        "curl --noproxy '*' --connect-timeout 3 --max-time 5 -fsS 'http://${ip}:${port}/' >/dev/null" \
        >/dev/null 2>&1
}

container_udp() {
    local container="$1" ip="$2" port="$3" out
    out=$(timeout 10 podman exec "$container" sh -c \
        "printf 'asf-combo\\n' | nc -u -w 3 '${ip}' '${port}'" 2>/dev/null || true)
    grep -q 'ok' <<<"$out"
}

wait_for_tcp() {
    local container="$1" ip="$2" port="$3" i
    for i in $(seq 1 25); do
        container_tcp "$container" "$ip" "$port" && return 0
        sleep 0.2
    done
    return 1
}

host_baseline() {
    hdr "C0  External target baseline"
    BASELINE_OK=1

    host_tcp "$TARGET_IP" "$ALLOWED_TCP" \
        && ok "host reached target TCP $ALLOWED_TCP" \
        || { bad "host could not reach target TCP $ALLOWED_TCP"; BASELINE_OK=0; }

    host_tcp "$TARGET_IP" "$BLOCKED_TCP" \
        && ok "host reached future-blocked target TCP $BLOCKED_TCP" \
        || { bad "host could not reach target TCP $BLOCKED_TCP"; BASELINE_OK=0; }

    host_udp "$TARGET_IP" "$ALLOWED_UDP" \
        && ok "host reached target UDP $ALLOWED_UDP" \
        || { bad "host could not reach target UDP $ALLOWED_UDP"; BASELINE_OK=0; }

    host_udp "$TARGET_IP" "$BLOCKED_UDP" \
        && ok "host reached future-blocked target UDP $BLOCKED_UDP" \
        || { bad "host could not reach target UDP $BLOCKED_UDP"; BASELINE_OK=0; }

    HOST_ICMP_OK=0
    if command -v ping >/dev/null 2>&1 && ping -c 1 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
        HOST_ICMP_OK=1
        ok "host reached target with ICMP echo"
    else
        warn "host ICMP baseline failed; ICMP rows will be conditional"
    fi
}

create_topology() {
    hdr "C1  Combined internal + routed topology"
    podman rm -f "$PARSER" "$SCANNER" "$GW" >/dev/null 2>&1 || true
    podman network rm -f "$INTERNAL_NET" "$SCAN_NET" "$EGRESS_NET" >/dev/null 2>&1 || true

    podman network create --internal \
        --subnet "$INTERNAL_SUBNET" --gateway "$INTERNAL_GW" \
        "$INTERNAL_NET" >/dev/null \
        && ok "created ASF internal network $INTERNAL_SUBNET" \
        || { bad "failed to create ASF internal network"; return 1; }

    podman network create --internal \
        --subnet "$SCAN_SUBNET" --gateway "$SCAN_NET_GW" \
        --route "$TARGET_ROUTE,$GW_SCAN_IP" \
        "$SCAN_NET" >/dev/null \
        && ok "created scan network with route $TARGET_ROUTE via $GW_SCAN_IP" \
        || { bad "failed to create scan network"; return 1; }

    podman network create \
        --subnet "$EGRESS_SUBNET" --gateway "$EGRESS_NET_GW" \
        "$EGRESS_NET" >/dev/null \
        && ok "created rootless egress network $EGRESS_SUBNET" \
        || { bad "failed to create egress network"; return 1; }

    podman run -d --name "$GW" \
        --cap-drop ALL --cap-add NET_ADMIN \
        --security-opt no-new-privileges \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.ipv6.conf.all.forwarding=0 \
        --network "$SCAN_NET:ip=$GW_SCAN_IP" \
        --network "$EGRESS_NET:ip=$GW_EGRESS_IP" \
        "$IMAGE" sleep infinity >/dev/null \
        && ok "gateway started on scan + egress networks" \
        || { bad "gateway failed to start"; return 1; }

    # The Podman route is injected into all scan-network members, including the
    # gateway itself. Remove its self-referential copy so the gateway uses its
    # egress default route for TARGET_ROUTE.
    podman exec "$GW" ip route del "$TARGET_ROUTE" via "$GW_SCAN_IP" >/dev/null 2>&1 || true

    podman run -d --name "$PARSER" \
        --cap-drop ALL --security-opt no-new-privileges \
        --sysctl net.ipv4.ip_forward=0 \
        --sysctl net.ipv6.conf.all.forwarding=0 \
        --network "$INTERNAL_NET:ip=$PARSER_IP" \
        "$IMAGE" python3 /usr/local/bin/internal-service.py parser "$PARSER_TCP" "$PARSER_UDP" \
        >/dev/null \
        && ok "parser/orchestrator service started on internal network only" \
        || { bad "parser service failed to start"; return 1; }

    scanner_caps=(--cap-drop ALL)
    if [[ "$SCANNER_NET_RAW" == "1" ]]; then
        scanner_caps+=(--cap-add NET_RAW)
    fi

    podman run -d --name "$SCANNER" \
        "${scanner_caps[@]}" --security-opt no-new-privileges \
        --sysctl net.ipv4.ip_forward=0 \
        --sysctl net.ipv6.conf.all.forwarding=0 \
        --network "$INTERNAL_NET:ip=$SCANNER_INTERNAL_IP" \
        --network "$SCAN_NET:ip=$SCANNER_SCAN_IP" \
        "$IMAGE" python3 /usr/local/bin/internal-service.py scanner "$SCANNER_SERVICE_TCP" 0 \
        >/dev/null \
        && ok "scanner started on internal + scan networks without NET_ADMIN" \
        || { bad "scanner failed to start"; return 1; }

    if wait_for_tcp "$SCANNER" "$PARSER_IP" "$PARSER_TCP"; then
        ok "internal parser service is ready"
    else
        bad "internal parser service did not become reachable"
        return 1
    fi

    if wait_for_tcp "$PARSER" "$SCANNER_INTERNAL_IP" "$SCANNER_SERVICE_TCP"; then
        ok "internal scanner service is ready"
    else
        bad "internal scanner service did not become reachable"
        return 1
    fi

    note "scanner IPv4 addresses:"
    podman exec "$SCANNER" ip -4 -o addr show | sed 's/^/        /'
    note "scanner routes:"
    podman exec "$SCANNER" ip route | sed 's/^/        /'
    note "parser routes:"
    podman exec "$PARSER" ip route | sed 's/^/        /'
    note "gateway routes:"
    podman exec "$GW" ip route | sed 's/^/        /'
}

validate_topology() {
    hdr "C2  Route, DNS and capability invariants"
    TOPOLOGY_OK=1

    if podman exec "$SCANNER" sh -c \
        "ip route show '$TARGET_ROUTE' | grep -q 'via $GW_SCAN_IP'"; then
        ok "scanner has the exact target route via the gateway"
    else
        bad "scanner target route is missing or incorrect"
        TOPOLOGY_OK=0
    fi

    if podman exec "$SCANNER" ip route | grep -q '^default '; then
        bad "scanner unexpectedly has a default route"
        TOPOLOGY_OK=0
    else
        ok "scanner has no default route despite joining two networks"
    fi

    if podman exec "$PARSER" ip route | grep -q '^default '; then
        bad "parser unexpectedly has a default route"
        TOPOLOGY_OK=0
    else
        ok "parser has no default route"
    fi

    if [[ "$(podman exec "$SCANNER" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 1)" == "0" ]]; then
        ok "scanner has IPv4 forwarding disabled"
    else
        bad "scanner has IPv4 forwarding enabled"
        TOPOLOGY_OK=0
    fi

    if [[ "$(podman exec "$SCANNER" cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 1)" == "0" ]]; then
        ok "scanner has IPv6 forwarding disabled"
    else
        bad "scanner has IPv6 forwarding enabled"
        TOPOLOGY_OK=0
    fi

    if [[ "$(podman exec "$PARSER" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 1)" == "0" ]]; then
        ok "parser has IPv4 forwarding disabled"
    else
        bad "parser has IPv4 forwarding enabled"
        TOPOLOGY_OK=0
    fi

    if [[ "$(podman exec "$PARSER" cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 1)" == "0" ]]; then
        ok "parser has IPv6 forwarding disabled"
    else
        bad "parser has IPv6 forwarding enabled"
        TOPOLOGY_OK=0
    fi

    if [[ "$(podman exec "$GW" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" == "1" ]]; then
        ok "gateway has IPv4 forwarding enabled"
    else
        bad "gateway does not have IPv4 forwarding enabled"
        TOPOLOGY_OK=0
    fi

    if [[ "$(podman exec "$GW" cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo 1)" == "0" ]]; then
        ok "gateway has IPv6 forwarding disabled"
    else
        bad "gateway has IPv6 forwarding enabled"
        TOPOLOGY_OK=0
    fi

    if podman exec "$SCANNER" sh -c \
        "ip route replace '$TARGET_ROUTE' via '$SCAN_NET_GW'" >/dev/null 2>&1; then
        bad "scanner altered the Podman-injected route"
        TOPOLOGY_OK=0
    else
        ok "scanner cannot alter its route"
    fi

    if podman exec "$SCANNER" sh -c \
        "ip route add default via '$INTERNAL_GW'" >/dev/null 2>&1; then
        bad "scanner added an internal-network default route"
        TOPOLOGY_OK=0
    else
        ok "scanner cannot add a default route through the internal network"
    fi

    if podman exec "$PARSER" sh -c \
        "ip route add '$TARGET_ROUTE' via '$SCANNER_INTERNAL_IP'" >/dev/null 2>&1; then
        bad "parser added a route through the scanner"
        TOPOLOGY_OK=0
    else
        ok "parser cannot turn the scanner into a transit router"
    fi

    # Internal Podman DNS should resolve agent/container names, while an
    # --internal network should return NXDOMAIN for non-container names.
    if podman exec "$SCANNER" nslookup "$PARSER" 2>/dev/null | grep -q "$PARSER_IP"; then
        ok "scanner resolves the parser through internal container DNS"
    else
        warn "scanner could not resolve parser name; internal IP communication still works"
    fi

    if podman exec "$PARSER" nslookup "$SCANNER" 2>/dev/null | grep -q "$SCANNER_INTERNAL_IP"; then
        ok "parser resolves the scanner through internal container DNS"
    else
        warn "parser could not resolve scanner name; internal IP communication still works"
    fi

    if podman exec "$SCANNER" nslookup example.com >/dev/null 2>&1; then
        bad "scanner resolved an external hostname; routed v1 is not literal-IP-only"
        TOPOLOGY_OK=0
    else
        ok "scanner external DNS query is refused/NXDOMAIN"
    fi

    if podman exec "$PARSER" nslookup example.com >/dev/null 2>&1; then
        bad "parser resolved an external hostname on the internal network"
        TOPOLOGY_OK=0
    else
        ok "parser external DNS query is refused/NXDOMAIN"
    fi
}

internal_matrix() {
    hdr "C3  Bidirectional agent-to-agent communication"
    INTERNAL_OK=1

    podman exec "$PARSER" sh -c ': > /tmp/hits' >/dev/null 2>&1 || true
    podman exec "$SCANNER" sh -c ': > /tmp/hits' >/dev/null 2>&1 || true

    if container_tcp "$SCANNER" "$PARSER_IP" "$PARSER_TCP"; then
        ok "scanner reached parser over internal TCP"
    else
        bad "scanner could not reach parser over internal TCP"
        INTERNAL_OK=0
    fi

    if container_udp "$SCANNER" "$PARSER_IP" "$PARSER_UDP"; then
        ok "scanner reached parser over internal UDP"
    else
        bad "scanner could not reach parser over internal UDP"
        INTERNAL_OK=0
    fi

    if container_tcp "$PARSER" "$SCANNER_INTERNAL_IP" "$SCANNER_SERVICE_TCP"; then
        ok "parser reached scanner service over the internal network"
    else
        bad "parser could not reach scanner service"
        INTERNAL_OK=0
    fi

    sleep 0.5
    if podman exec "$PARSER" grep -q "source=${SCANNER_INTERNAL_IP}:" /tmp/hits 2>/dev/null; then
        ok "parser observed the scanner's internal-network source address"
    else
        bad "parser did not observe source $SCANNER_INTERNAL_IP"
        INTERNAL_OK=0
    fi

    if podman exec "$SCANNER" grep -q "source=${PARSER_IP}:" /tmp/hits 2>/dev/null; then
        ok "scanner observed the parser's internal-network source address"
    else
        bad "scanner did not observe source $PARSER_IP"
        INTERNAL_OK=0
    fi

    if podman exec "$PARSER" ip route get "$TARGET_IP" >/dev/null 2>&1; then
        bad "parser has a route to the routed target"
        INTERNAL_OK=0
    else
        ok "parser has no route to the routed target"
    fi

    if podman exec "$PARSER" ping -c 1 -W 2 "$GW_SCAN_IP" >/dev/null 2>&1; then
        bad "parser reached the scan-side gateway from the internal network"
        INTERNAL_OK=0
    else
        ok "parser cannot reach the scan-side gateway"
    fi
}

load_permissive_policy() {
    podman exec -i "$GW" nft -f - <<EOF_NFT
flush ruleset
table inet asf_combo_filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
  }
  chain output {
    type filter hook output priority filter; policy accept;
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    counter
  }
}
table ip asf_combo_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $SCANNER_SCAN_IP ip daddr $TARGET_ROUTE counter masquerade
  }
}
EOF_NFT
}

load_enforced_policy() {
    podman exec -i "$GW" nft -f - <<EOF_NFT
flush ruleset
table inet asf_combo_filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related counter accept
  }
  chain output {
    type filter hook output priority filter; policy accept;
  }
  chain forward {
    type filter hook forward priority filter; policy drop;

    ct state established,related counter accept

    ip saddr $SCANNER_SCAN_IP ip daddr $TARGET_IP tcp dport $ALLOWED_TCP counter accept
    ip saddr $SCANNER_SCAN_IP ip daddr $TARGET_IP udp dport $ALLOWED_UDP counter accept
    ip saddr $SCANNER_SCAN_IP ip daddr $TARGET_IP icmp type echo-request counter accept

    counter drop
  }
}
table ip asf_combo_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $SCANNER_SCAN_IP ip daddr $TARGET_ROUTE counter masquerade
  }
}
EOF_NFT
}

positive_control() {
    hdr "C4  Routed positive control with internal network still active"
    CONTROL_OK=1

    if load_permissive_policy; then
        ok "loaded permissive forwarding policy"
    else
        bad "failed to load permissive forwarding policy"
        CONTROL_OK=0
        return 1
    fi

    container_tcp "$SCANNER" "$TARGET_IP" "$ALLOWED_TCP" \
        && ok "control reached target TCP $ALLOWED_TCP" \
        || { bad "control could not reach target TCP $ALLOWED_TCP"; CONTROL_OK=0; }

    container_tcp "$SCANNER" "$TARGET_IP" "$BLOCKED_TCP" \
        && ok "control reached future-blocked target TCP $BLOCKED_TCP" \
        || { bad "control could not reach target TCP $BLOCKED_TCP"; CONTROL_OK=0; }

    container_udp "$SCANNER" "$TARGET_IP" "$ALLOWED_UDP" \
        && ok "control reached target UDP $ALLOWED_UDP" \
        || { bad "control could not reach target UDP $ALLOWED_UDP"; CONTROL_OK=0; }

    container_udp "$SCANNER" "$TARGET_IP" "$BLOCKED_UDP" \
        && ok "control reached future-blocked target UDP $BLOCKED_UDP" \
        || { bad "control could not reach target UDP $BLOCKED_UDP"; CONTROL_OK=0; }

    ICMP_CONTROL_OK=0
    if (( HOST_ICMP_OK == 1 )) && podman exec "$SCANNER" ping -c 1 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
        ICMP_CONTROL_OK=1
        ok "control forwarded ICMP echo"
    else
        warn "ICMP positive control unavailable; ICMP enforcement row will be skipped"
    fi

    if container_tcp "$SCANNER" "$PARSER_IP" "$PARSER_TCP"; then
        ok "internal scanner-to-parser traffic still works during routed control"
    else
        bad "internal traffic broke while gateway forwarding was active"
        CONTROL_OK=0
    fi
}

enforced_matrix() {
    hdr "C5  Enforced routed policy with simultaneous internal traffic"
    ENFORCED_OK=1

    if (( CONTROL_OK == 0 )); then
        skip "enforced matrix inconclusive: positive control failed"
        ENFORCED_OK=0
        return 1
    fi

    if load_enforced_policy; then
        ok "loaded exact default-deny routed policy"
    else
        bad "failed to load enforced policy"
        ENFORCED_OK=0
        return 1
    fi

    container_tcp "$SCANNER" "$TARGET_IP" "$ALLOWED_TCP" \
        && ok "allowed target TCP $ALLOWED_TCP reached" \
        || { bad "allowed target TCP $ALLOWED_TCP failed"; ENFORCED_OK=0; }

    if container_tcp "$SCANNER" "$TARGET_IP" "$BLOCKED_TCP"; then
        bad "undeclared target TCP $BLOCKED_TCP reached"
        ENFORCED_OK=0
    else
        ok "undeclared target TCP $BLOCKED_TCP blocked"
    fi

    container_udp "$SCANNER" "$TARGET_IP" "$ALLOWED_UDP" \
        && ok "allowed target UDP $ALLOWED_UDP reached" \
        || { bad "allowed target UDP $ALLOWED_UDP failed"; ENFORCED_OK=0; }

    if container_udp "$SCANNER" "$TARGET_IP" "$BLOCKED_UDP"; then
        bad "undeclared target UDP $BLOCKED_UDP reached"
        ENFORCED_OK=0
    else
        ok "undeclared target UDP $BLOCKED_UDP blocked"
    fi

    if (( ICMP_CONTROL_OK == 1 )); then
        if podman exec "$SCANNER" ping -c 1 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
            ok "allowed ICMP echo reached target"
        else
            bad "allowed ICMP echo failed"
            ENFORCED_OK=0
        fi
    else
        skip "ICMP row inconclusive: positive control unavailable"
    fi

    if container_tcp "$SCANNER" "$PARSER_IP" "$PARSER_TCP" \
       && container_udp "$SCANNER" "$PARSER_IP" "$PARSER_UDP" \
       && container_tcp "$PARSER" "$SCANNER_INTERNAL_IP" "$SCANNER_SERVICE_TCP"; then
        ok "bidirectional internal agent traffic remains available"
    else
        bad "routed enforcement disrupted internal agent traffic"
        ENFORCED_OK=0
    fi

    if podman exec "$PARSER" ip route get "$TARGET_IP" >/dev/null 2>&1; then
        bad "parser has an undeclared route to the target"
        ENFORCED_OK=0
    else
        ok "parser remains unrouted from the external target"
    fi

    if podman exec "$SCANNER" ip route get "$EGRESS_NET_GW" >/dev/null 2>&1; then
        bad "scanner has a route to the gateway's egress network"
        ENFORCED_OK=0
    else
        ok "scanner has no route to the gateway's egress network"
    fi

    if podman exec "$SCANNER" ip route get 1.1.1.1 >/dev/null 2>&1; then
        bad "scanner has an undeclared internet route"
        ENFORCED_OK=0
    else
        ok "scanner has no undeclared internet route"
    fi

    if podman exec "$SCANNER" ip -6 route | grep -q '^default '; then
        bad "scanner has an IPv6 default route"
        ENFORCED_OK=0
    else
        ok "scanner has no IPv6 default route"
    fi

    if podman exec "$SCANNER" nft flush ruleset >/dev/null 2>&1; then
        bad "scanner unexpectedly modified netfilter state"
        ENFORCED_OK=0
    else
        ok "scanner cannot modify netfilter state"
    fi

    hdr "Gateway nftables counters"
    podman exec "$GW" nft list table inet asf_combo_filter | sed 's/^/  /'
    podman exec "$GW" nft list table ip asf_combo_nat | sed 's/^/  /'
}

gateway_removal_test() {
    hdr "C6  Enforcement-point removal while internal collaboration continues"

    podman stop -t 1 "$GW" >/dev/null 2>&1 || true

    if container_tcp "$SCANNER" "$TARGET_IP" "$ALLOWED_TCP"; then
        bad "scanner still reached target after gateway removal"
        REMOVAL_OK=0
    else
        ok "scanner cannot reach target after gateway removal"
        REMOVAL_OK=1
    fi

    if container_tcp "$SCANNER" "$PARSER_IP" "$PARSER_TCP" \
       && container_tcp "$PARSER" "$SCANNER_INTERNAL_IP" "$SCANNER_SERVICE_TCP"; then
        ok "internal agent collaboration still works without the routed gateway"
    else
        bad "gateway removal disrupted the independent internal network"
        REMOVAL_OK=0
    fi
}

verdict() {
    hdr "Verdict"
    printf '  external baseline:        %s\n' "$([[ ${BASELINE_OK:-0} == 1 ]] && echo passed || echo failed)"
    printf '  topology invariants:      %s\n' "$([[ ${TOPOLOGY_OK:-0} == 1 ]] && echo passed || echo failed)"
    printf '  internal communication:   %s\n' "$([[ ${INTERNAL_OK:-0} == 1 ]] && echo passed || echo failed)"
    printf '  routed positive control:  %s\n' "$([[ ${CONTROL_OK:-0} == 1 ]] && echo passed || echo failed)"
    printf '  enforced combined matrix: %s\n' "$([[ ${ENFORCED_OK:-0} == 1 ]] && echo passed || echo failed)"
    printf '  gateway removal:          %s\n' "$([[ ${REMOVAL_OK:-0} == 1 ]] && echo passed || echo failed)"
    echo

    if (( FAIL == 0 )) \
       && [[ ${BASELINE_OK:-0} == 1 ]] \
       && [[ ${TOPOLOGY_OK:-0} == 1 ]] \
       && [[ ${INTERNAL_OK:-0} == 1 ]] \
       && [[ ${CONTROL_OK:-0} == 1 ]] \
       && [[ ${ENFORCED_OK:-0} == 1 ]] \
       && [[ ${REMOVAL_OK:-0} == 1 ]]; then
        cat <<'TXT'
  RESULT: COMBINED TOPOLOGY VIABLE

  The scanner can collaborate with internal agents while reaching only the
  declared external target through a separate enforced gateway. Joining the
  second network introduced no default route, DNS egress, or policy bypass.
  Enforcement remains outside the scanner runtime.
TXT
    else
        cat <<'TXT'
  RESULT: COMBINED TOPOLOGY NOT YET PROVEN

  Review the first failed dependency. Do not infer enforcement from later
  negative tests when an earlier positive control or route invariant failed.
TXT
    fi

    echo
    printf '  passed: %d   failed: %d   skipped: %d   warnings: %d\n' \
        "$PASS" "$FAIL" "$SKIP" "$WARN"
}

build_image || exit 1
host_baseline
if [[ ${BASELINE_OK:-0} != 1 ]]; then
    bad "external target baseline failed; stopping before topology tests"
    verdict
    exit 1
fi
create_topology || { verdict; exit 1; }
validate_topology
internal_matrix
positive_control
enforced_matrix
gateway_removal_test
verdict

(( FAIL == 0 ))
