#!/usr/bin/env bash
# Verify the capability-less routed gateway design on the current host.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
P="asf-capspike-$$"
IMAGE="${P}/tools"
GW="${P}-gateway"
TARGET="${P}-target"
INIT="${P}-init"
SCAN_A="${P}-scan-a"
SCAN_B="${P}-scan-b"
TARGET_NET="${P}-target-net"
ALLOC_SESSION="$P"
PASS=0; FAIL=0
ok() { echo "  ✓ $*"; PASS=$((PASS + 1)); }
bad() { echo "  ✗ $*"; FAIL=$((FAIL + 1)); }
hdr() { echo; echo "── $* ─────────────────────────────────────"; }

cleanup() {
    podman rm -f "$GW" "$TARGET" "$INIT" >/dev/null 2>&1 || true
    podman network rm -f "$SCAN_A" "$SCAN_B" "$TARGET_NET" >/dev/null 2>&1 || true
    python3 "$ROOT/tools/allocate_subnets.py" --session "$ALLOC_SESSION" --release \
        >/dev/null 2>&1 || true
    podman rmi -f "$IMAGE" >/dev/null 2>&1 || true
    rm -rf "${TMP:-/nonexistent}"
}
trap cleanup EXIT INT TERM
command -v podman >/dev/null || { echo "podman not found"; exit 1; }
[[ "${1:-}" == --clean ]] && { cleanup; echo cleaned; exit 0; }
TMP=$(mktemp -d)

allocation_json=$(python3 "$ROOT/tools/allocate_subnets.py" \
    --session "$ALLOC_SESSION" --count 3 --owner-pid $$ --emit json) || exit 1
allocation_fields=$(python3 - "$allocation_json" <<'PYALLOC'
import ipaddress
import json
import sys
subnets = [ipaddress.ip_network(value, strict=True) for value in json.loads(sys.argv[1])]
if len(subnets) != 3:
    raise SystemExit("expected three allocated subnets")
fields = []
for subnet in subnets:
    fields.extend((str(subnet), str(subnet.network_address + 1),
                   str(subnet.network_address + 2), str(subnet.network_address + 10)))
print("\t".join(fields))
PYALLOC
) || exit 1
IFS=$'\t' read -r \
    SCAN_A_SUBNET SCAN_A_GW GW_A SCAN_A_RUNTIME \
    TARGET_SUBNET TARGET_GW GW_TARGET TARGET_IP \
    SCAN_B_SUBNET SCAN_B_GW GW_B CLIENT_IP <<< "$allocation_fields"

hdr "Build tools image"
mkdir -p "$TMP/image"
cat > "$TMP/image/asf-gateway-holder" <<'EOF'
#!/bin/sh
set -eu
trap 'exit 0' TERM INT HUP
while :; do
    sleep 86400 &
    wait "$!"
done
EOF
chmod 0755 "$TMP/image/asf-gateway-holder"
cat > "$TMP/image/Containerfile" <<'EOF'
FROM docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache iproute2 netcat-openbsd nftables socat
COPY asf-gateway-holder /usr/local/bin/asf-gateway-holder
EOF
if timeout 300 podman build -q -t "$IMAGE" "$TMP/image" >/dev/null; then
    ok "tools image"
else
    bad "tools image build failed"; exit 1
fi

hdr "Networks and target"
if podman network create --internal --opt no_default_route=true \
        --subnet "$SCAN_A_SUBNET" --gateway "$SCAN_A_GW" "$SCAN_A" >/dev/null \
    && podman network create --subnet "$TARGET_SUBNET" --gateway "$TARGET_GW" \
        "$TARGET_NET" >/dev/null \
    && podman run -d --name "$TARGET" --network "${TARGET_NET}:ip=${TARGET_IP}" \
        "$IMAGE" sh -c \
        'socat TCP-LISTEN:8080,reuseaddr,fork EXEC:/bin/cat & socat TCP-LISTEN:8081,reuseaddr,fork EXEC:/bin/cat & wait' \
        >/dev/null; then
    ok "allocated collision-free networks and target"
else
    bad "could not create the controlled gateway topology"
    exit 1
fi

holder() {
    local scan_net="$1" scan_ip="$2" persistent="${3:-false}"
    local -a caps=(--cap-drop=ALL)
    [[ "$persistent" == true ]] && caps+=(--cap-add=NET_ADMIN)
    podman run -d --name "$GW" \
        --network "${scan_net}:ip=${scan_ip}" \
        --network "${TARGET_NET}:ip=${GW_TARGET}" \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.ipv6.conf.all.forwarding=0 \
        "${caps[@]}" --security-opt=no-new-privileges \
        --read-only --tmpfs /run:rw,nosuid,nodev,noexec,size=4m \
        --stop-timeout=2 \
        --pids-limit=32 --memory=64m \
        "$IMAGE" /usr/local/bin/asf-gateway-holder >/dev/null
}

remove_holder() {
    local stop_output="" rm_output=""
    podman inspect "$GW" >/dev/null 2>&1 || return 0

    if ! stop_output=$(podman stop --ignore --time 2 "$GW" 2>&1); then
        if [[ "$stop_output" == *"netavark: Netlink error: No such process"* ]] \
                && ! podman inspect "$GW" >/dev/null 2>&1; then
            return 0
        fi
        if [[ "$(podman inspect --format '{{.State.Running}}' "$GW" \
                2>/dev/null || true)" == true ]]; then
            [[ -n "$stop_output" ]] && printf '%s\n' "$stop_output" >&2
            return 1
        fi
    fi

    if rm_output=$(podman rm --ignore "$GW" 2>&1); then
        return 0
    fi
    if [[ "$rm_output" == *"netavark: Netlink error: No such process"* ]] \
            && ! podman inspect "$GW" >/dev/null 2>&1; then
        return 0
    fi
    [[ -n "$stop_output" ]] && printf '%s\n' "$stop_output" >&2
    [[ -n "$rm_output" ]] && printf '%s\n' "$rm_output" >&2
    return 1
}

load_rules() {
    local scan_ip="$1" source_ip="$2"
    podman run --rm --name "$INIT" --network "container:${GW}" \
        --cap-drop=ALL --cap-add=NET_ADMIN --security-opt=no-new-privileges \
        --read-only --tmpfs /run:rw,nosuid,nodev,noexec,size=2m \
        --pids-limit=16 --memory=32m \
        -i "$IMAGE" sh -euc '
ip route del "$1" via "$2" 2>/dev/null || true
nft -f -
' sh "$TARGET_SUBNET" "$scan_ip" <<EOF
flush ruleset
table inet asf_test {
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    ip saddr $source_ip ip daddr $TARGET_IP tcp dport 8080 accept
  }
}
table ip asf_test_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $source_ip ip daddr $TARGET_SUBNET masquerade
  }
}
EOF
}

hdr "C1  forwarding sysctl without NET_ADMIN"
if holder "$SCAN_A" "$GW_A" false; then
    capeff=$(podman exec "$GW" awk '/^CapEff:/ {print $2}' /proc/1/status)
    capbnd=$(podman exec "$GW" awk '/^CapBnd:/ {print $2}' /proc/1/status)
    nonewprivs=$(podman exec "$GW" awk '/^NoNewPrivs:/ {print $2}' /proc/1/status)
    forwarding=$(podman exec "$GW" cat /proc/sys/net/ipv4/ip_forward)
    forwarding6=$(podman exec "$GW" cat /proc/sys/net/ipv6/conf/all/forwarding)
    [[ "$capeff" == 0000000000000000 ]] && ok "holder has zero effective capabilities" \
        || bad "holder effective capabilities: $capeff"
    [[ "$capbnd" == 0000000000000000 ]] && ok "holder has an empty capability bounding set" \
        || bad "holder capability bounding set: $capbnd"
    [[ "$nonewprivs" == 1 ]] && ok "holder has no-new-privileges" \
        || bad "holder no-new-privileges is disabled"
    [[ "$forwarding" == 1 ]] && ok "holder has IPv4 forwarding enabled" \
        || bad "holder forwarding is disabled"
    [[ "$forwarding6" == 0 ]] && ok "holder has IPv6 forwarding disabled" \
        || bad "holder IPv6 forwarding is enabled"
else
    bad "host rejected capability-less forwarding holder"
    exit 1
fi

hdr "C2/C3  ephemeral initializer and persistent rules"
if load_rules "$GW_A" "$SCAN_A_RUNTIME"; then
    if podman inspect "$INIT" >/dev/null 2>&1; then
        bad "NET_ADMIN initializer remained after policy load"
    else
        ok "NET_ADMIN initializer loaded rules and exited"
    fi
else
    bad "initializer failed"
    exit 1
fi
if podman run --rm --network "container:${GW}" --cap-drop=ALL --cap-add=NET_ADMIN \
    --security-opt=no-new-privileges --read-only --pids-limit=16 --memory=32m \
    "$IMAGE" nft list table inet asf_test \
    | grep -q 8080; then
    ok "rules persist after initializer exit"
else
    bad "rules did not persist"
    exit 1
fi
remove_holder || { bad "could not remove first holder cleanly"; exit 1; }

hdr "C4  forwarding through capability-less holder"
if ! podman network create --internal --opt no_default_route=true \
        --subnet "$SCAN_B_SUBNET" --gateway "$SCAN_B_GW" \
        --route "${TARGET_SUBNET},${GW_B}" "$SCAN_B" >/dev/null; then
    bad "could not create the routed scan network"
    exit 1
fi
holder "$SCAN_B" "$GW_B" false || { bad "could not recreate holder"; exit 1; }
load_rules "$GW_B" "$CLIENT_IP" || { bad "could not load routed policy"; exit 1; }
if timeout 12 podman run --rm --network "${SCAN_B}:ip=${CLIENT_IP}" --cap-drop=ALL \
    --security-opt=no-new-privileges "$IMAGE" nc -z -w 5 "$TARGET_IP" 8080; then
    ok "allowed target port reached"
else
    bad "allowed target port failed"
fi
if timeout 12 podman run --rm --network "${SCAN_B}:ip=${CLIENT_IP}" --cap-drop=ALL \
    --security-opt=no-new-privileges "$IMAGE" nc -z -w 5 "$TARGET_IP" 8081; then
    bad "blocked target port reached"
else
    ok "known-open blocked target port denied"
fi

hdr "C5  holder cannot alter nftables"
if podman exec "$GW" nft flush ruleset >/dev/null 2>&1; then
    bad "capability-less holder altered nftables"
else
    ok "capability-less holder cannot alter nftables"
fi

hdr "C6  namespace recreation drops old policy"
remove_holder || { bad "could not remove routed holder cleanly"; exit 1; }
holder "$SCAN_B" "$GW_B" false || { bad "could not recreate clean holder"; exit 1; }
if podman run --rm --network "container:${GW}" --cap-drop=ALL --cap-add=NET_ADMIN \
    --security-opt=no-new-privileges --read-only --pids-limit=16 --memory=32m \
    "$IMAGE" nft list table inet asf_test >/dev/null 2>&1; then
    bad "recreated namespace retained the old policy"
else
    ok "recreated namespace starts without the old policy"
fi
load_rules "$GW_B" "$CLIENT_IP" || { bad "could not reload policy"; exit 1; }
if timeout 12 podman run --rm --network "${SCAN_B}:ip=${CLIENT_IP}" --cap-drop=ALL \
    --security-opt=no-new-privileges "$IMAGE" nc -z -w 5 "$TARGET_IP" 8080; then
    ok "policy restored after namespace recreation"
else
    bad "reloaded policy did not restore allowed traffic"
fi

hdr "Verdict"
echo "  passed: $PASS"
echo "  failed: $FAIL"
(( FAIL == 0 )) || exit 1
echo "  RESULT: CAPABILITY-LESS GATEWAY PROVEN"
