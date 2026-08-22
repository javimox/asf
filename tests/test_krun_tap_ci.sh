#!/usr/bin/env bash
# Focused live acceptance test for the exact TAP-capable crun binary under test.
# It uses only local containers: one target exposes two known-open TCP ports,
# while nftables permits one and drops the other.
set -euo pipefail

if [[ ${ASF_KRUN_TAP_CI:-0} != 1 ]]; then
    echo "test_krun_tap_ci.sh: skipped (set ASF_KRUN_TAP_CI=1)"
    exit 0
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENGINE=${CONTAINER_ENGINE:-podman}
RUNTIME=${CRUN_TAP_RUNTIME:-"$ROOT/tools/krun-runtime/bin/crun"}
SUFFIX=$$
NET="asf-crun-tap-ci-$SUFFIX"
HOLDER="asf-crun-tap-gw-$SUFFIX"
TARGET="asf-crun-tap-target-$SUFFIX"
VM="asf-crun-tap-vm-$SUFFIX"
IMAGE="localhost/asf-crun-tap-ci:$SUFFIX"

ROUTED_SUBNET=10.89.246.0/24
ROUTED_GATEWAY=10.89.246.1
HOLDER_IP=10.89.246.10
TARGET_IP=10.89.246.20
TAP_IP=10.89.247.1
VM_IP=10.89.247.2
TAP=tap0
ALLOWED_PORT=18080
BLOCKED_PORT=19999

cleanup() {
    "$ENGINE" rm -f "$VM" "$TARGET" "$HOLDER" >/dev/null 2>&1 || true
    "$ENGINE" network rm -f "$NET" >/dev/null 2>&1 || true
    "$ENGINE" image rm -f "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
    echo 'test_krun_tap_ci.sh: Linux x86_64 only' >&2
    exit 1
}
command -v "$ENGINE" >/dev/null 2>&1 || { echo "missing command: $ENGINE" >&2; exit 1; }
[[ -x "$RUNTIME" ]] || { echo "TAP-capable crun is not executable: $RUNTIME" >&2; exit 1; }
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo '/dev/kvm is not usable' >&2; exit 1; }
[[ -r /dev/net/tun && -w /dev/net/tun ]] || { echo '/dev/net/tun is not usable' >&2; exit 1; }

cleanup

builddir=$(mktemp -d)
trap 'rm -rf "$builddir"; cleanup' EXIT
cat > "$builddir/Containerfile" <<'CF'
FROM alpine:3.22
RUN apk add --no-cache iproute2 netcat-openbsd nftables
CF
"$ENGINE" build -q -t "$IMAGE" "$builddir" >/dev/null

"$ENGINE" network create \
    --subnet "$ROUTED_SUBNET" \
    --gateway "$ROUTED_GATEWAY" \
    "$NET" >/dev/null

# Both target ports are genuinely open. The negative control is therefore the
# gateway policy, not an absent service.
"$ENGINE" run -d --name "$TARGET" \
    --network "$NET" --ip "$TARGET_IP" \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    "$IMAGE" \
    sh -ceu '
        mkdir -p /srv
        printf ok >/srv/index.html
        httpd -h /srv -f -p 18080 &
        httpd -h /srv -f -p 19999 &
        wait
    ' >/dev/null

"$ENGINE" run -d --name "$HOLDER" \
    --network "$NET" --ip "$HOLDER_IP" \
    --sysctl net.ipv4.ip_forward=1 \
    --sysctl net.ipv6.conf.all.forwarding=0 \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    "$IMAGE" \
    sh -c 'trap "exit 0" TERM INT HUP; while :; do sleep 86400 & wait "$!"; done' \
    >/dev/null

for port in "$ALLOWED_PORT" "$BLOCKED_PORT"; do
    ready=0
    for _ in $(seq 1 20); do
        if "$ENGINE" exec "$HOLDER" nc -z -w 1 "$TARGET_IP" "$port" >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.25
    done
    (( ready == 1 )) || {
        echo "target positive control failed on TCP/$port" >&2
        exit 1
    }
done

# This is the only NET_ADMIN component. It creates TAP and loads the restricted
# policy, then exits before the VMM starts.
"$ENGINE" run --rm \
    --network "container:$HOLDER" \
    --device /dev/net/tun \
    --cap-drop=ALL \
    --cap-add=NET_ADMIN \
    --security-opt=no-new-privileges \
    "$IMAGE" \
    sh -ceu '
        tap=$1
        tap_ip=$2
        vm_ip=$3
        target_ip=$4
        allowed_port=$5
        holder_ip=$6

        uplink=$(ip -o -4 addr show | awk -v ip="$holder_ip" '\''$4 ~ ("^" ip "/") {print $2; exit}'\'')
        test -n "$uplink"

        ip tuntap add dev "$tap" mode tap user 0
        ip addr add "$tap_ip/30" dev "$tap"
        ip link set "$tap" up

        nft -f - <<EOF_NFT
        table inet asf_crun_tap_ci {
            chain forward {
                type filter hook forward priority filter; policy drop;
                iifname "$uplink" oifname "$tap" ip saddr $target_ip ip daddr $vm_ip ct state established,related accept
                iifname "$tap" oifname "$uplink" ip saddr $vm_ip ip daddr $target_ip tcp dport $allowed_port ct state new,established accept
            }
        }
        table ip asf_crun_tap_ci_nat {
            chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                ip saddr $vm_ip ip daddr $target_ip masquerade
            }
        }
EOF_NFT
    ' sh "$TAP" "$TAP_IP" "$VM_IP" "$TARGET_IP" "$ALLOWED_PORT" "$HOLDER_IP"

set +e
output=$("$ENGINE" run --rm --name "$VM" \
    --runtime "$RUNTIME" \
    --annotation "run.oci.handler=krun" \
    --annotation "krun.tap_name=$TAP" \
    --network "container:$HOLDER" \
    --device /dev/net/tun \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    "$IMAGE" \
    sh -ceu "
        ip link set eth0 up
        ip addr add $VM_IP/30 dev eth0
        ip route add $TARGET_IP/32 via $TAP_IP dev eth0
        test -z \"\$(ip route show default)\"
        nc -z -w 3 $TARGET_IP $ALLOWED_PORT
        echo MARK:tap-allowed
        if nc -z -w 2 $TARGET_IP $BLOCKED_PORT; then
            echo MARK:FAIL-blocked-port-reached >&2
            exit 1
        fi
        echo MARK:tap-blocked
    " 2>&1)
status=$?
set -e

if (( status != 0 )); then
    echo 'test_krun_tap_ci.sh: VM/TAP test failed' >&2
    printf '%s\n' "$output" >&2
    exit "$status"
fi

grep -q 'MARK:tap-allowed' <<<"$output" || {
    echo 'missing TAP positive-control marker' >&2
    printf '%s\n' "$output" >&2
    exit 1
}
grep -q 'MARK:tap-blocked' <<<"$output" || {
    echo 'missing TAP negative-control marker' >&2
    printf '%s\n' "$output" >&2
    exit 1
}
! grep -q 'MARK:FAIL' <<<"$output" || {
    printf '%s\n' "$output" >&2
    exit 1
}

printf '%s\n' "$output"
echo 'test_krun_tap_ci.sh: all assertions passed'
