#!/usr/bin/env bash
# diagnose-network.sh — find WHICH layer breaks a connection.
#
# Tests the same destinations from three places, in order:
#   1. the host            (no podman involved)
#   2. a plain container   (podman networking + aardvark DNS)
#   3. through a VPN check (routes, interfaces, resolvers)
#
# Reading the result:
#   host fails AND container fails  → network/VPN/firewall policy. Not podman.
#   host works AND container fails  → podman networking or aardvark DNS.
#   both work                       → the problem is elsewhere (app config).
#
# Safe: read-only. Starts one throwaway alpine container, removes it on exit.
set -uo pipefail

IMAGE=docker.io/library/alpine:3.20
NET=asf-diag-net
CN=asf-diag

ok()   { echo "  ✓ $*"; }
no()   { echo "  ✗ $*"; }
info() { echo "  · $*"; }
hdr()  { echo; echo "── $* ──────────────────────────────────────"; }

cleanup() {
    podman rm -f "$CN" >/dev/null 2>&1
    podman network rm -f "$NET" >/dev/null 2>&1
}
trap cleanup EXIT

# Destinations: host:port:label
TARGETS=(
    "github.com:22:GitHub SSH (classic)"
    "ssh.github.com:443:GitHub SSH over 443"
    "github.com:443:GitHub HTTPS"
    "pypi.org:443:PyPI HTTPS"
    "1.1.1.1:53:public DNS"
)

# Timed TCP probe. Distinguishes refused (fast) from dropped (slow timeout),
# which is the difference between a REJECT rule and a silent blackhole.
probe_host() {
    local host="$1" port="$2" start end ms
    start=$(date +%s%N)
    if timeout 8 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
        end=$(date +%s%N); ms=$(( (end - start) / 1000000 ))
        echo "open ${ms}ms"
    else
        end=$(date +%s%N); ms=$(( (end - start) / 1000000 ))
        if (( ms > 5000 )); then echo "DROPPED ${ms}ms"; else echo "refused ${ms}ms"; fi
    fi
}

echo "diagnose-network.sh — $(date '+%F %T')"

# ── 1. VPN and routing state ────────────────────────────────────────────────
hdr "1. Host routing and VPN state"
default_route=$(ip route show default 2>/dev/null | head -1)
info "default route: ${default_route:-<none>}"
if grep -qE 'tun|tap|wg|ppp|utun' <<<"$default_route"; then
    no "default route goes through a VPN interface"
    VPN_LIKELY=1
elif ip -br link show 2>/dev/null | grep -qE '^(tun|tap|wg|ppp)'; then
    info "VPN interface exists but is not the default route (split tunnel)"
    ip -br link show | grep -E '^(tun|tap|wg|ppp)' | sed 's/^/      /'
    VPN_LIKELY=1
else
    ok "no VPN interface detected"
    VPN_LIKELY=0
fi
info "resolvers: $(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf)"

# ── 2. From the host ────────────────────────────────────────────────────────
hdr "2. From the HOST (podman not involved)"
declare -A HOST_RESULT
for entry in "${TARGETS[@]}"; do
    host="${entry%%:*}"; rest="${entry#*:}"; port="${rest%%:*}"; label="${rest#*:}"
    result=$(probe_host "$host" "$port")
    HOST_RESULT["$host:$port"]="$result"
    case "$result" in
        open*)    ok  "$(printf '%-34s' "$label") $result" ;;
        DROPPED*) no  "$(printf '%-34s' "$label") $result  ← silently blackholed" ;;
        *)        no  "$(printf '%-34s' "$label") $result" ;;
    esac
done

# ── 3. From a container ─────────────────────────────────────────────────────
hdr "3. From a CONTAINER (podman networking + aardvark DNS)"
if ! command -v podman >/dev/null; then
    info "podman not installed — skipping"
else
    podman image exists "$IMAGE" || podman pull -q "$IMAGE" >/dev/null 2>&1
    podman network create "$NET" >/dev/null 2>&1
    for entry in "${TARGETS[@]}"; do
        host="${entry%%:*}"; rest="${entry#*:}"; port="${rest%%:*}"; label="${rest#*:}"
        if timeout 15 podman run --rm --network "$NET" "$IMAGE" \
                sh -c "nc -z -w6 $host $port" >/dev/null 2>&1; then
            cresult="open"
        else
            cresult="failed"
        fi
        hresult="${HOST_RESULT[$host:$port]}"
        verdict=""
        [[ "$hresult" == open* && "$cresult" == failed ]] && verdict="  ← PODMAN-SPECIFIC"
        [[ "$hresult" != open* && "$cresult" == failed ]] && verdict="  (host fails too — not podman)"
        if [[ "$cresult" == open ]]; then
            ok "$(printf '%-34s' "$label") open"
        else
            no "$(printf '%-34s' "$label") failed${verdict}"
        fi
    done
fi

# ── 4. DNS comparison ───────────────────────────────────────────────────────
hdr "4. DNS: host vs container (aardvark)"
host_ip=$(getent hosts github.com 2>/dev/null | awk '{print $1; exit}')
info "host resolves github.com  -> ${host_ip:-FAILED}"
if command -v podman >/dev/null; then
    cont_ip=$(timeout 15 podman run --rm --network "$NET" "$IMAGE" \
        sh -c 'getent hosts github.com' 2>/dev/null | awk '{print $1; exit}')
    info "container resolves        -> ${cont_ip:-FAILED}"
    if [[ -z "$cont_ip" ]]; then
        no "container DNS FAILED — classic VPN + aardvark symptom"
        echo "      The VPN changed the host resolver after podman cached it."
        echo "      Try: podman network reload --all   (or restart the containers)"
    elif [[ -n "$host_ip" && "$cont_ip" != "$host_ip" ]]; then
        info "different answers — split-horizon DNS or a VPN resolver difference"
    else
        ok "host and container agree"
    fi
fi

# ── 5. Verdict ──────────────────────────────────────────────────────────────
hdr "5. Verdict"
ssh22="${HOST_RESULT[github.com:22]:-}"
ssh443="${HOST_RESULT[ssh.github.com:443]:-}"

if [[ "$ssh22" != open* && "$ssh443" == open* ]]; then
    echo "  github.com:22 fails from the HOST, but SSH over 443 works."
    echo "  Podman is not involved — the host itself cannot complete it."
    echo "  This does NOT prove port 22 is blocked in general: test another"
    echo "  external SSH host first. If that works, the cause is specific to"
    echo "  GitHub (often a broken IPv6 path to its AAAA records)."
    echo "  Run ./diagnose-github-ssh.sh to isolate that."
    echo
    echo "  Fix — add to ~/.ssh/config, then git@github.com URLs work unchanged:"
    echo
    echo "      Host github.com"
    echo "          HostName ssh.github.com"
    echo "          Port 443"
    echo
    echo "  GitLab equivalent: HostName altssh.gitlab.com, Port 443"
elif [[ "$ssh22" == open* ]]; then
    echo "  Port 22 works from the host. If git clone still hangs, compare the"
    echo "  container results above — a podman-specific failure is marked."
else
    echo "  Neither port 22 nor 443 SSH is reachable. Check VPN state and"
    echo "  whether any egress is permitted at all (see section 2)."
fi

if [[ "${VPN_LIKELY:-0}" == "1" ]]; then
    echo
    echo "  A VPN is active. Two known interactions:"
    echo "   • podman caches the resolver at network-create time; if the VPN"
    echo "     changed it since, containers get stale DNS."
    echo "     → podman network reload --all"
    echo "   • with a point-to-point VPN the default route has no 'via' gateway,"
    echo "     which some host-network detection logic does not expect."
fi
