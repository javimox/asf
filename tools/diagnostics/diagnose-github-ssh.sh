#!/usr/bin/env bash
# diagnose-github-ssh.sh — why does github.com:22 hang when other SSH works?
#
# Runs entirely on the HOST. No containers, no podman. Read-only.
#
# The hypothesis it tests first: github.com publishes both A and AAAA records.
# If the IPv6 path is broken, ssh/nc try addresses serially and each attempt
# burns a full timeout — which is why `nc -w5` can take 40+ seconds. Tools with
# Happy Eyeballs (curl, browsers) fall back quickly and appear unaffected.
#
# Usage:  ./diagnose-github-ssh.sh [known-good-ssh-host]
#         e.g. ./diagnose-github-ssh.sh myserver.example.com
set -uo pipefail

CONTROL="${1:-}"
ok()   { echo "  ✓ $*"; }
no()   { echo "  ✗ $*"; }
info() { echo "  · $*"; }
hdr()  { echo; echo "── $* ──────────────────────────────────────"; }

# Timed TCP connect to a literal address. Prints outcome + milliseconds.
try() {
    local addr="$1" port="$2" fam="$3" start end ms
    start=$(date +%s%N)
    if timeout 12 bash -c "cat < /dev/null > /dev/tcp/${addr}/${port}" 2>/dev/null; then
        end=$(date +%s%N); ms=$(( (end-start)/1000000 ))
        ok "$(printf '%-6s %-42s' "$fam" "$addr:$port") open      ${ms}ms"
        return 0
    fi
    end=$(date +%s%N); ms=$(( (end-start)/1000000 ))
    if (( ms > 9000 )); then
        no "$(printf '%-6s %-42s' "$fam" "$addr:$port") TIMEOUT   ${ms}ms  (packets dropped)"
    else
        no "$(printf '%-6s %-42s' "$fam" "$addr:$port") refused   ${ms}ms  (reachable, rejected)"
    fi
    return 1
}

echo "diagnose-github-ssh.sh — $(date '+%F %T')"

# ── 1. What does github.com actually resolve to? ────────────────────────────
hdr "1. DNS answers for github.com"
mapfile -t V4 < <(getent ahostsv4 github.com 2>/dev/null | awk '{print $1}' | sort -u)
mapfile -t V6 < <(getent ahostsv6 github.com 2>/dev/null | awk '{print $1}' | sort -u \
                   | grep -v '^::ffff:')

if (( ${#V4[@]} )); then ok "IPv4: ${V4[*]}"; else no "no IPv4 answer"; fi
if (( ${#V6[@]} )); then
    info "IPv6: ${V6[*]}"
    echo "      ↑ if these exist and your IPv6 path is broken, ssh/nc will try"
    echo "        them and burn a timeout EACH before falling back to IPv4."
else
    info "IPv6: none returned"
fi

# ── 2. Does this host have working IPv6 at all? ─────────────────────────────
hdr "2. Host IPv6 capability"
if ip -6 addr show scope global 2>/dev/null | grep -q inet6; then
    info "global IPv6 address present:"
    ip -6 addr show scope global 2>/dev/null | awk '/inet6/{print "      "$2}'
    if ip -6 route show default 2>/dev/null | grep -q .; then
        info "default IPv6 route: $(ip -6 route show default | head -1)"
        if try 2606:4700:4700::1111 53 IPv6 >/dev/null 2>&1; then
            ok "IPv6 egress works (reached a public resolver)"
            IPV6_OK=1
        else
            no "IPv6 address and route exist, but egress FAILS"
            echo "      ← this is the classic cause: broken IPv6 path, so every"
            echo "        AAAA attempt hangs before IPv4 is tried."
            IPV6_OK=0
        fi
    else
        info "no default IPv6 route (address is link-local only)"
        IPV6_OK=0
    fi
else
    ok "no global IPv6 — AAAA records cannot be the cause here"
    IPV6_OK=none
fi

# ── 3. Port 22 per address family, by literal IP (DNS bypassed) ─────────────
hdr "3. github.com:22 by literal address"
for ip in "${V4[@]}"; do try "$ip" 22 IPv4; done
for ip in "${V6[@]}"; do try "[$ip]" 22 IPv6; done

hdr "4. github.com:443 by literal address (control)"
for ip in "${V4[@]}"; do try "$ip" 443 IPv4; done

hdr "5. GitHub SSH on port 443"
mapfile -t SSH443 < <(getent ahostsv4 ssh.github.com 2>/dev/null | awk '{print $1}' | sort -u)
for ip in "${SSH443[@]}"; do try "$ip" 443 IPv4; done

# ── 6. A known-good SSH host, for comparison ────────────────────────────────
if [[ -n "$CONTROL" ]]; then
    hdr "6. Control host: $CONTROL"
    mapfile -t C4 < <(getent ahostsv4 "$CONTROL" 2>/dev/null | awk '{print $1}' | sort -u)
    mapfile -t C6 < <(getent ahostsv6 "$CONTROL" 2>/dev/null | awk '{print $1}' | sort -u \
                       | grep -v '^::ffff:')
    for ip in "${C4[@]}"; do try "$ip" 22 IPv4; done
    if (( ${#C6[@]} )); then
        for ip in "${C6[@]}"; do try "[$ip]" 22 IPv6; done
    else
        info "control host has NO IPv6 — which is why it never hits this problem"
    fi
else
    hdr "6. Control host"
    info "pass a known-good SSH host as an argument to compare:"
    info "  ./diagnose-github-ssh.sh myserver.example.com"
fi

# ── 7. Forced-family ssh attempts ───────────────────────────────────────────
hdr "7. ssh with the address family forced"
if command -v ssh >/dev/null; then
    for flag in -4 -6; do
        fam=$([[ "$flag" == "-4" ]] && echo IPv4 || echo IPv6)
        start=$(date +%s%N)
        out=$(timeout 20 ssh "$flag" -o BatchMode=yes -o StrictHostKeyChecking=no \
                -o ConnectTimeout=10 -T git@github.com 2>&1)
        ms=$(( ($(date +%s%N)-start)/1000000 ))
        if grep -qiE 'successfully authenticated|permission denied|publickey' <<<"$out"; then
            ok "ssh $flag ($fam): reached GitHub auth  ${ms}ms"
        else
            no "ssh $flag ($fam): $(head -c 60 <<<"$out")  ${ms}ms"
        fi
    done
fi

# ── 8. MTU / path-MTU black hole ────────────────────────────────────────────
hdr "8. MTU"
iface=$(ip route show default 2>/dev/null | awk '/via/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
if [[ -n "$iface" ]]; then
    mtu=$(ip link show "$iface" 2>/dev/null | grep -oE 'mtu [0-9]+' | awk '{print $2}')
    info "default interface $iface, MTU ${mtu:-unknown}"
    if [[ -n "${V4[0]:-}" ]]; then
        # A TCP handshake that opens but then stalls on the first large packet
        # is the PMTU signature. Ping with DF set probes for it.
        if ping -c1 -W3 -M do -s 1400 "${V4[0]}" >/dev/null 2>&1; then
            ok "1400-byte unfragmented packets get through"
        else
            no "1400-byte unfragmented packets FAIL — possible PMTU black hole"
            echo "      This makes a connection open and then stall during key"
            echo "      exchange. Try: sudo ip link set $iface mtu 1400"
        fi
    fi
fi

# ── 9. Host firewall rules ──────────────────────────────────────────────────
hdr "9. Host firewall (netavark/podman leave rules behind)"
if command -v nft >/dev/null && nft list ruleset >/dev/null 2>&1; then
    if nft list ruleset 2>/dev/null | grep -qE 'dport (22|ssh)'; then
        no "nftables has rules mentioning port 22:"
        nft list ruleset 2>/dev/null | grep -E 'dport (22|ssh)' | sed 's/^/      /'
    else
        ok "no nftables rules mention port 22"
    fi
elif command -v iptables >/dev/null && iptables -S >/dev/null 2>&1; then
    if iptables -S 2>/dev/null | grep -qE 'dport (22|ssh)'; then
        no "iptables has rules mentioning port 22:"; iptables -S | grep -E 'dport (22|ssh)' | sed 's/^/      /'
    else
        ok "no iptables rules mention port 22"
    fi
else
    info "cannot read firewall rules without root — rerun with sudo to include this"
fi

# ── Verdict ─────────────────────────────────────────────────────────────────
hdr "Interpretation"
cat <<'TXT'
  IPv4 literal :22 open, but github.com:22 hangs
      → DNS returns AAAA first and the IPv6 path is broken.
        Fix in ~/.ssh/config:   Host github.com
                                    AddressFamily inet
        Or system-wide, prefer IPv4: /etc/gai.conf
                                    precedence ::ffff:0:0/96  100

  IPv4 literal :22 TIMEOUT, but :443 open
      → port 22 specifically is dropped on the path to GitHub.
        Use GitHub's SSH-over-443 endpoint:
                                Host github.com
                                    HostName ssh.github.com
                                    Port 443

  Handshake opens, then ssh stalls
      → PMTU black hole (see section 8), not a port block.

  Everything open here but git still hangs
      → the problem is in git/ssh config, not the network:
        GIT_SSH_COMMAND="ssh -vvv" git clone git@github.com:owner/repo
TXT
