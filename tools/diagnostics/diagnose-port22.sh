#!/usr/bin/env bash
# diagnose-port22.sh — is outbound TCP/22 blocked generally, or only to GitHub?
#
# Established already:
#   • 140.82.121.4:443 opens in ~28ms, 140.82.121.4:22 times out (same IP)
#   • no IPv6 on this host, MTU fine, no nftables rules on 22
#   • the "working" external SSH host does NOT listen on 22, so outbound 22
#     to the internet has never actually been demonstrated
#
# This tests several public SSH endpoints. The pattern decides the cause.
# Read-only, no containers. Some checks want sudo; it still works without.
set -uo pipefail

ok()   { echo "  ✓ $*"; }
no()   { echo "  ✗ $*"; }
info() { echo "  · $*"; }
hdr()  { echo; echo "── $* ──────────────────────────────────────"; }

try() {  # host port label
    local host="$1" port="$2" label="$3" ip start ms
    ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')
    [[ -z "$ip" ]] && { no "$(printf '%-28s' "$label") DNS failed"; return 2; }
    start=$(date +%s%N)
    if timeout 12 bash -c "cat < /dev/null > /dev/tcp/${ip}/${port}" 2>/dev/null; then
        ms=$(( ($(date +%s%N)-start)/1000000 ))
        ok "$(printf '%-28s' "$label") open     ${ms}ms   ($ip:$port)"; return 0
    fi
    ms=$(( ($(date +%s%N)-start)/1000000 ))
    if (( ms > 9000 )); then
        no "$(printf '%-28s' "$label") DROPPED  ${ms}ms   ($ip:$port)"
    else
        no "$(printf '%-28s' "$label") refused  ${ms}ms   ($ip:$port)"
    fi
    return 1
}

echo "diagnose-port22.sh — $(date '+%F %T')"

# ── 1. Public SSH endpoints on port 22 ──────────────────────────────────────
hdr "1. Outbound TCP/22 to several providers"
open22=0; drop22=0
for entry in \
    "github.com:GitHub" \
    "gitlab.com:GitLab" \
    "bitbucket.org:Bitbucket" \
    "codeberg.org:Codeberg" \
    "git.sr.ht:SourceHut"
do
    host="${entry%%:*}"; label="${entry#*:}"
    if try "$host" 22 "$label :22"; then open22=$((open22+1)); else drop22=$((drop22+1)); fi
done

# ── 2. Same hosts on 443, as a control ──────────────────────────────────────
hdr "2. Same hosts on 443 (control — proves the path itself is fine)"
for entry in "github.com:GitHub" "gitlab.com:GitLab" "codeberg.org:Codeberg"; do
    host="${entry%%:*}"; label="${entry#*:}"
    try "$host" 443 "$label :443"
done

# ── 3. SSH-over-443 endpoints ───────────────────────────────────────────────
hdr "3. Provider SSH-over-443 endpoints"
try ssh.github.com     443 "GitHub  ssh:443"
try altssh.gitlab.com  443 "GitLab  ssh:443"

# ── 4. ufw default policies (the listed rules are INBOUND) ──────────────────
hdr "4. ufw default policies"
if command -v ufw >/dev/null; then
    if ufw status verbose >/dev/null 2>&1; then
        ufw status verbose 2>/dev/null | grep -i '^default' | sed 's/^/      /'
        if ufw status verbose 2>/dev/null | grep -qi 'deny (outgoing)'; then
            no "ufw DENIES outgoing by default — likely the cause"
        else
            ok "ufw allows outgoing by default (not the cause)"
        fi
    else
        info "need sudo for defaults:  sudo ufw status verbose"
    fi
else
    info "ufw not installed"
fi

# ── 5. Where does it die? ───────────────────────────────────────────────────
hdr "5. Path to GitHub on port 22 vs 443"
if command -v traceroute >/dev/null; then
    if [[ $EUID -eq 0 ]]; then
        echo "  port 22:"
        timeout 40 traceroute -T -p 22 -n -w2 -q1 -m12 github.com 2>&1 | sed 's/^/      /'
        echo "  port 443:"
        timeout 40 traceroute -T -p 443 -n -w2 -q1 -m12 github.com 2>&1 | sed 's/^/      /'
        echo
        info "compare: the hop where port 22 stops but 443 continues is the blocker."
        info "your router's LAN address = your router; the next hop = your ISP."
    else
        info "TCP traceroute needs root. Rerun:  sudo $0"
    fi
else
    info "traceroute not installed (pacman -S traceroute) — optional"
fi

# ── Verdict ─────────────────────────────────────────────────────────────────
hdr "Verdict"
if (( open22 == 0 && drop22 > 1 )); then
    cat <<'TXT'
  Port 22 is DROPPED to every provider tested, while 443 to the same hosts
  works. Outbound TCP/22 is blocked for your whole network — by your router
  or your ISP, not by GitHub, not by your host, and not by podman.

  Confirm with the traceroute above (run with sudo): if port 22 dies at the
  first or second hop, it is your router or ISP.

  Fix — SSH over 443, which every major provider supports:

      # ~/.ssh/config
      Host github.com
          HostName ssh.github.com
          Port 443
      Host gitlab.com
          HostName altssh.gitlab.com
          Port 443

  git@github.com: URLs then work unchanged.
TXT
elif (( open22 > 0 && drop22 > 0 )); then
    cat <<'TXT'
  Port 22 works for SOME providers but not others. The block is
  destination-specific — a router/ISP rule aimed at particular ranges, or
  filtering by the remote end. Check which succeeded above; use SSH-over-443
  for the ones that fail.
TXT
elif (( open22 > 0 )); then
    cat <<'TXT'
  Outbound port 22 works generally. If GitHub alone fails, the block is
  specific to GitHub's SSH range from your network — use ssh.github.com:443.
TXT
else
    echo "  Inconclusive: DNS or general connectivity failed. Check section 2."
fi

echo
echo "  Note: 'ufw allow 22/tcp' governs INBOUND connections to this machine."
echo "  It has no effect on outbound connections."
