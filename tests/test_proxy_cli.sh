#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp -a "$ROOT/." "$TMP/asf"
mkdir -p "$TMP/bin"
cat > "$TMP/bin/podman" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
joined=" $* "
case "${1:-}" in
  ps)
    if [[ "$joined" == *asf.role=proxy* ]]; then
      echo proxy-id
    elif [[ "$joined" == *asf.session=* ]]; then
      echo agent-id
    fi
    ;;
  inspect)
    cat <<'JSON'
[{"Id":"proxy-id","Name":"proxy-test","Config":{"Image":"caddy:test","Labels":{"asf.access-logs":"true","asf.role":"proxy"}},"State":{"Status":"running","Running":true},"NetworkSettings":{"Networks":{"egress":{},"internal":{}}}}]
JSON
    ;;
  logs) echo '{"request":{"method":"CONNECT","host":"github.com:443"}}' ;;
  exec)
    printf ':3128 {\n  log { output stdout format json }\n  forward_proxy {\n    ports 443\n    acl {\n      allow github.com\n      deny all\n    }\n  }\n}\n'
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$TMP/bin/podman"

EVIDENCE_DIR="$TMP/asf/.devcontainer/sessions/claude/evidence/test-session"
mkdir -p "$EVIDENCE_DIR"
printf '%s\n' '{"request":{"method":"CONNECT","host":"github.com:443"}}' > "$EVIDENCE_DIR/caddy-access.jsonl"
cat > "$TMP/asf/.devcontainer/sessions/claude/egress-current.json" <<EOF
{
  "active": true,
  "allowlisted_domains": ["github.com"],
  "directory": ".devcontainer/sessions/claude/evidence/test-session",
  "runtime": "claude",
  "session_id": "test-session",
  "started_at": "2026-08-03T00:00:00Z"
}
EOF

status=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh proxy status claude)
grep -q 'Caddy proxy for claude' <<< "$status"
grep -q 'access logs: true' <<< "$status"
grep -q 'internal' <<< "$status"
grep -q 'permitted port: 443' <<< "$status"
grep -q 'github.com' <<< "$status"
logs=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh proxy logs claude)
grep -q 'CONNECT' <<< "$logs"
config=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh proxy config claude)
grep -q ':3128' <<< "$config"
follow=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh proxy logs --follow claude)
grep -q 'CONNECT' <<< "$follow"
if (cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh proxy status not-an-agent >/dev/null 2>&1); then
    echo "proxy CLI accepted an unknown argument" >&2
    exit 1
fi

# The migrated command must not source unrelated lifecycle libraries.
status=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh proxy status claude)
grep -q 'Caddy proxy for claude' <<< "$status"

echo "test_proxy_cli.sh: all assertions passed"
