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
    if [[ "$joined" == *asf.role=broker* ]]; then
      echo broker-id
    elif [[ "$joined" == *asf.session=* ]]; then
      echo runtime-id
    fi
    ;;
  inspect)
    cat <<'JSON'
[{"Id":"broker-id","Name":"/broker-test","Config":{"Image":"litellm:test","Labels":{"asf.provider":"openai","asf.model-route":"openai/* (all models)","asf.agent":"claude","asf.default-model":"gpt-5.5"}},"State":{"Status":"running","Running":true},"NetworkSettings":{"Networks":{"internal":{}}}}]
JSON
    ;;
  exec) echo 'gpt-5.5, gpt-5.6' ;;
  logs) echo 'broker diagnostic log' ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$TMP/bin/podman"

status=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh broker status claude)
grep -q 'LiteLLM broker' <<< "$status"
grep -q 'container: broker-test' <<< "$status"
grep -q 'models:    gpt-5.5, gpt-5.6' <<< "$status"
logs=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh broker logs claude)
grep -q 'broker diagnostic log' <<< "$logs"
follow=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh broker logs --follow claude)
grep -q 'broker diagnostic log' <<< "$follow"

# Read-only migrated commands dispatch before unrelated Bash libraries load.
status=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh broker status claude)
grep -q 'LiteLLM broker' <<< "$status"

echo "test_broker_cli.sh: all assertions passed"
