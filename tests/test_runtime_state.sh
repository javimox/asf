#!/usr/bin/env bash
# reset must remove every manifest-declared state volume and the runtime's own
# history, without touching another runtime.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp -a "$ROOT/." "$TMP/asf"
mkdir -p "$TMP/bin"
MOCK_LOG="$TMP/podman.log"
REMOVED_VOLUMES="$TMP/removed-volumes"
: >"$REMOVED_VOLUMES"
export MOCK_LOG REMOVED_VOLUMES TERM=xterm
cat > "$TMP/bin/podman" <<'PODMAN'
#!/usr/bin/env bash
set -euo pipefail
printf 'podman %s\n' "$*" >>"${MOCK_LOG:?}"
case "${1:-}" in
  ps) exit 0 ;;
  inspect) echo 'no such container' >&2; exit 1 ;;
  network)
    case "${2:-}" in
      inspect) echo 'no such network' >&2; exit 1 ;;
      exists) exit 1 ;;
    esac
    ;;
  secret)
    case "${2:-}" in
      ls) exit 0 ;;
      inspect) echo 'no such secret' >&2; exit 1 ;;
    esac
    ;;
  volume)
    case "${2:-}" in
      inspect)
        if grep -Fqx -- "${3:-}" "${REMOVED_VOLUMES:?}"; then
          echo 'no such volume' >&2
          exit 1
        fi
        exit 0
        ;;
      rm)
        shift 2
        printf '%s\n' "$@" >>"${REMOVED_VOLUMES:?}"
        exit 0
        ;;
    esac
    ;;
esac
exit 0
PODMAN
chmod +x "$TMP/bin/podman"

output=$(cd "$TMP/asf" && PATH="$TMP/bin:$PATH" ./sandbox.sh reset crewai 2>&1)
grep -q 'Cleared all crewai state' <<<"$output"
line=$(grep '^podman volume rm ' "$MOCK_LOG")
[[ "$line" == *-crewai-venv* ]]
[[ "$line" == *-crewai-cache* ]]
[[ "$line" == *-crewai-shell-history* ]]
[[ "$line" != *-claude-* ]]

# Reset now reuses StopService, so session support lookups happen before the
# explicit volume deletion without touching another runtime.
grep -q '^podman ps ' "$MOCK_LOG"

echo "test_runtime_state.sh: all assertions passed"
