#!/usr/bin/env bash
# pretooluse-guard.sh — defense in depth, NOT a security boundary.
#
# Catches honest mistakes via regex on the literal command string; trivially
# bypassed by substitution, encoding, or splitting. Real isolation is the
# container, the firewall, and the non-root user.
#
# IMPORTANT: on pass, emit NOTHING and exit 0. That defers to the normal
# permission flow (settings.json allow/ask/deny). Emitting an approve decision
# here would bypass the permission system and disable every "ask" rule.
set -euo pipefail

payload="$(cat)"

tool_name="$(jq -r '.tool_name // empty' <<<"$payload")"
command="$(jq -r '.tool_input.command // empty' <<<"$payload")"
path="$(jq -r '.tool_input.file_path // .tool_input.path // empty' <<<"$payload")"

deny() {
  jq -n --arg reason "$1" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
}

# Word boundary: start of string or a separator. Prevents "confirm -r" from
# matching the rm rule, "inform" matching rm, etc.
W='(^|[;&|[:space:]])'

case "$tool_name" in
  Bash)
    # Privilege escalation
    if grep -Eq "${W}(sudo|su)([[:space:]]|\$)" <<<"$command"; then
      deny "Blocked privilege escalation command."
    fi

    # Remote script piped to a shell
    if grep -Eq "${W}(curl|wget)[[:space:]].*\|[[:space:]]*(sh|bash|zsh|fish)([[:space:]]|\$)" <<<"$command"; then
      deny "Blocked remote script piping. Download, inspect, then run manually."
    fi

    # Recursive delete
    if grep -Eq "${W}rm[[:space:]]+(-[a-zA-Z]*[rR]|--recursive)" <<<"$command"; then
      deny "Blocked recursive delete."
    fi

    # find -delete
    if grep -Eq "${W}find[[:space:]].*[[:space:]]-delete([[:space:]]|\$)" <<<"$command"; then
      deny "Blocked find -delete."
    fi

    # Broad git staging: add . / -A / --all / -u, with optional -C <dir>
    if grep -Eq "${W}git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+add[[:space:]]+(-A|--all|-u|\.)([[:space:]]|\$)" <<<"$command"; then
      deny "Blocked broad git add. Stage specific paths: git add src/file.ts"
    fi

    # Force push
    if grep -Eq "${W}git[[:space:]]+push[[:space:]]+.*(-f([[:space:]]|\$)|--force([[:space:]]|=|\$)|--force-with-lease)" <<<"$command"; then
      deny "Blocked force push."
    fi

    # Hard reset: --hard or its unambiguous abbreviations (--ha, --har).
    # Deliberately does NOT match --help or file names containing "-h".
    if grep -Eq "${W}git[[:space:]]+reset([[:space:]]|\$)" <<<"$command" \
       && grep -Eq '(^|[[:space:]])--ha(r|rd)?([[:space:]]|$)' <<<"$command"; then
      deny "Blocked hard reset. Use --soft or --mixed."
    fi

    # Sandbox policy paths (mount is read-only; this adds a clear message)
    if grep -Eq '/workspace/sandbox/(agents|containers)' <<<"$command"; then
      deny "Blocked access to sandbox policy paths."
    fi

    # Likely secret material. Command-string variants of the Read/Edit path
    # patterns: word-bounded, since args follow spaces rather than start of
    # string. Deliberately trigger-happy — this is a nudge, not a boundary.
    if grep -Eq '(^|[[:space:]"'"'"'/])\.env([./[:space:]"'"'"']|$)|[^[:space:]]+\.(pem|key)([[:space:]"'"'"']|$)|credentials|secrets/' <<<"$command"; then
      deny "Blocked command touching likely secret material."
    fi
    ;;

  Read)
    if grep -Eq '(^|/)\.env(\.|$)|\.pem$|\.key$|credentials|secrets/' <<<"$path"; then
      deny "Blocked read of likely secret material."
    fi
    ;;

  Edit|Write)
    if grep -Eq '(^|/)\.env(\.|$)|\.pem$|\.key$|credentials|secrets/' <<<"$path"; then
      deny "Blocked write to likely secret material."
    fi
    if grep -Eq '/workspace/sandbox/(agents|containers)' <<<"$path"; then
      deny "Blocked modification of sandbox policy files."
    fi
    ;;
esac

# No opinion: no output, exit 0 — defer to the permission system.
exit 0
