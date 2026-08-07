#!/usr/bin/env bash
# on-start.sh — postStartCommand, runs before the shell is handed to the user.
# waitFor: postStartCommand in devcontainer.json means nothing is accessible until this exits.
# We exit non-zero on critical failure — devcontainer up will surface it.
#
# Order:
#   1. Secrets   — verify host secret files are hidden by an empty tmpfs
#   2. Firewall  — must succeed or we abort startup (fail closed)
#   3. SSH       — populate known_hosts for supported Git hosts
#   4. Agent     — dispatch to agents/<name>/setup.sh
#   5. Welcome

set -euo pipefail

# ── 1. Host secret-file isolation (fail closed) ──────────────────────────────
# sandbox.sh overlays /workspace/sandbox/secrets with an empty read-only tmpfs
# (`notmpcopyup`). Verify it is (a) a tmpfs and (b) empty — catches a removed
# runArg and an accidental copy-up of the host directory.
SECRET_SOURCE_DIR="/workspace/sandbox/secrets"
SECRET_FS_TYPE=$(stat -f -c '%T' "$SECRET_SOURCE_DIR" 2>/dev/null || true)

if [[ "$SECRET_FS_TYPE" != "tmpfs" ]]; then
    echo "  ✗ Host secret directory is not masked by tmpfs — aborting startup" >&2
    echo "    Expected tmpfs at: $SECRET_SOURCE_DIR" >&2
    exit 1
fi

if find "$SECRET_SOURCE_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | grep -q .; then
    echo "  ✗ Secret tmpfs is not empty — aborting startup" >&2
    echo "    Podman's notmpcopyup protection may be missing or unsupported." >&2
    exit 1
fi

echo "  ✓ Host secret files hidden (empty read-only tmpfs)"

# ── 2. SSH over the egress proxy ─────────────────────────────────────────────
# The agent has no direct route out, so git+SSH must go through the proxy.
# GitHub and GitLab both serve SSH on 443, which needs no extra proxy rule
# (CONNECT is permitted on 443 only).
if [[ -n "${ASF_PROXY:-}" ]]; then
    proxy_hostport="${ASF_PROXY#http://}"
    mkdir -p "${HOME}/.ssh" && chmod 700 "${HOME}/.ssh"
    cat > "${HOME}/.ssh/config" <<SSHEOF
Host github.com
    HostName ssh.github.com
    Port 443
    ProxyCommand nc -X connect -x ${proxy_hostport} %h %p

Host gitlab.com
    HostName altssh.gitlab.com
    Port 443
    ProxyCommand nc -X connect -x ${proxy_hostport} %h %p
SSHEOF
    chmod 600 "${HOME}/.ssh/config"
    echo "  ✓ SSH configured via the egress proxy (port 443)"
fi

# ── 3. SSH known_hosts (only when agent forwarding is enabled) ───────────────
# Agent forwarding is opt-in (container-hardening.conf). In the default
# workflow the agent commits into the bind-mounted repository and the human
# pushes from the host, so no SSH credential exists in here and known_hosts
# would serve no purpose. Populate it only when a socket was actually
# forwarded. Non-fatal either way: HTTPS git remains available.
if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
    mkdir -p "${HOME}/.ssh" && chmod 700 "${HOME}/.ssh"
    if ssh-keyscan -H -T 5 github.com gitlab.com >> "${HOME}/.ssh/known_hosts" 2>/dev/null; then
        echo "  ✓ SSH known_hosts populated (github.com, gitlab.com)"
    else
        echo "  ⚠ SSH known_hosts lookup failed — SSH git may be unavailable"
    fi
    chmod 600 "${HOME}/.ssh/known_hosts" 2>/dev/null || true
    echo "  ⚠ SSH agent forwarding is ACTIVE — this container can sign with every"
    echo "    identity the forwarded agent holds, for the whole session."
else
    echo "  ✓ No SSH credentials in container (commit here, push from the host)"
fi

# ── 4. Agent setup ────────────────────────────────────────────────────────────
# Each runtime owns its setup.sh (policy injection, hook registration, etc.).
# ASF_AGENT is injected as containerEnv. The Docker build ARG named AGENT is
# build-time only and is intentionally not expected at runtime.
RUNTIME_NAME="${ASF_AGENT:?ASF_AGENT is required but was not injected}"
AGENT_SETUP="/workspace/sandbox/agents/${RUNTIME_NAME}/setup.sh"

# setup.sh is OPTIONAL: adapters use it to inject policy (Claude hooks, Hermes
# SOUL.md). A generic runtime has none, which is not an error.
if [[ ! -f "$AGENT_SETUP" ]]; then
    if [[ -d "/workspace/sandbox/agents/${RUNTIME_NAME}" ]]; then
        echo "  ✓ Generic runtime '${RUNTIME_NAME}' (no adapter setup)"
        SKIP_AGENT_SETUP=true
    else
        echo "  ✗ Unknown runtime '${RUNTIME_NAME}' — no agents/${RUNTIME_NAME}/ directory" >&2
        echo "    Available runtimes:" >&2
        for d in /workspace/sandbox/agents/*/; do
            [[ -f "${d}runtime.yml" ]] && echo "      $(basename "$d")" >&2
        done
        exit 1
    fi
fi

[[ "${SKIP_AGENT_SETUP:-false}" == "true" ]] || bash "$AGENT_SETUP"

# ── 5. Welcome ────────────────────────────────────────────────────────────────
echo ""
echo "  Agent Sandboxing Framework  [agent: ${RUNTIME_NAME}]"
echo ""

mapfile -t repos < <(ls /workspace/repos/ 2>/dev/null)

if (( ${#repos[@]} == 0 )); then
    echo "  No repos mounted."
    echo "  On your host: ./sandbox.sh repo add ${RUNTIME_NAME} ~/path/to/repo"
else
    echo "  Repos:"
    for r in "${repos[@]}"; do
        echo "    /workspace/repos/$r"
    done
fi

echo ""
if [[ -z "${SSH_AUTH_SOCK:-}" ]]; then
    echo "  Git: commit in here — repos are bind mounts, so commits land on the"
    echo "       host. Review and push from the host:  git log -p && git push"
    echo ""
fi
