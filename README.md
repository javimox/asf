Agent Sandboxing Framework (ASF) was born as a Master's degree thesis, but the original idea
evolved far beyond its initial scope through many hours of design, experimentation, and
development. I hope you enjoy using it as much as I enjoyed designing and building it.

# Agent Sandboxing Framework

**Release:** `1.0` · [Dependencies](docs/DEPENDENCIES.md) · [Trust model](TRUST.md) · [BSD 4-Clause licensed](LICENSE)

Isolated AI coding-agent environments running on rootless Podman. You choose which
repositories are mounted; ASF handles the remaining lifecycle and security controls.

## How it works in 60 seconds

`sandbox.sh` is a command-line tool (not a daemon). When you open a session it
generates a devcontainer config, starts an optional ephemeral LiteLLM broker,
and launches **one** locked-down container on a network with no gateway. Its
only reachable peers are an egress proxy (which allows a listed set of domains)
and the LLM broker. Secrets are injected from the host at start; on exit
everything ephemeral is torn down, the terminal is restored after interruption,
and only declared state volumes remain. The agent works inside the box; you keep
your shell.

**Deciding whether to trust it?** Read [TRUST.md](TRUST.md) — one page listing
exactly what ASF protects, what it deliberately doesn't, and every privilege it
uses.

## Demo

<p align="center">
  <img src="docs/assets/asf-demo-small.gif" alt="ASF terminal demo">
</p>

## Quick start

**Requirements:** Python with PyYAML, rootless Podman, and Dev Container CLI (`@devcontainers/cli`).
See [Prerequisites](#prerequisites) for installation details.

ASF runtimes are configured per agent. In general, the workflow is:

1. Configure any credentials required by the runtime.
2. Grant the agent access only to the repositories it needs.
3. Open the sandbox.
4. Start the agent inside the constrained environment.

The following example uses **Claude Code** with ASF's default LiteLLM broker configuration.

First, configure the Anthropic API key:

```bash
cp secrets/claude.env.example secrets/claude.env
chmod 600 secrets/claude.env
$EDITOR secrets/claude.env
```

Set `ANTHROPIC_API_KEY` in `secrets/claude.env`.

Then grant Claude access to the repositories it needs:

```bash
# Read-write repository
./sandbox.sh repo add claude ~/projects/my-api

# Optional read-only repository
./sandbox.sh repo add claude ~/projects/reference --mode ro
```

Start the sandbox:

```bash
./sandbox.sh open claude
```

Inside the container:

```bash
cd /workspace/repos/my-api
claude
```

> **Prefer Claude Code `/login`?** Set `llm.broker: false` in
> `agents/claude/runtime.yml` before opening the sandbox. Claude Code can then
> authenticate directly with Anthropic using `/login`. Caddy remains enabled
> and continues enforcing the configured egress allowlist.

Repository access is configured separately for each agent. Repositories are
read-write by default; use `--mode ro` for inputs or reference material that
the agent should not modify.

## Why ASF — the strong points

- **Isolation by topology, not by filtering.** In proxy and isolated mode the
  agent's network has *no gateway*; there is no firewall to misconfigure
  because there is no route to abuse.
- **Generated, then verified.** Proxy and nftables policy are generated from
  the manifest — never hand-written — and every session startup empirically
  probes allow, deny, private-address, port, and no-bypass behavior from a
  throwaway container before the agent starts. Deny failures abort the
  session; an unreachable positive control degrades to an explicit warning.
- **One immutable plan.** The full session topology is decided and persisted
  *before* any Podman resource exists; runtime services only execute it.
- **Owned teardown.** Every created resource lands in a ledger and is removed
  in dependency order on exit, `stop`, signals, and stale recovery.
- **Brokered credentials.** With LiteLLM enabled the provider key is a file
  inside the broker container only; the agent gets a short-lived local token
  and the proxy refuses direct provider-API egress.
- **Auditable sessions.** Each session persists its evidence:
  `runtime-plan.json`, `verification-report.json`, `cleanup-report.json`, and
  (in proxy mode) a bounded Caddy access-log summary under
  `.devcontainer/sessions/<agent>/`.
- **Policy that learns from enforcement evidence.** After proxy sessions,
  `./sandbox.sh advise <agent>` reports repeatedly denied destinations and
  allowlisted domains that remained unused across a full 12-session window.
  It never edits policy automatically; every change remains a human-reviewed
  manifest edit.

## All commands

`./sandbox.sh --version` prints the installed ASF version.

```
./sandbox.sh open <agent>      start one agent runtime
                               (removes ephemeral containers automatically on exit)
./sandbox.sh shell [agent]     attach to an already-running container
./sandbox.sh ls                show running and deployed agent sessions
./sandbox.sh stop [agent]      stop one session, or all of them
./sandbox.sh reset <agent>     clear one agent's persistent state volume
./sandbox.sh build <agent>     rebuild one agent image
./sandbox.sh scan [repo] [agent]
                               run Semgrep on all repos, or one named repo
./sandbox.sh test [agent]      re-run the active session security checks
./sandbox.sh advise <agent>    suggest allowlist changes from recent evidence
./sandbox.sh proxy ...         inspect the active Caddy proxy
./sandbox.sh broker ...        inspect or test the active LiteLLM broker
./sandbox.sh repo add <agent> <path> [--mode ro|rw]
                               add or update a repository for one agent
./sandbox.sh repo remove <agent> <name>
                               remove a repository by exact basename
./sandbox.sh repo list <agent>
                               show repositories available to one agent
./sandbox.sh repository ...    long-form alias for `repo`
```

## Prerequisites

### Podman (rootless)

The sandbox runs on rootless Podman. Rootless means the engine runs as your own
unprivileged user — there is no root daemon.

```bash
# Arch
sudo pacman -S podman

# Debian / Ubuntu
sudo apt-get install podman

# Fedora / RHEL
sudo dnf install podman

# macOS
brew install podman && podman machine init && podman machine start
```

Docs: https://podman.io/docs/installation

Podman uses your `/etc/subuid` and `/etc/subgid` ranges for user-namespace
mapping. The `podman` package sets these up for your user on install. Verify:

```bash
grep "$(id -un)" /etc/subuid /etc/subgid    # should print a range for your user
```

### devcontainer CLI

Install it as normal (unprivileged) user:

```bash
curl -fsSL https://raw.githubusercontent.com/devcontainers/cli/main/scripts/install.sh | sh
```

Or using npm:
```bash
npm install -g @devcontainers/cli
```

### Python 3

ASF uses Python for all host-side orchestration, deterministic configuration
generation, lifecycle control, cleanup, and security verification. Runtime
manifests require PyYAML; the rest of the host package uses the standard library.

```bash
python3 --version
python3 -c 'import yaml'
```

ASF uses one Python production path for every command and network mode.

The sandbox drives the devcontainer CLI with `--docker-path podman`, so it uses
Podman everywhere with no Docker installed.

### Pinned build dependencies

Top-level image, agent, and tool versions live in `asf.conf`. ASF passes
them into the generated devcontainer build arguments. The LiteLLM image is pinned
separately in `asf.conf`. Update those files deliberately and run the tests; do
not replace exact versions with `latest` or moving branch tags.

## File ownership: how it works

The container runs as the unprivileged **`node`** user. Podman's
`--userns=keep-id` (auto-injected by the devcontainer CLI for Podman) maps your
host user into the container; because `node` is UID 1000 and most Linux host
accounts are too, this maps host -> node with no extra flag. The result:

| | Inside container | On host |
|---|------------------|---------|
| Files Agent creates | owned by `node` | owned by **you** |

So files are directly editable on the host, owned by `node` in the container,
and the container never holds host root. This is the one clean configuration
that satisfies all three at once — and it's why the sandbox uses Podman rather
than Docker (Docker has no per-container `keep-id` equivalent in rootless mode).

The `1000` in the `keep-id` mapping is the `node` user's fixed UID in the image,
not your host UID — so this works regardless of what UID your host account has.

**Note on `--userns`:** the devcontainer CLI auto-injects `--userns=keep-id` for
Podman, which maps your host user to the same UID inside the container. Since
`node` is UID 1000 and most Linux host accounts are also 1000, this maps
host→node correctly with no extra flag. **If your host UID is not 1000**, add
`"--userns=keep-id:uid=1000,gid=1000"` to `runArgs` in `devcontainer.base.json`
so files stay owned by you. (Check with `id -u` on the host.)

## Security model — what each layer does

Defense in depth, from outside in:

1. **Container boundary.** The host filesystem is invisible to the agent. Only paths
   listed in `agents/<name>/repos.yml` are bind-mounted into that runtime, plus
   its declared named volumes. Repository entries may be `rw` or `ro`.
2. **Rootless engine.** Podman runs as your unprivileged user; there is no root
   daemon. A container escape yields only your existing user privileges.
3. **Non-root container user, no capabilities.** The container runs as `node`
   with `--cap-drop=ALL`, `no-new-privileges`, and **no `sudo` at all** — there
   is no sudoers rule, because nothing inside needs privilege.
4. **Network topology.** The agent joins one `--internal` network, which has no
   gateway. It cannot reach the internet directly; there is no route to filter.
   All egress goes through a Caddy proxy container that allows only the domains
   a runtime declares in its manifest — there is no implicit base list — and
   only port 443, on both the `CONNECT` and plain-HTTP paths. SSH is tunnelled
   via `ssh.github.com:443`. The
   proxy config is generated, never hand-written. Before the agent starts, ASF
   verifies from a throwaway container that an allowlisted host is reachable, a
   non-allowlisted one is not, and no route bypasses the proxy — a failure
   aborts the session (fail closed). See [docs/EGRESS-DESIGN.md](docs/EGRESS-DESIGN.md).
5. **Permission rules** (`.claude/settings.json`). Claude Code's permission system
   asks before commits, pushes, and dependency installs; denies destructive
   patterns outright.
6. **Pre-tool-use hook** (`pretooluse-guard.sh`). Defense in depth on top of (5).
   Uses regex on the literal command string and **can be bypassed** with command
   substitution, variable expansion, or splitting commands across files. It
   catches honest mistakes, not determined adversaries. The real boundary is
   layers 1–4. When the hook has no opinion it emits nothing, deferring to the
   permission rules in (5) — it never auto-approves (an approve decision from a
   PreToolUse hook would bypass the permission system and disable every `ask`
   rule).

## What persists between sessions

Agent's state lives in a named Podman volume (eg claude: `<checkout>-<path-hash>-claude-config` → `/home/node/.claude/`).
It survives `./sandbox.sh open <agent>` and rebuilds — only `./sandbox.sh reset <agent>` (or
`podman volume rm`) removes it. The container itself is removed on exit; only the
volumes persist.

| Persisted | Where |
|-----------|-------|
| Memory (things you ask Claude to remember) | `/home/node/.claude/` |
| Conversation history | `/home/node/.claude/` |
| Todos | `/home/node/.claude/` |
| Skills installed during sessions | `/home/node/.claude/skills/` |
| Project context | `/workspace/repos/<name>/CLAUDE.md` |

Shell history lives in its own volume (`<checkout>-<path-hash>-shell-history` → `/commandhistory/`).

## What on-start.sh overwrites on every start

Three files are copied fresh from `agents/` each time the container starts.
These are **policy you own**, not state Claude builds — overwriting them ensures
Claude cannot weaken its own guardrails between sessions.

| File | What it controls |
|------|-----------------|
| `agents/claude/.claude/settings.json` | Permitted, asked, and denied commands |
| `agents/claude/.claude/hooks/pretooluse-guard.sh` | Pre-tool-use security hook |
| `agents/claude/CLAUDE.md` | Operating rules (user-level, always loaded) |

Edit any of these in `agents/`, then run `./sandbox.sh open <agent>` to apply — no image rebuild needed.

Anything else in the volume (memory, history, todos, skills) is preserved untouched.

## CLAUDE.md — two levels, two purposes

| File | Written by | Overwritten on start | Purpose |
|------|-----------|----------------------|---------|
| `agents/claude/CLAUDE.md` → `~/.claude/CLAUDE.md` | You | Yes | Immutable rules and workflow |
| `/workspace/repos/<name>/CLAUDE.md` | Claude or you | No | Project-specific context and notes |

Keep `agents/claude/CLAUDE.md` for rules that must always hold. Let Claude accumulate
project context in each repo's own `CLAUDE.md`, which the sandbox never touches.

## Choosing an agent

```bash
./sandbox.sh open claude    # Claude Code
./sandbox.sh open hermes    # Hermes agent
```

Each agent has its **own image**. Opening `claude` builds and runs an image that
contains only Claude Code — it never runs the Hermes installer (which is slow).
Opening `hermes` builds a separate image with only Hermes. The two images share
all the common tooling layers (git, zsh, uv, etc.) from the build
cache, so the first build of each agent is the only slow one; switching back to
an already-built agent is fast.

Agent selection is injected as a Docker build arg (`AGENT`), which gives each
agent a distinct image. Policy files for the active agent are injected at every
container start from `agents/<agent>/`.

To pre-build an agent without starting a session:

```bash
./sandbox.sh build hermes
```

## Implementation layout

`sandbox.sh` is a minimal launcher. The Python package is split by responsibility:

```text
sandbox.sh                 thin `python3 -m asf` launcher
asf/cli.py                 command routing and output/exit boundary
asf/runtime.py             session orchestration
asf/runtime_plan.py        immutable topology and owned resources
asf/networks.py            plan-driven Podman networks
asf/proxy.py               Caddy policy and lifecycle
asf/broker.py              LiteLLM policy, secrets, lifecycle, readiness
asf/routed*.py             subnet allocation, nftables, gateway lifecycle
asf/cleanup.py             ordered cleanup and stale recovery
asf/verification/          typed probes and fail-closed evidence
asf.conf                    pinned dependencies and host settings
agents/<name>/runtime.yml  per-runtime manifest
tests/                     unit, fixture, lifecycle, and real-host checks
```

## Secrets (host-side files are not exposed to the container)

API keys and tokens live on the **host**, never inside the container image or
volumes. At container start `sandbox.sh` injects them into the container's
process environment only — never written to `~/.hermes/.env` inside the
container, never baked into the image, never stored in `devcontainer.json`.

The ASF project root is mounted read-only at `/workspace/sandbox` so the live
policy files are available at startup. To prevent that broad mount from exposing
`secrets/*.env`, `sandbox.sh` always overlays `/workspace/sandbox/secrets` with
an **empty, read-only tmpfs**. The mount uses Podman's `notmpcopyup` option so
the underlying host files are not copied into the nested tmpfs. `on-start.sh`
verifies that the path is a tmpfs and is empty; container startup aborts if the
check fails. This mask remains enabled even when optional hardening is disabled.

```
secrets/
  common.env      # shared by all agents      (gitignored)
  claude.env      # claude only               (gitignored)
  hermes.env      # hermes only               (gitignored)
  *.example       # tracked templates
```

Setup:

```bash
cp secrets/hermes.env.example secrets/hermes.env
$EDITOR secrets/hermes.env # add your API key
chmod 600 secrets/hermes.env
./sandbox.sh open hermes
```

`common.env` loads first, then the active agent's file (per-agent keys override
common). `sandbox.sh` warns if a secret file is not `chmod 600`.

With the LiteLLM broker enabled, neither Claude nor Hermes receives its reusable
provider credential. Each agent receives only a short-lived token valid for the
local broker. With the broker disabled, the real provider key is injected into
the active agent process. The tmpfs mask protects the host files, not values
intentionally injected into a process.

## Optional LiteLLM credential broker

LiteLLM broker use is declared per runtime with `llm.broker` in
`agents/<name>/runtime.yml`. It is enabled by default in the supplied Claude and
Hermes manifests. Broker image and timeout settings remain in `asf.conf`, and
the broker is started and removed automatically with the sandbox:

```text
Claude container → temporary Podman network → LiteLLM → Anthropic
Hermes container → temporary Podman network → LiteLLM → OpenAI
```

For the active agent, `sandbox.sh` loads the configured provider key from the
existing `secrets/*.env` files and exposes it only to LiteLLM through a temporary
Podman secret. The agent receives a random session token and the local broker URL.
That provider API domain is dropped from the proxy allowlist while
the broker is active.

The minimal database-free deployment uses one read-only LiteLLM container with no
PostgreSQL, Redis, dashboard, or persistent broker state. Prompt/response logging
and spend logs are disabled. The provider key is delivered as a mounted secret
file (not container env), so `podman exec`/`inspect` never see it. The master key
can reach every proxy route (route allowlisting, LiteLLM's
`allowed_routes`, is an Enterprise-only feature and is not set on the OSS
image). This is acceptable because the broker is single-session, on a private
network reachable only by its agent container, holds one upstream key, keeps no
database, and is destroyed on exit — so management routes have nothing
persistent to manage and no spend data to read (`disable_spend_logs`). To
restrict routes anyway, add a LiteLLM Enterprise license via `LITELLM_LICENSE`.
Virtual keys were considered and rejected: they require a database, which
outweighs the benefit at this scale. The container, temporary network, session token, and
Podman secret are removed when the shell exits or `./sandbox.sh stop` is run.

Shutdown is intentionally explicit: ASF reports removal of the agent container,
LiteLLM container, temporary provider secret, private network, and state file as
separate timed steps. Podman's default forced-removal grace period is 10 seconds;
ASF uses 2 seconds because the interactive agent shell has already exited. Override
it for one invocation when needed:

```bash
ASF_SHUTDOWN_TIMEOUT=5 ./sandbox.sh open hermes
```

The upstream provider is configurable per agent — any LiteLLM provider slug
(openai, anthropic, openrouter, mistral, groq, deepseek, ...). The agent's own
wire protocol never changes: Claude Code speaks Anthropic Messages and Hermes
speaks OpenAI Chat Completions *to the broker*, and LiteLLM translates
upstream. Three settings move together per agent: `_PROVIDER` (the slug),
`_API_KEY` (which variable in `secrets/<agent>.env` holds the key), and
`_DIRECT_DOMAIN` (the provider API the proxy blocks while brokered). One
provider per agent per session; to switch, edit the three values and re-open.
Providers whose model discovery LiteLLM does not support need an explicit
`LITELLM_<AGENT>_MODELS` list.

Configuration:

```bash
# asf.conf
BROKER_ENABLED=true
LITELLM_IMAGE=ghcr.io/berriai/litellm:v1.93.0

LITELLM_CLAUDE_PROVIDER=anthropic
LITELLM_CLAUDE_API_KEY=ANTHROPIC_API_KEY
LITELLM_CLAUDE_DIRECT_DOMAIN=api.anthropic.com

LITELLM_HERMES_PROVIDER=openai
LITELLM_HERMES_API_KEY=OPENAI_API_KEY
LITELLM_HERMES_DIRECT_DOMAIN=api.openai.com

# Optional model allowlists. Leave undefined to expose all provider models.
# LITELLM_CLAUDE_MODELS="claude-sonnet-4-6 claude-opus-4-6"
# LITELLM_HERMES_MODELS="gpt-5.5 gpt-5-nano"

LITELLM_STARTUP_TIMEOUT=60
LITELLM_DETAILED_DEBUG=false
```

Model selection remains owned by the agent. ASF applies the same simple rule to
both providers:

- If `LITELLM_CLAUDE_MODELS` or `LITELLM_HERMES_MODELS` is undefined or empty,
  the broker exposes a wildcard route (`<provider>/*`): every model the key can
  reach is available, and startup makes no provider call at all.
- If the variable is defined, only the whitespace-separated models in that
  list are exposed. Provider prefixes are optional.

There is no ASF-maintained model catalog and no host-side provider request. An
explicit Hermes list must include the `model.default` value configured in
`agents/hermes/config.yaml`; ASF fails early with a clear error otherwise.

The Hermes routes remove `temperature` before forwarding because Hermes uses
`temperature=0.3` for auxiliary title generation while some OpenAI reasoning
models accept only their provider-default temperature.

To disable brokering for a runtime, set `llm.broker: false` in 
`runtime.yml`. In direct-provider mode, ASF does not start LiteLLM; the runtime
authenticates directly and its provider API remains subject to the Caddy proxy
allowlist.

For Claude, `agents/claude/runtime.yml` enables `llm.broker` by default. That
mode requires an Anthropic API token, normally provided as `ANTHROPIC_API_KEY`
in `secrets/claude.env`. To authenticate interactively with Claude Code's
`/login` command instead, set `llm.broker: false` in the Claude manifest
`agents/claude/runtime.yml` before opening Claude agent. Claude Code then authenticates
directly with Anthropic. Caddy Proxy remains enabled and continues to enforce the declared
domain allowlist; disabling the LLM broker does not disable egress filtering.

Hermes uses its existing `openai-api` configuration. When the broker is active,
ASF sets `OPENAI_BASE_URL` to LiteLLM's OpenAI-compatible `/v1` endpoint and
replaces `OPENAI_API_KEY` with the temporary session token. The reusable OpenAI
key is filtered out of both normal and attached shells.

### Broker diagnostics

Run these commands from a second terminal while either agent session is active:

```bash
./sandbox.sh broker status
./sandbox.sh broker logs
./sandbox.sh broker logs --follow
./sandbox.sh broker test                 # uses Hermes' configured default model
./sandbox.sh broker test claude-sonnet-4-6 # pass a model explicitly for Claude
```

`broker test` selects the correct protocol for the active agent: Anthropic
Messages for Claude and OpenAI Chat Completions for Hermes. It sends a small
diagnostic request and therefore uses a small amount of provider quota. Hermes
uses the default model from `agents/hermes/config.yaml`; for Claude, pass the
model to test explicitly. The Hermes probe uses `max_completion_tokens` and
disables reasoning so reasoning models have enough room to return visible output.

The broker container is started before the agent container and its readiness is
confirmed afterwards, so LiteLLM's boot (~10-15s, mostly importing its
dependency tree) overlaps with the image check, container creation, and
proxy startup rather than adding to them. `LITELLM_STARTUP_TIMEOUT` bounds the
wait; exceeding it aborts the session and prints the broker log.

ASF disables LiteLLM deployment cooldowns because each session has only one
deployment. Provider errors therefore remain visible instead of being replaced
by the secondary `429 No deployments available` message.

For deeper temporary troubleshooting, set `LITELLM_DETAILED_DEBUG=true` in
`asf.conf`. Detailed logs may contain request content or credentials, so
disable it again after diagnosis.

## Container hardening (asf.conf)

Resource and capability limits are applied as Podman run-args from
`asf.conf` (all on by default, documented, edit and re-open — no rebuild).
Adapted from the wnstify Hermes sandbox:

- `cap-drop=ALL` by default; only manifest-declared `NET_RAW` may be added for
  workloads such as SYN scanning. `NET_ADMIN` is never permitted in a runtime
- `pids-limit`, `memory`, `cpus` — DoS / runaway protection
- `ulimit core=0` — no core dumps, so in-memory secrets never hit disk
- `tmpfs /tmp,/run` with `nosuid,nodev` — dropped binaries there can't escalate
- `ipc=private` — no shared-memory leakage

Separately from these tunable options, `/workspace/sandbox/secrets` is always
masked by an empty read-only tmpfs. It is a framework invariant, not controlled
by `EXTENDED_HARDENING_ENABLED` or `TMPFS_ENABLED`.

`no-new-privileges` is **on**. Earlier versions had to disable it because the
in-container firewall ran through `sudo`; moving enforcement out removed that
constraint along with the sudo rule and all nine capabilities.

## Hermes-specific hardening

`./sandbox.sh open hermes` applies these automatically:

- **`HERMES_WRITE_SAFE_ROOT=/workspace/repos:/home/node/.hermes`** — hard
  write-jail. `write_file`/`patch` outside these roots are rejected outright,
  no prompt. The agent cannot write to sandbox config, `/etc`, or anywhere else.
- **`HERMES_YOLO_MODE=0`** — approval-bypass **defaulted** off. Note: this sets
  the initial state only; the operator can still enable it at runtime with
  `/yolo`, which bypasses approvals and the Tirith gate. The agent cannot enable
  it (`/yolo` is a user command, not a tool), and the container boundary still
  applies, but treat YOLO as an operator footgun, not a hard lock.
- **`HERMES_REDACT_SECRETS=true`** — key patterns scrubbed from output/logs.
- From `config.yaml`: `approvals.mode: manual`, `allow_private_urls: false`
  (SSRF protection), `allow_lazy_installs: false`, `guard_agent_created: true`.



## Git workflow: commit inside, push outside

**No SSH credentials enter the container by default.** Repositories are bind
mounts, so a `git commit` made by the agent lands directly in the host
repository. You review it and push yourself:

```bash
# inside the container — the agent works and commits
git add src/thing.ts && git commit -m "..."

# on the host — you review, then you push
git -C ~/projects/my-project log -p
git -C ~/projects/my-project push
```

Under this project's threat model (the agent is not trusted) this is the
correct default: the agent's output passes a human before it can reach a
remote, and there is no credential in the container to misuse or exfiltrate.

### Opt-in: SSH agent forwarding for automation

When you want the agent to push unattended, forwarding is available — but it
must be enabled explicitly and pointed at a dedicated agent.

Agent forwarding does **not** leak private key material; the SSH agent protocol
is a signing oracle. But while the socket is live, the container can sign with
**every identity the agent holds**, for the whole session. That means push
access to every repository those keys reach, plus authentication to any host
allowed on port 22. Forwarding your desktop or GNOME Keyring agent hands the
container your entire identity set.

So: a separate agent, holding one key, scoped to one repository.

```bash
# 1. a key that exists only for the sandbox
ssh-keygen -t ed25519 -f ~/.ssh/asf_sandbox -C asf-sandbox

# 2. a dedicated agent holding only that key, expiring after 4h
export ASF_AGENT_SOCK="/run/user/$(id -u)/asf-agent.sock"
rm -f "$ASF_AGENT_SOCK"
ssh-agent -a "$ASF_AGENT_SOCK" >/dev/null
SSH_AUTH_SOCK="$ASF_AGENT_SOCK" ssh-add -t 4h ~/.ssh/asf_sandbox
```

Register `~/.ssh/asf_sandbox.pub` as a per-repository **deploy key** with write
access. Deploy keys are scoped to one repository, so the blast radius is one
repo instead of your whole account.

Then in `asf.conf`:

```bash
SSH_AGENT_FORWARDING=true
SSH_AGENT_SOCKET="/run/user/1000/asf-agent.sock"
```

There is no auto-discovery — the path is stated explicitly so the startup log
always records which agent was exposed. ASF prints a warning at session start
whenever forwarding is active, and refuses to start if the socket is missing
rather than starting silently without the key you expected.

**Notes.** GitHub rejects the same deploy key on multiple repositories; for
several repos, generate several keys and use `Host` aliases in `~/.ssh/config`
with `IdentitiesOnly yes`. `ssh-add -c` additionally prompts for confirmation
on every signature, which is excellent here, but it needs `SSH_ASKPASS` and a
graphical session — it fails silently when headless, so test it before relying
on it.

**Residual risk.** Even with one scoped key and a confirmation prompt, an
approved push can carry different content than you reviewed. That is why the
commit-inside/push-outside default exists.

## Network modes

A runtime declares how it reaches anything outside itself:

```yaml
network:
  mode: proxy | isolated | routed
```

**`proxy`** (default) — egress through Caddy to the domains the manifest
declares, port 443 only, on both request paths. `allow_domains` is the complete
list; there is no implicit base set.

**`isolated`** — no proxy and no egress network. The runtime has **no direct
external path**.

> `isolated` does not mean offline. The runtime can still reach services on its
> private internal network, especially LiteLLM, and the broker forwards to an
> external provider on its own network. Logical agents inside one application
> still share the same container. Separate ASF runtimes are not connected by
> default. Data can therefore still leave through the broker.

**`routed`** — exact IPv4 CIDR/protocol/port access through a separate
nftables gateway. The runtime receives only declared static routes, never a
default route. The long-lived gateway has no capabilities; a short-lived
`NET_ADMIN` initializer loads policy and exits. ASF explicitly verifies its
absence and re-inspects the capability-less holder before startup succeeds.
Startup requires a reachable
allowed TCP control and a second known-open port that policy must block.

All modes are verified before the agent container starts. Every **deny**
check is fatal: a policy that fails to block aborts the session. The
**positive control** (an allowlisted host being reachable) is an availability
check, not a security property: if it fails *inconclusively* — upstream down,
5xx — startup continues with an explicit warning, while an outright proxy
denial of an allowlisted host still aborts as a policy misconfiguration. The
full check-by-check verdict is persisted to
`.devcontainer/sessions/<agent>/verification-report.json`. Routed startup
exercises TCP end to end; UDP and ICMP rules retain unit and spike coverage. See `agents/isolated-worker/runtime.yml`,
`examples/routed-runtime.yml`, and [docs/TESTING.md](docs/TESTING.md).

## Runtime manifests

Each runtime is declared by `agents/<name>/runtime.yml` — its identity, state
volumes, LLM/broker settings, secrets, and static environment. ASF discovers
runtimes by that file, so adding one needs no code change:

```yaml
name: my-app
adapter: generic
runtime:
  mode: service
  command: ["python", "-m", "my_app"]
llm:
  broker: true
  protocol: openai        # wire protocol spoken TO the broker
  provider: openrouter    # upstream provider LiteLLM talks to
filesystem:
  state:
    - key: cache
      target: /home/node/.cache/my-app
secrets:
  files: [common.env]
```

Validate one with `python3 -m asf.manifest agents/<name>/runtime.yml`.
Unknown keys are rejected, so a typo fails loudly instead of silently doing
nothing. Manifests currently declare only what ASF reads from them; repository
mounts stay in `agents/<name>/repos.yml` and hardening in `asf.conf`. Extra
egress domains for a runtime go in its manifest under
`network.allow_domains`.

Requires PyYAML on the host (`pacman -S python-yaml`, `apt install python3-yaml`,
or `pip install pyyaml`).

### LangGraph, CrewAI, smolagents, or your own Python agent

ASF sandboxes these as **one workload** — there is no CrewAI adapter and no
LangGraph adapter, because ASF does not need to understand their internal
programming model. They are ordinary Python workloads whose protocol, provider,
and credentials are declared by the runtime manifest. The bundled examples use
LiteLLM's OpenAI-compatible interface and `OPENAI_BASE_URL`, but that is an
example configuration rather than an ASF requirement. A runtime may instead
use another supported protocol and provider, such as Anthropic with
`protocol: anthropic`, `provider: anthropic`, and `ANTHROPIC_API_KEY`.

Ready-made runtimes ship for each:

```bash
./sandbox.sh repo add langgraph ~/projects/my-graph
./sandbox.sh open langgraph             # or: crewai, smolagents
```

Each lives in `agents/<framework>/` and holds exactly three files:

| File | Purpose |
|---|---|
| `runtime.yml` | manifest — state volumes, LLM/broker settings, secrets, env |
| `requirements.txt` | what to install (the real per-framework difference) |
| `setup.sh` | installs into a venv on a persistent volume, once |

The venv sits on a named volume, so dependencies download on first start only.
The supplied OpenAI-compatible examples set both `OPENAI_BASE_URL` and
`OPENAI_API_BASE` because client libraries disagree about which variable they
read: the OpenAI SDK and newer LangChain releases use the first, while some
LiteLLM-based clients use the second. These variables are example-specific,
not ASF requirements; runtimes using another protocol declare the matching
broker settings and credential variable instead.

For your own app, copy `agents/python-agent/` instead — same structure, no
framework preinstalled. Either way, add a section named after the runtime to
`network.allow_domains` in its `runtime.yml` if it needs egress beyond the
shared defaults (GitHub, GitLab, npm).

To run the app directly instead of getting a shell, set `mode: service` and a
`command:` in the manifest — `./sandbox.sh open langgraph` then runs it and
tears everything down on exit.

**Versions are deliberately unpinned** in each `requirements.txt`. ASF pins its
own dependencies in `asf.conf`; these belong to *your* application, so pin them
yourself for reproducible builds.

**Isolation limit, stated plainly:** ASF isolates the *application* from the
host. It does **not** isolate that application's internal agents (crew members,
graph nodes) from each other — they share one container, one filesystem, one
environment, one set of credentials. Per-agent isolation requires running each
as its own ASF runtime.

## Running two agents at once

Agents run side by side from a single checkout — no second copy, no git needed:

```bash
# terminal 1
./sandbox.sh open hermes

# terminal 2
./sandbox.sh open claude
```

Each session is fully separate: its own container, its own LiteLLM broker
container, its own private Podman network, its own provider secret and session
token, its own state volume, and its own repository list. Repositories are
shared only when you explicitly add the same host path to more than one agent.

Internal support services use short, session-network-scoped DNS aliases
(`asf-proxy` and `asf-broker`). Their full checkout/PID-scoped container names
are still used for ownership, diagnostics, and cleanup.

How it works: `sandbox.sh` generates
`.devcontainer/sessions/<agent>/devcontainer.json` per agent (the CLI requires
that exact filename, so agents get separate directories) and passes `--config`
plus `--id-label asf.session=<checkout>-<agent>` to `up`/`exec`, so the CLI
treats each agent as a distinct container instead of recreating a shared one.
`build` takes only `--config`; it creates an image, not a container. The agent
name reaches the container through `ASF_AGENT` (`containerEnv`), and each
session gets its own three networks, so there is no shared state for two
sessions to race over. Locks are per agent: opening
`claude` twice is refused, opening `claude` alongside `hermes` is not.

### Two sessions of the *same* agent

Not supported inside one checkout (they would share a state volume). Copy the
directory instead — resource names derive from the checkout path, so a copy is
fully isolated:

```bash
cp -a ~/projects/asf ~/projects/asf-2      # includes secrets/ (gitignored)
cd ~/projects/asf-2 && ./sandbox.sh open hermes
```

Its containers, volumes, broker, locks, and per-agent repository files are
separate. The first build in the new location re-tags the image (mostly cache
hits).

Commands that act on a session take an optional agent, needed only when more
than one is running:

```bash
./sandbox.sh ls                  # show active/deployed sessions
./sandbox.sh shell hermes        # attach
./sandbox.sh broker status claude
./sandbox.sh scan my-api hermes
./sandbox.sh stop claude         # stop one session
./sandbox.sh stop                # stop every session in this checkout
```

### Evidence-driven allowlist review

With `CADDY_ACCESS_LOGS=true`, every proxy session writes bounded JSON access
logs into its own evidence directory. Teardown reduces those logs to counts;
ASF startup-verification probes are tagged and excluded from the result.

```bash
./sandbox.sh advise claude
```

Example:

```text
Egress policy advice for claude (12 recorded sessions; window 12)
  - sentry.io was allowlisted but unused in your last 12 sessions — consider removing it.
  - The agent attempted 47 denied CONNECTs to registry.npmjs.org across 12 sessions — consider adding it.
```

Removal advice requires 12 completed sessions in which the domain was present
in the effective allowlist and never contacted. Addition advice requires at
least three denied CONNECTs across at least two sessions. These conservative
thresholds avoid turning one typo or one unusual run into a policy change.
Advice is read-only and available after the session has stopped; edit
`agents/<agent>/runtime.yml` yourself after reviewing the destination.

## Known limitations

Documented gaps, not oversights. Each is a deliberate trade-off:

- **DNS tunnelling through the legitimate resolver.** Port 53 is restricted to
  the container's configured resolvers, which closes direct connections to
  arbitrary hosts — but a low-bandwidth channel through the recursive resolver
  itself remains.
- **CDN-shared IPs widen effective egress.** Filtering is IP-based and HTTPS
  routing is SNI-based. Allowlisting domains served from shared CDN edges
  (e.g. Cloudflare, Fastly, Azure blob frontends) allows every other domain
  behind the same IPs. Port-constraining outbound to 80/443 shrinks this to
  web traffic, but does not remove it.
- **IPs are resolved once at container start.** CDN rotation during long
  sessions can break allowlisted services until the container is restarted.
- **Secrets are visible in host argv during a session.** `devcontainer exec
  --remote-env KEY=value` places values in the host-side command line, and
  `/proc/*/cmdline` is world-readable on Linux. On a single-user host this is
  harmless; on shared hosts, enable the LiteLLM broker (the reusable provider
  key then never appears in argv — only session-scoped values do).

## Semgrep scanning

Semgrep is installed in the container and scans source code in your repos.

```bash
# From the host
./sandbox.sh scan              # scan all mounted repos
./sandbox.sh scan my-api       # scan one repo

# Or from inside the container
semgrep scan --config auto /workspace/repos/my-api
semgrep scan --config p/security-audit /workspace/repos/
```

Semgrep scans source code, not Claude Code policy files. Reviewing `CLAUDE.md`
or hooks for safety is a human task (or a separate Claude session).

## Notes

- Containers are named `<checkout>-<hash>-<agent>` (e.g. `asf-940911e5e800-hermes`)
  and brokers `<checkout>-<hash>-<agent>-litellm-<pid>`, so `podman ps` shows
  which session is which
- Put the checkout wherever you like; nothing depends on its location. Volume and
  container names include a hash of that path, so **moving or renaming the
  directory starts fresh state** — stop sessions first, and expect new (empty)
  agent volumes afterwards
- `.devcontainer/sessions/<agent>/devcontainer.json` files are auto-generated — never edit them by hand
- `open` recreates that agent's container each time, so mount changes take
  effect immediately, and removes it on exit so nothing lingers
- `shell` attaches to a running container without recreating it
- Persistent-volume names include a hash of the canonical checkout path, so two
  ASF clones with the same directory basename remain isolated.
- Two repositories with the same basename cannot be assigned to the same agent
  because both would mount at the same container path; `repo add` rejects the
  second one.

## Development checks

The repository includes standard-library unit tests, mocked lifecycle tests,
resource-isolation tests, dependency-pin checks, and optional ShellCheck analysis:

```bash
./tests/run.sh

# Real host tests: Caddy proxy, isolated, and capability-less gateway
bash tests/run-host.sh

# Optional for unusually slow first-time image builds (default: 900 seconds):
ASF_HOST_OPEN_TIMEOUT=1800 bash tests/run-host.sh

# Optional comparative evidence; Tinyproxy is not supported by ASF:
bash tests/experiments/compare-tinyproxy-caddy.sh

# Individual proxy and isolated integration tests:
ASF_INTEGRATION=1 ./tests/test_integration.sh
ASF_INTEGRATION=1 ./tests/test_isolated_integration.sh

# Live checks and Caddy observability for a running session:
./sandbox.sh test hermes
./sandbox.sh proxy status hermes
./sandbox.sh proxy logs -f hermes
./sandbox.sh advise hermes

# Routed end-to-end test against a prepared target:
ASF_INTEGRATION=1 \
ASF_ROUTED_TARGET_IP=192.0.2.2 \
ASF_ROUTED_ALLOWED_PORT=18080 \
ASF_ROUTED_BLOCKED_PORT=19999 \
bash tests/test_routed_integration.sh
```

The integration tests open real sessions and assert the security claims from
inside the runtime. `./sandbox.sh test [agent]` repeats the applicable checks on
an already-running session. Caddy policy, status, and live JSON access logs are
available through `./sandbox.sh proxy`; retained cross-session policy evidence
is summarized by `./sandbox.sh advise`. See [docs/TESTING.md](docs/TESTING.md).

The Python tests use the standard library plus PyYAML for runtime-manifest
coverage. GitHub Actions runs the same suite and ShellCheck on every push and
pull request. Release dependency and SBOM scope are documented in
[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md).

### Proxy implementation

Caddy is the only proxy accepted by the production lifecycle because it is the
only tested implementation combining private/special-address denial with
port-443 enforcement on both CONNECT and plain-HTTP paths. tinyproxy and
g3proxy remain available in clearly labelled comparison experiments only.

### CONNECT-only proxy behavior

ASF permits outbound web access only through HTTP `CONNECT` to allowed hosts
on port 443. Generated Caddy policy rejects every plain forward-proxy request
with an explicit HTTP 403 before `forward_proxy`. Proxy and default-route
verdicts are computed inside the probe container and transported as reserved
exit codes; attached stdout/stderr is diagnostic only. HTTP 5xx responses are
never accepted as proof of policy denial.
