# Runtime configuration

ASF treats an agent as an executable workload with declared capabilities. This
guide covers runtime state, agent policy files, secrets, LLM brokering, runtime
manifests, generic Python applications, and concurrent sessions.

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

## Runtime manifests

Most ASF policy options are **agent-agnostic**. The adapter chooses what is
installed/configured; it does not lock the runtime to one network or isolation
mode. Hermes, Claude, and generic Python workloads can use the same ASF policy
knobs when the combination is supported.

| Setting | Options / constraint |
|---|---|
| `runtime.isolation` | `container` or `microvm` |
| `network.mode` | `proxy`, `routed`, or `isolated` |
| `capabilities` | optional; `net_raw` only. With `microvm`, requires `routed` |
| `observability.llm_prompts` | requires `llm.broker: true` |
| `observability.network_activity` | requires `microvm` + `routed` |
| proxy fields | `verify_domain`, `allow_domains` |
| routed fields | `allow`, optional `verify` |

A normal interactive agent defaults to `container` + `proxy`. Keep only the
selected network mode's fields active:

```yaml
name: my-agent
adapter: generic

runtime:
  mode: interactive
  isolation: container  # container or microvm

# Optional. NET_RAW is the only supported runtime capability.
# capabilities: [net_raw]

llm:
  broker: true
  protocol: openai
  provider: openai

observability:
  llm_prompts: false      # requires broker; stores full prompts on host
  network_activity: false # requires microvm+routed; no packet payloads

network:
  # proxy (usual default)
  mode: proxy
  verify_domain: github.com
  allow_domains:
    - github.com

  # routed (replace the proxy fields above)
  # mode: routed
  # allow:
  #   - cidr: 192.0.2.10/32
  #     # protocol: tcp
  #     # ports: [22, 443]
  # verify:                     # optional live policy proof
  #   address: 192.0.2.10
  #   protocol: tcp
  #   port: 22
  #   blocked_port: 19999

  # isolated (replace all external destination fields)
  # mode: isolated
```


Validate one with `python3 -m asf.manifest agents/<name>/runtime.yml`.
Unknown keys are rejected, so a typo fails loudly instead of silently doing
nothing. Manifests currently declare only what ASF reads from them; repository
mounts stay in `agents/<name>/repos.yml` and hardening in `asf.conf`. Extra
Network fields are mode-specific: `proxy` uses `verify_domain` and
`allow_domains`; `routed` uses `allow` and optional `verify`; `isolated` uses
none of those destination fields.

Requires PyYAML on the host (`pacman -S python-yaml`, `apt install python3-yaml`,
or `pip install pyyaml`).

`runtime.isolation` is optional. `container` is the default and preserves the
existing Dev Container lifecycle. `krun` runs only the agent workload behind a
libkrun/KVM boundary and has deliberate runtime constraints; see
[krun microVM isolation](KRUN.md).
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
./sandbox.sh observe [agent]     # host-side session and privilege state
./sandbox.sh shell hermes        # attach
./sandbox.sh broker status claude
./sandbox.sh scan my-api hermes
./sandbox.sh stop claude         # stop one session
./sandbox.sh stop                # stop every session in this checkout
```
