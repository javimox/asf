# LiteLLM broker

ASF starts one database-free LiteLLM container for the active agent. The broker
receives the reusable provider key through a temporary Podman secret; the agent
receives only a short-lived local token.

## Model routing

Model selection stays with Claude Code or Hermes. ASF supports one optional
whitespace-separated allowlist per agent:

```bash
# broker.conf
LITELLM_CLAUDE_MODELS="claude-sonnet-4-6 claude-opus-4-6"
LITELLM_HERMES_MODELS="gpt-5.5 gpt-5-nano"
```

When the relevant variable is undefined or empty, the broker queries the
provider during startup and generates concrete LiteLLM routes from the returned
model IDs. Literal wildcard rows such as `openai/*` and `anthropic/*` are
filtered out before LiteLLM starts. Defining a list skips provider discovery and
exposes only those models.

Hermes routes also drop `temperature`, because Hermes sends `temperature=0.3`
for auxiliary title generation and some OpenAI reasoning models accept only the
provider default.

The generated LiteLLM YAML exists only in the broker container's temporary
filesystem. It contains references to environment variables, never the provider
key itself, and disappears with the container.

The broker root filesystem is read-only. `/tmp` and `/run/secrets` are small
tmpfs mounts; the provider secret is mounted below `/run/secrets`.

## krun + routed

Routed krun reaches LiteLLM through the TAP gateway. The guest receives one
session-local broker `/32` route and no default route. The gateway allows only
TCP/4000 from the guest to that broker address.

```text
krun guest -> TAP gateway -> LiteLLM:4000 -> provider
           -> authorised routed target
```

For OpenAI-compatible agents:

```bash
echo "$OPENAI_BASE_URL"
curl -fsS "${OPENAI_BASE_URL%/v1}/health/liveliness"
```

The broker keeps the reusable provider credential. The guest receives only the
short-lived ASF broker token.

## Diagnostics

```bash
./sandbox.sh broker status
./sandbox.sh broker logs --follow
./sandbox.sh broker test                 # Hermes: configured default model
./sandbox.sh broker test <model>         # explicit model, required for Claude
```

LiteLLM deployment cooldowns are disabled because ASF creates exactly one
deployment per model per session; the original provider error remains visible.
