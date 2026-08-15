# Agent Sandboxing Framework

[![CI](https://github.com/javimox/asf/actions/workflows/ci.yml/badge.svg)](https://github.com/javimox/asf/actions/workflows/ci.yml)
![Podman](https://img.shields.io/badge/Podman-rootless-892CA0?logo=podman&logoColor=white)

A rootless, daemonless Podman-based orchestration framework for sandboxing AI agents.

## Demo

<p align="center">
  <img src="docs/assets/asf-demo.gif" alt="ASF terminal demo">
</p>

ASF was born as a Master's degree thesis, but the original idea evolved far
beyond its initial scope through many hours of design, experimentation, and
development. I hope you enjoy using it as much as I enjoyed designing and
building it.

## Quick start

**Requirements:** Python with PyYAML, rootless Podman, and the Dev Container CLI
(`@devcontainers/cli`). See
[Getting started](docs/GETTING-STARTED.md#prerequisites) for installation details.

ASF runtimes are configured per agent. In general:

1. Configure any credentials required by the runtime.
2. Grant the agent access only to the repositories it needs.
3. Open the sandbox.
4. Start the agent inside the constrained environment.

The following example uses **Claude Code** with ASF's default LiteLLM broker
configuration. Provider credentials stay outside the agent container. The agent receives only a temporary broker token.

```bash
# Configure the Anthropic API key
cp secrets/claude.env.example secrets/claude.env
chmod 600 secrets/claude.env

# Set ANTHROPIC_API_KEY
$EDITOR secrets/claude.env

# Give Claude access only to the repositories it needs
./sandbox.sh repo add claude ~/projects/my-api
./sandbox.sh repo add claude ~/projects/reference --mode ro

# Open the sandbox
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
read-write by default; use `--mode ro` for inputs or reference material that the
agent should not modify.

## Why ASF

- **Capabilities, not cognition.** ASF constrains executable workloads without
  needing to understand how an agent reasons, plans, or orchestrates tasks.
- **Isolation by topology.** In proxy and isolated modes, the agent network has
  no normal gateway; outbound access follows explicitly created paths.
- **Generated, then verified.** ASF generates policy from the runtime manifest
  and verifies important allow, deny, private-address, port, and no-bypass
  properties before the session is considered ready.
- **Per-agent filesystem access.** Each runtime receives only the repositories
  assigned to it, with read-write or read-only mounts.
- **Brokered credentials.** LiteLLM can keep the reusable provider credential
  outside the agent runtime and expose only a short-lived local token.
- **Owned teardown and evidence.** ASF tracks the resources it creates, removes
  ephemeral state on exit, and records verification and cleanup evidence.

## Supported runtimes

ASF currently includes runtime support for:

- **Claude Code**
- **Hermes**
- **Generic Python agent applications**, including applications built with
  LangGraph, CrewAI, smolagents, or custom frameworks

The runtime model is intentionally agent-agnostic: product-specific adapters
should stay thin while Podman lifecycle, filesystem access, networking, secrets,
verification, and cleanup remain generic ASF responsibilities.

## Documentation

The full documentation is organized under [docs/](docs/README.md):

### Using ASF

- [Getting started](docs/GETTING-STARTED.md) — prerequisites, CLI commands,
  repository access, file ownership, Git workflow, and everyday usage
- [Runtime configuration](docs/RUNTIME-CONFIGURATION.md) — secrets, persistence,
  LiteLLM, manifests, generic runtimes, and multiple sessions
- [Trust model](docs/TRUST.md) — what ASF protects, what it does not, and the
  privileges it relies on
- [Security model](docs/SECURITY-MODEL.md) — defense-in-depth controls,
  hardening, network modes, limitations, and enforcement evidence

### Architecture and development

- [Network design](docs/NETWORK-DESIGN.md)
- [Egress design](docs/EGRESS-DESIGN.md)
- [Dev Container integration](docs/DEVCONTAINER.md)
- [Dependencies and SBOM scope](docs/DEPENDENCIES.md)
- [Testing](docs/TESTING.md)
- [Releasing](docs/RELEASING.md)
- [Security policy](docs/SECURITY.md)
- [Known bugs](docs/BUGS.md)

## Contributing

Contributions, bug reports, ideas, and pull requests are welcome. Please keep
changes small and reviewable, preserve explicit security invariants, and include
tests for security-sensitive behavior.

See [Testing](docs/TESTING.md) before submitting changes.

## License

ASF is distributed under the [BSD 4-Clause License](LICENSE).
