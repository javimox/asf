# ASF documentation

The README is intentionally short. Detailed usage, configuration, security, and
implementation material lives here.

## Using ASF

- [Getting started](GETTING-STARTED.md) — prerequisites, CLI commands,
  repository access, file ownership, Git workflow, and everyday usage
- [Runtime configuration](RUNTIME-CONFIGURATION.md) — secrets, persistence,
  LiteLLM, runtime manifests, generic Python agents, and concurrent sessions
- [LiteLLM broker](BROKER.md) — brokered provider credentials, model routing,
  and broker diagnostics
- [Routed runtime example](examples/routed-runtime.yml) — example manifest for
  routed-mode target access
- [Trust model](TRUST.md) — concise trust boundaries and threat model
- [Security model](SECURITY-MODEL.md) — defense-in-depth controls, hardening,
  network modes, known limitations, and enforcement evidence

## Architecture

- [Network design](NETWORK-DESIGN.md) — internal, proxy, isolated, and routed
  network topology
- [Egress design](EGRESS-DESIGN.md) — Caddy policy, verification, and outbound
  traffic controls
- [Dev Container integration](DEVCONTAINER.md) — how ASF uses the Dev Container
  CLI with Podman
- [Dependencies](DEPENDENCIES.md) — pinned dependencies and SBOM scope

## Development

- [Testing](TESTING.md) — unit, shell, integration, and host tests
- [Releasing](RELEASING.md) — release preparation and checks
- [Security policy](SECURITY.md) — reporting security issues
- [Known bugs](BUGS.md) — currently known limitations or defects
