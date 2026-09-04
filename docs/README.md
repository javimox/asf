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
- [CI-tested routed runtime template](../agents/routed-scanner/example-runtime-ci-tested.yml) — example manifest for
  routed-mode target access
- [Trust model](TRUST.md) — concise trust boundaries and threat model
- [Security model](SECURITY-MODEL.md) — defense-in-depth controls, hardening,
  network modes, known limitations, and enforcement evidence

## Architecture

- [Network design](NETWORK-DESIGN.md) — internal, proxy, isolated, and routed
  network topology
- [Egress design](EGRESS-DESIGN.md) — Caddy policy, verification, and outbound
  traffic controls
- [microVM isolation](KRUN.md) — optional KVM isolation for the agent workload (krun backend)
- [observability](OBSERVABILITY.md) — host-side session, LLM, privilege, and routed PCAP evidence
- [Dependencies](DEPENDENCIES.md) — pinned dependencies and SBOM scope

## Development

- [Testing](TESTING.md) — unit, shell, integration, and host tests
- [Releasing](RELEASING.md) — release preparation and checks
- [Security policy](SECURITY.md) — reporting security issues
- [Known bugs](BUGS.md) — currently known limitations or defects
- [Release history](RELEASES.md) — released ASF versions and detailed notes
- [Changes in ASF 2.0](CHANGES-v2.0.md) — release changes and upgrade notes
