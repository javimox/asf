# Dependency inventory — ASF 2.0

This inventory separates dependencies ASF pins from host tools and example-app
dependencies that the operator controls.

## Host requirements

| Component | Requirement | Pin status | Purpose |
|---|---:|---|---|
| Python | `>=3.10` | version range | ASF CLI and lifecycle |
| PyYAML | `>=6,<7` | major range | runtime manifests |
| setuptools | `>=77` when building a wheel | build range | package metadata/build backend |
| Podman | rootless, Netavark backend | host-managed | containers, networks, secrets, volumes |
| Dev Container CLI | compatible current release | host-managed | default `container` backend build/up/exec boundary |
| ASF TAP-capable crun | optional | repository-pinned source + CI-tested | routed `runtime.isolation: microvm` backend |
| system krun + libkrun + KVM | optional | host-managed | microVM boundary; system `krun` is used for isolated/proxy mode |
| Bash | `>=4` for test harnesses | host-managed | tests and small fixed scripts |
| ShellCheck | optional | host-managed | shell static analysis |

Podman, Dev Container CLI, system krun and libkrun are host-managed. Routed
microVM mode pins the small TAP-capable crun frontend by source under
`tools/krun-runtime/`; hosts build it locally and dedicated CI validates the
pin. Record the versions relevant to the backend used for release validation:

```bash
python3 --version
python3 -c 'import yaml; print(yaml.__version__)'
podman --version
podman info --format '{{.Host.NetworkBackend}}'
devcontainer --version
krun --version                 # system runtime for isolated/proxy microVM
tools/krun-runtime/bin/crun --version  # routed local runtime
```

## Pinned runtime/build inputs

Pins below come from `asf.conf` and security-sensitive Python constants.

| Component | Pin |
|---|---|
| Node base image | `node:22.23.1-bookworm-slim` |
| uv image | `ghcr.io/astral-sh/uv:0.11.31` |
| Semgrep | `1.171.0` |
| Claude Code | `2.1.216` |
| Hermes Agent | commit `f9eca7e15f1c2bfe5194aae5aa489af53c0a1a23` |
| git-delta | `0.18.2` |
| fzf | `0.74.1` plus architecture-specific SHA-256 checksums |
| zsh-in-docker | `1.2.0` |
| LiteLLM image | `ghcr.io/berriai/litellm:v1.93.0` |
| Alpine utility/runtime image | `docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc` |
| Caddy builder image | `docker.io/library/caddy@sha256:cc6c40aa7cdea02ef9cb99f3c4e4664ecdb6066ae93ae52ed5288afc511e1241` |
| Caddy | `v2.10.0` |
| Caddy forwardproxy | commit `0aab84dad4fc2830789f34e27b4d7bc22a40889e` |
| Routed crun | `tools/krun-runtime/VERSION` + `COMMIT` (binary built locally) |

The Node, uv, and LiteLLM references are exact tags rather than immutable image
digests. Release builds should record resolved image digests, and a future pin
update may move them to digests without changing the lifecycle design.

## Example workload dependencies

`agents/crewai`, `agents/langgraph`, and `agents/smolagents` intentionally leave
their application libraries unpinned. They are examples of user workloads, not
ASF host dependencies. Users should pin those requirements for reproducible
applications.

## GitHub Actions

GitHub Actions are pinned by commit SHA. CI installs ShellCheck from the Ubuntu
runner and runs `tests/run.sh`. The manual integration workflow installs the
Dev Container CLI and runs the real lifecycle.

## SBOM scope

`docs/sbom/asf-v2.0.spdx.json` is a deterministic source/deployment inventory
generated from this checkout. In Git checkouts it inventories tracked files only,
so local untracked files do not change the release digest. Its timestamp comes
from `CITATION.cff`'s release date.
It records ASF, PyYAML, pinned tools, and image references.
It is not an image-layer SBOM. Generate image-specific SBOMs on the release host
after builds, for example with Syft or Podman's available SBOM tooling, and
archive them with the release artifacts.
