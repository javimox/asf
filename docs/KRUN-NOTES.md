# krun implementation notes

These notes capture the stable design decisions behind ASF microVM isolation.
For usage, see [KRUN.md](KRUN.md).

- Only the untrusted workload runs in libkrun/KVM.
- Trusted ASF services remain rootless Podman containers.
- Routed mode uses one TAP-backed guest NIC and no guest default route.
- The long-lived routed gateway has no capabilities.
- A short-lived initializer receives `NET_ADMIN`, configures TAP/nftables, then exits.
- `NET_RAW` is the only guest capability opt-in.
- Routed LiteLLM access is a narrow broker `/32` route with TCP/4000 only.
- Routed mode uses the locally built TAP-capable crun under `tools/krun-runtime/`; ASF commits its upstream pin and build recipe, while the executable is git-ignored. `CRUN_TAP_RUNTIME` is only a development override.
- The current TAP and broker topology is frozen; new work should not add network paths without a concrete requirement.
