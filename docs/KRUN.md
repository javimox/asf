# microVM isolation (krun backend)

ASF can run the untrusted agent workload inside a libkrun/KVM microVM.
The default remains `runtime.isolation: container`.

## Enable it

```yaml
runtime:
  mode: interactive
  isolation: microvm
```

Only the agent workload moves into the microVM. Trusted ASF services remain
rootless Podman containers on the host.

```text
host
└── rootless Podman
    ├── Caddy
    ├── LiteLLM
    ├── routed gateway
    └── agent workload
         └── libkrun/KVM microVM
```

ASF does not add a VM manager or guest SSH daemon.

## Host requirements

- Linux with `/dev/kvm` available to the user. The routed CI acceptance path is currently verified on x86_64.
- Podman.
- libkrun 1.x with virtio-net/TAP support.
- `/dev/net/tun` for routed mode.
- A system `krun` OCI runtime for isolated/proxy microVM mode.

Routed microVM mode uses ASF's locally built TAP-capable crun at:

```text
tools/krun-runtime/bin/crun
```

Stock crun does not yet expose libkrun TAP selection to ASF, so the routed
runtime carries one small source extension for `krun.tap_name=<tap>`. ASF
commits the upstream pin, guarded build recipe, and reviewable reference patch;
the executable itself is built locally and git-ignored:

```bash
tools/krun-runtime/build.sh
tools/krun-runtime/verify-runtime.sh
```

ASF fails closed at `open` time if the default local build is missing or its
`VERSION`/`COMMIT` provenance does not match the release pinned by ASF.
`CRUN_TAP_RUNTIME=/path/to/crun` remains an explicit development override.

The `crun TAP` CI workflow uses one focused real KVM/TAP acceptance test. Push
and pull-request runs test the pinned release; scheduled and manually dispatched
runs test the latest upstream release and act as the drift alarm for a future
pin update.

## Guest identity

Agent-controlled work runs as `node` (`uid=1000`) with `NoNewPrivs=1`.
Capabilities are empty by default.

Routed scanners may opt into only `NET_RAW`:

```yaml
capabilities: [net_raw]
```

`NET_RAW` is granted inside the guest only. The host-side VMM does not receive
it.

## Networking

### isolated

No direct external route. Internal ASF services can still be reachable.

### proxy

HTTP/HTTPS goes through the existing Caddy allowlist path.

### routed

Routed microVM isolation uses TAP-backed virtio-net through the krun backend:

```text
microVM eth0
    │
   tap0
    │
    ▼
ASF routed gateway
    ├── nftables/NAT ── authorised target
    └── TCP/4000 ────── LiteLLM broker
```

The guest has no default route. ASF adds only explicit routes for declared
routed destinations and, when enabled, the session broker.

Destination-only access:

```yaml
network:
  mode: routed
  allow:
    - cidr: 192.0.2.10/32
```

This allows all IP traffic to that destination/CIDR.

Restricted access:

```yaml
network:
  mode: routed
  allow:
    - cidr: 192.0.2.10/32
      protocol: tcp
      ports: [22, 443]
```

Undeclared destinations have no guest route, except an optional
verification-only `blocked_address` used for a controlled negative policy
proof.

## Optional routed verification

`network.verify` is optional. Normal pentest/discovery sessions do not need
known-open services on the target.

Without it, ASF verifies structural invariants:

- no IPv4 default route;
- no IPv6 default route;
- declared routes are present;
- an undeclared destination has no route;
- external DNS is unavailable.

Controlled acceptance tests can add a live positive/negative check:

```yaml
network:
  mode: routed
  allow:
    - cidr: 192.0.2.10/32
      protocol: tcp
      ports: [18080]
  verify:
    address: 192.0.2.10
    protocol: tcp
    port: 18080
    blocked_port: 19999
```

Use `blocked_address` when the denied control is on a different known-open IP.

## LiteLLM broker over TAP

Routed microVM sessions can use the normal ASF LiteLLM broker through the krun
backend.

ASF gives the broker one private address on the session scan network and adds a
single broker `/32` route inside the guest. The gateway permits only guest →
broker TCP/4000 plus established replies.

OpenAI-compatible agents receive:

```text
OPENAI_BASE_URL=http://<broker-ip>:4000/v1
```

Liveness check:

```bash
curl -fsS "${OPENAI_BASE_URL%/v1}/health/liveliness"
```

The broker keeps its separate provider network for upstream LLM access.

## Privilege boundary

Long-lived components do not hold network-administration capability:

```text
guest                 no caps, or NET_RAW when requested
krun/VMM              no capabilities
LiteLLM               no capabilities
routed gateway        no capabilities
routed initializer    temporary NET_ADMIN, then exits
```

The initializer creates/configures TAP and loads nftables before the agent
starts.

## Interactive lifecycle

Start:

```bash
./sandbox.sh open <agent>
```

Routed microVM mode resolves `tools/krun-runtime/bin/crun` automatically.

Detach without stopping:

```text
Ctrl-P, Ctrl-Q
```

Reattach:

```bash
./sandbox.sh shell <agent>
```

Stop:

```bash
./sandbox.sh stop <agent>
```

A failed microVM launch also cleans the broker, gateway, temporary secrets and
session networks.

## Host-side observation

Use:

```bash
./sandbox.sh observe <agent>
```

This reports the session-start policy snapshot, host-side process capability
state, lifecycle events, LiteLLM request metadata, and the status/path of any
on-demand routed PCAP captures. LLM response bodies are not captured. Prompt bodies are recorded
only when
`observability.llm_prompts: true` is explicitly enabled.

See [OBSERVABILITY.md](OBSERVABILITY.md).

## Design decisions

These are the stable decisions behind ASF microVM isolation; new work should
not add network paths without a concrete requirement.

- Only the untrusted workload runs in libkrun/KVM.
- Trusted ASF services remain rootless Podman containers.
- Routed mode uses one TAP-backed guest NIC and no guest default route.
- The long-lived routed gateway has no capabilities.
- A short-lived initializer receives `NET_ADMIN`, configures TAP/nftables, then exits.
- `NET_RAW` is the only guest capability opt-in.
- Routed LiteLLM access is a narrow broker `/32` route with TCP/4000 only.
- Routed mode uses the locally built TAP-capable crun under `tools/krun-runtime/`;
  ASF commits its upstream pin and build recipe, while the executable is
  git-ignored. `CRUN_TAP_RUNTIME` is only a development override.
- The current TAP and broker topology is frozen.

## Validation status

Manual acceptance has demonstrated:

- real guest TCP, UDP, ICMP and raw SYN traffic;
- destination-only and protocol/port-restricted routed policy;
- no route to undeclared neighboring networks;
- normal and failed-start cleanup;
- reopen after cleanup;
- Hermes → LiteLLM → OpenAI over TAP;
- Hermes → authorised routed target in the same session;
- guest `NET_RAW` opt-in without capability leakage to the VMM;
- capability-less broker and long-lived gateway.

The routed TAP and broker topology is frozen. On-demand packet capture stays
outside the guest and does not alter enforcement. The focused
`tests/test_krun_tap_ci.sh` job verifies only the TAP-capable crun boundary;
broader ASF feature-flow testing remains separate.
