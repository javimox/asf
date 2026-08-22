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

- Linux with `/dev/kvm` available to the user.
- Podman with a krun runtime for isolated/proxy mode.
- TAP-capable crun for routed mode.

For routed mode ASF currently uses a small patch against crun 1.29.1. Stock
crun does not yet expose libkrun TAP configuration. ASF does not install or
manage this runtime.

```bash
export CRUN_TAP_RUNTIME="$HOME/.local/share/asf/krun-tap/1.29.1/bin/crun"
```

The review patch is kept at:

```text
tools/experiments/patches/crun-1.29.1-tap.patch
```

A build helper remains under `tools/experiments/` for development use.

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
    - cidr: 192.168.252.2/32
```

This allows all IP traffic to that destination/CIDR.

Restricted access:

```yaml
network:
  mode: routed
  allow:
    - cidr: 192.168.252.2/32
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
    - cidr: 192.168.252.2/32
      protocol: tcp
      ports: [18080]
  verify:
    address: 192.168.252.2
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
CRUN_TAP_RUNTIME="$HOME/.local/share/asf/krun-tap/1.29.1/bin/crun" \
./sandbox.sh open <agent>
```

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
state, lifecycle events, and LiteLLM request metadata. Packet payloads and LLM
response bodies are not captured. Prompt bodies are recorded only when
`observability.llm_prompts: true` is explicitly enabled.

See [OBSERVABILITY.md](OBSERVABILITY.md).

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

The routed TAP and broker topology is frozen. Experimental scripts remain under
`tests/experiments/` as development evidence, not normal CI.
