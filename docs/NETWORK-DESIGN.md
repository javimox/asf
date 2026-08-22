# ASF network design

How a runtime reaches anything outside itself. Three modes, one invariant, and
a verification gate on each.

Status: **implemented for proxy, isolated, and routed modes.**
Routed startup always checks structural invariants; live target verification is optional.

---

## 1. The invariant

> `NET_ADMIN` never exists in a container that runs model output.

Everything below follows from this. A runtime cannot alter the policy that
constrains it, because the policy lives somewhere the runtime cannot reach —
either in the shape of the network (no route exists) or in a namespace owned by
a separate gateway container.

Corollaries, all measured:

- the runtime receives **no** Linux capabilities by default (`--cap-drop=ALL`); `NET_RAW` is the only supported explicit opt-in
- `no-new-privileges` is on
- there is no `sudo` and no privileged helper inside the runtime
- routes are injected by Podman, never by the runtime
- a capability-less runtime cannot add a route, alter one, or touch netfilter

### Capability vocabulary (closed set)

| Capability | Runtimes | Notes |
|---|---|---|
| `NET_ADMIN` | **never** | not expressible in a manifest; rejected by validation |
| `NET_RAW` | opt-in | the only supported opt-in; needed for SYN scans / OS detection |
| anything else | not supported in v1 | add deliberately, never by passthrough |

`capabilities: [net_raw]` widens the runtime's own abilities, not its reach.
It does not change what the gateway permits.

### Non-disableable invariants

These are not configurable and `asf.conf` cannot switch them off:

- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- `net.ipv4.ip_forward=0` and `net.ipv6.conf.all.forwarding=0` in every runtime
- no Podman socket, no host mounts beyond declared ones

## 2. The three modes

```yaml
network:
  mode: isolated | proxy | routed      # default: proxy
```

| Mode | Reaches | Enforced by | Runtime capabilities |
|---|---|---|---|
| `isolated` | ASF internal services only | topology (no gateway) | none |
| `proxy` | HTTP/HTTPS to declared domains | Caddy forward proxy | none |
| `routed` | declared IPv4 CIDR/protocol/port tuples | gateway + nftables | none by default; optional `NET_RAW` |

Every runtime is attached to its private internal service network. `proxy` or
`routed` adds the enforcement attachment required by that mode. Combining
`proxy` and `routed` in one runtime is rejected in v1 because that topology has
not yet been verified.

### 2.1 `isolated`

One `--internal` network, no gateway. The runtime reaches other ASF containers
by name and nothing else. Container DNS resolves internal names; external
lookups fail.

Use for: pure orchestration, workers fed through runtime-local services, and
anything that must not touch the outside directly.

**`isolated` does not mean offline.** The runtime may still reach services on
its private internal network, especially LiteLLM, and LiteLLM forwards to an
external provider. Logical agents inside one application share the same
runtime. Separate ASF runtimes are not connected by default. So:

> `isolated` means **no direct external network path**.
> It does not mean data cannot leave the environment.

State this wherever `isolated` is documented; the weaker reading is a
dangerous assumption to let a user form.

### 2.2 `proxy` (default)

```
runtime ──► internal network ──► Caddy ──► declared domains (443)
```

Caddy is dual-homed (internal + egress). The runtime has no gateway, so the
proxy is the only route out — enforcement by construction, not by rule.

```yaml
network:
  mode: proxy
  allow_domains:
    - pypi.org
    - files.pythonhosted.org
```

Use for: package installs, git hosting, LLM APIs, remote HTTP MCP servers,
ordinary web APIs.

**Why Caddy.** It is the only tested proxy that enforces ports on *both* the
`CONNECT` and plain-HTTP request paths. tinyproxy's `ConnectPort` covers
`CONNECT` only, so a plain `GET http://host:9000/` reaches any port on an
allowlisted host — a 443-only claim is false for it. See §7.

### 2.3 `routed`

```
runtime ──► scan network ──► capability-less gateway ──► declared CIDRs
                                      ▲
                                      └─ short-lived NET_ADMIN initializer
```

For traffic no HTTP proxy can carry: raw TCP/UDP/ICMP, port scans, SNMP,
databases on odd ports. The runtime gets a **static route injected by Podman**
pointing at the gateway; it never configures anything itself.

```yaml
network:
  mode: routed
  allow:
    - cidr: 192.168.40.20/32       # destination only: all IP traffic
    - cidr: 192.168.50.0/24
      protocol: tcp                # ONE protocol per restricted rule
      ports: any
    - cidr: 192.168.50.0/24
      protocol: icmp_echo          # no ports key: echo request/reply only
    - cidr: 192.168.60.20/32
      protocol: udp
      ports: [161]
  verify:                          # known-open positive and negative controls
    address: 192.168.40.20
    protocol: tcp
    port: 18080                    # allowed
    blocked_address: 192.0.2.3     # optional; defaults to address
    blocked_port: 19999            # open there, denied by policy
```

A destination-only rule omits both `protocol` and `ports` and allows all IP
traffic to that declared IP/CIDR. Restricted rules keep one protocol per rule,
which makes each generated nftables rule a direct translation of one manifest
line and removes the `ports`-with-`icmp` ambiguity. `icmp_echo` names exactly
what is permitted (echo request/reply), not all of ICMP.

The gateway enables IPv4 forwarding, installs a default-deny nftables `forward`
chain with one accept rule per declared tuple, and source-NATs to the declared
destinations.

**The gateway itself holds no capability.** IP forwarding is a sysctl set at
container creation, and nftables rules persist in the namespace once loaded —
neither needs a running process to hold `NET_ADMIN`. So the gateway splits in
two, exactly like the proven sidecar model:

```
gateway container      --sysctl net.ipv4.ip_forward=1, --cap-drop=ALL, sleeps
  └─ init sidecar      --network container:<gateway>, NET_ADMIN,
                       loads nftables, EXITS
```

`NET_ADMIN` therefore exists only during initialization, in a container that no
longer runs when the runtime starts.

ASF verifies the holder at startup: IPv4 forwarding must be enabled while
`CapEff` and `CapBnd` remain zero. If the host cannot provide that combination,
routed mode aborts. A persistent-`NET_ADMIN` compatibility path exists only
behind the explicit `ROUTED_ALLOW_PERSISTENT_NET_ADMIN=true` setting.

Gateway container requirements:

| Property | Value |
|---|---|
| capabilities | none (init sidecar holds `NET_ADMIN` briefly) |
| nftables policy | `input drop`, `output drop`, `forward drop` |
| filesystem | read-only root |
| image | pinned by digest; read-only at runtime |
| mounts | none from the host |
| Podman socket | none |
| DNS | not required |

### Generated forward rules bind every dimension

A rule that omits a dimension is broader than the manifest line it came from.
Each generated `forward` rule binds:

```
input interface · output interface · runtime scan-side source IP ·
destination CIDR/IP · protocol · destination port or ICMP type ·
connection state
```

Source IP matters especially: without it, any container that reaches the
gateway inherits the runtime's policy.

**Routed targets must be literal IPs or CIDRs.** External DNS does not resolve
from a routed runtime (measured), and adding a resolver would mean opening
UDP/53 through the gateway — a channel the design otherwise closes. Resolve
names on the host and declare addresses.

**`NET_RAW` is explicit and opt-in.** ICMP echo worked *without* `NET_RAW`
on the test host, so ASF does not grant it automatically. Raw-socket scanning
(nmap `-sS`, OS detection) can request `capabilities: [net_raw]`; this widens
the runtime's own abilities but does not change the gateway policy.

### The `verify` block

A deny-check only means something if a matching allow-check succeeded. Without
a known-reachable destination, "everything was blocked" and "nothing was
configured" are indistinguishable.

`verify` is optional. Normal pentest/discovery sessions do not need to prepare
known-open services on the target. Without `verify`, ASF still checks the
structural routed invariants it controls: declared routes are present, IPv4 and
IPv6 default routes are absent, undeclared destinations have no route, and
external DNS is unavailable.

For controlled acceptance tests, `verify` adds a stronger live proof. It declares
one allowed TCP endpoint and one known-open TCP endpoint that policy must block.
ASF first confirms both endpoints are reachable from the host, then proves that
the runtime can reach the allowed endpoint and cannot reach the blocked one. A
closed service is never accepted as evidence that nftables blocked a connection.

## 3. Manifest schema

```yaml
network:
  mode: proxy                    # isolated | proxy | routed

  # mode: proxy
  allow_domains: [pypi.org]      # port 443 only, both request paths

  # mode: routed
  allow:
    - cidr: 192.168.40.20/32     # no protocol/ports: all IP traffic
    - cidr: 192.168.50.0/24      # literal IP/CIDR, never a hostname
      protocol: tcp              # one protocol per restricted rule
      ports: [18080]
    - cidr: 192.168.50.0/24
      protocol: icmp_echo        # no ports key
  verify:
    address: 192.168.40.20
    protocol: tcp
    port: 18080
    blocked_address: 192.168.50.11  # optional; defaults to address
    blocked_port: 19999
```

Rules:

- unknown keys are **rejected**, as everywhere else in `runtime.yml`
- `allow_domains` is only valid with `mode: proxy`; `allow` only with `routed`
- omitting both `protocol` and `ports` allows all IP traffic to that CIDR
- `ports` without `protocol` is rejected
- `icmp_echo` accepts no `ports` key; TCP and UDP require `ports`
- a field that cannot be enforced is rejected rather than ignored
- `mode: isolated` accepts neither
- routed `verify` is optional; when present it uses known-open allowed and blocked
  TCP endpoints for a live enforcement proof; `blocked_address` defaults to
  `address`
- when `blocked_address` is separate, ASF installs a verification-only `/32`
  route and masquerades that probe destination so a deny result cannot be
  explained by a missing return route; nftables still denies it because the
  address is absent from every accept rule

### `proxy` + `routed` is rejected in v1

Validation refuses a manifest declaring both. The combination is plausible but
**untested**, and shipping an untested network path is how the tinyproxy port
hole happened.

Workarounds that need no new mechanism:

- build a prebuilt image containing the scanner's dependencies
- prepare dependencies in a separate `proxy`-mode runtime, then run the scan
  in a `routed` one over shared state

Introducing the combination later changes no security basis — it adds a second
attachment to a runtime that already has one.

## 4. Resource naming and allocation

The spike hardcoded subnets and a static gateway IP. ASF cannot: concurrent
sessions would collide — and not only with each other.

**Checking whether a network *name* exists is not sufficient.** The allocator
must compare actual subnet ranges against everything that could already claim
them:

- existing Podman network subnets (`podman network inspect`, not `ls`)
- host routes, including VPN routes (`ip route`)
- QEMU/libvirt networks
- the CIDRs the manifest itself declares as routed targets
- other concurrent ASF sessions

Algorithm:

1. an allocation pool configured in `asf.conf` (user-adjustable, default a
   private range unlikely to collide)
2. a rootless-user-wide allocation **lock**, so sessions and checkouts cannot race
3. deterministic candidate selection from the session hash — the same session
   gets the same subnet across restarts
4. overlap check of the candidate against podman subnets **and** the host
   routing table **and** the manifest's declared target CIDRs
5. bounded probing of alternatives on overlap
6. **fail closed** when no non-overlapping subnet is available — never fall
   back to a possibly-colliding range

The gateway's scan-side IP is **pinned** at container creation, because the
route injected into the runtime's network references it by address.

Every network, container and rule table carries the session label already used
for cleanup.

## 5. Lifecycle

Ordering is security-relevant: a runtime must never start while its policy is
absent.

```
1. resolve manifest, validate network section
2. create networks          (internal, plus proxy-egress or scan+egress)
3. start enforcement point  (Caddy, or gateway + nftables load)
4. VERIFY POLICY            ← gate; failure aborts before the runtime exists
5. start the runtime container
6. on exit: remove runtime, enforcement point, networks, temp secrets
```

### Verification per mode

Run from a throwaway container on the runtime's network, before step 5:

| Mode | Checks |
|---|---|
| `isolated` | no route out; an internal service is reachable when present |
| `proxy` | a declared domain is reachable **through the proxy**; an undeclared one is refused; no route bypasses the proxy |
| `routed` | a declared tuple is reachable; an undeclared port and an undeclared destination are both blocked; the runtime has no default route |

Three rules learned the hard way:

- **a probe must not hide its own exit status.** `nc ... | head` returns
  *head's* status — 0 even when nc failed — so the positive control could never
  fail. Probe commands run bare, never in a pipeline. A mocked test cannot
  catch this (the mock matches the command string but never executes it), so
  the suite extracts the real probe commands and runs them against a failing
  `nc` stub.


- **every deny-check must be gated on a working allow-check.** A proxy that
  denies everything passes all deny-tests trivially. This produced a false
  "secure" result during evaluation.
- **use one mechanism per property.** Positive reachability uses CONNECT;
  policy denials require Caddy's explicit 403; route checks inspect the route
  table directly. TLS, DNS, and upstream service failures never stand in for
  enforcement.
- **judge enforcement by the end state observed from the client**, not by
  parsing the enforcement point's logs. Log formats differ per proxy and change
  between versions; that is per-implementation code ASF should not carry.
  ASF does parse its pinned production Caddy JSON logs for *post-session policy
  advice*, but those records never contribute to a startup security verdict.

## 6. What lives where

| Concern | Location | Why |
|---|---|---|
| which domains / CIDRs | `agents/<name>/runtime.yml` | per runtime, reviewable |
| Caddy access logging and policy advice | `asf.conf` (`CADDY_ACCESS_LOGS`), `asf/egress_evidence.py` | bounded deployment observability and human-reviewed allowlist tightening |
| optional capability requests | `agents/<name>/runtime.yml` | per-runtime and closed vocabulary |
| resource limits | `asf.conf` | deployment-wide ceiling/defaults |
| repositories | `agents/<name>/repos.yml` | per-runtime, machine-edited by `sandbox.sh repo` |
| proxy / gateway config | **generated** from the manifest | never hand-written |

Generated, not hand-written, is deliberate: a hand-edited Squid ACL with rules
in the wrong order silently became an open relay during evaluation. Config is
the most dangerous artifact in the system and must come from a template with
the ordering fixed.

## 7. Evidence

All measured on Podman 6.0.1, rootless, netavark. Production host tests and
comparison experiments are kept separate.

| Test or experiment | Covers |
|---|---|
| `tests/test_caddy_proxy_paths.sh` | production Caddy: both request paths |
| `tests/experiments/compare-tinyproxy-caddy.sh` | comparative evidence: Tinyproxy positive control vs Caddy |
| `tests/experiments/spike-gateway.sh` | routed stage 1: controlled targets |
| `tests/experiments/spike-rootless-gateway-stage2.sh` | routed stage 2: real LAN / VM |
| `tests/experiments/spike-combined-internal-routed-v2.sh` | internal + routed together |

### Proxy — both request paths (`tests/experiments/compare-tinyproxy-caddy.sh`)

| Proxy | plain HTTP | host ACL | port restriction |
|---|---|---|---|
| **Caddy** + forwardproxy | supported | enforced | **enforced on both paths** |
| tinyproxy | supported | enforced | **bypassable** (`ConnectPort` = CONNECT only) |

tinyproxy runs as a positive control: if its known bypass is not detected, the
suite is broken and its other verdicts are worthless.

### Routed — stage 1, controlled targets (`tests/experiments/spike-gateway.sh`), 47/47

Podman injects the static route, so the runtime needs no `NET_ADMIN`. Gateway
enforces exact destination/protocol/port; capability-less runtime cannot alter
route or rules.

### Routed — stage 2, real LAN and VM, 45/45 and 40/40

A capability-less scanner reached a real VM only through the gateway. TCP
connect, SYN and UDP scans all resolve correctly. Enforcement-point removal
blocks all access.

### Combined internal + routed, 58/58

The spike's scanner and parser shared an explicit collaboration network while
the scanner also joined the scan network. Target policy remained enforced and
the second attachment introduced no default route, DNS egress, or bypass. This
is topology evidence only; the production lifecycle does not yet create shared
networks between separate ASF runtimes.

## 8. Known limitations

- **OS fingerprinting does not work** in routed mode. TTLs are rewritten across
  the gateway; nmap reports negative hop distance and no match.
- **Target-side attribution shows the host**, not the runtime — double NAT
  (gateway masquerade, then rootless Podman NAT). Do not rely on source IP at
  the target to identify which runtime probed it.
- **NSE / service detection** depends on Nmap's shared data files. Nmap is not
  installed in the shared agent image; if a dedicated scanner image adds it,
  its NSE data must be packaged with it. That is an image-packaging concern,
  not a routed-topology limitation.
- **IPv4 only, for now.** Routed mode is IPv4-only; runtimes have no IPv6
  default route and IPv6 forwarding is disabled. The spikes verify both. This
  is a deliberate v1 scope limit, not a permanent design choice — IPv6 support
  means a parallel `ip6` ruleset and IPv6 subnet allocation.
- **Exfiltration through allowed destinations is not prevented.** A runtime
  that may reach `github.com` can push a branch. Allowlisting governs *which*
  destinations, not what is sent.
- **`routed` widens the blast radius by design.** It exists for workloads that
  need raw protocols; use `proxy` unless a workload genuinely cannot.

## 9. Implementation status


Caddy is now mandatory in the production lifecycle (`PROXY_IMPL=caddy`).
tinyproxy and g3proxy remain comparison-only in dedicated experiments and are
rejected by normal startup. Verification checks the
plain-HTTP path explicitly — a `GET http://<allowed-host>:9000/` must fail —
so the port claim is re-proven every session rather than trusted from the
evaluation.


| Step | State |
|---|---|
| 2. Non-disableable invariants | **done** — emitted before `asf.conf` is read; `NET_ADMIN` rejected by the loader *and* the shell layer |
| 4. Routed schema | **done** — one protocol per rule, `icmp_echo`, literal-IPv4 CIDRs, `verify`, proxy+routed rejected |
| Fail-closed lifecycle | **done** — every mode verifies before the runtime starts |
| Empty-allowlist verification | **done** — allow probe skipped, distinct verdict, no false claim |
| `verify` must match a rule | **done** — a positive control that can never pass is rejected |
| CONNECT-based positive control | **done** — no dependency on `/` returning 200, no http fallback |
| 1. Caddy proxy mode | **done** — default, pinned build, generated Caddyfile, both-path verification |
| 3. `isolated` mode | **done** — no proxy, no egress network, isolation verified at startup |
| 5. Subnet allocation | **done** — fail-closed discovery and a user-wide lock held through network creation |
| Capability-less gateway | **done** — long-lived holder has no capabilities; initializer exits after loading nftables |
| 6. Routed lifecycle | **done** — routes, gateway, nftables, verification, runtime attachment, and cleanup |

`RT_NET_MODE`, `RT_CAPABILITIES`, `RT_ROUTED_RULES_JSON` and `RT_VERIFY_JSON`
are consumed directly by the lifecycle. A host may explicitly opt into a
persistent-`NET_ADMIN` compatibility fallback, but the default is to abort.

## 10. Install-time vs runtime egress

A runtime's allowlist currently has to include whatever its *installer* needed.
Hermes reaches GitHub so it can fetch Tirith at container start — which means
the running model can use GitHub for the rest of the session.

Runtime egress should describe what the workload needs **while operating**, not
what its installer needed once. Dependencies that can be resolved at image
build time belong there, where the model never sees them.

▶ Move adapter installs into the image where possible, then narrow the
manifests. Confirm each adapter's real requirements with a fresh-volume
integration test rather than assuming the redirect chain.

## 11. Resolved: the global domain allowlist

ASF currently grants every runtime a base set of domains (GitHub, GitLab, npm)
regardless of manifest. That is convenient and wrong by default: a runtime that
never touches git can still reach it.

**Decided: removed.** `network.allow_domains` is the complete allowlist. There
is no implicit base list, so a reviewer reading `runtime.yml` sees the effective
policy rather than a delta from an invisible default. `allow_groups` shorthand
is deliberately not introduced in v1: explicit lists are easier to audit and the
duplication is small.
