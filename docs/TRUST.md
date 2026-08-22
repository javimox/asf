# Trusting ASF

Decide whether to trust ASF **without reading every script first**. This page
states what it protects, what it deliberately does not, and every privilege it
uses. If a claim here disagrees with the code, the code wins and this page has
a bug — please report it.

Each claim names the file that enforces it, so you can spot-check one thing
rather than audit the tree.

---

## What ASF is

ASF runs an AI agent (Claude Code, Hermes, or any containerised workload)
inside a locked-down Podman container. You keep a shell; the agent works in the
box. The controller is **`sandbox.sh`** — a command-line tool that runs, sets
up, and exits. It is not a daemon and holds no privileges between runs.

## The 60-second mental model

```
./sandbox.sh open <agent>
   │
   ├─ reads the runtime manifest         agents/<agent>/runtime.yml
   ├─ builds and persists one plan       asf/runtime_plan.py
   ├─ creates only the planned networks  asf/networks.py
   │     proxy/isolated: internal, egress/provider as required
   │     routed: internal + scan + routed-egress
   ├─ starts Caddy / LiteLLM             asf/proxy.py, asf/broker.py [as required]
   ├─ routed only: starts a capability-less gateway and a short-lived
   │               NET_ADMIN initializer asf/routed.py
   ├─ VERIFIES the effective policy      aborts if it fails
   ├─ starts ONE agent container
   └─ on exit removes every ephemeral owned resource
```

## If you read only three files

1. **`asf/runtime_plan.py` + `asf/networks.py` + `asf/runtime.py`** — the
   immutable topology and complete session lifecycle.
2. **`asf/proxy.py` + `asf/routed.py`** — the two external-access enforcement
   paths: Caddy allowlisting and the routed gateway/nftables boundary.
3. **`asf.conf`** — every deployment pin, privilege switch, and resource limit.

## The central idea

In proxy and isolated mode, the agent cannot reach the internet **because no
direct route exists**. Its internal network has no gateway, so its only
reachable peers are the explicitly attached support services.

Routed mode deliberately adds narrowly declared routes through a separate
gateway. Enforcement still remains outside the agent: the agent has no
`NET_ADMIN`, no `iptables`, and no `sudo`. A short-lived trusted initializer
loads nftables in the gateway namespace and exits; the long-lived gateway is
capability-less by default.

## What ASF protects against

- **The agent reaching arbitrary destinations.** Proxy/isolated runtimes have
  no direct external gateway. Proxy egress goes through Caddy, which allows
  only manifest-declared domains on port 443. Routed runtimes receive only the
  declared static routes, and the gateway nftables policy binds source,
  destination, protocol, and ports. (`asf/networks.py`, `asf/proxy.py`,
  `asf/routed.py`, `asf/routed_policy.py`)

  Egress is also restricted to **port 443**, on both request paths (`CONNECT`
  and plain HTTP). The default proxy is Caddy, which was measured enforcing
  both; startup verification re-checks it every session, including a plain-HTTP
  request to a non-443 port on an allowlisted host.

  Caddy is the only proxy accepted by the production lifecycle. tinyproxy and
  g3proxy remain in dedicated comparison spikes; selecting either through
  `PROXY_IMPL` aborts startup rather than weakening the security claim.
- **A misconfigured proxy going unnoticed.** Before the agent starts, ASF
  runs a compact critical-path verification from a throwaway container: an
  allowlisted host must be reachable, a forbidden port must be denied, the
  direct provider path (when brokered) or one undeclared destination must be
  denied, and no route or DNS path may bypass the proxy. Failure aborts the
  session. The broader loopback/private/link-local/metadata deny matrix is
  available through `./sandbox.sh test <agent>`. (`StartupVerifier` in
  `asf/runtime.py`)
- **The provider API key leaking to the agent.** With the broker enabled the
  key is mounted as a file into the broker only, never in the agent's
  environment, and the proxy drops the provider's domain from the allowlist so
  a key found elsewhere still cannot be used directly. (`asf/broker.py`)
- **Host secret files leaking in.** `secrets/` is masked inside the container
  by an empty read-only tmpfs; startup aborts if the mask is missing. Values
  are injected at run time, never baked into an image or volume.
  (`asf/runtime.py`, `asf/devcontainer.py`, `.devcontainer/on-start.sh`)
- **The container acting as root on your host.** Unprivileged user
  (`--user=1000:1000`), every capability dropped, `no-new-privileges` set.
  Two further layers are inherited from rootless Podman rather than pinned
  by ASF, and you should know that: syscall filtering uses Podman's
  *default seccomp profile* (version-dependent), and host isolation rests
  on the rootless *user-namespace mapping* of your Podman installation.
  ASF adds no custom seccomp profile on purpose — keeping the delta
  against a stock rootless Podman small keeps this page auditable.
- **The agent managing containers.** No container receives the Podman socket.
  Only `sandbox.sh`, on your host, talks to Podman.
- **Leftovers.** Runtime and support containers, networks, routed reservation,
  and the temporary provider secret are removed on exit; only declared state
  volumes persist. Generated session configuration remains under
  `.devcontainer/sessions/` for diagnostics and deterministic reuse,
  together with the per-session evidence records: `runtime-plan.json`
  (the immutable topology), `verification-report.json` (every startup
  policy check, its verdict, and whether it was blocking), and
  `cleanup-report.json` (every teardown action and its outcome). The
  records are redaction-safe diagnostics; writing them can never change
  a security or cleanup verdict. With `CADDY_ACCESS_LOGS=true`, proxy sessions
  additionally retain bounded Caddy request metadata and a counted
  `summary.json`. Sensitive credential headers are redacted by Caddy, but host,
  method, timing, and other request metadata remain visible; disable the option
  where that retention is inappropriate. Compact summaries cover the latest
  100 completed proxy sessions; raw logs are retained only for the latest 12.
  `./sandbox.sh advise <agent>` reads the 12-session advice window.

## The complete privilege list

| Privilege | Value |
|---|---|
| Linux capabilities | **none by default** — `--cap-drop=ALL`; only manifest-declared `NET_RAW` is supported |
| `no-new-privileges` | **on** |
| `sudo` inside the container | **none** — no sudoers rule exists |
| User | `1000:1000`, non-root |
| Networks joined by the agent | private internal network; routed mode adds one scan network with declared routes only |

`NET_ADMIN` is never permitted in a model-output runtime. `NET_RAW`, when
explicitly requested for scanning, widens raw-socket access but cannot alter
routes or netfilter. In routed mode, only the short-lived gateway initializer
receives `NET_ADMIN`; it exits before the runtime starts. The long-lived holder
has zero effective and bounding capabilities by default. Before routed startup
succeeds, ASF reads `/proc/1/status` directly and verifies both effective and
bounding capability masks, `no-new-privileges`, IPv4 forwarding enabled, and IPv6
forwarding disabled. After the nftables loader returns, ASF explicitly proves
the `--rm` initializer is absent and repeats the holder inspection. Frozen
baseline ruleset vectors and deterministic mutation tests protect this
boundary in addition to the real-host capability test.

`ROUTED_ALLOW_PERSISTENT_NET_ADMIN=true` compatibility fallback weakens that
claim and prints a warning. There is no supported privilege-escalation helper
inside the agent container. Earlier versions granted nine capabilities and one
`NOPASSWD` sudo rule so an in-container firewall could run; moving enforcement
out removed all of it.

The proxy container is separately constrained: `--cap-drop=ALL`,
`no-new-privileges`, read-only root, 128 MB, 64 PIDs. The LiteLLM broker is
also capability-less and read-only, with a 64 MB tmpfs, 256 PIDs, 768 MB, and
one CPU. Its provider key is sent to Podman through standard input and mounted
as a temporary secret. Dev Container startup output is streamed through the
shared redactor before it reaches stdout, stderr, or retained failure
diagnostics, and the session token is scoped to `devcontainer up` rather than
inherited by the later exec client. (`asf/broker.py`, `asf/process.py`,
`asf/runtime.py`)

## Network modes

| Mode | The runtime can reach | Verified at startup |
|---|---|---|
| `proxy` (default) | declared domains, port 443, both request paths | allow path, deny path, port, no-bypass |
| `isolated` | internal services only — no external path | no external TCP, no external DNS, internal reachable |
| `routed` | declared IPv4 CIDR/protocol/port tuples | declared routes and no default route; optional live allow/deny controls |

**`isolated` is not offline.** The runtime may still reach services on its
private internal network, especially LiteLLM; the broker forwards to an
external provider on its own network. Logical agents inside one application
share the runtime. Separate ASF runtime containers are not connected by
default. `isolated` means the runtime has no direct external path, not that
data cannot leave through trusted internal services.

## What ASF does NOT protect against (by design)

- **It does not isolate logical agents from each other.** A multi-agent app
  (CrewAI, LangGraph, smolagents) run as one workload is isolated from the
  host, not internally. Those agents share a filesystem, environment, and
  credentials.
- **It does not prevent exfiltration through allowed destinations.** An agent
  that may reach `github.com` can push a branch or open a gist. Allowlisting is
  about *which* destinations, not what is sent to them.
- **It does not meter LLM spend, rate, or prompt size.** The OSS broker has no
  budget enforcement, and route restriction is an Enterprise LiteLLM feature.
- **It does not judge what the agent does** within its granted capabilities.
  ASF controls capabilities, not reasoning.
- **The pre-tool-use hook is a safety net, not a boundary.** Regex on the
  command string, bypassable by design. The real boundaries are the container,
  the network topology, and the non-root user.

## Verifying this yourself

```bash
# Start one runtime, then verify it from another terminal.
./sandbox.sh open claude
./sandbox.sh test claude

# Inspect the active proxy policy and request decisions.
./sandbox.sh proxy config claude
./sandbox.sh proxy logs -f claude

# After teardown, review evidence-backed allowlist suggestions. This reads
# local summaries only and never edits the manifest.
./sandbox.sh advise claude

# Rebuild and verify the host-level proxy, isolated, and gateway paths.
bash tests/run-host.sh
```

For routed end-to-end testing, start `tests/helpers/routed_test_target.py` on the target
and provide the `ASF_ROUTED_*` variables described in `docs/TESTING.md`.

### Explicit proxy and route evidence

ASF computes proxy HTTP status and default-route presence inside the relevant
probe container, next to the raw bytes. Fixed scripts accept only validated
positional arguments and return reserved exit codes below Podman
infrastructure-status ranges. Attached output is diagnostic only. Plain HTTP is
rejected before `forward_proxy` with explicit HTTP 403; CONNECT denial requires
403 or 407. HTTP 5xx and missing status evidence remain infrastructure failures
and cannot satisfy a deny expectation.
