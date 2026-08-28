# ASF egress enforcement

Status: **implemented for proxy, isolated, and routed modes.**

## Production proxy

Caddy is the only proxy accepted by the normal lifecycle. It provides:

- an explicit hostname allowlist;
- port 443 enforcement for CONNECT and plain HTTP;
- private and special-address denial before hostname allows;
- a per-session generated Caddyfile;
- optional per-session JSON access logs in the session evidence directory;
- no published host port;
- no Linux capabilities;
- an unprivileged runtime user and read-only root filesystem.

The agent joins an internal network with no default route. Caddy joins that
network and a separate egress network, so it is the agent's only external path.

Tinyproxy remains only as archived comparative material on the
`research-spikes` branch. Tinyproxy and g3proxy cannot be selected with
`PROXY_IMPL` in
production.

## Startup verification

ASF keeps startup verification intentionally small so every interactive open
checks the critical boundary without rerunning the full security suite. Before
the agent starts it verifies:

1. the declared positive-control hostname accepts CONNECT on port 443;
2. a forbidden port on that hostname is denied;
3. while brokered, the provider API is rejected directly; otherwise one
   non-allowlisted destination is denied;
4. the runtime network has no IPv4 or IPv6 default route;
5. no public IPv4 route exists outside Caddy;
6. direct external DNS is unavailable.

The exhaustive Caddy deny matrix (generic undeclared destination, loopback,
private IPv4/IPv6, link-local, and metadata destinations) remains in
`./sandbox.sh test <agent>`. This keeps startup fail-closed on the critical
path while leaving the broader security-boundary validation available on
demand.

Infrastructure errors and generic connection failures are not counted as policy
denials. A deny verdict requires Caddy's explicit rejection.

## Observability

```bash
./sandbox.sh proxy status [agent]
./sandbox.sh proxy config [agent]
./sandbox.sh proxy logs [agent]
./sandbox.sh proxy logs -f [agent]
```

`proxy status` shows the active container, networks, permitted port, and
allowlisted hosts. `CADDY_ACCESS_LOGS=true` enables JSON access records under
`${XDG_STATE_HOME:-$HOME/.local/state}/asf/<checkout-id>/sessions/<agent>/runs/<session-id>/caddy/`. The active file is
available through `proxy logs`; Caddy rotates it at 10 MiB and retains two
uncompressed backups for that session.

For HTTPS, Caddy records the CONNECT decision and destination. The tunneled TLS
content remains encrypted. Plain HTTP request metadata is visible to the proxy,
so access logging should be disabled when it is not needed.

## Evidence-driven policy review

At successful teardown ASF parses the session's Caddy logs and stores:

- `egress-summary.json` in the run directory;
- a bounded host-state `egress-history.json` containing the latest 100 summaries;
- raw log files and metadata for the latest 12 runs, matching the advice
  window.

Startup verification requests carry `X-ASF-Probe: verification` and are
excluded, so ASF's own positive and negative controls cannot bias the policy
recommendations. Only actual agent CONNECT attempts count.

```bash
./sandbox.sh advise <agent>
```

The command is deliberately read-only. It recommends removing a domain only
after a complete 12-session window in which that domain was present in the
effective allowlist and never contacted. It recommends reviewing a denied
destination only after at least three denied CONNECTs across at least two
sessions. IP literals and malformed hostnames are never suggested. Operators
must still decide whether the dependency is legitimate and edit
`agents/<agent>/runtime.yml` manually.

This feedback is operational guidance, not security-verdict evidence. Startup
allow/deny checks still judge the effective boundary from explicit client-side
responses and routes; access-log parsing cannot turn a failed security check
into a pass.

When `CADDY_ACCESS_LOGS=true`, creation of the private session evidence
directory is required: startup fails explicitly if ASF cannot provide the log
destination. Once the session is ending, summary/history persistence is
best-effort and cannot change the cleanup verdict.

## Limits

- Allowlisting controls destinations, not content. An allowed site remains a
  possible exfiltration channel.
- LiteLLM is a separate trusted egress component and is not constrained by the
  agent's Caddy policy.
- Proxy mode does not carry arbitrary TCP, UDP, or ICMP. Use routed mode for
  those protocols.
- Proxy and routed modes cannot be combined in one runtime in v1.
