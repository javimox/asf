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

Comparison proxies remain in `tests/experiments/compare-tinyproxy-caddy.sh`; they cannot be
selected with `PROXY_IMPL` in production.

## Startup verification

ASF verifies the policy before the agent container exists:

1. the declared positive-control hostname accepts CONNECT on port 443;
2. Caddy returns an explicit 403 for an undeclared hostname;
3. Caddy returns an explicit 403 for forbidden ports on CONNECT and plain HTTP;
4. loopback, private, link-local, and metadata destinations are rejected;
5. the runtime network has no IPv4 or IPv6 default route;
6. no public IPv4 route exists outside Caddy;
7. direct external DNS is unavailable;
8. while brokered, the provider API is rejected directly.

Infrastructure errors and generic connection failures are not counted as policy
denials. A deny verdict requires Caddy's 403 response.

## Observability

```bash
./sandbox.sh proxy status [agent]
./sandbox.sh proxy config [agent]
./sandbox.sh proxy logs [agent]
./sandbox.sh proxy logs -f [agent]
```

`proxy status` shows the active container, networks, permitted port, and
allowlisted hosts. `CADDY_ACCESS_LOGS=true` enables JSON access records under
`.devcontainer/sessions/<agent>/evidence/<session-id>/`. The active file is
available through `proxy logs`; Caddy rotates it at 10 MiB and retains two
uncompressed backups for that session.

For HTTPS, Caddy records the CONNECT decision and destination. The tunneled TLS
content remains encrypted. Plain HTTP request metadata is visible to the proxy,
so access logging should be disabled when it is not needed.

## Evidence-driven policy review

At successful teardown ASF parses the session's Caddy logs and stores:

- `summary.json` in the dedicated session evidence directory;
- a bounded `egress-history.json` containing the latest 100 summaries;
- raw log files and per-session metadata for the latest 12 sessions, matching
  the advice window.

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
