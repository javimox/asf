# ASF runtime testing

## Fast local suite

```bash
bash tests/run.sh
```

Runs shell syntax checks, the Python unit tests (`tests/test_*.py`, fake
Podman engines, no containers), the reference-output tests under `tests/reference/`
(recorded CLI transcripts and argv vectors that pin user-visible behavior), and
the mocked shell suites. This is what CI runs.

## Complete host test

Run the real proxy lifecycle, isolated lifecycle, Caddy request-path policy,
and private-address denial tests:

```bash
bash tests/run-host.sh
```

The first session may build several images. The discovery harness copies ASF to
a temporary checkout, writes a mode-0600 dummy provider credential, and changes
only that copy to a signal-aware service workload. It requires three consecutive
running-state observations before executing security checks, so a briefly
visible interactive container cannot race with teardown. Background `open`
output is kept in a temporary redacted log with a progress heartbeat every ten
seconds. The harness fails immediately if `open` exits early. The default
startup bound is 900 seconds and can be adjusted for a slow build host:

```bash
ASF_HOST_OPEN_TIMEOUT=1800 bash tests/run-host.sh
```

The external routed lifecycle test is added automatically when the three
`ASF_ROUTED_*` target variables are set.

Design spikes, stand-alone diagnostics, and the Tinyproxy/Caddy comparison
live on the archival `research-spikes` branch, not on `main`. They are retained
as historical and comparative evidence only.

## Running-session checks

Start a runtime in one terminal, then test it from another:

```bash
./sandbox.sh open hermes
./sandbox.sh test hermes
```

The test checks the runtime's network attachments, `NET_ADMIN`,
`no-new-privileges`, forwarding, host-secret masking, read-only framework mount,
Podman-socket absence, and the policy for its selected network mode. For proxy
mode this is also where ASF runs the exhaustive Caddy deny matrix (undeclared,
loopback, private IPv4/IPv6, link-local, and metadata destinations); normal
startup runs only the smaller critical-path subset.

For `runtime.isolation: microvm`, ASF cannot start a diagnostic process inside the
already-running guest. `./sandbox.sh test <agent>` therefore runs the host-side,
support-container and network checks it can prove, reports the result as
**partial**, and exits with status `2`. Status `0` is reserved for a complete
security-test pass.

## Caddy observability

```bash
./sandbox.sh proxy status hermes
./sandbox.sh proxy config hermes
./sandbox.sh proxy logs hermes
./sandbox.sh proxy logs -f hermes
```

`CADDY_ACCESS_LOGS=true` in `asf.conf` enables JSON access logs. For HTTPS,
Caddy records the `CONNECT host:443` decision; tunneled HTTPS content remains
encrypted. Plain-HTTP request metadata is visible. The active file is shown by
`proxy logs`; after teardown the raw files stay under
`${XDG_STATE_HOME:-$HOME/.local/state}/asf/<checkout-id>/sessions/<agent>/runs/<session-id>/caddy/` next to
`egress-summary.json`. Logs rotate at 10 MiB, two backups are kept per session,
ASF retains the latest 12 runs, and `egress-history.json` keeps compact
summaries for the latest 100 completed sessions.
Disable access logging when request metadata should not be retained.

After several completed proxy sessions, inspect evidence-backed policy advice:

```bash
./sandbox.sh advise hermes
```

The command needs no running container or Podman access. Startup-verification
traffic is tagged and excluded from summaries. Removal advice needs 12 complete
sessions; addition advice needs at least three denied CONNECTs in at least two
sessions. Advice never modifies a manifest.

## Routed-mode verification

Normal routed sessions do not need target-side test listeners. ASF always
checks routes, no IPv4/IPv6 default route, no undeclared route, and no external
DNS path.

For controlled acceptance tests, add optional `network.verify`. Use two
known-open TCP endpoints so ASF can prove one allow and one policy denial.

```bash
python3 tests/helpers/routed_test_target.py --allowed-port 18080 --blocked-port 19999
```

Use `agents/routed-scanner/example-runtime-ci-tested.yml` as the live-verification
example. Adjust the addresses/ports, then run:

```bash
./sandbox.sh open <name>
./sandbox.sh test <name>
```

For automated end-to-end runs:

```bash
ASF_INTEGRATION=1 bash tests/test_integration.sh
ASF_INTEGRATION=1 bash tests/test_isolated_integration.sh

ASF_INTEGRATION=1 \
ASF_ROUTED_TARGET_IP=192.0.2.2 \
ASF_ROUTED_ALLOWED_PORT=18080 \
ASF_ROUTED_BLOCKED_PORT=19999 \
bash tests/test_routed_integration.sh
```

## krun validation

Keep the automated krun integration surface deliberately small. These tests
cover security properties that are difficult to infer from source-level tests
and useful to catch as regressions on a real KVM host:

```bash
# Guest hardening + isolated topology + repository ownership
ASF_KRUN_INTEGRATION=1 bash tests/test_krun_integration.sh

# Caddy allowlist path + direct-bypass denial
ASF_KRUN_PROXY_INTEGRATION=1 bash tests/test_krun_proxy_integration.sh
```

The base test covers the post-drop UID/GID 1000, zero capability sets,
`NoNewPrivs=1`, secret masking, isolated direct-egress denial, and repository
UID/GID ownership. The proxy test covers allowlisted HTTPS through Caddy,
direct proxy-bypass denial, non-allowlisted HTTPS denial, and retained Caddy
evidence for the allow and deny requests.

For krun development, feature-progress checks such as starting Hermes,
reaching LiteLLM/OpenAI, interactive microVM console behavior, and routed-mode experiments are
manual acceptance tests unless they uncover a stable regression that cannot be
covered cheaply at unit level. Avoid adding one permanent integration script
per feature combination. Before a krun release, review the live tests and
remove any whose original uncertainty is already covered by simpler tests or by
stable product behavior.

Temporary krun broker/Hermes integration scripts used during early validation
were intentionally removed after the private broker path and real Hermes flow
were proven manually. Existing broker/proxy/unit coverage remains responsible
for those components outside the microVM-specific security boundary.

The routed lifecycle allocates its subnets, starts a capability-less gateway,
loads nftables through a short-lived `NET_ADMIN` initializer, verifies structural
routing invariants, then starts the runtime. Optional `network.verify` adds live
allow/deny controls.

`test_routed_integration.sh` is the primary production-lifecycle test; the
lower-level routed spikes it superseded are on the `research-spikes` branch.

### Routed verification scope

Every routed startup verifies structural invariants: declared routes, no IPv4 or
IPv6 default route, no undeclared route, and no external DNS path. If the
manifest includes optional `network.verify`, startup additionally proves one
known-reachable allowed TCP path and one known-open blocked TCP path. UDP and
ICMP rules are generated and covered by unit and manual tests, but are not
positively exercised on every session. Routed mode is IPv4-only.

## Proxy ACL ordering (real host)

`tests/test_caddy_private_resolution.sh` is part of `run-host.sh` and proves
that an allowlisted hostname resolving to a private Podman IP is still rejected
on CONNECT and on plain HTTP.

For a running session, use the built-in commands:

```bash
./sandbox.sh observe [agent]
./sandbox.sh capture start|stop [agent]
./sandbox.sh proxy status|config|logs [agent]
./sandbox.sh broker status|logs [agent]
./sandbox.sh test <agent>
```
Each session also persists its evidence records under
`${XDG_STATE_HOME:-$HOME/.local/state}/asf/<checkout-id>/sessions/<agent>/runs/<session-id>/`: `policy.json`,
`events.jsonl`, `verification-report.json`, `cleanup-report.json`, and for
proxy mode the Caddy logs and `egress-summary.json`. `egress-history.json` stays
at the host-state session level; `runtime-plan.json` stays in the checkout. See
[OBSERVABILITY.md](OBSERVABILITY.md).
