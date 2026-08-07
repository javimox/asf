# ASF runtime testing

## Complete host test

Run the real proxy lifecycle, isolated lifecycle, Caddy request-path policy,
private-address denial, and the capability-less gateway test:

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

Tinyproxy is not part of the production suite. Run the optional comparison
experiment only when collecting design evidence:

```bash
bash tests/experiments/compare-tinyproxy-caddy.sh
```

The external routed lifecycle test is added automatically when the three
`ASF_ROUTED_*` target variables are set.

Optional design evidence:

```bash
ASF_RUN_DESIGN_SPIKES=1 bash tests/run-host.sh
```

The older stage-2 and combined spikes also exercise UDP and require six target
variables. Enable them only for the full lab target:

```bash
ASF_RUN_LEGACY_ROUTED_SPIKES=1 \
ASF_ROUTED_TARGET_IP=192.0.2.2 \
ASF_ROUTED_TARGET_CIDR=192.0.2.0/24 \
ASF_ROUTED_ALLOWED_PORT=18080 \
ASF_ROUTED_BLOCKED_PORT=19999 \
ASF_ROUTED_ALLOWED_UDP=18161 \
ASF_ROUTED_BLOCKED_UDP=19998 \
bash tests/run-host.sh
```

## Running-session checks

Start a runtime in one terminal, then test it from another:

```bash
./sandbox.sh open hermes
./sandbox.sh test hermes
```

The test checks the runtime's network attachments, `NET_ADMIN`,
`no-new-privileges`, forwarding, host-secret masking, read-only framework mount,
Podman-socket absence, and the policy for its selected network mode.

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
`proxy logs`; after teardown, raw files and `summary.json` remain under
`.devcontainer/sessions/<agent>/evidence/<session-id>/`. Logs rotate at 10 MiB,
two backups are kept per session, and ASF retains raw evidence for the latest
12 sessions plus compact summaries for the latest 100 completed sessions.
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

Routed mode needs a target with two known-open TCP ports: one declared as
allowed and one deliberately omitted from policy. This distinguishes firewall
enforcement from a closed service.

On the target host:

```bash
python3 tools/routed_test_target.py --allowed-port 18080 --blocked-port 19999
```

Copy `examples/routed-runtime.yml` to `agents/<name>/runtime.yml`, adjust the
address/CIDR, then run:

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

The routed lifecycle allocates collision-free internal, scan, and egress
subnets, creates a scan network with only declared routes, starts a
capability-less gateway, loads nftables
through a short-lived `NET_ADMIN` initializer, verifies allow and deny paths,
and only then starts the runtime.

## Lower-level routed tests

```bash
bash tests/spike-gateway-caps.sh
bash tests/experiments/spike-gateway.sh
bash tests/experiments/spike-rootless-gateway-stage2.sh
bash tests/experiments/spike-combined-internal-routed-v2.sh
```

`test_routed_integration.sh` is the primary production-lifecycle test. The
spikes preserve lower-level design evidence. Some legacy spikes use configurable
static subnets; review their defaults for collisions before running them. The
stage-2 and combined spikes also require the LAN/VM target described in their
headers.

### Routed verification scope

Startup proves one allowed and one known-open blocked TCP path. UDP and ICMP
rules are generated and covered by unit/spike tests, but are not positively
exercised on every session. Routed mode is IPv4-only.

## Diagnostic tools (real host, read-mostly)

These are not part of any suite; run them when a session misbehaves and you
need to know *which layer* is at fault.

```bash
# Which layer breaks a connection: host vs plain container vs VPN/routes.
bash tools/diagnostics/diagnose-network.sh

# SSH / port-22 reachability for the host-push git workflow.
bash tools/diagnostics/diagnose-github-ssh.sh
bash tools/diagnostics/diagnose-port22.sh

# Exercise the EXACT Caddy image and probe image this checkout selects.
# Unlike ad-hoc image discovery, this cannot accidentally test a stale
# localhost/asf-proxy-caddy tag left behind by an older ASF candidate.
bash tests/experiments/spike-current-caddy-responses.sh

# Prove ACL ordering: an allowlisted hostname that resolves to a private
# Podman IP must still be rejected on CONNECT and on plain HTTP.
bash tests/spike-caddy-private-resolution.sh
```

For a *running* session, prefer the built-in commands first:
`./sandbox.sh proxy status|config|logs`, `./sandbox.sh broker status|logs`,
and `./sandbox.sh test <agent>` for the on-demand security-boundary suite.
Each session also persists its evidence records under
`.devcontainer/sessions/<agent>/`: `runtime-plan.json`,
`verification-report.json`, `cleanup-report.json`, and for proxy mode
`egress-history.json` plus per-session Caddy evidence directories.
