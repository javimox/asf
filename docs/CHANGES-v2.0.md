# ASF 2.0

ASF 2.0 consolidates the Python implementation, simplifies session evidence
and runtime internals, and replaces ASF's custom routed packet-event observer
with explicit, on-demand PCAP capture for routed microVM sessions.

The release deliberately reduces framework-specific observability logic: ASF
captures traffic at the host-controlled TAP boundary and leaves packet analysis
to standard tools such as tcpdump or Wireshark. It also removes migration and
design-spike scaffolding from the supported tree, unifies per-run evidence,
and hardens `observe` output.

## 1. On-demand routed microVM packet capture

Packet capture is controlled explicitly while a routed microVM session is
running:

```bash
./sandbox.sh capture start <agent>
./sandbox.sh capture stop <agent>
```

Each capture is written as a private timestamped PCAP in the current run
directory. The capture helper shares the routed gateway network namespace and
captures `tap0` from outside the guest.

The helper:

- drops all capabilities and adds only `CAP_NET_RAW`;
- has no `NET_ADMIN`, `SETUID`, or `SETGID`;
- uses `no-new-privileges` and a read-only root filesystem;
- records a bounded capture (`snaplen=256`, 200,000 packets per capture);
- does not parse or interpret packet contents inside ASF.

The former `observability.network_activity` option and custom packet-event
pipeline have been removed. PCAP files can be inspected directly with, for
example:

```bash
tcpdump -nn -r <capture.pcap>
```

## 2. Evidence stores unified — `asf/runs.py`

### Before

One `open` produced separate observability and egress session identifiers,
separate `current` pointers and different retention rules, plus flat
verification and cleanup reports:

```text
sessions/<agent>/
  observability/<id-A>/   policy.json events.jsonl broker-requests.jsonl ...
  observability/current
  evidence/<id-B>/        caddy-access.jsonl metadata.json summary.json
  egress-current.json
  verification-report.json
  cleanup-report.json
```

### After

```text
sessions/<agent>/
  runtime-plan.json          (outlives a run)
  egress-history.json        (outlives a run)
  runs/current               latest session id
  runs/<session-id>/
    policy.json
    events.jsonl
    verification-report.json
    cleanup-report.json
    broker-requests.jsonl    broker sessions
    llm-prompts.jsonl        opt-in
    egress-metadata.json     proxy mode
    egress-summary.json      proxy mode, written at teardown
    caddy/                   proxy mode, raw Caddy access logs
    network-<ts>.pcap        on-demand captures
```

- `asf/runs.py` replaces `asf/observation_sessions.py` and provides the common
  run lifecycle and policy helpers.
- `MAX_RETAINED_RUNS = 12`, enforced when a run begins. The current run is
  never pruned. This also bounds retained PCAP and prompt-log growth.
- Egress evidence no longer maintains a second session id, pointer file or
  pruning policy; proxy metadata and summaries live in the current run.
- Isolation is preserved: Caddy is bind-mounted only on `caddy/` and LiteLLM
  only on its JSONL files. Neither container can access the rest of the run.
- `cleanup-report.json` falls back to the legacy flat path when no run exists,
  such as stopping a runtime that was never opened with ASF 2.0.
- LiteLLM receives `ASF_SESSION_ID` instead of
  `ASF_OBSERVATION_SESSION_ID`.

## 3. `observe` hardening

- Every field printed from `events.jsonl` or `broker-requests.jsonl` is escaped
  before reaching the operator terminal, including non-printable characters
  and `ESC`.
- Capability display decodes `CapEff`/`CapBnd` bitmasks instead of matching one
  hard-coded value.
- `observe` reports capture state and PCAP paths but does not decode packet
  contents.

These behaviours are covered by `tests/test_observability.py`.

## 4. Removed migration and design-spike scaffolding

Removed from the supported `main` tree:

- obsolete design-spike scripts and routed capability spikes;
- `tools/diagnostics/`;
- `tools/allocate_subnets.py`, the compatibility shim for
  `asf.routed_allocation`;
- per-module command-line wrappers that were only needed by the former Bash
  implementation.

`python3 -m asf.manifest` and `asf.proxy` retain their supported command-line
interfaces.

The Tinyproxy/Caddy comparison is archived on the `research-spikes` branch.
The Caddy private-resolution test remains in the normal host suite because it
verifies a current security invariant.

Experimental and diagnostic material removed during this consolidation is
preserved separately on the archival `research-spikes` branch; that branch is
not intended to be merged into `main`.

## 5. Internal consolidation

| Where | Change |
|---|---|
| `asf/schema.py` | Shared schema primitives back validation in `runtime_plan.py`, `podman.py`, and `runs.py`, replacing duplicated private helpers while preserving errors. |
| `RuntimeService.open` | Split into smaller support-service, broker-wait, environment, microVM, and container preparation phases. |
| `manifest.validate` | Validation is divided by manifest section; duplicated routed-rule permission checks share one helper. |
| `runtime_plan._validate_runtime_plan` | Validation is grouped into network, attachment, capability, and resource invariants. |
| `cli.main` | Normal commands use a dispatch table while streaming/process-replacing commands keep explicit handling. |
| `identity.state_volume_names` | Moved out of the reset command module. |
| `tests/parity/` → `tests/reference/` | The retained expected-output tests are stable reference outputs rather than Bash/Python migration parity tests. |

Long but linear builders such as `render_routed_policy`, `build_runtime_plan`,
`run_capture_command`, and `diagnostics._run_broker` are intentionally left
intact where splitting them would add indirection without improving clarity.

## 6. Documentation and test cleanup

- `docs/KRUN-NOTES.md` is merged into `docs/KRUN.md` as design decisions.
- Observability, testing, egress, trust, security, and network documentation is
  updated for the unified run layout and on-demand PCAP capture.
- The default host suite no longer contains switches for archived design
  spikes.
- Unused imports, compatibility helpers, and migration-only tests are removed.

## 7. Compatibility

### Runtime manifests

The obsolete option:

```yaml
observability:
  network_activity: true
```

has been removed. Use on-demand capture instead:

```bash
./sandbox.sh capture start <agent>
./sandbox.sh capture stop <agent>
```

Other existing runtime configuration remains compatible.

### CLI and state

- `asf.conf`: no change.
- Existing primary CLI commands remain available. `observe` and `capture`
  report the run id and paths under `runs/<session-id>/`.
- `./sandbox.sh advise` continues to read `egress-history.json`; existing
  history files remain valid.
