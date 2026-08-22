# Observability

ASF observes from the host, outside the untrusted guest.

## Snapshot

```bash
./sandbox.sh observe [agent]
```

It shows the current run ID, declared guest boundary, host-side process
capabilities, recent lifecycle events, broker metadata, prompt-capture status,
and optional routed network attempts.

## Per-run files

Each `open` gets a new private directory:

```text
.devcontainer/sessions/<agent>/observability/<session-id>/
  policy.json
  events.jsonl
  broker-requests.jsonl
  llm-prompts.jsonl        # only when enabled
  network-activity.jsonl   # only when enabled
```

`observability/current` contains the latest run ID. Directories are mode `0700`;
files and the current pointer are mode `0600`. Previous runs are retained.

`policy.json` freezes the non-secret isolation/network/capability policy at
session start. `observe` reads this snapshot rather than the editable
`runtime.yml`, so changing a manifest cannot reclassify a running session's
historical activity.

## Lifecycle events

`events.jsonl` is host-written and best-effort. Typical events:

```text
session_start
broker_started
gateway_ready
network_observer_ready
broker_ready
runtime_starting
cleanup_started
cleanup_complete
```

## Broker request metadata

`broker-requests.jsonl` is written by LiteLLM. It may contain model/provider,
success or failure, latency, token counts, cost, and stream/cache flags when
available. Prompt and response bodies are excluded.

## Optional LLM prompt capture

Prompt capture is off by default:

```yaml
observability:
  llm_prompts: true
```

This requires `llm.broker: true`. Full broker-visible prompts are written to the
current run's `llm-prompts.jsonl`. `observe` reports the path but does not print
prompt bodies.

Prompt logs may contain system prompts, source code, secrets, tool data, or
personal data. LiteLLM's general message logging remains disabled.

## Optional routed network activity

For TAP-backed routed microVM sessions:

```yaml
observability:
  network_activity: true
```

ASF starts a separate observer sharing the routed gateway network namespace.
The observer has `NET_RAW` only; the long-lived gateway remains capability-less.
It records guest-originated IPv4 attempts only:

- TCP initial SYN packets
- UDP datagrams
- ICMP echo requests

No packet payloads or response packets are stored. LiteLLM broker traffic is
excluded because broker requests have their own metadata stream. Records go to
the current run's `network-activity.jsonl`. The file is capped at 64 MiB per
run; once the cap is reached ASF records a truncation marker when space permits
and stops collecting additional packet metadata for that run.

`observe` also shows `policy-match=allow|deny`, derived from the frozen
session-start routed policy. This is not an observed nftables verdict.
Enforcement remains unchanged.
The observer is operational telemetry, not lossless forensic packet capture.

## Existing logs

```bash
./sandbox.sh broker logs [agent]
./sandbox.sh proxy logs [agent]
```
