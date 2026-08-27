# Observability

ASF keeps observability outside the untrusted guest and limits it to boundaries
that ASF already controls.

## Snapshot

```bash
./sandbox.sh observe [agent]
```

It shows the current run ID, declared guest boundary, host-side process
capabilities, recent lifecycle events, broker request metadata, prompt-capture
status, and the status/path of any routed PCAP captures.

ASF does not try to reconstruct normal command execution inside a container or
microVM.

## Per-run files

Each `open` mints one session id and one private directory that holds every
host-side artifact for that run:

```text
.devcontainer/sessions/<agent>/runs/<session-id>/
  policy.json               frozen isolation/network/capability policy
  events.jsonl              lifecycle events
  verification-report.json  startup verification verdicts
  cleanup-report.json       teardown actions and outcomes
  broker-requests.jsonl     LiteLLM request metadata (broker sessions)
  llm-prompts.jsonl         only when prompt capture is enabled
  egress-metadata.json      proxy mode: Caddy evidence bookkeeping
  egress-summary.json       proxy mode: CONNECT summary written at teardown
  caddy/                    proxy mode: raw Caddy access logs
  network-<timestamp>.pcap  one file per on-demand capture
```

`runs/current` names the latest session id. Directories are mode `0700`; files
and the pointer are mode `0600`. The newest 12 runs are kept; older ones are
removed when the next session starts. `runtime-plan.json` and
`egress-history.json` stay at the session level because they outlive a run.

Caddy is bind-mounted only on the `caddy/` subdirectory, and LiteLLM only on
its two `.jsonl` files; neither container can reach the rest of the run.

`policy.json` freezes the non-secret isolation/network/capability policy at
session start. `observe` reads this snapshot rather than the editable
`runtime.yml`. Fields read back from `events.jsonl` and
`broker-requests.jsonl` are escaped before display; a log line can never drive
the operator's terminal.

## Lifecycle events

`events.jsonl` is host-written and best-effort. Typical events:

```text
session_start
broker_started
gateway_ready
network_capture_started
network_capture_stopped
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

## On-demand routed packet capture

Packet capture is explicit and only available for a running TAP-backed routed
microVM session:

```bash
./sandbox.sh capture start [agent]
# run the task you want to observe
./sandbox.sh capture stop [agent]
```

Each `start` creates a new private timestamped PCAP such as
`network-20260825T220733Z.pcap`. Starting capture never restarts or changes the
running microVM. Stopping capture sends `SIGINT` to `tcpdump` before removing
the helper so the PCAP is finalized cleanly. Repeating `start`/`stop` creates
additional files rather than overwriting earlier evidence.

ASF runs `tcpdump` in a separate container sharing the routed gateway network
namespace. It captures `tap0` with `NET_RAW` only; the long-lived gateway
remains capability-less and the guest receives no additional capability.

The capture stores full packets (`tcpdump -s 0`) and continues until explicitly
stopped, the session ends, or the capture helper exits. ASF does not parse,
classify, deduplicate, or reinterpret packet contents. `observe` reports only
whether capture is active, how many PCAPs
exist, the latest/current file and a `tcpdump -r` command. Use `tcpdump` or
Wireshark for packet analysis.

The PCAP is sensitive evidence. It can contain packet payloads and, when broker
traffic traverses the TAP, broker traffic as well. Plaintext protocols may
therefore expose complete request and response bodies; HTTPS application
payloads remain encrypted at the TAP boundary. Capture has no packet-count or
file-size limit, so an unattended capture can consume substantial disk space.
Treat the session directory accordingly.

Packet capture is evidence, not enforcement. Routed nftables policy remains the
authoritative traffic-control mechanism. A capture failure does not stop the
running agent session.

## Existing logs

```bash
./sandbox.sh broker logs [agent]
./sandbox.sh proxy logs [agent]
```
