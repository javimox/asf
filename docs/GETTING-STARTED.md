# Getting started

This guide contains the operational material that does not need to live on the
project front page: prerequisites, CLI reference, repository access, file
ownership, agent selection, Git workflow, and useful local notes.

## All commands

`./sandbox.sh --version` prints the installed ASF version.

```
./sandbox.sh open <agent>      start one agent runtime
                               (removes ephemeral containers automatically on exit)
./sandbox.sh shell [agent]     attach to an already-running container
./sandbox.sh ls                show running and deployed agent sessions
./sandbox.sh observe [agent]   show host-side session and privilege state
./sandbox.sh capture start [agent]
                             start routed microVM PCAP capture
./sandbox.sh capture stop [agent]
                             stop capture and finalize the PCAP
./sandbox.sh stop [agent]      stop one session, or all of them
./sandbox.sh reset <agent>     clear one agent's persistent state volume
./sandbox.sh build <agent>     rebuild one agent image
./sandbox.sh scan [repo] [agent]
                               run Semgrep on all repos, or one named repo
./sandbox.sh test [agent]      re-run the active session security checks
./sandbox.sh advise <agent>    suggest allowlist changes from recent evidence
./sandbox.sh proxy ...         inspect the active Caddy proxy
./sandbox.sh broker ...        inspect or test the active LiteLLM broker
./sandbox.sh repo add <agent> <path> [--mode ro|rw]
                               add or update a repository for one agent
./sandbox.sh repo remove <agent> <name>
                               remove a repository by exact basename
./sandbox.sh repo list <agent>
                               show repositories available to one agent
./sandbox.sh repository ...    long-form alias for `repo`
```

## Prerequisites
### Podman (rootless)

The sandbox runs on rootless Podman. Rootless means the engine runs as your own
unprivileged user — there is no root daemon.

```bash
# Arch
sudo pacman -S podman

# Debian / Ubuntu
sudo apt-get install podman

# Fedora / RHEL
sudo dnf install podman

# macOS
brew install podman && podman machine init && podman machine start
```

Docs: https://podman.io/docs/installation

Podman uses your `/etc/subuid` and `/etc/subgid` ranges for user-namespace
mapping. The `podman` package sets these up for your user on install. Verify:

```bash
grep "$(id -un)" /etc/subuid /etc/subgid    # should print a range for your user
```
### devcontainer CLI (default container backend)

Install it as normal (unprivileged) user:

```bash
curl -fsSL https://raw.githubusercontent.com/devcontainers/cli/main/scripts/install.sh | sh
```

Or using npm:
```bash
npm install -g @devcontainers/cli
```

The optional `runtime.isolation: microvm` backend does not use the Dev Container
CLI. It requires a Linux host with KVM plus krun/libkrun instead. Routed microVM
mode also needs the local TAP-capable runtime built once with
`tools/krun-runtime/build.sh`. See [microVM isolation](KRUN.md) for details.
### Python 3

ASF uses Python for all host-side orchestration, deterministic configuration
generation, lifecycle control, cleanup, and security verification. Runtime
manifests require PyYAML; the rest of the host package uses the standard library.

```bash
python3 --version
python3 -c 'import yaml'
```

ASF uses one Python production path for every command and network mode.

The default backend drives the devcontainer CLI with `--docker-path podman`, so
it uses Podman everywhere with no Docker installed. The krun backend calls Podman
directly and likewise does not require Docker.
### Pinned build dependencies

Top-level image, agent, and tool versions live in `asf.conf`. ASF passes
them into the generated devcontainer build arguments. The LiteLLM image is pinned
separately in `asf.conf`. Update those files deliberately and run the tests; do
not replace exact versions with `latest` or moving branch tags.

## Repository access

Repository access is configured separately for each runtime in
`agents/<name>/repos.yml`. Use `./sandbox.sh repo ...` rather than editing the
file manually for normal operation.

```yaml
repos:
  - path: /home/user/projects/my-api
    mode: rw
  - path: /home/user/projects/reference-docs
    mode: ro
```

A simple path entry is accepted as shorthand for `mode: rw`. Repositories are
shared only when the same host path is explicitly assigned to more than one
agent.

## File ownership: how it works

The container runs as the unprivileged **`node`** user. Podman's
`--userns=keep-id` (auto-injected by the devcontainer CLI for Podman) maps your
host user into the container; because `node` is UID 1000 and most Linux host
accounts are too, this maps host -> node with no extra flag. The result:

| | Inside container | On host |
|---|------------------|---------|
| Files Agent creates | owned by `node` | owned by **you** |

So files are directly editable on the host, owned by `node` in the container,
and the container never holds host root. This is the one clean configuration
that satisfies all three at once — and it's why the sandbox uses Podman rather
than Docker (Docker has no per-container `keep-id` equivalent in rootless mode).

The `1000` in the `keep-id` mapping is the `node` user's fixed UID in the image,
not your host UID — so this works regardless of what UID your host account has.

**Note on `--userns`:** the devcontainer CLI auto-injects `--userns=keep-id` for
the default container backend. The krun backend sets
`--userns=keep-id:uid=1000,gid=1000` explicitly. Since
`node` is UID 1000 and most Linux host accounts are also 1000, this maps
host→node correctly with no extra flag. **If your host UID is not 1000**, add
`"--userns=keep-id:uid=1000,gid=1000"` to `runArgs` in `devcontainer.base.json`
so files stay owned by you. (Check with `id -u` on the host.)

## Choosing an agent

```bash
./sandbox.sh open claude    # Claude Code
./sandbox.sh open codex     # OpenAI Codex CLI
./sandbox.sh open hermes    # Hermes agent
```

Each agent has its **own image**. Opening `claude` builds and runs an image that
contains only Claude Code — it never runs the Hermes installer (which is slow).
Opening `hermes` or `codex` builds a separate image containing only that agent.
The agent images share the common tooling layers (git, zsh, uv, etc.) from the
build cache, so the first build of each agent is the only slow one; switching
back to an already-built agent is fast.

Agent selection is injected as a Docker build arg (`AGENT`), which gives each
agent a distinct image. Policy files for the active agent are injected at every
container start from `agents/<agent>/`.

To pre-build an agent without starting a session:

```bash
./sandbox.sh build hermes
```

For automation that needs one non-interactive process but the normal ASF
lifecycle and security policy, use `run`:

```bash
./sandbox.sh run codex -- codex --version
```

`run` starts a fresh session using the runtime's configured isolation backend,
executes the command as an argv vector, and performs the normal ASF cleanup when
it exits. With `container` isolation it uses the Dev Container execution path;
with `microvm` isolation the command becomes the krun guest's initial foreground
workload after the normal startup checks. It does not pipe a shell command
through the interactive `open` path.

### Codex ChatGPT login

The supplied `codex` runtime uses Codex's native ChatGPT authentication and does
not start LiteLLM. It deliberately declares no host secret environment files,
so an API key or unrelated shared credential is not injected into Codex merely
because it exists in `secrets/common.env`. After opening it, sign in from inside
the sandbox with device-code authentication:

```bash
./sandbox.sh open codex
# inside the sandbox
codex login --device-auth
codex login status
codex
```

Device-code login avoids exposing a localhost callback port from the sandbox.
Codex stores its local login/session state under `/home/node/.codex`, which ASF
persists in the agent's declared state volume. `./sandbox.sh reset codex`
removes that state, including ChatGPT authentication and the model selection
stored by Codex in `config.toml`; the next open recreates an empty private
`CODEX_HOME`. The supplied proxy policy permits only `auth.openai.com` for
authentication/token refresh and `chatgpt.com` for the Codex service.

## Git workflow: commit inside, push outside

**No SSH credentials enter the container by default.** Repositories are bind
mounts, so a `git commit` made by the agent lands directly in the host
repository. You review it and push yourself:

```bash
# inside the container — the agent works and commits
git add src/thing.ts && git commit -m "..."

# on the host — you review, then you push
git -C ~/projects/my-project log -p
git -C ~/projects/my-project push
```

Under this project's threat model (the agent is not trusted) this is the
correct default: the agent's output passes a human before it can reach a
remote, and there is no credential in the container to misuse or exfiltrate.
### Opt-in: SSH agent forwarding for automation

When you want the agent to push unattended, forwarding is available — but it
must be enabled explicitly and pointed at a dedicated agent.

Agent forwarding does **not** leak private key material; the SSH agent protocol
is a signing oracle. But while the socket is live, the container can sign with
**every identity the agent holds**, for the whole session. That means push
access to every repository those keys reach, plus authentication to any host
allowed on port 22. Forwarding your desktop or GNOME Keyring agent hands the
container your entire identity set.

So: a separate agent, holding one key, scoped to one repository.

```bash
# 1. a key that exists only for the sandbox
ssh-keygen -t ed25519 -f ~/.ssh/asf_sandbox -C asf-sandbox

# 2. a dedicated agent holding only that key, expiring after 4h
export ASF_AGENT_SOCK="/run/user/$(id -u)/asf-agent.sock"
rm -f "$ASF_AGENT_SOCK"
ssh-agent -a "$ASF_AGENT_SOCK" >/dev/null
SSH_AUTH_SOCK="$ASF_AGENT_SOCK" ssh-add -t 4h ~/.ssh/asf_sandbox
```

Register `~/.ssh/asf_sandbox.pub` as a per-repository **deploy key** with write
access. Deploy keys are scoped to one repository, so the blast radius is one
repo instead of your whole account.

Then in `asf.conf`:

```bash
SSH_AGENT_FORWARDING=true
SSH_AGENT_SOCKET="/run/user/1000/asf-agent.sock"
```

There is no auto-discovery — the path is stated explicitly so the startup log
always records which agent was exposed. ASF prints a warning at session start
whenever forwarding is active, and refuses to start if the socket is missing
rather than starting silently without the key you expected.

**Notes.** GitHub rejects the same deploy key on multiple repositories; for
several repos, generate several keys and use `Host` aliases in `~/.ssh/config`
with `IdentitiesOnly yes`. `ssh-add -c` additionally prompts for confirmation
on every signature, which is excellent here, but it needs `SSH_ASKPASS` and a
graphical session — it fails silently when headless, so test it before relying
on it.

**Residual risk.** Even with one scoped key and a confirmation prompt, an
approved push can carry different content than you reviewed. That is why the
commit-inside/push-outside default exists.

## Semgrep scanning

Semgrep is installed in the container and scans source code in your repos.

```bash
# From the host
./sandbox.sh scan              # scan all mounted repos
./sandbox.sh scan my-api       # scan one repo

# Or from inside the container
semgrep scan --config auto /workspace/repos/my-api
semgrep scan --config p/security-audit /workspace/repos/
```

Semgrep scans source code, not Claude Code policy files. Reviewing `CLAUDE.md`
or hooks for safety is a human task (or a separate Claude session).

## Notes

- Containers are named `<checkout>-<hash>-<agent>` (e.g. `asf-940911e5e800-hermes`)
  and brokers `<checkout>-<hash>-<agent>-litellm-<pid>`, so `podman ps` shows
  which session is which
- Put the checkout wherever you like; nothing depends on its location. Volume and
  container names include a hash of that path, so **moving or renaming the
  directory starts fresh state** — stop sessions first, and expect new (empty)
  agent volumes afterwards
- `.devcontainer/sessions/<agent>/devcontainer.json` files are auto-generated — never edit them by hand
- `open` recreates that agent's container each time, so mount changes take
  effect immediately, and removes it on exit so nothing lingers
- `shell` attaches to a running container without recreating it
- Persistent-volume names include a hash of the canonical checkout path, so two
  ASF clones with the same directory basename remain isolated.
- Two repositories with the same basename cannot be assigned to the same agent
  because both would mount at the same container path; `repo add` rejects the
  second one.

## Experimental AI review loop

`tools/ai-review-loop.sh` is a deliberately small host-side prototype for a
three-round Codex -> Claude -> Codex coding review. It creates a disposable
linked worktree/branch, mounts the task worktree read-write, and mounts
host-generated Git evidence separately read-only. ASF's normal framework
checkout remains visible read-only at `/workspace/sandbox`; it is not used as
the task branch's writable Git authority.

```bash
cat > /tmp/asf-task.txt <<'EOF'
Describe one small ASF issue here.
EOF

tools/ai-review-loop.sh example-task /tmp/asf-task.txt HEAD
```

Start from a clean ASF checkout; the loop rejects tracked or ordinary untracked
changes that would not be represented by the selected base commit.

The host commits each round and remains the merge authority. Agents do not
communicate directly. Each round gets a fresh ASF session and uses that agent's
configured isolation backend (`container` or `microvm`). The defaults are
`gpt-5.6-sol` for Codex and `claude-opus-5` for Claude; override them with
`ASF_REVIEW_CODEX_MODEL` and `ASF_REVIEW_CLAUDE_MODEL`.

Each model round uses the CLI's structured automation output. The loop keeps the
raw JSONL, sandbox/runtime log, final answer, and usage summary under the host-only
evidence directory. Agents receive only a read-only `*-input` subdirectory with
the original task and host-generated Git evidence, so later reviewers cannot read
previous model transcripts. Before each host commit, ignored untracked scratch
files are removed so Git remains the authoritative round-to-round handoff. The
terminal prints compact live tool activity instead of build noise. A round is bounded by
`ASF_REVIEW_TIMEOUT` (30 minutes by default), so a stalled CLI cannot wait
forever.

The gate is intentionally smaller than the repository's full test suite. Its
purpose is to execute any untrusted task code away from the host, not to recreate
every CI environment inside an agent image. Before any model round, the loop
runs the selected gate once on the untouched base. If that preflight is red, the
normal path stops before spending model tokens. After round 3, the host
orchestrator runs the derived-file refresh inside ASF and commits any resulting
changes, then runs the same gate again. By default the refresh and gate are:

```bash
# sandboxed refresh after round 3
python3 tools/generate_sbom.py

# sandboxed preflight/final gate
python3 tools/generate_sbom.py --check
```

Set `ASF_REVIEW_REFRESH=` to skip the derived-file refresh, or override it with
another explicit sandboxed command. The review/audit agents are told not to
spend turns regenerating derived files unless the task itself changes their
generator or policy.

For a task with a deterministic focused check, override the gate explicitly:

```bash
ASF_REVIEW_GATE='python3 tools/generate_sbom.py --check; python3 -m unittest tests.test_dependencies' \
  tools/ai-review-loop.sh example-task /tmp/asf-task.txt HEAD
```

If a focused gate is knowingly red on the selected base for known unittest
tests, `ASF_REVIEW_BASELINE=1` changes the strict preflight into attribution of
those named `FAIL:`/`ERROR:` tests and allows the same failures at the end. The
comparison is
intentionally narrow: if the baseline failure cannot be identified safely, the
loop stops instead of guessing. The baseline gate must also leave the worktree
unchanged.

```bash
ASF_REVIEW_BASELINE=1 \
ASF_REVIEW_GATE='python3 -m unittest tests.test_example' \
  tools/ai-review-loop.sh example-task /tmp/asf-task.txt HEAD
```

The base-gate result is also written to the agents' read-only input directory as
`base-gate.txt`, naming any pre-existing `FAIL:`/`ERROR:` tests. Review rounds
are told to treat it as their baseline rather than rediscovering it; a named
failure is only revisited when the task or current diff directly targets that
behavior.

The agents are still instructed to run focused tests during their own rounds.
Claude's review is bounded by `ASF_REVIEW_CLAUDE_MAX_TURNS` (40 by default) as a
runaway stop rather than a budget; `ASF_REVIEW_TIMEOUT` bounds the round. If a
round hits the cap, the loop says so explicitly instead of reporting a generic
stream failure. If that failed round changed the task tree, the host commits the
partial work as `ai-review: <label> ... (round N failed)` before stopping; if it
changed nothing, no empty failure commit is added. In both cases the worktree and
evidence remain for inspection, and the loop prints the exact unlock/remove
commands needed to discard the failed review. A successful final gate must also
leave the reviewed worktree clean;
ignored test scratch is removed and any other gate-side mutation fails the loop.
Run the complete regression matrix in the repository's disposable CI workflows
after human inspection. The loop prints the `git push -u origin ai/<task>`
command when an `origin` remote exists, but never executes it. Nothing is merged
or pushed automatically; the worktree and evidence remain for human review.
