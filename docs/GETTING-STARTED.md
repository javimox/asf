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
### devcontainer CLI

Install it as normal (unprivileged) user:

```bash
curl -fsSL https://raw.githubusercontent.com/devcontainers/cli/main/scripts/install.sh | sh
```

Or using npm:
```bash
npm install -g @devcontainers/cli
```
### Python 3

ASF uses Python for all host-side orchestration, deterministic configuration
generation, lifecycle control, cleanup, and security verification. Runtime
manifests require PyYAML; the rest of the host package uses the standard library.

```bash
python3 --version
python3 -c 'import yaml'
```

ASF uses one Python production path for every command and network mode.

The sandbox drives the devcontainer CLI with `--docker-path podman`, so it uses
Podman everywhere with no Docker installed.
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
Podman, which maps your host user to the same UID inside the container. Since
`node` is UID 1000 and most Linux host accounts are also 1000, this maps
host→node correctly with no extra flag. **If your host UID is not 1000**, add
`"--userns=keep-id:uid=1000,gid=1000"` to `runArgs` in `devcontainer.base.json`
so files stay owned by you. (Check with `id -u` on the host.)

## Choosing an agent

```bash
./sandbox.sh open claude    # Claude Code
./sandbox.sh open hermes    # Hermes agent
```

Each agent has its **own image**. Opening `claude` builds and runs an image that
contains only Claude Code — it never runs the Hermes installer (which is slow).
Opening `hermes` builds a separate image with only Hermes. The two images share
all the common tooling layers (git, zsh, uv, etc.) from the build
cache, so the first build of each agent is the only slow one; switching back to
an already-built agent is fast.

Agent selection is injected as a Docker build arg (`AGENT`), which gives each
agent a distinct image. Policy files for the active agent are injected at every
container start from `agents/<agent>/`.

To pre-build an agent without starting a session:

```bash
./sandbox.sh build hermes
```

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
