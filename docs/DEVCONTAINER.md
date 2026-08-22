# The Dev Container CLI in ASF

What the default ASF container backend uses it for and what it provides.
`runtime.isolation: microvm` bypasses this layer and uses direct Podman commands;
see [microVM isolation](KRUN.md).

## What ASF uses

Three subcommands:

| Command | Used for |
|---|---|
| `devcontainer build` | build the runtime image |
| `devcontainer up` | create and start the container |
| `devcontainer exec` | run the shell (or the manifest's command) inside it |

Nine `devcontainer.json` keys — every one maps to a plain `podman` flag:

| devcontainer.json | podman equivalent |
|---|---|
| `build.dockerfile` / `context` / `args` | `podman build -f … --build-arg …` |
| `runArgs` | passed straight through to `podman run` |
| `workspaceMount` | `--mount type=bind,…` |
| `workspaceFolder` | `--workdir` |
| `containerEnv` | `--env` |
| `remoteUser` | `--user` (ASF also sets this in `runArgs`) |
| `postStartCommand` | run `.devcontainer/on-start.sh` after start |
| `waitFor` | startup ordering |
| `name` | `--name` (ASF also sets this in `runArgs`) |

ASF uses **no** devcontainer Features, templates, or prebuilds. The generated
config is produced by `asf.devcontainer` from the runtime
manifest; it is never hand-edited.

## What it provides

- **Editor attach.** VS Code and Cursor can open a folder inside a running
  devcontainer. This is the main reason the dependency is kept.
- **A familiar config format.** People recognise `devcontainer.json`.
- **Lifecycle handling.** `postStartCommand` ordering, wired to `on-start.sh`.

## What it costs

- A Node.js toolchain plus the `@devcontainers/cli` npm package on the host.
- An indirection layer between the config ASF generates and the podman flags
  ASF already computes.
- Constraints on container networking: the CLI manages the container's network
  setup, which remains an open question for any future shared-network-namespace
  design.

Because every key maps closely to Podman flags, a direct lifecycle is feasible.
The krun backend uses direct `podman build` / `run`, while the default container
backend keeps Dev Containers for editor attach and `exec` support.

## CLI quirks discovered the hard way

Each of these cost a debugging round. Keep them in mind before changing how
ASF invokes the CLI:

1. **`--id-label` is rejected by `build`.** It identifies a *container*, and
   `build` produces an image. ASF therefore keeps two flag sets:
   `DC_BUILD_FLAGS` (build) and `DC_FLAGS` (up/exec).
2. **The config file must be *named* `devcontainer.json`.** Only its directory
   is free. Per-agent configs therefore live at
   `.devcontainer/sessions/<agent>/devcontainer.json`, not
   `.devcontainer/devcontainer.<agent>.json`.
3. **Relative paths resolve against the config file's location.** Moving the
   generated config deeper means `build.context` and `build.dockerfile` must be
   re-anchored — the Python Dev Container renderer does this automatically.
4. **`--id-label` on `up`/`exec` is what separates concurrent runtimes.** ASF
   additionally labels the container itself (`--label` in `runArgs`) so
   `podman ps --filter label=…` works regardless of how the CLI treats
   `--id-label`.

## Version

Tested against `@devcontainers/cli` 0.87.0 with rootless Podman on Linux.
