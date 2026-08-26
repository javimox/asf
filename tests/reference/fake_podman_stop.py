#!/usr/bin/env python3
"""Scripted stand-in for `podman`, for the stop-command reference vectors.

Covers the subcommands `stop` uses on both sides of the migration: listing,
inspection, and the three removals. Unlike the read-only fakes in earlier
phases this one *mutates*, so a scenario can be scanned, cleaned, and rescanned
to prove nothing is left.

State lives in ASF_FAKE_PODMAN_STATE and is rewritten in place after every
removal:

    {
      "containers": [{"id", "name", "role", "agent", "session", "sandbox",
                      "networks", "state"}],
      "networks": ["name", ...],
      "secrets": ["name", ...],
      "fail": {"rm": [125, "stderr"], "network rm": [...], "secret rm": [...]}
    }
"""

from __future__ import annotations

import json
import os
import sys

STATE_PATH = os.environ.get("ASF_FAKE_PODMAN_STATE", "")


def load() -> dict:
    if not STATE_PATH:
        return {"containers": [], "networks": [], "secrets": []}
    with open(STATE_PATH, encoding="utf-8") as handle:
        state = json.load(handle)
    state.setdefault("containers", [])
    state.setdefault("networks", [])
    state.setdefault("secrets", [])
    return state


def save(state: dict) -> None:
    if STATE_PATH:
        with open(STATE_PATH, "w", encoding="utf-8") as handle:
            json.dump(state, handle)


def labels_of(container: dict) -> dict[str, str]:
    labels = dict(container.get("labels", {}))
    for key, label in (
        ("role", "asf.role"),
        ("agent", "asf.agent"),
        ("session", "asf.session"),
        ("sandbox", "asf.sandbox"),
    ):
        if container.get(key):
            labels.setdefault(label, container[key])
    return labels


def filters(argv: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for index, argument in enumerate(argv):
        if argument == "--filter" and index + 1 < len(argv):
            value = argv[index + 1]
            if value.startswith("label="):
                key, _, wanted = value[len("label="):].partition("=")
                found[key] = wanted
    return found


def find(state: dict, reference: str) -> dict | None:
    for container in state["containers"]:
        if reference in (container["id"], container["id"][:12], container.get("name")):
            return container
    return None


def forced(state: dict, key: str):
    entry = state.get("fail", {}).get(key)
    if not entry:
        return None
    code, message = entry
    sys.stderr.write(message)
    return int(code)


def do_ps(state: dict, argv: list[str]) -> int:
    wanted = filters(argv)
    names = "{{.Names}}" in " ".join(argv)
    include_stopped = any(a in ("-a", "--all", "-aq", "-qa") for a in argv)
    for container in state["containers"]:
        have = labels_of(container)
        if not all(have.get(k) == v for k, v in wanted.items()):
            continue
        if not include_stopped and container.get("state", "running") != "running":
            continue
        sys.stdout.write(
            (container.get("name", container["id"]) if names else container["id"][:12])
            + "\n"
        )
    return 0


def do_inspect(state: dict, argv: list[str]) -> int:
    template = ""
    references: list[str] = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument in ("-f", "--format"):
            template = argv[index + 1] if index + 1 < len(argv) else ""
            index += 2
            continue
        if argument == "--type":
            index += 2
            continue
        if argument.startswith("-"):
            index += 1
            continue
        references.append(argument)
        index += 1

    for reference in references:
        container = find(state, reference)
        if container is None:
            sys.stderr.write(f'Error: no such object: "{reference}"\n')
            return 125
        if "NetworkSettings.Networks" in template:
            for name in sorted(container.get("networks", [])):
                sys.stdout.write(name + "\n")
        elif ".State.Status" in template:
            sys.stdout.write(container.get("state", "running") + "\n")
        elif ".State.Running" in template:
            sys.stdout.write(
                str(container.get("state", "running") == "running").lower() + "\n"
            )
        elif ".Name" in template:
            sys.stdout.write(container.get("name", container["id"]) + "\n")
        elif 'index .Config.Labels "' in template:
            key = template.split('index .Config.Labels "', 1)[1].split('"', 1)[0]
            sys.stdout.write(labels_of(container).get(key, "") + "\n")
        elif not template:
            sys.stdout.write(
                json.dumps(
                    [
                        {
                            "Id": container["id"],
                            "Name": container.get("name", container["id"]),
                            "State": {
                                "Status": container.get("state", "running"),
                                "Running": container.get("state", "running")
                                == "running",
                            },
                            "Config": {
                                "Image": "localhost/asf:test",
                                "Labels": labels_of(container),
                            },
                            "NetworkSettings": {
                                "Networks": {
                                    name: {} for name in container.get("networks", [])
                                }
                            },
                        }
                    ],
                    indent=4,
                )
                + "\n"
            )
        else:
            sys.stderr.write(f"fake podman: unsupported template: {template}\n")
            return 125
    return 0


def do_rm(state: dict, argv: list[str]) -> int:
    code = forced(state, "rm")
    if code is not None:
        return code
    references = [a for a in argv if not a.startswith("-")]
    skip = False
    cleaned: list[str] = []
    for argument in argv:
        if skip:
            skip = False
            continue
        if argument in ("--time", "-t"):
            skip = True
            continue
        if argument.startswith("-"):
            continue
        cleaned.append(argument)
    references = cleaned
    ignore = "--ignore" in argv
    status = 0
    for reference in references:
        container = find(state, reference)
        if container is None:
            if not ignore:
                sys.stderr.write(f'Error: no such container "{reference}"\n')
                status = 1
            continue
        state["containers"].remove(container)
    save(state)
    return status


def do_stop(state: dict, argv: list[str]) -> int:
    code = forced(state, "stop")
    if code is not None:
        return code
    skip = False
    for argument in argv:
        if skip:
            skip = False
            continue
        if argument in ("--time", "-t"):
            skip = True
            continue
        if argument.startswith("-"):
            continue
        container = find(state, argument)
        if container is not None:
            container["state"] = "exited"
    save(state)
    return 0


def do_network(state: dict, argv: list[str]) -> int:
    if argv[:1] == ["rm"]:
        code = forced(state, "network rm")
        if code is not None:
            return code
        names = [a for a in argv[1:] if not a.startswith("-")]
        for name in names:
            if name in state["networks"]:
                state["networks"].remove(name)
        save(state)
        return 0
    if argv[:1] == ["inspect"]:
        names = [a for a in argv[1:] if not a.startswith("-")]
        for name in names:
            if name not in state["networks"]:
                sys.stderr.write(f'Error: no such network "{name}"\n')
                return 125
        sys.stdout.write("[]\n")
        return 0
    sys.stderr.write(f"fake podman: unsupported network command: {argv}\n")
    return 125


def do_secret(state: dict, argv: list[str]) -> int:
    if argv[:1] == ["ls"]:
        for name in state["secrets"]:
            sys.stdout.write(name + "\n")
        return 0
    if argv[:1] == ["rm"]:
        code = forced(state, "secret rm")
        if code is not None:
            return code
        names = [a for a in argv[1:] if not a.startswith("-")]
        status = 0
        for name in names:
            if name in state["secrets"]:
                state["secrets"].remove(name)
            else:
                sys.stderr.write(f'Error: no such secret "{name}"\n')
                status = 1
        save(state)
        return status
    if argv[:1] == ["inspect"]:
        names = [a for a in argv[1:] if not a.startswith("-")]
        for name in names:
            if name not in state["secrets"]:
                sys.stderr.write(f'Error: no such secret "{name}"\n')
                return 125
        sys.stdout.write("[]\n")
        return 0
    sys.stderr.write(f"fake podman: unsupported secret command: {argv}\n")
    return 125


def main(argv: list[str]) -> int:
    if not argv:
        sys.stderr.write("fake podman: no subcommand\n")
        return 125
    state = load()
    dispatch = {
        "ps": lambda: do_ps(state, argv[1:]),
        "inspect": lambda: do_inspect(state, argv[1:]),
        "rm": lambda: do_rm(state, argv[1:]),
        "stop": lambda: do_stop(state, argv[1:]),
        "network": lambda: do_network(state, argv[1:]),
        "secret": lambda: do_secret(state, argv[1:]),
        "version": lambda: (sys.stdout.write("5.0.0-fake\n"), 0)[1],
    }
    handler = dispatch.get(argv[0])
    if handler is None:
        sys.stderr.write(f"fake podman: unsupported command: {' '.join(argv)}\n")
        return 125
    return handler()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
