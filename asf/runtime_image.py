"""Build the OCI image used by an ASF runtime.

ASF keeps one shared base image and one thin image per adapter. Both container
and microVM isolation consume the same final image.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Sequence

from .errors import ConfigurationError
from .models import RuntimeManifest
from .paths import RepoPaths

__all__ = [
    "base_image_name",
    "build_base_image_argv",
    "build_runtime_image_argv",
    "runtime_image_name",
]

_BUILD_ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DECLARED_ARG = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
_SUPPORTED_ADAPTERS = frozenset({"claude", "codex", "hermes", "generic"})


def base_image_name(paths: RepoPaths) -> str:
    return f"localhost/{paths.identity.prefix.lower()}-base:runtime"


def runtime_image_name(paths: RepoPaths, runtime: str) -> str:
    return f"localhost/{paths.identity.session_key(runtime).lower()}:runtime"


def _build_values(
    manifest: RuntimeManifest,
    build_arguments: Sequence[str],
) -> dict[str, str]:
    values: dict[str, str] = {"TZ": os.environ.get("TZ", "UTC") or "UTC"}
    for item in manifest.runtime.build_arguments:
        values[item.name] = item.value
    for raw in build_arguments:
        name, separator, value = raw.partition("=")
        if not separator or not _BUILD_ARG_NAME.fullmatch(name):
            raise ConfigurationError(
                f"Invalid build argument (expected NAME=VALUE): {raw}"
            )
        values[name] = value
    return values


def _append_build_args(
    args: list[str], containerfile: Path, values: dict[str, str]
) -> None:
    """Pass only the arguments this Containerfile declares.

    ``asf.conf`` pins every dependency in one list, but the base consumes none
    of the agent pins and an agent layer consumes none of the base pins.
    Selecting by declared ``ARG`` keeps the recorded build command equal to what
    the build actually uses, and keeps Podman from warning about the rest.
    """

    try:
        text = containerfile.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read {containerfile}: {exc}") from exc
    declared = frozenset(_DECLARED_ARG.findall(text))
    for name in sorted(values):
        if name in declared:
            args.extend(("--build-arg", f"{name}={values[name]}"))


def build_base_image_argv(
    paths: RepoPaths,
    manifest: RuntimeManifest,
    *,
    build_arguments: Sequence[str] = (),
    engine: str = "podman",
) -> tuple[str, ...]:
    containerfile = paths.containers_dir / "base" / "Containerfile"
    args = [
        engine,
        "build",
        "--tag",
        base_image_name(paths),
        "--file",
        str(containerfile),
    ]
    _append_build_args(args, containerfile, _build_values(manifest, build_arguments))
    args.append(str(paths.root))
    return tuple(args)


def build_runtime_image_argv(
    paths: RepoPaths,
    manifest: RuntimeManifest,
    *,
    build_arguments: Sequence[str] = (),
    engine: str = "podman",
) -> tuple[str, ...]:
    adapter = manifest.adapter
    if adapter not in _SUPPORTED_ADAPTERS:
        raise ConfigurationError(
            f"unsupported adapter {adapter!r}; expected one of "
            + ", ".join(sorted(_SUPPORTED_ADAPTERS))
        )
    containerfile = paths.containers_dir / adapter / "Containerfile"
    if not containerfile.is_file():
        raise ConfigurationError(f"runtime Containerfile not found: {containerfile}")
    args = [
        engine,
        "build",
        "--tag",
        runtime_image_name(paths, manifest.name),
        "--file",
        str(containerfile),
        "--build-arg",
        f"ASF_BASE_IMAGE={base_image_name(paths)}",
    ]
    _append_build_args(args, containerfile, _build_values(manifest, build_arguments))
    args.append(str(paths.root))
    return tuple(args)
