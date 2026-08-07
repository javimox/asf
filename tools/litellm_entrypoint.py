#!/usr/bin/env python3
"""Discover provider models, generate a concrete LiteLLM config, and start proxy."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterable

MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
PROVIDER_SLUG = re.compile(r"^[a-z][a-z0-9_-]*$")

# LiteLLM reads the upstream key from the provider's conventional env variable
# during discovery. The convention is <PROVIDER>_API_KEY; add overrides here
# only for providers that deviate (e.g. "gemini" for Google AI Studio).
PROVIDER_KEY_ENV_OVERRIDES = {
    "gemini": "GEMINI_API_KEY",
    "vertex_ai": "GOOGLE_APPLICATION_CREDENTIALS",
}


def provider_key_env(provider: str) -> str:
    return PROVIDER_KEY_ENV_OVERRIDES.get(
        provider, f"{provider.upper().replace('-', '_')}_API_KEY"
    )


def normalize_models(provider: str, candidates: Iterable[str]) -> list[str]:
    """Return stable, unprefixed, concrete model IDs for one provider."""
    prefix = f"{provider}/"
    normalized: list[str] = []
    seen: set[str] = set()

    for raw in candidates:
        model = raw.strip()
        if not model or "*" in model:
            continue
        if model.startswith(prefix):
            model = model[len(prefix) :]
        elif "/" in model:
            # Ignore models explicitly owned by another provider.
            continue
        if not MODEL_ID.fullmatch(model):
            continue
        if model not in seen:
            seen.add(model)
            normalized.append(model)

    return sorted(normalized)


def resolve_models(provider: str, configured: str) -> tuple[list[str], str]:
    """Explicit list -> concrete routes. Empty -> wildcard (all provider models).

    Wildcard is the default deliberately: no provider call at startup (fast,
    works for providers without discovery support) and every model the key can
    reach is available. An explicit list is the opt-in restriction.
    """
    requested = configured.split()
    if not requested:
        return [], "wildcard"
    models = normalize_models(provider, requested)
    if not models:
        raise RuntimeError(
            f"LITELLM_<AGENT>_MODELS is set but contains no valid {provider} "
            "model IDs. Fix the list, or unset it to expose all models."
        )
    return models, "allowlist"


def yaml_string(value: str) -> str:
    # JSON strings are valid YAML scalars and safely escape model IDs.
    return json.dumps(value)


# NOTE on limiting the master key's authority:
# LiteLLM's `allowed_routes` (route allowlist) is an Enterprise-only feature —
# the OSS image errors at request time with "This is an Enterprise feature".
# So we do NOT set it. The master key can therefore reach every proxy route,
# including management routes. This is acceptable here because the broker is
# single-session, on a private network reachable only by this agent container,
# holds one upstream key, keeps no database, and is destroyed on exit — so
# key-management routes have nothing persistent to manage and no spend data to
# read (disable_spend_logs). Virtual keys were considered and rejected: they
# require a database, which outweighs the benefit at this scale.
# To restrict routes anyway, add a LiteLLM Enterprise license via
# LITELLM_LICENSE and reinstate `allowed_routes` in render_config.


def _route(provider: str, model_name: str, upstream: str) -> list[str]:
    lines = [
        f"  - model_name: {yaml_string(model_name)}",
        "    litellm_params:",
        f"      model: {yaml_string(upstream)}",
        "      api_key: os.environ/LITELLM_PROVIDER_API_KEY",
    ]
    if provider == "openai":
        lines += ["      additional_drop_params:", "        - temperature"]
    return lines


def render_config(provider: str, models: list[str], agent: str = "") -> str:
    # `agent` is retained for a stable signature (callers/tests pass it). It is
    # unused since route allowlisting moved out (Enterprise-only); see the note
    # on the master key above.
    del agent
    lines = ["model_list:"]
    if not models:
        # Wildcard: both prefixed and bare request forms map onto provider/*.
        lines += _route(provider, f"{provider}/*", f"{provider}/*")
        lines += _route(provider, "*", f"{provider}/*")
    for model in models:
        lines += _route(provider, model, f"{provider}/{model}")

    lines.extend(
        [
            "",
            "litellm_settings:",
            "  set_verbose: false",
            "  turn_off_message_logging: true",
            "",
            "general_settings:",
            "  master_key: os.environ/LITELLM_MASTER_KEY",
            "  disable_spend_logs: true",
            "  block_robots: true",
        ]
    )
    lines.extend(
        [
            "",
            "router_settings:",
            "  disable_cooldowns: true",
            "",
        ]
    )
    return "\n".join(lines)


def write_config(contents: str) -> Path:
    target = Path("/tmp/asf-litellm-config.yaml")
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=target.parent,
        prefix=f".{target.name}.",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(contents)
    os.replace(temporary, target)
    return target


def main() -> int:
    provider = os.environ.get("ASF_LITELLM_PROVIDER", "").strip()
    agent = os.environ.get("LITELLM_AGENT", "").strip()
    configured = os.environ.get("ASF_LITELLM_MODELS", "")
    detailed_debug = os.environ.get("ASF_LITELLM_DETAILED_DEBUG", "false") == "true"

    if not PROVIDER_SLUG.fullmatch(provider):
        print(f"ASF LiteLLM startup failed: invalid provider slug: {provider!r}", file=sys.stderr)
        return 1

    # The provider key arrives as a mounted file (podman --secret type=mount),
    # NOT as container env: `podman exec` and `podman inspect` see Config.Env,
    # so a key there would leak into every diagnostic shell. Reading the file
    # here confines it to this process tree (litellm inherits it via exec).
    key_file = Path(os.environ.get("ASF_PROVIDER_KEY_FILE", "/run/secrets/provider_api_key"))
    if key_file.is_file():
        provider_key = key_file.read_text(encoding="utf-8").strip()
    else:
        provider_key = os.environ.get("LITELLM_PROVIDER_API_KEY", "")
    if not provider_key:
        print("ASF LiteLLM startup failed: provider key is missing", file=sys.stderr)
        return 1
    # LiteLLM's config and discovery read these two variables.
    os.environ["LITELLM_PROVIDER_API_KEY"] = provider_key
    os.environ[provider_key_env(provider)] = provider_key

    try:
        models, mode = resolve_models(provider, configured)
    except Exception as exc:  # startup must fail clearly instead of serving no models
        print(f"ASF LiteLLM startup failed: {exc}", file=sys.stderr)
        return 1

    config_path = write_config(render_config(provider, models, agent))
    if models:
        print(
            f"ASF LiteLLM: {mode} exposed {len(models)} {provider} model(s): "
            + ", ".join(models),
            flush=True,
        )
    else:
        print(f"ASF LiteLLM: {mode} route {provider}/* (all provider models)", flush=True)

    command = ["litellm", "--config", str(config_path), "--port", "4000"]
    if detailed_debug:
        command.append("--detailed_debug")
    os.execvp(command[0], command)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
