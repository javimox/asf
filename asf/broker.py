"""LiteLLM configuration and lifecycle for ASF runtime sessions.

The persisted :class:`~asf.runtime_plan.RuntimePlan` owns resource identity and
network topology.  The validated runtime manifest owns provider, wire protocol,
models, and declared secret files.  This module combines those two trusted
inputs, creates the temporary provider secret, starts the planned LiteLLM
container, writes its short-lived host state, and checks readiness.

Network creation, runtime startup, shell attachment, and routed policy live in
their own modules (:mod:`asf.networks`, :mod:`asf.runtime`, :mod:`asf.routed`).
"""

from __future__ import annotations

import argparse
import os
import re
import secrets as stdlib_secrets
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Sequence, TextIO

from .errors import ConfigurationError, InfrastructureError, ValidationError
from .manifest import load_model
from .models import LlmSettings, RuntimeManifest
from .ownership import ResourceKind
from .paths import RepoPaths
from .podman import ContainerState, PodmanClient
from .process import CommandResult, SensitiveArgument
from .runtime_plan import (
    BROKER_INTERNAL_ALIAS,
    ContainerPlan,
    NetworkRole,
    RuntimePlan,
    load_runtime_plan,
    runtime_plan_path,
    validate_runtime_plan_context,
)
from .secrets import SecretValue
from .session import SessionRole

__all__ = [
    "BrokerError",
    "BrokerLifecycleError",
    "BROKER_PORT",
    "PROVIDER_DEFAULTS",
    "BrokerModels",
    "BrokerProviderSettings",
    "BrokerRequest",
    "BrokerService",
    "BrokerSettings",
    "build_model_policy",
    "describe_lines",
    "generate_session_token",
    "load_request",
    "main",
    "prepare_models",
    "provider_api_key_name",
    "provider_direct_domain",
    "resolve_provider_settings",
    "read_declared_secret",
]

BROKER_PORT = 4000
PROVIDER_DEFAULTS: Mapping[str, str] = MappingProxyType({
    "openai": "api.openai.com",
    "anthropic": "api.anthropic.com",
    "openrouter": "openrouter.ai",
    "mistral": "api.mistral.ai",
    "groq": "api.groq.com",
    "deepseek": "api.deepseek.com",
})
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")


class BrokerError(ConfigurationError):
    """The persisted plan or manifest cannot form a safe LiteLLM broker."""


class BrokerLifecycleError(InfrastructureError):
    """LiteLLM image, secret, container, state, or readiness failed."""


@dataclass(frozen=True, slots=True)
class BrokerProviderSettings:
    """Provider identity and direct-egress policy resolved from the manifest."""

    provider: str
    protocol: str
    api_key_name: str
    direct_domain: str


def resolve_provider_settings(manifest: RuntimeManifest) -> BrokerProviderSettings:
    """Resolve provider defaults without performing I/O or Podman operations."""

    llm = _broker_llm(manifest)
    assert llm.provider is not None and llm.protocol is not None
    api_key_name = llm.api_key_env or (
        llm.provider.upper().replace("-", "_") + "_API_KEY"
    )
    if _ENV_RE.fullmatch(api_key_name) is None:
        raise BrokerError(f"invalid provider secret variable name: {api_key_name!r}")
    direct_domain = llm.direct_domain or PROVIDER_DEFAULTS.get(llm.provider, "")
    if not direct_domain:
        raise BrokerError(
            f"No direct API domain is known for provider {llm.provider!r}; "
            "set llm.direct_domain in the runtime manifest"
        )
    return BrokerProviderSettings(
        provider=llm.provider,
        protocol=llm.protocol,
        api_key_name=api_key_name,
        direct_domain=direct_domain,
    )


@dataclass(frozen=True, slots=True)
class BrokerSettings:
    image: str
    startup_timeout: int = 60
    detailed_debug: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not self.image or "\x00" in self.image:
            raise ValidationError("LiteLLM image must be non-empty safe text")
        if any(character.isspace() for character in self.image):
            raise ValidationError("LiteLLM image must not contain whitespace")
        if (
            isinstance(self.startup_timeout, bool)
            or not isinstance(self.startup_timeout, int)
            or self.startup_timeout <= 0
        ):
            raise ValidationError("LiteLLM startup timeout must be a positive integer")
        if not isinstance(self.detailed_debug, bool):
            raise TypeError("LiteLLM detailed_debug must be boolean")


@dataclass(frozen=True, slots=True)
class BrokerModels:
    mode: str
    models: tuple[str, ...]
    route: str
    default_model: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "models", tuple(self.models))
        if self.mode not in {"wildcard", "restricted"}:
            raise ValidationError("broker model mode must be wildcard or restricted")
        if not all(_MODEL_RE.fullmatch(model) for model in self.models):
            raise ValidationError("broker models contain an invalid model ID")
        if len(self.models) != len(set(self.models)):
            raise ValidationError("broker models must not contain duplicates")
        if self.mode == "wildcard" and self.models:
            raise ValidationError("wildcard broker mode cannot contain explicit models")
        if self.mode == "restricted" and not self.models:
            raise ValidationError("restricted broker mode requires explicit models")
        if not isinstance(self.route, str) or not self.route or "\x00" in self.route:
            raise ValidationError("broker route must be non-empty safe text")
        if not isinstance(self.default_model, str) or "\x00" in self.default_model:
            raise ValidationError("broker default model must be safe text")
        if (
            self.default_model
            and self.mode == "restricted"
            and self.default_model not in self.models
        ):
            raise ValidationError("broker default model is outside the restricted model list")

    @property
    def restricted(self) -> bool:
        return self.mode == "restricted"

    @property
    def model_text(self) -> str:
        return " ".join(self.models)


@dataclass(frozen=True, slots=True)
class BrokerRequest:
    paths: RepoPaths
    manifest: RuntimeManifest
    plan: RuntimePlan
    settings: BrokerSettings
    provider_settings: BrokerProviderSettings = field(init=False)
    models: BrokerModels = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.paths, RepoPaths):
            raise TypeError("paths must be RepoPaths")
        if not isinstance(self.manifest, RuntimeManifest):
            raise TypeError("manifest must be a RuntimeManifest")
        if not isinstance(self.plan, RuntimePlan):
            raise TypeError("plan must be a RuntimePlan")
        if not isinstance(self.settings, BrokerSettings):
            raise TypeError("settings must be BrokerSettings")
        object.__setattr__(
            self, "provider_settings", resolve_provider_settings(self.manifest)
        )
        _validate_broker_context(self)
        object.__setattr__(self, "models", prepare_models(self.paths, self.manifest))

    @property
    def container(self) -> ContainerPlan:
        container = self.plan.container(SessionRole.BROKER)
        if container is None:
            raise BrokerError("runtime plan does not contain a LiteLLM broker")
        return container

    @property
    def internal_network(self) -> str:
        network = self.plan.network(NetworkRole.INTERNAL)
        if network is None:
            raise BrokerError("broker plan is missing the internal network")
        return network.name

    @property
    def provider_network(self) -> str:
        network = self.plan.network(NetworkRole.PROVIDER)
        if network is None:
            raise BrokerError("broker plan is missing the provider network")
        return network.name

    @property
    def provider(self) -> str:
        return self.provider_settings.provider

    @property
    def protocol(self) -> str:
        return self.provider_settings.protocol

    @property
    def api_key_name(self) -> str:
        return self.provider_settings.api_key_name

    @property
    def direct_domain(self) -> str:
        return self.provider_settings.direct_domain

    @property
    def secret_name(self) -> str:
        expected = self.paths.identity.broker_secret(self.plan.runtime, self.plan.owner_pid)
        matches = tuple(
            resource.name
            for resource in self.plan.ephemeral_resources
            if resource.kind is ResourceKind.SECRET
        )
        if matches != (expected,):
            raise BrokerError("broker plan must contain exactly its provider secret")
        return expected

    @property
    def state_path(self) -> Path:
        expected = self.paths.identity.broker_state(self.plan.runtime)
        matches = tuple(
            Path(resource.name)
            for resource in self.plan.ephemeral_resources
            if resource.kind is ResourceKind.BROKER_STATE
        )
        if matches != (expected,):
            raise BrokerError("broker plan must contain exactly its host state path")
        if self.paths.devcontainer_dir.is_symlink():
            raise BrokerError(".devcontainer must not be a symlink")
        try:
            safe = self.paths.child(".devcontainer", expected.name)
        except ValidationError as exc:
            raise BrokerError("broker state path escaped .devcontainer") from exc
        if safe != expected:
            raise BrokerError("broker state path escaped .devcontainer")
        return safe

    @property
    def entrypoint(self) -> Path:
        lexical = self.paths.litellm_entrypoint
        if lexical.is_symlink():
            raise BrokerError(f"LiteLLM entrypoint must not be a symlink: {lexical}")
        try:
            path = self.paths.child("tools", "litellm_entrypoint.py")
        except ValidationError as exc:
            raise BrokerError("LiteLLM entrypoint escaped tools/") from exc
        if not path.is_file():
            raise BrokerError(f"LiteLLM entrypoint is missing or unsafe: {path}")
        return path


@dataclass(frozen=True, slots=True)
class BrokerService:
    podman: PodmanClient = field(default_factory=PodmanClient)
    readiness_delay: float = 0.5
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")
        if (
            isinstance(self.readiness_delay, bool)
            or not isinstance(self.readiness_delay, (int, float))
            or self.readiness_delay < 0
        ):
            raise ValidationError("broker readiness delay must be non-negative")
        if not callable(self.sleep):
            raise TypeError("sleep must be callable")

    def start(
        self,
        request: BrokerRequest,
        token: SecretValue,
        *,
        output: TextIO = sys.stdout,
        error: TextIO = sys.stderr,
    ) -> None:
        if not isinstance(request, BrokerRequest):
            raise TypeError("request must be a BrokerRequest")
        _validate_session_token(token)
        self.podman.require_available()
        _clear_state(request.state_path)

        provider_key = read_declared_secret(request, request.api_key_name, error=error)
        if not provider_key.reveal():
            files = "\n".join(f"    secrets/{item.filename}" for item in request.plan.secret_files)
            suffix = f"\n{files}" if files else "\n    (no secret files declared)"
            raise BrokerError(
                f"Broker enabled but {request.api_key_name} is missing for "
                f"{request.plan.runtime}.\n"
                f"  Provider: {request.provider}\n"
                f"  Add it to one of the runtime's declared secret files:{suffix}"
            )

        output.write("\033[0;34mPreparing LiteLLM broker...\033[0m\n")
        image_exists = self.podman.observe(
            (self.podman.engine, "image", "exists", request.settings.image),
            timeout=20,
        )
        if image_exists.returncode == 0:
            output.write(
                f"  \033[0;32m✓\033[0m Image available: "
                f"\033[2m{request.settings.image}\033[0m\n"
            )
        elif image_exists.returncode == 1:
            output.write(
                f"  \033[0;34m→\033[0m Pulling image (first run only): "
                f"\033[2m{request.settings.image}\033[0m\n"
            )
            result = self.podman.observe(
                (self.podman.engine, "pull", request.settings.image), timeout=900
            )
            _require_success(result, "Failed to pull the LiteLLM image")
        else:
            raise BrokerLifecycleError(
                "Could not inspect the LiteLLM image "
                f"(Podman status {image_exists.returncode})"
            )

        output.write(
            f"  \033[0;34m→\033[0m Loading {request.api_key_name} into a "
            "temporary Podman secret\n"
        )
        result = self.podman.observe(
            self.secret_create_argv(request),
            timeout=30,
            input_text=provider_key.reveal(),
        )
        _require_success(result, "Could not create the temporary provider secret")

        if request.settings.detailed_debug:
            error.write(
                "  \033[1;33m⚠ Detailed LiteLLM debugging enabled; logs may "
                "contain request content or credentials.\033[0m\n"
            )

        output.write("  \033[0;34m→\033[0m Starting broker container\n")
        result = self.podman.observe(
            self.run_argv(request, token),
            timeout=60,
        )
        _require_success(result, "Could not start the LiteLLM broker")
        _write_state(request.state_path, request.container.name, request.direct_domain)
        output.write(
            f"  \033[0;32m✓\033[0m Broker container started "
            f"\033[2m(agent: {request.plan.runtime}, models: "
            f"{request.models.route})\033[0m\n"
        )

    def wait_ready(
        self,
        request: BrokerRequest,
        *,
        output: TextIO = sys.stdout,
        error: TextIO = sys.stderr,
    ) -> None:
        if not isinstance(request, BrokerRequest):
            raise TypeError("request must be a BrokerRequest")
        self.podman.require_available()
        attempts = request.settings.startup_timeout * 2
        for attempt in range(attempts):
            result = self.podman.exec_container(
                request.container.name,
                self.readiness_command(),
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                output.write("  \033[0;32m✓ LiteLLM broker ready\033[0m\n")
                return
            if result.returncode in {125, 126, 127}:
                raise BrokerLifecycleError(
                    "LiteLLM readiness probe could not execute "
                    f"(Podman status {result.returncode})"
                )

            inspection = self.podman.inspect_container(
                request.container.name, timeout=10
            )
            if inspection.state in {ContainerState.EXITED, ContainerState.STOPPED} or (
                inspection.status.strip().lower() == "dead"
            ):
                logs = self._logs(request.container.name)
                detail = f"\n{logs}" if logs else ""
                raise BrokerLifecycleError(
                    f"LiteLLM broker exited during startup.{detail}"
                )
            if attempt > 0 and attempt % 10 == 0:
                output.write(
                    f"    \033[2mwaiting for LiteLLM ({attempt // 2}s)...\033[0m\n"
                )
            if attempt + 1 < attempts:
                self.sleep(float(self.readiness_delay))

        logs = self._logs(request.container.name)
        if logs:
            error.write(logs.rstrip() + "\n")
        raise BrokerLifecycleError(
            "LiteLLM broker failed to become ready after "
            f"{request.settings.startup_timeout}s"
        )

    def secret_create_argv(self, request: BrokerRequest) -> tuple[str, ...]:
        """Build the provider-secret command; the credential is supplied on stdin."""

        if not isinstance(request, BrokerRequest):
            raise TypeError("request must be a BrokerRequest")
        return (
            str(self.podman.engine),
            "secret",
            "create",
            "--label",
            request.plan.sandbox_label,
            request.secret_name,
            "-",
        )

    def run_argv(
        self, request: BrokerRequest, token: SecretValue
    ) -> tuple[str | SensitiveArgument, ...]:
        if not isinstance(request, BrokerRequest):
            raise TypeError("request must be a BrokerRequest")
        _validate_session_token(token)
        return (
            str(self.podman.engine),
            "run",
            "-d",
            "--name",
            request.container.name,
            "--network",
            f"{request.internal_network}:alias={BROKER_INTERNAL_ALIAS}",
            "--network",
            request.provider_network,
            "--label",
            request.plan.sandbox_label,
            "--label",
            "asf.role=broker",
            "--label",
            f"asf.agent={request.plan.runtime}",
            "--label",
            f"asf.provider={request.provider}",
            "--label",
            f"asf.model-mode={request.models.mode}",
            "--label",
            f"asf.model-route={request.models.route}",
            "--label",
            f"asf.default-model={request.models.default_model}",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=64m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=256",
            "--memory=768m",
            "--cpus=1",
            "--secret",
            f"{request.secret_name},type=mount,target=provider_api_key",
            "-e",
            SensitiveArgument(f"LITELLM_MASTER_KEY={token.reveal()}"),
            "-e",
            f"LITELLM_AGENT={request.plan.runtime}",
            "-e",
            f"ASF_LITELLM_PROVIDER={request.provider}",
            "-e",
            f"ASF_LITELLM_MODELS={request.models.model_text}",
            "-e",
            "ASF_LITELLM_DETAILED_DEBUG="
            f"{'true' if request.settings.detailed_debug else 'false'}",
            "-e",
            "NO_DOCS=True",
            "-e",
            "NO_REDOC=True",
            "-e",
            "DISABLE_ADMIN_UI=True",
            "-v",
            f"{request.entrypoint}:/asf/litellm_entrypoint.py:ro",
            "--entrypoint",
            "python",
            request.settings.image,
            "/asf/litellm_entrypoint.py",
        )

    @staticmethod
    def readiness_command() -> tuple[str, ...]:
        """Fixed in-container liveness probe; the broker publishes no host port."""

        return (
            "python",
            "-c",
            'import urllib.request; urllib.request.urlopen('
            '"http://127.0.0.1:4000/health/liveliness", timeout=2)',
        )

    def _logs(self, container: str) -> str:
        try:
            result = self.podman.container_logs(container, tail=200)
        except InfrastructureError:
            return ""
        return (result.stdout or result.stderr).strip()


def load_request(
    root: str | os.PathLike[str],
    runtime: str,
    *,
    image: str,
    startup_timeout: int = 60,
    detailed_debug: bool = False,
) -> BrokerRequest:
    paths = RepoPaths.for_root(root)
    manifest = load_model(paths.identity.runtime_manifest(runtime))
    plan = load_runtime_plan(runtime_plan_path(paths, runtime))
    validate_runtime_plan_context(plan, manifest, paths)
    return BrokerRequest(
        paths,
        manifest,
        plan,
        BrokerSettings(image, startup_timeout, detailed_debug),
    )


def provider_api_key_name(manifest: RuntimeManifest) -> str:
    return resolve_provider_settings(manifest).api_key_name


def provider_direct_domain(manifest: RuntimeManifest) -> str:
    return resolve_provider_settings(manifest).direct_domain


def build_model_policy(
    manifest: RuntimeManifest,
    provider: str,
    *,
    default_model: str = "",
) -> BrokerModels:
    """Normalize and validate the broker model policy without performing I/O."""

    llm = _broker_llm(manifest)
    models: list[str] = []
    seen: set[str] = set()
    prefix = f"{provider}/"
    for raw in llm.models:
        model = raw[len(prefix) :] if raw.startswith(prefix) else raw
        if _MODEL_RE.fullmatch(model) is None:
            raise BrokerError(
                f"Invalid {manifest.name} model ID in runtime.yml: {model}"
            )
        if model not in seen:
            seen.add(model)
            models.append(model)

    default = default_model.strip()
    if default.startswith(prefix):
        default = default[len(prefix) :]
    if default and _MODEL_RE.fullmatch(default) is None:
        raise BrokerError(f"Invalid default model: {default!r}")
    if default and models and default not in seen:
        raise BrokerError(
            f"Hermes default model {default!r} is not in llm.models. "
            "Add it to the runtime manifest, or remove llm.models to expose all."
        )

    mode = "restricted" if models else "wildcard"
    route = " ".join(models) if models else f"{provider}/* (all models)"
    return BrokerModels(mode, tuple(models), route, default)


def prepare_models(paths: RepoPaths, manifest: RuntimeManifest) -> BrokerModels:
    provider = resolve_provider_settings(manifest).provider
    default_model = ""
    if manifest.adapter == "hermes":
        default_model = _hermes_default_model(paths, manifest.name, provider)
    return build_model_policy(
        manifest, provider, default_model=default_model
    )


def read_declared_secret(
    request: BrokerRequest,
    wanted: str,
    *,
    error: TextIO = sys.stderr,
) -> SecretValue:
    if not _ENV_RE.fullmatch(wanted):
        raise BrokerError(f"invalid provider secret variable name: {wanted!r}")
    value = ""
    if request.paths.secrets_dir.is_symlink():
        raise BrokerError("secrets directory must not be a symlink")
    try:
        physical_secrets = request.paths.secrets_dir.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BrokerError("secrets directory is missing or unsafe") from exc
    for secret in request.plan.secret_files:
        source = secret.source
        if source.is_symlink():
            raise BrokerError(f"declared secret file must not be a symlink: {source}")
        if not source.exists():
            continue
        try:
            physical = source.resolve(strict=True)
            physical.relative_to(physical_secrets)
        except (OSError, RuntimeError, ValueError) as exc:
            raise BrokerError(f"declared secret file escapes secrets/: {source}") from exc
        if not physical.is_file():
            raise BrokerError(f"declared secret path is not a file: {source}")
        mode = stat.S_IMODE(physical.stat().st_mode)
        if mode not in {0o400, 0o600}:
            relative = source.relative_to(request.paths.root)
            error.write(
                f"  \033[1;33m⚠ {relative} is mode {mode:o} — tighten with: "
                f"chmod 600 {relative}\033[0m\n"
            )
        try:
            lines = physical.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise BrokerError(f"cannot read declared secret file {source}: {exc}") from exc
        for line in lines:
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, item = stripped.split("=", 1)
            key = key.rstrip()
            if _ENV_RE.fullmatch(key) is None:
                raise BrokerError(
                    f"Invalid environment variable name in "
                    f"{source.relative_to(request.paths.root)}: {key}"
                )
            if key == wanted:
                value = item
    return SecretValue(value)


def describe_lines(request: BrokerRequest) -> tuple[str, ...]:
    """Stable newline-safe fields for diagnostics and CLI output."""

    values = (
        request.container.name,
        request.secret_name,
        request.provider,
        request.protocol,
        request.api_key_name,
        request.direct_domain,
        request.models.mode,
        request.models.default_model,
        request.models.model_text,
        request.models.route,
    )
    if any("\n" in value or "\r" in value for value in values):
        raise BrokerError("broker description contains an unsafe newline")
    return values


def _broker_llm(manifest: RuntimeManifest) -> LlmSettings:
    llm = manifest.llm
    if llm is None or not llm.broker:
        raise BrokerError(
            f"Runtime {manifest.name} does not request an LLM broker"
        )
    if llm.provider is None or llm.protocol is None:
        raise BrokerError("broker manifest is missing provider or protocol")
    return llm


def _validate_broker_context(request: BrokerRequest) -> None:
    validate_runtime_plan_context(request.plan, request.manifest, request.paths)
    _broker_llm(request.manifest)
    if not request.plan.broker_enabled:
        raise BrokerError("runtime plan does not enable the LLM broker")
    broker = request.plan.container(SessionRole.BROKER)
    if broker is None:
        raise BrokerError("broker-enabled plan is missing the LiteLLM container")
    expected_networks = (request.internal_network, request.provider_network)
    if broker.networks != expected_networks:
        raise BrokerError(
            "LiteLLM must attach to the internal and provider networks in that order"
        )
    if broker.capabilities:
        raise BrokerError("LiteLLM must not receive Linux capabilities")
    _ = request.secret_name
    _ = request.state_path
    _ = request.entrypoint
    _ = request.direct_domain


def _hermes_default_model(paths: RepoPaths, runtime: str, provider: str) -> str:
    lexical = paths.agents_dir / runtime / "config.yaml"
    if lexical.is_symlink():
        raise BrokerError(f"Hermes config must not be a symlink: {lexical}")
    try:
        config = paths.child("agents", runtime, "config.yaml")
    except ValidationError as exc:
        raise BrokerError("Hermes config escaped agents/") from exc
    if not config.is_file():
        raise BrokerError(f"Hermes config is missing or unsafe: {config}")
    try:
        import yaml
    except ImportError as exc:
        raise BrokerError("PyYAML is required to read Hermes configuration") from exc
    try:
        payload = yaml.safe_load(config.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise BrokerError(f"cannot read Hermes model configuration: {exc}") from exc
    model = payload.get("model") if isinstance(payload, dict) else None
    default = model.get("default") if isinstance(model, dict) else None
    if not isinstance(default, str) or not default:
        raise BrokerError("Hermes config has no model.default value")
    prefix = f"{provider}/"
    value = default[len(prefix) :] if default.startswith(prefix) else default
    if _MODEL_RE.fullmatch(value) is None:
        raise BrokerError(f"Hermes default model is invalid: {value!r}")
    return value



def _clear_state(path: Path) -> None:
    if path.is_symlink():
        raise BrokerError(f"broker state must not be a symlink: {path}")
    if path.exists() and not path.is_file():
        raise BrokerError(f"broker state path is not a file: {path}")
    path.unlink(missing_ok=True)

def _write_state(path: Path, container: str, direct_domain: str) -> None:
    if path.is_symlink():
        raise BrokerError(f"broker state must not be a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise BrokerError(f"broker state directory must not be a symlink: {path.parent}")
    text = f"{container}\n{direct_domain}\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def _require_success(result: CommandResult, description: str) -> None:
    if result.returncode == 0:
        return
    detail = result.stderr.strip() or result.stdout.strip()
    suffix = f": {detail}" if detail else f" (Podman status {result.returncode})"
    raise BrokerLifecycleError(description + suffix)


def _validate_session_token(token: SecretValue) -> None:
    if not isinstance(token, SecretValue):
        raise TypeError("token must be a SecretValue")
    if _TOKEN_RE.fullmatch(token.reveal()) is None:
        raise BrokerError(
            "broker session token must be 64 lowercase hexadecimal characters"
        )


def generate_session_token() -> SecretValue:
    """Return a fresh opaque 64-character hexadecimal broker session token."""

    return SecretValue(stdlib_secrets.token_hex(32))


def _parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("value must be true or false")


def _add_request_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--startup-timeout", type=int, default=60)
    parser.add_argument("--detailed-debug", type=_parse_bool, default=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m asf.broker")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("token")
    for action in ("describe", "start", "wait"):
        command = sub.add_parser(action)
        _add_request_arguments(command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    namespace = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if namespace.action == "token":
            print(generate_session_token().reveal())
            return 0
        request = load_request(
            namespace.root,
            namespace.runtime,
            image=namespace.image,
            startup_timeout=namespace.startup_timeout,
            detailed_debug=namespace.detailed_debug,
        )
        if namespace.action == "describe":
            print("\n".join(describe_lines(request)))
            return 0
        if namespace.action == "start":
            raw_token = os.environ.get("ASF_BROKER_TOKEN", "")
            if not raw_token:
                raise BrokerError("ASF_BROKER_TOKEN is required to start LiteLLM")
            BrokerService().start(request, SecretValue(raw_token))
            return 0
        BrokerService().wait_ready(request)
        return 0
    except (ConfigurationError, InfrastructureError) as exc:
        print(f"\033[0;31m{exc}\033[0m", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
