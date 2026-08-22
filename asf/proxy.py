"""Caddy policy rendering and lifecycle for proxy-mode ASF sessions.

Runtime planning owns topology and resource identity. This module consumes the
persisted
runtime plan, renders the effective proxy policy from the validated manifest,
and starts the planned Caddy container. It does not create networks, start the
broker, or open the runtime container.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence, TextIO

from .egress_evidence import (
    ACCESS_LOG_CONTAINER_PATH,
    EgressSessionContext,
    begin_egress_session,
)
from .errors import ConfigurationError, InfrastructureError, ValidationError
from .manifest import DOMAIN_RE, load_model
from .models import RuntimeManifest
from .paths import RepoPaths
from .podman import PodmanClient
from .process import CommandResult
from .runtime_plan import (
    ContainerPlan,
    GeneratedFileKind,
    NetworkRole,
    PROXY_INTERNAL_ALIAS,
    RuntimePlan,
    load_runtime_plan,
    runtime_plan_path,
    validate_runtime_plan_context,
)
from .session import SessionRole

__all__ = [
    "ALPINE_RUNTIME_IMAGE",
    "CADDY_BUILDER_IMAGE",
    "CADDY_FORWARDPROXY",
    "CADDY_IMAGE_REVISION",
    "CADDY_RUNTIME_IMAGE",
    "CADDY_VERSION",
    "ALLOWED_PORT",
    "PRIVATE_DENY_RULES",
    "PROXY_PORT",
    "ProxyError",
    "ProxyLifecycleError",
    "ProxyRequest",
    "ProxyService",
    "caddy_image_tag",
    "effective_proxy_domains",
    "load_request",
    "main",
    "format_policy_file",
    "render_caddyfile",
    "render_containerfile",
]

PROXY_PORT = 3128
ALLOWED_PORT = 443
CADDY_IMAGE_REVISION = "v2"
ALPINE_RUNTIME_IMAGE = (
    "docker.io/library/alpine@sha256:"
    "d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
)
CADDY_BUILDER_IMAGE = (
    "docker.io/library/caddy@sha256:"
    "cc6c40aa7cdea02ef9cb99f3c4e4664ecdb6066ae93ae52ed5288afc511e1241"
)
CADDY_RUNTIME_IMAGE = ALPINE_RUNTIME_IMAGE
CADDY_VERSION = "v2.10.0"
CADDY_FORWARDPROXY = (
    "github.com/caddyserver/forwardproxy@"
    "0aab84dad4fc2830789f34e27b4d7bc22a40889e"
)

PRIVATE_DENY_RULES = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "192.88.99.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/96",
    "::1/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001:db8::/32",
    "2002::/16",
    "fc00::/7",
    "fec0::/10",
    "fe80::/10",
    "ff00::/8",
)
_PROVIDER_DOMAINS = {
    "openai": "api.openai.com",
    "anthropic": "api.anthropic.com",
    "openrouter": "openrouter.ai",
    "mistral": "api.mistral.ai",
    "groq": "api.groq.com",
    "deepseek": "api.deepseek.com",
}


class ProxyError(ConfigurationError):
    """The persisted plan cannot produce a safe Caddy proxy."""


class ProxyLifecycleError(InfrastructureError):
    """Caddy image preparation, startup, or readiness failed."""


@dataclass(frozen=True, slots=True)
class ProxyRequest:
    paths: RepoPaths
    manifest: RuntimeManifest
    plan: RuntimePlan
    access_logs: bool = True
    port: int = PROXY_PORT

    def __post_init__(self) -> None:
        if not isinstance(self.paths, RepoPaths):
            raise TypeError("paths must be RepoPaths")
        if not isinstance(self.manifest, RuntimeManifest):
            raise TypeError("manifest must be a RuntimeManifest")
        if not isinstance(self.plan, RuntimePlan):
            raise TypeError("plan must be a RuntimePlan")
        if not isinstance(self.access_logs, bool):
            raise TypeError("access_logs must be boolean")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise TypeError("proxy port must be an integer")
        if not 1 <= self.port <= 65535:
            raise ValidationError("proxy port must be between 1 and 65535")
        _validate_proxy_context(self)

    @property
    def container(self) -> ContainerPlan:
        container = self.plan.container(SessionRole.PROXY)
        if container is None:
            raise ProxyError("runtime plan does not contain a proxy container")
        return container

    @property
    def internal_network(self) -> str:
        network = self.plan.network(NetworkRole.INTERNAL)
        if network is None:
            raise ProxyError("proxy plan is missing the internal network")
        return network.name

    @property
    def egress_network(self) -> str:
        network = self.plan.network(NetworkRole.EGRESS)
        if network is None:
            raise ProxyError("proxy plan is missing the egress network")
        return network.name

    @property
    def policy_path(self) -> Path:
        matches = tuple(
            item.destination
            for item in self.plan.generated_files
            if item.kind is GeneratedFileKind.PROXY_POLICY
        )
        if len(matches) != 1:
            raise ProxyError("proxy plan must contain exactly one policy destination")
        expected = self.paths.identity.proxy_config_dir(self.plan.runtime) / "Caddyfile"
        if matches[0] != expected:
            raise ProxyError("proxy policy destination does not match checkout identity")
        return matches[0]

    @property
    def config_dir(self) -> Path:
        return self.policy_path.parent

    @property
    def domains(self) -> tuple[str, ...]:
        return effective_proxy_domains(self.manifest, self.plan)

    @property
    def removed_domain(self) -> str:
        if not self.plan.broker_enabled:
            return ""
        return _provider_domain(self.manifest)


@dataclass(frozen=True, slots=True)
class ProxyService:
    podman: PodmanClient = field(default_factory=PodmanClient)
    readiness_attempts: int = 30
    readiness_delay: float = 1.0
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")
        if (
            isinstance(self.readiness_attempts, bool)
            or not isinstance(self.readiness_attempts, int)
            or self.readiness_attempts <= 0
        ):
            raise ValidationError("readiness_attempts must be a positive integer")
        if (
            isinstance(self.readiness_delay, bool)
            or not isinstance(self.readiness_delay, (int, float))
            or self.readiness_delay < 0
        ):
            raise ValidationError("readiness_delay must be non-negative")
        if not callable(self.sleep):
            raise TypeError("sleep must be callable")

    def start(self, request: ProxyRequest, *, output: TextIO = sys.stdout) -> None:
        if not isinstance(request, ProxyRequest):
            raise TypeError("request must be a ProxyRequest")
        self.podman.require_available()
        started = time.monotonic()
        _print_policy(request, output)
        _prepare_directory(request)
        _write_atomic(request.config_dir / "Containerfile", render_containerfile())
        evidence = (
            begin_egress_session(request.paths, request.plan.runtime, request.domains)
            if request.access_logs
            else None
        )
        _write_atomic(
            request.policy_path,
            render_caddyfile(request.domains, access_logs=request.access_logs, port=request.port),
        )

        tag = caddy_image_tag()
        image_exists = self.podman.observe(
            (self.podman.engine, "image", "exists", tag), timeout=20
        )
        if image_exists.returncode == 0:
            output.write("  \033[0;32m✓\033[0m Proxy image available \033[2m(caddy)\033[0m\n")
        elif image_exists.returncode == 1:
            output.write("  \033[0;34m→\033[0m Building caddy image (first run only)\n")
            result = self.podman.observe(
                (self.podman.engine, "build", "-q", "-t", tag, request.config_dir),
                timeout=900,
            )
            _require_success(result, "Could not build the caddy image")
        else:
            raise ProxyLifecycleError(
                f"could not inspect Caddy image {tag} (Podman status {image_exists.returncode})"
            )

        output.write("  \033[0;34m→\033[0m Formatting generated Caddy policy\n")
        format_policy_file(request.config_dir, tag, self.podman)
        output.write("  \033[0;34m→\033[0m Validating generated Caddy policy\n")
        self._validate_policy(request, tag, evidence)
        output.write("  \033[0;34m→\033[0m Starting egress proxy \033[2m(caddy)\033[0m\n")
        self._start_container(request, tag, evidence)
        self._wait_ready(request)
        output.write(
            f"  \033[0;32m✓\033[0m Egress proxy ready "
            f"\033[2m(caddy, :{request.port}; "
            f"{time.monotonic() - started:.1f}s)\033[0m\n"
        )


    def _validate_policy(
        self,
        request: ProxyRequest,
        tag: str,
        evidence: EgressSessionContext | None,
    ) -> None:
        evidence_args = _evidence_mount_args(evidence)
        result = self.podman.observe(
            (
                self.podman.engine,
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                *evidence_args,
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--mount",
                f"type=bind,src={request.policy_path},dst=/etc/caddy/Caddyfile,ro=true",
                *_caddy_tmpfs_mounts(),
                tag,
                "caddy",
                "validate",
                "--config",
                "/etc/caddy/Caddyfile",
                "--adapter",
                "caddyfile",
            ),
            timeout=60,
        )
        _require_success(result, "Generated Caddy policy is invalid")

    def _start_container(
        self,
        request: ProxyRequest,
        tag: str,
        evidence: EgressSessionContext | None,
    ) -> None:
        evidence_args = _evidence_mount_args(evidence)
        result = self.podman.observe(
            (
                self.podman.engine,
                "run",
                "-d",
                "--name",
                request.container.name,
                "--network",
                f"{request.internal_network}:alias={PROXY_INTERNAL_ALIAS}",
                "--network",
                request.egress_network,
                "--label",
                request.plan.sandbox_label,
                "--label",
                "asf.role=proxy",
                "--label",
                f"asf.agent={request.plan.runtime}",
                "--label",
                f"asf.access-logs={'true' if request.access_logs else 'false'}",
                "--read-only",
                *evidence_args,
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,size=16m",
                *_caddy_tmpfs_mounts(),
                "--mount",
                f"type=bind,src={request.policy_path},dst=/etc/caddy/Caddyfile,ro=true",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=64",
                "--memory=128m",
                tag,
            ),
            timeout=60,
        )
        _require_success(result, "Could not start the egress proxy")

    def _wait_ready(self, request: ProxyRequest) -> None:
        for attempt in range(self.readiness_attempts):
            result = self.podman.exec_container(
                request.container.name,
                ("nc", "-z", "127.0.0.1", str(request.port)),
                check=False,
                timeout=5,
            )
            if result.returncode == 0:
                return
            if attempt + 1 < self.readiness_attempts:
                self.sleep(float(self.readiness_delay))
        try:
            logs = self.podman.container_logs(request.container.name, tail=30)
        except InfrastructureError:
            logs = None
        detail = ""
        if logs is not None and logs.stdout.strip():
            detail = f"\n{logs.stdout.rstrip()}"
        raise ProxyLifecycleError(f"Egress proxy did not start{detail}")



def _evidence_mount_args(
    evidence: EgressSessionContext | None,
) -> tuple[str, ...]:
    if evidence is None:
        return ()
    return (
        "--userns=keep-id:uid=10001,gid=10001",
        "--mount",
        f"type=bind,src={evidence.directory},dst=/var/log/asf,rw=true",
    )


def format_policy_file(
    config_dir: str | os.PathLike[str],
    tag: str,
    podman: PodmanClient | None = None,
) -> None:
    """Format ``config_dir/Caddyfile`` through the pinned Caddy image."""

    directory = Path(config_dir)
    if directory.is_symlink():
        raise ProxyError(f"Caddy directory must not be a symlink: {directory}")
    source = directory / "Caddyfile"
    if source.is_symlink() or not source.is_file():
        raise ProxyError(f"Caddy policy not found or unsafe: {source}")
    if not isinstance(tag, str) or not tag or "\x00" in tag:
        raise ValidationError("Caddy image tag must be non-empty safe text")
    client = PodmanClient() if podman is None else podman
    if not isinstance(client, PodmanClient):
        raise TypeError("podman must be a PodmanClient")
    client.require_available()

    format_dir = directory / "format"
    if format_dir.is_symlink():
        raise ProxyError(f"Caddy format directory must not be a symlink: {format_dir}")
    if format_dir.exists():
        shutil.rmtree(format_dir)
    format_dir.mkdir(mode=0o700)
    formatted = format_dir / "Caddyfile"
    shutil.copyfile(source, formatted)
    try:
        result = client.observe(
            (
                client.engine,
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--userns=keep-id",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--mount",
                f"type=bind,src={format_dir},dst=/work,rw=true",
                tag,
                "caddy",
                "fmt",
                "--overwrite",
                "/work/Caddyfile",
            ),
            timeout=60,
        )
        _require_success(result, "Could not format the generated Caddy policy")
        if not formatted.is_file() or formatted.stat().st_size == 0:
            raise ProxyLifecycleError("Caddy formatting produced an empty policy")
        os.replace(formatted, source)
    finally:
        shutil.rmtree(format_dir, ignore_errors=True)

def load_request(
    root: str | os.PathLike[str],
    runtime: str,
    *,
    access_logs: bool = True,
) -> ProxyRequest:
    paths = RepoPaths.for_root(root)
    manifest = load_model(paths.identity.runtime_manifest(runtime))
    plan = load_runtime_plan(runtime_plan_path(paths, runtime))
    validate_runtime_plan_context(plan, manifest, paths)
    return ProxyRequest(paths, manifest, plan, access_logs=access_logs)


def effective_proxy_domains(
    manifest: RuntimeManifest,
    plan: RuntimePlan,
) -> tuple[str, ...]:
    if not isinstance(manifest, RuntimeManifest):
        raise TypeError("manifest must be a RuntimeManifest")
    if not isinstance(plan, RuntimePlan):
        raise TypeError("plan must be a RuntimePlan")
    blocked = _provider_domain(manifest) if plan.broker_enabled else ""
    return tuple(
        sorted(
            domain
            for domain in set(manifest.network.allow_domains)
            if domain != blocked
        )
    )


def render_containerfile() -> str:
    return f"""FROM {CADDY_BUILDER_IMAGE} AS build
RUN xcaddy build {CADDY_VERSION} --with {CADDY_FORWARDPROXY}

FROM {CADDY_RUNTIME_IMAGE}
RUN apk add --no-cache ca-certificates netcat-openbsd
RUN addgroup -S -g 10001 caddy && adduser -S -D -H -u 10001 -G caddy caddy
# xcaddy applies cap_net_bind_service to its output. A multi-stage COPY can
# preserve that security.capability xattr, but ASF deliberately starts Caddy
# as an unprivileged user with an empty capability bounding set. Create a new
# file from the binary contents so no file capability survives. Port 3128 does
# not need NET_BIND_SERVICE.
COPY --from=build /usr/bin/caddy /tmp/caddy-xcaddy
RUN cat /tmp/caddy-xcaddy > /usr/local/bin/caddy \\
    && chmod 0755 /usr/local/bin/caddy \\
    && rm -f /tmp/caddy-xcaddy \\
    && mkdir -p /etc/caddy /config /data \\
    && chown -R caddy:caddy /config /data
USER 10001:10001
ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data
# The base image sets its own entrypoint; clear it so CMD is used as written.
ENTRYPOINT []
CMD [\"caddy\", \"run\", \"--config\", \"/etc/caddy/Caddyfile\", \"--adapter\", \"caddyfile\"]
"""


def render_caddyfile(
    domains: Sequence[str],
    *,
    access_logs: bool = True,
    port: int = PROXY_PORT,
) -> str:
    if isinstance(domains, (str, bytes)):
        raise TypeError("domains must be a sequence")
    normalised = tuple(domains)
    if not all(isinstance(domain, str) and domain for domain in normalised):
        raise ValidationError("proxy domains must be non-empty strings")
    invalid = tuple(domain for domain in normalised if DOMAIN_RE.fullmatch(domain) is None)
    if invalid:
        raise ValidationError(f"proxy domain is not a plain hostname: {invalid[0]!r}")
    if len(normalised) != len(set(normalised)):
        raise ValidationError("proxy domains must not contain duplicates")
    if not isinstance(access_logs, bool):
        raise TypeError("access_logs must be boolean")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValidationError("proxy port must be between 1 and 65535")

    lines = [
        "{",
        "    admin off",
        "    servers {",
        "        protocols h1",
        "    }",
        "}",
        "",
        f":{port} {{",
    ]
    if access_logs:
        lines.extend(
            (
                "    log {",
                f"        output file {ACCESS_LOG_CONTAINER_PATH} {{",
                "            mode 0600",
                "            roll_size 10MiB",
                "            roll_keep 2",
                "            roll_uncompressed",
                "        }",
                "        format json",
                "    }",
            )
        )
    lines.extend(
        (
            "    route {",
            "        # ASF egress is CONNECT-only. forwardproxy also enforces ports",
            "        # and ACL on plain requests, but surfaces those denials as",
            "        # ambiguous 502s (the 403 is wrapped by net/http's transport),",
            "        # so plain proxying is denied here with an explicit 403.",
            "        @plain not method CONNECT",
            "        respond @plain 403",
            "        forward_proxy {",
            f"            ports {ALLOWED_PORT}",
            "            acl {",
        )
    )
    lines.extend(f"                deny {network}" for network in PRIVATE_DENY_RULES)
    lines.extend(f"                allow {domain}" for domain in normalised)
    lines.extend(
        (
            "                deny all",
            "            }",
            "        }",
            "    }",
            "}",
            "",
        )
    )
    return "\n".join(lines)


def caddy_image_tag() -> str:
    inputs = "|".join(
        (
            f"caddy-image-{CADDY_IMAGE_REVISION}",
            CADDY_BUILDER_IMAGE,
            CADDY_RUNTIME_IMAGE,
            CADDY_VERSION,
            CADDY_FORWARDPROXY,
        )
    )
    fingerprint = hashlib.sha256(inputs.encode("utf-8")).hexdigest()
    return f"asf-proxy-caddy:{fingerprint[:16]}"


def _provider_domain(manifest: RuntimeManifest) -> str:
    llm = manifest.llm
    if llm is None or not llm.broker:
        raise ProxyError("broker-enabled plan has no broker manifest configuration")
    if llm.direct_domain:
        return llm.direct_domain
    if llm.provider in _PROVIDER_DOMAINS:
        return _PROVIDER_DOMAINS[llm.provider]
    raise ProxyError(
        f"no direct API domain is known for provider {llm.provider!r}; "
        "set llm.direct_domain in the runtime manifest"
    )


def _validate_proxy_context(request: ProxyRequest) -> None:
    if request.plan.network_mode != "proxy" or request.manifest.network.mode != "proxy":
        raise ProxyError("Caddy lifecycle is valid only for proxy-mode runtimes")
    validate_runtime_plan_context(request.plan, request.manifest, request.paths)
    proxy = request.plan.container(SessionRole.PROXY)
    if proxy is None:
        raise ProxyError("proxy-mode runtime plan is missing the Caddy container")
    expected_networks = (request.internal_network, request.egress_network)
    if proxy.networks != expected_networks:
        raise ProxyError(
            "Caddy must attach to the internal and egress networks in that order"
        )
    if proxy.capabilities:
        raise ProxyError("Caddy must not receive Linux capabilities")
    _ = request.policy_path
    _ = request.domains


def _prepare_directory(request: ProxyRequest) -> None:
    lexical_session = request.paths.identity.session_dir(request.plan.runtime)
    lexical_dir = request.paths.identity.proxy_config_dir(request.plan.runtime)
    if lexical_session.is_symlink() or lexical_dir.is_symlink():
        raise ProxyError("generated proxy directories must not be symlinks")
    secure_dir = request.paths.session_artifact(request.plan.runtime, "proxy")
    if secure_dir != lexical_dir.resolve(strict=False):
        raise ProxyError("proxy configuration directory escaped the session")
    if lexical_dir.exists():
        if not lexical_dir.is_dir():
            raise ProxyError(f"proxy configuration path is not a directory: {lexical_dir}")
        shutil.rmtree(lexical_dir)
    lexical_dir.mkdir(parents=True, mode=0o700)


def _write_atomic(path: Path, text: str) -> None:
    if path.is_symlink():
        raise ProxyError(f"generated proxy file must not be a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _caddy_tmpfs_mounts() -> tuple[str, ...]:
    return (
        "--mount",
        "type=tmpfs,dst=/config,tmpfs-size=4194304,tmpfs-mode=0700,U=true",
        "--mount",
        "type=tmpfs,dst=/data,tmpfs-size=4194304,tmpfs-mode=0700,U=true",
    )


def _require_success(result: CommandResult, description: str) -> None:
    if result.returncode == 0:
        return
    detail = result.stderr.strip() or result.stdout.strip()
    suffix = f": {detail}" if detail else f" (Podman status {result.returncode})"
    raise ProxyLifecycleError(description + suffix)


def _print_policy(request: ProxyRequest, output: TextIO) -> None:
    output.write(f"  \033[2mProxy policy for {request.plan.runtime}:\033[0m\n")
    if request.domains:
        for domain in request.domains:
            output.write(f"    \033[2m{domain}\033[0m\n")
    else:
        output.write(
            "    \033[1;33m(none — this runtime can reach no external host)\033[0m\n"
        )
    if request.removed_domain:
        output.write("  \033[2mRemoved while brokered:\033[0m\n")
        output.write(f"    \033[2m{request.removed_domain}\033[0m\n")


def _parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("value must be true or false")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m asf.proxy")
    sub = parser.add_subparsers(dest="action", required=True)

    for action in ("start", "name"):
        command = sub.add_parser(action)
        command.add_argument("--root", required=True)
        command.add_argument("--runtime", required=True)
        if action == "start":
            command.add_argument("--access-logs", type=_parse_bool, default=True)

    image_files = sub.add_parser("write-image-files")
    image_files.add_argument("--directory", required=True)

    format_file = sub.add_parser("format-file")
    format_file.add_argument("--directory", required=True)
    format_file.add_argument("--image", required=True)

    image_info = sub.add_parser("image-info")
    image_info.add_argument(
        "--field",
        required=True,
        choices=("tag", "alpine", "builder", "runtime", "version", "plugin", "revision"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    namespace = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if namespace.action == "image-info":
            values = {
                "tag": caddy_image_tag(),
                "alpine": ALPINE_RUNTIME_IMAGE,
                "builder": CADDY_BUILDER_IMAGE,
                "runtime": CADDY_RUNTIME_IMAGE,
                "version": CADDY_VERSION,
                "plugin": CADDY_FORWARDPROXY,
                "revision": CADDY_IMAGE_REVISION,
            }
            print(values[namespace.field])
            return 0
        if namespace.action == "write-image-files":
            directory = Path(namespace.directory)
            if directory.is_symlink():
                raise ProxyError(f"Caddy directory must not be a symlink: {directory}")
            directory.mkdir(parents=True, exist_ok=True)
            _write_atomic(directory / "Containerfile", render_containerfile())
            return 0
        if namespace.action == "format-file":
            format_policy_file(namespace.directory, namespace.image)
            return 0

        request = load_request(
            namespace.root,
            namespace.runtime,
            access_logs=getattr(namespace, "access_logs", True),
        )
        if namespace.action == "name":
            print(request.container.name)
            return 0
        ProxyService().start(request)
        return 0
    except (ConfigurationError, InfrastructureError) as exc:
        print(f"\033[0;31m{exc}\033[0m", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
