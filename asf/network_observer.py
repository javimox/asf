"""Lifecycle for the optional routed TAP network observer."""

from __future__ import annotations

import hashlib
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TextIO

from .errors import InfrastructureError
from .network_activity import prepare_network_activity_log
from .observation_sessions import current_observation_session
from .paths import RepoPaths
from .podman import PodmanClient
from .runtime_plan import RuntimePlan, routed_broker_address
from .routed import routed_tap_addresses
from .session import SessionRole

__all__ = ["NetworkObserverError", "NetworkObserverService"]

_IMAGE_BASE = (
    "docker.io/library/alpine@sha256:"
    "d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
)
_IMAGE_REV = "v1"
_READY = "/tmp/asf-network-observer-ready"


class NetworkObserverError(InfrastructureError):
    """The requested TAP observer could not be started safely."""


@dataclass(slots=True)
class NetworkObserverService:
    podman: PodmanClient = field(default_factory=PodmanClient)
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)

    def start(
        self,
        paths: RepoPaths,
        plan: RuntimePlan,
        *,
        output: TextIO = sys.stdout,
    ) -> None:
        observer = plan.container(SessionRole.NETWORK_OBSERVER)
        gateway = plan.container(SessionRole.ROUTED_GATEWAY)
        if observer is None:
            return
        if gateway is None or plan.runtime_isolation != "microvm" or plan.network_mode != "routed":
            raise NetworkObserverError("network observer requires routed microVM")
        observation = current_observation_session(paths, plan.runtime)
        if observation is None:
            raise NetworkObserverError("network observer requires an observability session")

        log_path = prepare_network_activity_log(paths, plan.runtime)
        image = self._ensure_image(output=output)
        _, guest_ip = routed_tap_addresses(plan)
        output.write("  \033[0;34m→\033[0m Starting passive TAP network observer\n")
        argv = (
            str(self.podman.engine),
            "run",
            "-d",
            "--name",
            observer.name,
            "--network",
            f"container:{gateway.name}",
            "--label",
            plan.sandbox_label,
            "--label",
            "asf.role=network-observer",
            "--label",
            f"asf.agent={plan.runtime}",
            "--cap-drop=ALL",
            "--cap-add=NET_RAW",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=2m",
            "--pids-limit=16",
            "--memory=32m",
            "-e",
            "ASF_TAP_NAME=tap0",
            "-e",
            f"ASF_TAP_GUEST_IP={guest_ip}",
            "-e",
            f"ASF_RUNTIME={plan.runtime}",
            "-e",
            f"ASF_OBSERVATION_SESSION_ID={observation.session_id}",
            "-e",
            f"ASF_IGNORE_DESTINATION={routed_broker_address(plan) or ''}",
            "-e",
            "ASF_NETWORK_ACTIVITY_LOG=/asf/network-activity.jsonl",
            "-v",
            f"{log_path}:/asf/network-activity.jsonl:rw",
            image,
        )
        result = self.podman.observe(argv, timeout=60)
        if not result.succeeded:
            detail = result.stderr.strip() or result.stdout.strip()
            raise NetworkObserverError(
                "Could not start TAP network observer" + (f": {detail}" if detail else "")
            )
        self._wait_ready(observer.name)
        output.write("  \033[0;32m✓\033[0m Network observer ready (NET_RAW only)\n")

    def _wait_ready(self, container: str) -> None:
        for _ in range(20):
            result = self.podman.observe(
                (str(self.podman.engine), "exec", container, "test", "-f", _READY),
                timeout=5,
            )
            if result.succeeded:
                return
            inspection = self.podman.inspect_container(container, timeout=10)
            if not inspection.running:
                raise NetworkObserverError("TAP network observer exited during startup")
            self.sleep(0.1)
        raise NetworkObserverError("TAP network observer did not become ready")

    def _ensure_image(self, *, output: TextIO) -> str:
        source = Path(__file__).with_name("network_observer_runtime.py")
        code = source.read_bytes()
        material = _IMAGE_REV.encode() + b"|" + _IMAGE_BASE.encode() + b"|" + code
        fingerprint = hashlib.sha256(material).hexdigest()[:16]
        tag = f"asf-network-observer:{fingerprint}"
        exists = self.podman.observe(
            (str(self.podman.engine), "image", "exists", tag), timeout=30
        )
        if exists.succeeded:
            return tag
        if exists.returncode != 1:
            detail = exists.stderr.strip() or exists.stdout.strip()
            raise NetworkObserverError(
                "Could not inspect the network observer image"
                + (f": {detail}" if detail else "")
            )
        output.write("  \033[0;34m→\033[0m Building network observer image (first run only)\n")
        with tempfile.TemporaryDirectory(prefix="asf-network-observer-") as directory:
            root = Path(directory)
            (root / "network_observer.py").write_bytes(code)
            (root / "Containerfile").write_text(
                f"FROM {_IMAGE_BASE}\n"
                "RUN apk add --no-cache python3\n"
                "COPY network_observer.py /usr/local/lib/asf-network-observer.py\n"
                "ENTRYPOINT [\"python3\", \"/usr/local/lib/asf-network-observer.py\"]\n",
                encoding="utf-8",
            )
            built = self.podman.observe(
                (str(self.podman.engine), "build", "-q", "-t", tag, directory),
                timeout=900,
            )
        if not built.succeeded:
            raise NetworkObserverError("Could not build the network observer image")
        return tag
