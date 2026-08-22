"""Create Podman networks exactly as described by a runtime plan."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, TextIO

from .errors import AsfError, InfrastructureError
from .podman import PodmanClient
from .runtime_plan import NetworkPlan, NetworkRole, RuntimePlan

__all__ = [
    "CREATE_ATTEMPTS",
    "CREATE_RETRY_DELAY",
    "NetworkCreationError",
    "NetworkService",
    "create_argv",
    "remove_argv",
]

CREATE_ATTEMPTS = 3
CREATE_RETRY_DELAY = 0.5
_RACE_MARKERS = ("already exists", "is being used", "in use")

_BLUE = "\033[0;34m"
_GREEN = "\033[0;32m"
_DIM = "\033[2m"
_RESET = "\033[0m"


class NetworkCreationError(InfrastructureError):
    """A planned session network could not be created safely."""


def create_argv(
    plan: RuntimePlan,
    network: NetworkPlan,
    *,
    engine: str = "podman",
) -> tuple[str, ...]:
    """Return the fixed argv for one planned network."""

    if plan.network_mode not in {"proxy", "isolated", "routed"}:
        raise NetworkCreationError(f"unsupported network mode: {plan.network_mode}")
    argv: list[str] = [
        engine,
        "network",
        "create",
        "--label",
        plan.sandbox_label,
    ]
    if network.internal:
        argv.append("--internal")
    if network.no_default_route:
        argv.extend(("--opt", "no_default_route=true"))
    if network.subnet is not None:
        assert network.gateway is not None
        argv.extend(
            ("--subnet", str(network.subnet), "--gateway", str(network.gateway))
        )
    for route in network.routes:
        argv.extend(("--route", f"{route.destination},{route.gateway}"))
    argv.append(network.name)
    return tuple(argv)


def remove_argv(name: str, *, engine: str = "podman") -> tuple[str, ...]:
    """Return the idempotent removal argv used before network creation."""

    return (engine, "network", "rm", "-f", name)


@dataclass(frozen=True, slots=True)
class NetworkService:
    """Create exactly the networks described by a runtime plan."""

    podman: PodmanClient
    sleeper: Callable[[float], None] = field(
        default=time.sleep,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.podman, PodmanClient):
            raise TypeError("podman must be a PodmanClient")
        if not callable(self.sleeper):
            raise TypeError("sleeper must be callable")

    def create(self, plan: RuntimePlan, *, output: TextIO) -> None:
        if plan.network_mode not in {"proxy", "isolated", "routed"}:
            raise NetworkCreationError(
                f"Python network creation does not support {plan.network_mode!r}"
            )
        output.write(f"  {_BLUE}→{_RESET} Creating session networks\n")
        started = time.monotonic()
        for network in plan.networks:
            self._create_one(plan, network)

        internal = plan.network(NetworkRole.INTERNAL)
        if internal is None:
            raise NetworkCreationError("runtime plan has no internal network")
        if plan.network_mode == "routed":
            scan = plan.network(NetworkRole.SCAN)
            if scan is None:
                raise NetworkCreationError("routed plan has no scan network")
            runtime_address = next(
                (str(item.address) for item in plan.runtime_container.attachments
                 if item.network == scan.name and item.address is not None),
                "unknown",
            )
            output.write(
                f"  {_GREEN}✓{_RESET} Routed networks ready "
                f"{_DIM}(runtime: {runtime_address}; "
                f"{time.monotonic() - started:.1f}s){_RESET}\n"
            )
        elif plan.network_mode == "isolated":
            output.write(
                f"  {_GREEN}✓{_RESET} Networks ready "
                f"{_DIM}(isolated: {internal.name}, no egress network; "
                f"{time.monotonic() - started:.1f}s){_RESET}\n"
            )
        else:
            output.write(
                f"  {_GREEN}✓{_RESET} Networks ready "
                f"{_DIM}(agent is on {internal.name} only; "
                f"{time.monotonic() - started:.1f}s){_RESET}\n"
            )

    def _create_one(self, plan: RuntimePlan, network: NetworkPlan) -> None:
        engine = str(self.podman.engine)
        last_result = None
        for attempt in range(1, CREATE_ATTEMPTS + 1):
            try:
                # The common result is "not found", which is the desired state.
                self.podman.observe(
                    remove_argv(network.name, engine=engine),
                    timeout=30,
                )
                result = self.podman.observe(
                    create_argv(plan, network, engine=engine),
                    timeout=60,
                )
            except AsfError as exc:
                raise NetworkCreationError(
                    f"Could not create network {network.name}: {exc}"
                ) from exc
            if result.succeeded:
                return
            last_result = result
            if attempt == CREATE_ATTEMPTS or not _is_removal_race(result):
                break
            self.sleeper(CREATE_RETRY_DELAY)

        assert last_result is not None
        detail = _last_line(last_result.stderr or last_result.stdout)
        suffix = f": {detail}" if detail else ""
        raise NetworkCreationError(
            f"Could not create network {network.name} "
            f"(Podman status {last_result.returncode}){suffix}"
        )


def _is_removal_race(result) -> bool:
    text = f"{result.stdout}\n{result.stderr}".lower()
    return any(marker in text for marker in _RACE_MARKERS)


def _last_line(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""
