"""Runtime entrypoint for the routed TAP network observer container."""

from __future__ import annotations

import json
import os
import socket
import struct
import time
from datetime import datetime, timezone

ETH_P_IP = 0x0800
TCP = 6
UDP = 17
ICMP = 1
MAX_LOG_BYTES = 64 * 1024 * 1024


def parse_frame(
    frame: bytes, guest_ip: str, ignored_destination: str = ""
) -> dict[str, object] | None:
    """Return metadata for one guest-originated attempt, or ``None``."""

    if len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != ETH_P_IP:
        return None
    ip = frame[14:]
    version_ihl = ip[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    # Non-first IPv4 fragments do not contain the transport header we need to
    # classify a connection attempt. Ignore them rather than misreading bytes.
    if struct.unpack("!H", ip[6:8])[0] & 0x1FFF:
        return None
    source = socket.inet_ntoa(ip[12:16])
    if source != guest_ip:
        return None
    destination = socket.inet_ntoa(ip[16:20])
    if ignored_destination and destination == ignored_destination:
        return None
    protocol = ip[9]
    transport = ip[ihl:]

    if protocol == TCP and len(transport) >= 20:
        source_port, destination_port = struct.unpack("!HH", transport[:4])
        flags = transport[13]
        if flags & 0x02 and not flags & 0x10:
            return {
                "source": source,
                "destination": destination,
                "protocol": "tcp",
                "source_port": source_port,
                "destination_port": destination_port,
            }
    elif protocol == UDP and len(transport) >= 8:
        source_port, destination_port = struct.unpack("!HH", transport[:4])
        return {
            "source": source,
            "destination": destination,
            "protocol": "udp",
            "source_port": source_port,
            "destination_port": destination_port,
        }
    elif protocol == ICMP and len(transport) >= 2 and transport[0] == 8:
        return {
            "source": source,
            "destination": destination,
            "protocol": "icmp_echo",
            "icmp_type": 8,
        }
    return None


def _line(payload: dict[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def _bounded_write(
    output,
    line: str,
    truncation_line: str,
    written: int,
) -> tuple[int, bool]:
    size = len(line.encode("utf-8"))
    if written + size > MAX_LOG_BYTES:
        truncated_size = len(truncation_line.encode("utf-8"))
        if written + truncated_size <= MAX_LOG_BYTES:
            output.write(truncation_line)
            written += truncated_size
        return written, True
    output.write(line)
    return written + size, False


def main() -> None:
    interface = os.environ.get("ASF_TAP_NAME", "tap0")
    guest_ip = os.environ["ASF_TAP_GUEST_IP"]
    path = os.environ["ASF_NETWORK_ACTIVITY_LOG"]
    ignored_destination = os.environ.get("ASF_IGNORE_DESTINATION", "")
    base: dict[str, object] = {
        "runtime": os.environ["ASF_RUNTIME"],
        "session_id": os.environ["ASF_OBSERVATION_SESSION_ID"],
    }

    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    capture.bind((interface, 0))
    with open("/tmp/asf-network-observer-ready", "w", encoding="ascii") as ready:
        ready.write("ready\n")

    written = os.path.getsize(path)
    with open(path, "a", encoding="utf-8", buffering=1) as output:
        while True:
            record = parse_frame(
                capture.recv(65535), guest_ip, ignored_destination
            )
            if record is None:
                continue
            line = _line(
                {
                    **base,
                    **record,
                    "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "event": "network_attempt",
                }
            )
            truncated = _line(
                {
                    **base,
                    "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "event": "network_activity_truncated",
                    "limit_bytes": MAX_LOG_BYTES,
                }
            )
            written, limit_reached = _bounded_write(
                output, line, truncated, written
            )
            if limit_reached:
                capture.close()
                while True:
                    time.sleep(3600)


if __name__ == "__main__":
    main()
