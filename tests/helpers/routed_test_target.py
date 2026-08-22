#!/usr/bin/env python3
"""Run TCP and UDP listeners for ASF routed-mode verification."""
from __future__ import annotations

import argparse
import signal
import socketserver
import threading


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(b"ASF routed TCP test target\n")


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(b"ASF routed UDP test target: " + data, self.client_address)


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def _port(parser: argparse.ArgumentParser, name: str, value: int) -> None:
    if not 1 <= value <= 65535:
        parser.error(f"{name} must be between 1 and 65535")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--allowed-port", type=int, default=18080)
    parser.add_argument("--blocked-port", type=int, default=19999)
    parser.add_argument("--allowed-udp-port", type=int, default=18161)
    parser.add_argument("--blocked-udp-port", type=int, default=19998)
    args = parser.parse_args()

    ports = {
        "--allowed-port": args.allowed_port,
        "--blocked-port": args.blocked_port,
        "--allowed-udp-port": args.allowed_udp_port,
        "--blocked-udp-port": args.blocked_udp_port,
    }
    for name, value in ports.items():
        _port(parser, name, value)
    if len(set(ports.values())) != len(ports):
        parser.error("test ports must be different")

    servers = [
        TCPServer((args.bind, args.allowed_port), TCPHandler),
        TCPServer((args.bind, args.blocked_port), TCPHandler),
        UDPServer((args.bind, args.allowed_udp_port), UDPHandler),
        UDPServer((args.bind, args.blocked_udp_port), UDPHandler),
    ]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()

    print(
        "ASF routed target listening on "
        f"{args.bind}:tcp/{args.allowed_port}, tcp/{args.blocked_port}, "
        f"udp/{args.allowed_udp_port}, udp/{args.blocked_udp_port}",
        flush=True,
    )

    stopped = threading.Event()

    def stop(*_: object) -> None:
        stopped.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, stop)
    stopped.wait()

    for server in servers:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
