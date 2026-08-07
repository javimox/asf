#!/usr/bin/env python3
"""Run two TCP listeners for ASF routed-mode verification."""
from __future__ import annotations

import argparse
import signal
import socketserver
import threading


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(b"ASF routed test target\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--allowed-port", type=int, default=18080)
    parser.add_argument("--blocked-port", type=int, default=19999)
    args = parser.parse_args()
    if not 1 <= args.allowed_port <= 65535:
        parser.error("--allowed-port must be between 1 and 65535")
    if not 1 <= args.blocked_port <= 65535:
        parser.error("--blocked-port must be between 1 and 65535")
    if args.allowed_port == args.blocked_port:
        parser.error("the two ports must differ")

    servers = [
        Server((args.bind, args.allowed_port), Handler),
        Server((args.bind, args.blocked_port), Handler),
    ]
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads:
        thread.start()

    print(f"ASF routed target listening on {args.bind}:{args.allowed_port} and {args.blocked_port}", flush=True)
    stopped = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopped.set())
    stopped.wait()
    for server in servers:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
