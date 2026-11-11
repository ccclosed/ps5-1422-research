#!/usr/bin/env python3
"""End-to-end self-test: start the mock loader, send frames, decode the answer.

Starts `mock_loader.MockLoader` on an ephemeral port (default 127.0.0.1:9026 when
free, else a free port), runs `lab_client.run_checks` against it, prints a
per-check summary, and exits non-zero on any failure.

    python3 protocol_selftest.py            # ephemeral/auto port
    python3 protocol_selftest.py --port 9026
"""

from __future__ import annotations

import argparse
import socket
import sys

import lab_client
import mock_loader


def pick_port(preferred: int) -> int:
    """Return `preferred` if it can be bound, else an OS-assigned free port."""
    for candidate in (preferred, 0):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", candidate))
            return s.getsockname()[1]
        except OSError:
            continue
        finally:
            s.close()
    raise SystemExit("cannot bind any port")


def main() -> int:
    ap = argparse.ArgumentParser(description="Mock-loader protocol self-test")
    ap.add_argument("--port", type=int, default=9026)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    port = pick_port(args.port)
    srv = mock_loader.MockLoader("127.0.0.1", port, crash=True, verbose=not args.quiet).start()
    print(f"# protocol self-test: mock loader on 127.0.0.1:{srv.port_actual}")
    try:
        results = lab_client.run_checks("127.0.0.1", srv.port_actual)
    finally:
        srv.stop()

    failed = 0
    for name, ok, detail in results:
        if not ok:
            failed += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")

    print(f"# mock stats: {srv.stats.as_line()}")
    print(f"# protocol checks: {len(results) - failed}/{len(results)} passed")
    if failed:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())