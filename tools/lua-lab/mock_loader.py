#!/usr/bin/env python3
"""Mock of the PS5 remote-Lua-loader (TCP 9026) for PC-side protocol testing.

Implements the wire protocol of `n0llptr/remote_lua_loader` (the loader used by
the Hamidashi Creative Demo save exploit), so that senders / decoders can be
tested without a console:

    frame 1 (Lua source):  <u64 LE size><size bytes of Lua source>
    frame 2 (command):     <u64 LE 0xFFFFFFFF><u8 command>      0=disable 1=enable signal handler
    crash frame (loader->host, after the text reply):
                           <u64 LE 0x13371337><u64 signal><u64 fault_addr><0x100 bytes mcontext>

The mock never executes Lua.  It reads the frame, validates the framing and
answers with a text banner plus an optional synthetic crash frame, which is
exactly what the real loader emits when a probe segfaults.

Usage:
    python3 mock_loader.py                 # serve 127.0.0.1:9026 until Ctrl-C
    python3 mock_loader.py --port 0        # pick a free port, print it
    python3 mock_loader.py --once          # serve a single connection and exit
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

# Protocol constants, taken from the published loader source
# (savedata/main.lua: command_magic = 0xffffffff, maxsize = 500*1024,
#  signal handler writes 0x13371337 + <QQ> + 0x100-byte mcontext).
COMMAND_MAGIC = 0xFFFFFFFF
CRASH_MAGIC = 0x13371337
MAXSIZE = 500 * 1024
MCONTEXT_LEN = 0x100
SIGNAL_LEN = 16

# struct mcontext_t as decoded by upstream payloads/send_lua.py
MCONTEXT_FMT = "<QQQQQQQQQQQQQQQQIHHQIHHQQQQQQ"
REG_NAMES = [
    "onstack", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax",
    "rbx", "rbp", "r10", "r11", "r12", "r13", "r14", "r15",
    "trapno", "fs", "gs", "addr", "flags", "es", "ds", "err",
    "rip", "cs", "rflags", "rsp", "ss",
]
SIGNAL_NAMES = {4: "SIGILL", 10: "SIGBUS", 11: "SIGSEGV"}


def build_crash_frame(signal: int = 11, addr: int = 0xDEADBEEF,
                      rip: int = 0x0000000800012345,
                      rsp: int = 0x00007FFF0000A000,
                      rdi: int = 0x1122334455667788) -> bytes:
    """Build a synthetic 0x13371337 crash frame (magic + signal/addr + mcontext)."""
    regs = {name: 0 for name in REG_NAMES}
    regs.update(trapno=14, addr=addr, rip=rip, rsp=rsp, rdi=rdi,
                rflags=0x10246, cs=0x3B, ss=0x3B)
    values = [regs[name] for name in REG_NAMES[:16]]
    mcontext = struct.pack(
        MCONTEXT_FMT,
        *values, regs["trapno"], regs["fs"], regs["gs"], regs["addr"],
        regs["flags"], regs["es"], regs["ds"], regs["err"],
        regs["rip"], regs["cs"], regs["rflags"], regs["rsp"], regs["ss"],
    )
    mcontext += b"\x00" * (MCONTEXT_LEN - len(mcontext))
    assert len(mcontext) == MCONTEXT_LEN
    return struct.pack("<Q", CRASH_MAGIC) + struct.pack("<QQ", signal, addr) + mcontext


@dataclass
class MockStats:
    payload_frames: int = 0
    command_frames: int = 0
    oversized_frames: int = 0
    bad_magic_cmds: int = 0
    payload_sizes: list[int] = field(default_factory=list)

    def as_line(self) -> str:
        return (f"payload_frames={self.payload_frames} command_frames={self.command_frames} "
                f"oversized_frames={self.oversized_frames} sizes={self.payload_sizes}")


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            raise ConnectionError(f"peer closed after {len(buf)}/{size} bytes")
        buf += chunk
    return buf


def handle_connection(conn: socket.socket, stats: MockStats, log,
                      crash: bool = True, reply: str = "[mock-loader] hello from fake loader\n") -> None:
    """Serve one connection: one frame per connection, like the real loader."""
    head = _recv_exact(conn, 8)
    size = struct.unpack("<Q", head)[0]

    if size == COMMAND_MAGIC:
        cmd = _recv_exact(conn, 1)[0]
        stats.command_frames += 1
        if cmd == 0:
            msg = "command: Disabled signal handler"
        elif cmd == 1:
            msg = "command: Enabled signal handler"
        else:
            stats.bad_magic_cmds += 1
            msg = f"error: invalid command {cmd}\n"
        log(f"COMMAND cmd={cmd}")
        conn.sendall(msg.encode())
        return

    if size == 0 or size >= MAXSIZE:
        stats.oversized_frames += 1
        msg = f"error: lua code exceed maxsize (given {size} maxsize {MAXSIZE})\n"
        log(f"OVERSIZED size={size}")
        conn.sendall(msg.encode())
        try:
            conn.shutdown(socket.SHUT_WR)          # FIN first ...
            conn.settimeout(0.2)
            while conn.recv(65536):                # ... then drain, so close() is not RST
                pass
        except (OSError, socket.timeout):
            pass
        return

    payload = _recv_exact(conn, size)
    stats.payload_frames += 1
    stats.payload_sizes.append(size)
    log(f"PAYLOAD size={size} first40={payload[:40]!r}")
    conn.sendall(reply.encode())
    if crash:
        conn.sendall(build_crash_frame())
        log("CRASH sent 0x13371337 SIGSEGV addr=0xdeadbeef")


class MockLoader:
    """Threaded mock loader; usable both standalone and from a test process."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9026,
                 crash: bool = True, verbose: bool = True):
        self.host, self.port = host, port
        self.crash = crash
        self.verbose = verbose
        self.stats = MockStats()
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.port_actual: int | None = None
        self.lines: list[str] = []

    def log(self, line: str) -> None:
        stamped = f"[mock] {line}"
        self.lines.append(stamped)
        if self.verbose:
            print(stamped, file=sys.stderr, flush=True)

    def start(self) -> "MockLoader":
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.port_actual = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        self.log(f"listening {self.host}:{self.port_actual}")
        return self

    def _serve(self) -> None:
        assert self.sock is not None
        while not self._stop.is_set():
            try:
                conn, peer = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(5.0)
                try:
                    handle_connection(conn, self.stats, self.log, crash=self.crash)
                except (ConnectionError, socket.timeout) as exc:
                    self.log(f"connection error: {exc}")

    def stop(self) -> None:
        self._stop.set()
        if self.thread:
            self.thread.join(timeout=2)
        if self.sock:
            self.sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Mock PS5 Lua loader (TCP 9026)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9026)
    ap.add_argument("--no-crash", action="store_true", help="do not emit the synthetic crash frame")
    ap.add_argument("--once", action="store_true", help="exit after the first connection")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    srv = MockLoader(args.host, args.port, crash=not args.no_crash, verbose=not args.quiet).start()
    print(f"READY {srv.host}:{srv.port_actual}", flush=True)
    try:
        if args.once:
            while srv.stats.payload_frames + srv.stats.command_frames == 0:
                srv.thread.join(timeout=0.1) if srv.thread else None
        else:
            while True:
                srv.thread.join(timeout=0.5) if srv.thread else None
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
    print(f"STATS {srv.stats.as_line()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())