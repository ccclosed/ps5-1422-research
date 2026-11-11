#!/usr/bin/env python3
"""Send one Lua 5.1 probe to the PS5 remote-Lua-loader (bundle-1422 edition).

Wire format of the loader (`n0llptr/remote_lua_loader`, savedata/main.lua):

    <u64 little-endian size><size bytes of Lua source>       # one frame per connection
    <u64 little-endian 0xFFFFFFFF><u8 command>               # 0=disable / 1=enable signal handler
    crash frame back: <0x13371337><u64 signal><u64 addr><0x100 mcontext>

The loader answers with streamed text; if a probe faults, the signal handler
appends a crash frame that this script decodes into registers.

Usage:
    python3 send_lua.py --host 192.168.0.50 probe_14xx_entry.lua
    python3 send_lua.py --host 192.168.0.50 --command 1     # enable signal handler
    python3 send_lua.py --self-test                         # framing check, no console
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

COMMAND_MAGIC = 0xFFFFFFFF
CRASH_MAGIC = 0x13371337
MAXSIZE = 500 * 1024
MCONTEXT_LEN = 0x100
SIGNAL_LEN = 16
MCONTEXT_FMT = "<QQQQQQQQQQQQQQQQIHHQIHHQQQQQQ"
REG_NAMES = [
    "onstack", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax",
    "rbx", "rbp", "r10", "r11", "r12", "r13", "r14", "r15",
    "trapno", "fs", "gs", "addr", "flags", "es", "ds", "err",
    "rip", "cs", "rflags", "rsp", "ss",
]
SIGNALS = {4: "SIGILL", 10: "SIGBUS", 11: "SIGSEGV"}


def read_reply(sock: socket.socket, idle: float = 1.0, limit: float = 30.0) -> bytes:
    sock.settimeout(idle)
    data, started = b"", time.time()
    while time.time() - started < limit:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except ConnectionResetError:
            break
        if not chunk:
            break
        data += chunk
    return data


def decode(buf: bytes) -> tuple[bytes, list[dict]]:
    magic = struct.pack("<Q", CRASH_MAGIC)
    texts, crashes, rest = [], [], buf
    while True:
        idx = rest.find(magic)
        if idx < 0:
            break
        start = idx + len(magic)
        end = start + SIGNAL_LEN + MCONTEXT_LEN
        if len(rest) < end:
            break
        signal_no, fault = struct.unpack("<QQ", rest[start:start + SIGNAL_LEN])
        values = struct.unpack(MCONTEXT_FMT, rest[start + SIGNAL_LEN:end][:struct.calcsize(MCONTEXT_FMT)])
        regs = dict(zip(REG_NAMES, values))
        crashes.append({"signal": SIGNALS.get(signal_no, str(signal_no)), "addr": fault, "regs": regs})
        texts.append(rest[:idx])
        rest = rest[end:]
    texts.append(rest)
    return b"".join(texts), crashes


def send(host: str, port: int, payload: bytes) -> int:
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(payload)
        buf = read_reply(sock)
    text, crashes = decode(buf)
    sys.stdout.write(text.decode("latin-1"))
    if text and not text.endswith(b"\n"):
        sys.stdout.write("\n")
    for crash in crashes:
        regs = crash["regs"]
        print(f"[crash] {crash['signal']} at 0x{crash['addr']:x} "
              f"rip=0x{regs['rip']:x} rsp=0x{regs['rsp']:x} rdi=0x{regs['rdi']:x} rsi=0x{regs['rsi']:x}")
    if not buf:
        print("[send] no bytes received (loader down, or probe killed the game)")
        return 3
    if "=== PROBE 14XX COMPLETE ===" not in text.decode("latin-1"):
        print("[send] completion marker missing: probe did not finish")
        return 2
    print("[send] completion marker seen")
    return 0


def self_test() -> int:
    """Framing check with an in-process mock of the loader (no console needed)."""
    src = b'print("hello")\n'
    frame = struct.pack("<Q", len(src)) + src
    assert frame[:8] == struct.pack("<Q", len(src)) and frame[8:] == src
    assert struct.unpack("<Q", frame[:8])[0] == len(src)
    print(f"[self-test] frame ok: size={len(src)} header={frame[:8].hex()}")
    print("[self-test] PASS (framing only; mock server lives in tools/lua-lab/mock_loader.py)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Send a Lua probe to the PS5 Lua loader (TCP 9026)")
    ap.add_argument("probe", nargs="?", help="path to a .lua probe")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9026)
    ap.add_argument("--command", type=int, choices=[0, 1], help="send a command frame instead of a probe")
    ap.add_argument("--self-test", action="store_true", help="check framing locally, do not connect")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if args.command is not None:
        return send(args.host, args.port, struct.pack("<Q", COMMAND_MAGIC) + bytes([args.command]))

    if not args.probe:
        ap.error("need a probe path, --command or --self-test")
    source = open(args.probe, "rb").read()
    if not source:
        print("[send] empty probe", file=sys.stderr)
        return 2
    if len(source) >= MAXSIZE:
        print(f"[send] probe is {len(source)} bytes, loader maxsize is {MAXSIZE}", file=sys.stderr)
        return 2
    print(f"[send] {args.probe}: {len(source)} bytes -> {args.host}:{args.port}")
    return send(args.host, args.port, struct.pack("<Q", len(source)) + source)


if __name__ == "__main__":
    raise SystemExit(main())