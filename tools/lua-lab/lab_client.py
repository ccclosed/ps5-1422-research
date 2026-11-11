#!/usr/bin/env python3
"""Standalone client for the mock loader: send the three frame kinds, decode replies.

This is a clean-room reimplementation of the decoder that upstream
`payloads/send_lua.py` uses, kept dependency-free so the lab works without the
research checkout.  It verifies:

  1. payload frame       <u64 LE size><lua source>      -> text banner + crash frame
  2. command frame       <u64 LE 0xFFFFFFFF><u8 cmd>    -> "command: ..." reply
  3. crash frame decode  <0x13371337><signal,addr><mcontext> -> registers printed

Exit code 0 only when every expectation holds.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

COMMAND_MAGIC = 0xFFFFFFFF
CRASH_MAGIC = 0x13371337
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


class Failure(AssertionError):
    pass


def recv_until_idle(sock: socket.socket, idle: float = 0.5, limit: float = 5.0) -> bytes:
    """Read until the peer goes idle for `idle` seconds (the loader streams output)."""
    sock.settimeout(idle)
    data, start = b"", time.time()
    while time.time() - start < limit:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except ConnectionResetError:
            # the loader closes without draining a rejected frame; nothing left to read
            break
        if not chunk:
            break
        data += chunk
    return data


def parse_response(buf: bytes) -> dict:
    """Split a loader reply into text, crash records and leftovers."""
    crashes, texts, rest = [], [], buf
    magic = struct.pack("<Q", CRASH_MAGIC)
    while True:
        idx = rest.find(magic)
        if idx < 0:
            break
        start = idx + len(magic)                      # body starts after the 0x13371337 magic
        end = start + SIGNAL_LEN + MCONTEXT_LEN
        if len(rest) < end:
            break
        texts.append(rest[:idx])                      # streamed console text before the dump
        crashes.append(decode_crash(rest[start:end]))
        rest = rest[end:]
    texts.append(rest)                                # trailing text after the last dump
    text = b"".join(texts)
    return {"text": text, "crashes": crashes}


def decode_crash(frame: bytes) -> dict:
    """Decode <signal,addr><mcontext> (the 0x13371337 magic is already consumed)."""
    signal_no, fault_addr = struct.unpack("<QQ", frame[:SIGNAL_LEN])
    mctx = frame[SIGNAL_LEN: SIGNAL_LEN + MCONTEXT_LEN]
    values = struct.unpack(MCONTEXT_FMT, mctx[:struct.calcsize(MCONTEXT_FMT)])
    regs = dict(zip(REG_NAMES, values))
    return {
        "signal": SIGNALS.get(signal_no, f"signal {signal_no}"),
        "addr": fault_addr,
        "regs": regs,
    }


def send_payload(host: str, port: int, source: bytes) -> dict:
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(struct.pack("<Q", len(source)) + source)
        return parse_response(recv_until_idle(sock))


def send_command(host: str, port: int, cmd: int) -> str:
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(struct.pack("<Q", COMMAND_MAGIC) + bytes([cmd]))
        return recv_until_idle(sock).decode("latin-1").strip()


def run_checks(host: str, port: int) -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []

    # --- 1. payload frame + crash-frame decode -------------------------------
    src = b'print("hello from lua-lab")\n'
    resp = send_payload(host, port, src)
    text = resp["text"].decode("latin-1").strip()
    ok_text = "hello from fake loader" in text
    results.append(("payload frame: 8-byte LE size + Lua source echoed",
                    ok_text, f"text={text!r}"))

    if resp["crashes"]:
        crash = resp["crashes"][0]
        ok_crash = crash["signal"] == "SIGSEGV" and crash["addr"] == 0xDEADBEEF
        regs = crash["regs"]
        results.append(("crash frame 0x13371337 decoded (signal + fault address)",
                        ok_crash,
                        f"{crash['signal']} at 0x{crash['addr']:x}; "
                        f"rip=0x{regs['rip']:x} rsp=0x{regs['rsp']:x} rdi=0x{regs['rdi']:x}"))
        results.append(("mcontext register block parsed (29 fields)",
                        len(regs) == 29 and regs["cs"] == 0x3B,
                        f"fields={len(regs)} cs=0x{regs['cs']:x} trapno={regs['trapno']}"))
    else:
        results.append(("crash frame 0x13371337 decoded", False, "no crash frame in reply"))

    # --- 2. command frames ---------------------------------------------------
    for cmd, expected in ((1, "Enabled"), (0, "Disabled")):
        reply = send_command(host, port, cmd)
        results.append((f"command frame 0xFFFFFFFF + cmd={cmd} ", expected in reply, f"reply={reply!r}"))

    # --- 3. oversized frame is rejected, not executed ------------------------
    # The real loader rejects on the 8-byte header alone (`if size >= maxsize`),
    # so only the header is sent; a body would stay unread and turn close() into RST.
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(struct.pack("<Q", 500 * 1024))
        reply = recv_until_idle(sock).decode("latin-1").strip()
    results.append(("oversized frame rejected (maxsize 500 KiB, strict <)",
                    "exceed maxsize" in reply, f"reply={reply!r}"))
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="Send test frames to the mock loader and decode replies")
    ap.add_argument("host", nargs="?", default="127.0.0.1")
    ap.add_argument("port", nargs="?", type=int, default=9026)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    print(f"# client -> {args.host}:{args.port}")
    results = run_checks(args.host, args.port)
    failed = 0
    for name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"[{status}] {name} :: {detail}")
    print(f"# client checks: {len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())