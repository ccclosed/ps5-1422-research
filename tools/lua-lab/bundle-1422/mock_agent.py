#!/usr/bin/env python3
"""bundle-1422 / mock_agent.py — ПК-заглушка агента в игре (тот же line-протокол).

Играет роль `agent_lua.lua` / `agent_yarpe.py`: подключается к bridge_server.py, шлёт
`HELLO mock 1.0` и отвечает на строки `R/W/A/?/.`, держа память в словаре. Нужен, чтобы
проверять мост и JS-клиент БЕЗ консоли.

    python3 mock_agent.py --port 9138
"""

from __future__ import annotations

import argparse
import socket
import threading

CHUNK = 0x1000


class MockMemory:
    def __init__(self):
        self.pages: dict[int, bytearray] = {}
        self.next_alloc = 0x10000000

    def _page(self, addr: int) -> tuple[bytearray, int]:
        base = addr & ~(CHUNK - 1)
        page = self.pages.get(base)
        if page is None:
            page = bytearray(CHUNK)
            self.pages[base] = page
        return page, addr - base

    def read(self, addr: int, length: int) -> bytes:
        if addr < 0x1000:
            raise ValueError("unmapped address 0x%x (mock maps >= 0x1000)" % addr)
        out = bytearray()
        cur, remaining = addr, length
        while remaining > 0:
            page, off = self._page(cur)
            take = min(remaining, CHUNK - off)
            out += page[off:off + take]
            cur += take
            remaining -= take
        return bytes(out)

    def write(self, addr: int, data: bytes) -> None:
        cur, idx = addr, 0
        while idx < len(data):
            page, off = self._page(cur)
            take = min(len(data) - idx, CHUNK - off)
            page[off:off + take] = data[idx:idx + take]
            cur += take
            idx += take

    def alloc(self, size: int) -> int:
        addr = self.next_alloc
        self.next_alloc += (size + CHUNK - 1) & ~(CHUNK - 1)
        self.write(addr, b"\x00" * size)
        return addr


class MockAgent:
    def __init__(self, port: int, host: str = "127.0.0.1", verbose: bool = True,
                 entry: str = "mock", memory: MockMemory | None = None):
        self.host, self.port = host, port
        self.verbose = verbose
        self.entry = entry
        self.memory = memory or MockMemory()
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.served = 0

    def log(self, line: str) -> None:
        if self.verbose:
            print("[mock-agent] " + line, flush=True)

    def start(self, timeout: float = 5.0) -> "MockAgent":
        for _ in range(int(timeout * 20)):
            try:
                self.sock = socket.create_connection((self.host, self.port), timeout=1.0)
                break
            except OSError:
                self._stop.wait(0.05)
        if self.sock is None:
            raise RuntimeError("cannot connect to bridge agent port %d" % self.port)
        self.sock.sendall(("HELLO %s 1.0\n" % self.entry).encode())
        self.log("hello sent")
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def _serve(self) -> None:
        assert self.sock is not None
        buf = b""
        while not self._stop.is_set():
            try:
                chunk = self.sock.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", "replace").strip()
                if not text:
                    continue
                try:
                    reply = self.handle(text)
                except Exception as exc:            # noqa: BLE001 - always answer
                    reply = "ERR " + str(exc)
                self.sock.sendall((reply + "\n").encode())

    def handle(self, text: str) -> str:
        self.served += 1
        op, _, rest = text.partition(" ")
        if op == "?":
            return "RDY 1 mock agent, memory dict"
        if op == ".":
            self._stop.set()
            return "OK"
        if op == "R":
            addr_s, _, len_s = rest.partition(" ")
            return "V " + self.memory.read(int(addr_s, 16), int(len_s)).hex()
        if op == "W":
            addr_s, _, hex_s = rest.partition(" ")
            self.memory.write(int(addr_s, 16), bytes.fromhex(hex_s))
            return "OK"
        if op == "A":
            return "V 0x%x" % self.memory.alloc(int(rest))
        return "ERR unknown op %r" % op

    def stop(self) -> None:
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Mock console agent for the bundle-1422 bridge")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9138)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    agent = MockAgent(args.port, args.host, verbose=not args.quiet).start()
    print("READY mock-agent -> %s:%d" % (args.host, args.port), flush=True)
    try:
        while not agent._stop.is_set():
            agent._stop.wait(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())