#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bundle-1422 / kernel-runner.py — «JS-цепочка ↔ Python-примитив» через бинарный TCP.

Формат кадра (little-endian), как заказано: 1 байт команда + 8 байт адрес + 8 байт длина/данные,
дальше — данные для записи. Ответ зеркальный: 1 байт статус (0=OK, 1=ERR) + payload.

    0x01 READ      [addr u64][len u64]                 -> [0][data:len]
    0x02 WRITE     [addr u64][len u64][data:len]       -> [0]
    0x03 MALLOC    [size u64][align u64]               -> [0][addr u64]
    0x04 SYSCALL   [num u64][argc u8][args: u64*argc]  -> [0][ret i64]
    0x05 READY                                         -> [0][1]
    0x06 REASON                                        -> [0][ascii...]
    0x07 PING                                          -> [0]["PONG"]

Режимы:
  --mock                примитив на MockBackend (ПК, без консоли)          [тестируется]
  --in-game --port N    слушать ВНУТРИ YARPE (Python 2.7 в игре), p=P()   [консоль]
  --relay --agent H:P   ПК-релей: бинарный кадр -> line-протокол агента    [ПК]
  --selftest            20 операций через реальный TCP на mock-примитиве   [ПК]

Зачем релей: если JS-часть работает на ПК/в Node, она говорит с нами бинарным протоколом,
а мы транслируем операции в тот же line-протокол, что понимает `agent_lua.lua` / `agent_yarpe.py`
(см. bridge_server.py). Если же JS может подключаться к игре напрямую — работает --in-game.
"""

from __future__ import print_function

import argparse
import socket
import struct
import sys
import threading
import time

from primitive import P, MockBackend

CMD_READ, CMD_WRITE, CMD_MALLOC, CMD_SYSCALL = 0x01, 0x02, 0x03, 0x04
CMD_READY, CMD_REASON, CMD_PING = 0x05, 0x06, 0x07
# ВАЖНО: память ПРОЦЕССА и память ЯДРА — разные пространства (см. jb1422 §15.4).
CMD_READK, CMD_WRITEK = 0x08, 0x09
STATUS_OK, STATUS_ERR = 0, 1


# --------------------------------------------------------------------------- codec
def recv_exact(sock, size):
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("peer closed after %d/%d bytes" % (len(buf), size))
        buf += chunk
    return buf


def read_frame(sock):
    """Read one request frame; returns (cmd, payload_bytes)."""
    head = recv_exact(sock, 1)
    cmd = head[0]
    if cmd in (CMD_READ, CMD_READK):
        addr, length = struct.unpack("<QQ", recv_exact(sock, 16))
        return cmd, {"addr": addr, "len": length}
    if cmd in (CMD_WRITE, CMD_WRITEK):
        addr, length = struct.unpack("<QQ", recv_exact(sock, 16))
        return cmd, {"addr": addr, "data": recv_exact(sock, length)}
    if cmd == CMD_MALLOC:
        size, align = struct.unpack("<QQ", recv_exact(sock, 16))
        return cmd, {"size": size, "align": align}
    if cmd == CMD_SYSCALL:
        num = struct.unpack("<Q", recv_exact(sock, 8))[0]
        argc = struct.unpack("<B", recv_exact(sock, 1))[0]
        args = list(struct.unpack("<%dQ" % argc, recv_exact(sock, 8 * argc))) if argc else []
        return cmd, {"num": num, "args": args}
    if cmd in (CMD_READY, CMD_REASON, CMD_PING):
        return cmd, {}
    raise ValueError("unknown command 0x%02x" % cmd)


def error_frame(text):
    return struct.pack("<B", STATUS_ERR) + str(text).encode("utf-8", "replace")


def handle_frame(p, cmd, args):
    """Execute one decoded frame against primitive p; returns reply bytes."""
    if cmd == CMD_READ:
        return struct.pack("<B", STATUS_OK) + p.read(args["addr"], args["len"])
    if cmd == CMD_READK:
        return struct.pack("<B", STATUS_OK) + p.read_kernel(args["addr"], args["len"])
    if cmd == CMD_WRITE:
        p.write(args["addr"], args["data"])
        return struct.pack("<B", STATUS_OK)
    if cmd == CMD_WRITEK:
        p.write_kernel(args["addr"], args["data"])
        return struct.pack("<B", STATUS_OK)
    if cmd == CMD_MALLOC:
        return struct.pack("<B", STATUS_OK) + struct.pack("<Q", p.malloc(args["size"], args["align"]))
    if cmd == CMD_SYSCALL:
        ret = p.syscall(args["num"], *args["args"])
        return struct.pack("<B", STATUS_OK) + struct.pack("<q", int(ret))
    if cmd == CMD_READY:
        return struct.pack("<BB", STATUS_OK, 1 if p.ready() else 0)
    if cmd == CMD_REASON:
        return struct.pack("<B", STATUS_OK) + str(p.reason()).encode("utf-8", "replace")
    if cmd == CMD_PING:
        return struct.pack("<B", STATUS_OK) + b"PONG"
    raise ValueError("unknown command 0x%02x" % cmd)


# --------------------------------------------------------------------------- server
class BinaryServer(object):
    def __init__(self, primitive, host="127.0.0.1", port=0, verbose=True, one_shot=False):
        self.p = primitive
        self.host, self.port = host, port
        self.verbose = verbose
        self.one_shot = one_shot
        self.sock = None
        self.port_actual = None
        self._stop = threading.Event()
        self.served = 0

    def log(self, line):
        if self.verbose:
            print("[runner] " + line, flush=True)

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.port_actual = self.sock.getsockname()[1]
        self.sock.listen(4)
        self.sock.settimeout(0.2)
        threading.Thread(target=self._serve, daemon=True).start()
        self.log("listening on %s:%d" % (self.host, self.port_actual))
        return self

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, peer = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.log("client %s" % (peer,))
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()
            if self.one_shot:
                return

    def _client(self, conn):
        with conn:
            conn.settimeout(30.0)
            while not self._stop.is_set():
                try:
                    cmd, args = read_frame(conn)
                except (ConnectionError, ValueError, OSError) as exc:
                    self.log("client closed: %s" % exc)
                    return
                try:
                    reply = handle_frame(self.p, cmd, args)
                except Exception as exc:                # noqa: BLE001 - report to client
                    reply = error_frame(exc)
                self.served += 1
                conn.sendall(reply)

    def stop(self):
        self._stop.set()
        if self.sock:
            self.sock.close()


class Client(object):
    """Минимальный клиент бинарного протокола (используется в selftest и JS-эквивалентах)."""

    def __init__(self, host, port, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)

    def _call(self, frame):
        self.sock.sendall(frame)
        status = recv_exact(self.sock, 1)[0]
        if status != STATUS_OK:
            raise RuntimeError("remote error: " + recv_until_close_or_eof(self.sock).decode("utf-8", "replace"))
        return self.sock

    def read(self, addr, length):
        self._call(struct.pack("<BQQ", CMD_READ, addr, length))
        return recv_exact(self.sock, length)

    def write(self, addr, data):
        self._call(struct.pack("<BQQ", CMD_WRITE, addr, len(data)) + data)

    def malloc(self, size, align=1):
        self._call(struct.pack("<BQQ", CMD_MALLOC, size, align))
        return struct.unpack("<Q", recv_exact(self.sock, 8))[0]

    def syscall(self, num, *args):
        self._call(struct.pack("<BQB", CMD_SYSCALL, num, len(args)) +
                   (struct.pack("<%dQ" % len(args), *args) if args else b""))
        return struct.unpack("<q", recv_exact(self.sock, 8))[0]

    def ready(self):
        self._call(bytes([CMD_READY]))
        return recv_exact(self.sock, 1)[0] == 1

    def reason(self):
        self._call(bytes([CMD_REASON]))
        return recv_until_close_or_eof(self.sock).decode("utf-8", "replace")

    def ping(self):
        self._call(bytes([CMD_PING]))
        return recv_until_close_or_eof(self.sock).decode("ascii", "replace")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def recv_until_close_or_eof(sock):
    """Read what the server sent for variable-length payloads (reason/ping)."""
    sock.settimeout(1.0)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 4096:
                break
    except socket.timeout:
        pass
    sock.settimeout(10.0)
    return data


# --------------------------------------------------------------------------- in-game (YARPE)
def serve_in_game(port, p):
    """Слушать внутри YARPE: Ren'Py/Python 2.7 + utils.tcp (сырые syscall'ы, без socket-модуля)."""
    from utils.tcp import (                     # noqa: F401 - exists only in yarpe runtime
        create_tcp_server, accept_client, read_from_socket, write_to_socket, close_socket,
    )
    server_fd, _ = create_tcp_server(port)
    log = print
    log("[runner] yarpe binary server on port %d" % port)
    while True:
        client_fd = accept_client(server_fd)
        log("[runner] client fd=%s" % str(client_fd))
        buf = b""
        while True:
            chunk = read_from_socket(client_fd, 4096)
            if not chunk:
                break
            buf += chunk
            while True:
                # parse as many complete frames as the buffer holds
                try:
                    cmd = bytearray(buf[:1])[0] if buf else None
                except IndexError:
                    cmd = None
                if cmd is None:
                    break
                need = 1
                if cmd in (CMD_READ, CMD_WRITE, CMD_MALLOC):
                    need = 17
                elif cmd == CMD_SYSCALL:
                    if len(buf) < 9:
                        break
                    need = 9 + 8 * bytearray(buf[8:9])[0]
                elif cmd not in (CMD_READY, CMD_REASON, CMD_PING):
                    write_to_socket(client_fd, error_frame("unknown command 0x%02x" % cmd))
                    buf = b""
                    break
                if cmd == CMD_WRITE and len(buf) >= 17:
                    need = 17 + struct.unpack("<Q", buf[9:17])[0]
                if len(buf) < need:
                    break
                frame, buf = buf[:need], buf[need:]
                sock_like = _BufSock(frame)
                try:
                    parsed = read_frame(sock_like)
                    reply = handle_frame(p, *parsed)
                except Exception as exc:            # noqa: BLE001
                    reply = error_frame(exc)
                write_to_socket(client_fd, reply)
        close_socket(client_fd)


class _BufSock(object):
    """Adapter: already-read bytes presented with a recv() interface for read_frame()."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def recv(self, size):
        chunk = self.data[self.pos:self.pos + size]
        self.pos += len(chunk)
        return chunk


# --------------------------------------------------------------------------- relay (JS -> line agent)
def serve_relay(listen_host, listen_port, agent_host, agent_port, verbose=True):
    """Принимать бинарный протокол от JS и переводить в line-протокол агента (bridge_server)."""
    import bridge_server

    session = bridge_server.LineSession(
        socket.create_connection((agent_host, agent_port), timeout=10.0),
        "relay-%s:%d" % (agent_host, agent_port))
    session.handshake()
    p = _LinePrimitive(session)
    print("READY relay %s:%d -> agent %s:%d" % (listen_host, listen_port, agent_host, agent_port),
          flush=True)
    BinaryServer(p, listen_host, listen_port, verbose=verbose).start()
    while True:
        time.sleep(0.5)


class _LinePrimitive(object):
    """Primitive поверх line-протокола (bridge_server.LineSession)."""

    def __init__(self, session):
        self.session = session

    def ready(self):
        reply = self.session.request("?")
        return reply.startswith("RDY 1")

    def reason(self):
        reply = self.session.request("?")
        return reply[4:].strip() if reply.startswith("RDY ") else reply

    def read(self, addr, length):
        reply = self.session.request("R 0x%x %d" % (addr, length))
        return bytes.fromhex(reply[2:].strip())

    def write(self, addr, data):
        self.session.request("W 0x%x %s" % (addr, data.hex()))

    def malloc(self, size, align=1):
        reply = self.session.request("A %d" % size)
        return int(reply[2:].strip(), 16)

    def syscall(self, num, *args):
        raise RuntimeError("syscall() is not exposed by the line agent; use --in-game mode")


# --------------------------------------------------------------------------- selftest
def _selftest():
    backend = MockBackend()
    backend.syscall_table[20] = lambda args: 4242
    p = P(backend)
    server = BinaryServer(p, "127.0.0.1", 0, verbose=False).start()
    client = Client("127.0.0.1", server.port_actual)
    ok = True
    ops = 0

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(("[PASS] " if condition else "[FAIL] ") + name + (" :: " + detail if detail else ""))

    check("handshake p.ready()", client.ready() is True)
    check("p.reason()", client.reason() == "yarpe", client.reason())
    check("PING", client.ping() == "PONG")

    addr = client.malloc(0x100)
    check("MALLOC", addr > 0, "0x%x" % addr)

    # 20 операций read/write/syscall через TCP
    for i in range(8):
        value = (0x1111 << (i % 4)) + i
        client.write(addr + i * 8, struct.pack("<Q", value))
        got = struct.unpack("<Q", client.read(addr + i * 8, 8))[0]
        ops += 1
        check("op%d write8/read8 @+0x%x" % (i + 1, i * 8), got == value, hex(got))
    for i in range(6):
        buf = bytes(bytearray([(i * 37 + k) & 0xFF for k in range(4)]))
        client.write(addr + 0x60 + i * 4, buf)
        got = client.read(addr + 0x60 + i * 4, 4)
        ops += 1
        check("op%d byte-block %d" % (9 + i, i), got == buf, got.hex())
    for i in range(4):
        ret = client.syscall(20, i)
        ops += 1
        check("op%d syscall(20, %d)" % (15 + i, i), ret == 4242, str(ret))
    for i in range(2):
        ret = client.syscall(202, 0x10 + i, 0x20 + i)
        ops += 1
        check("op%d syscall(202, ..)" % (19 + i,), ret == 0x10 + i, str(ret))

    check("20 binary operations executed", ops == 20, str(ops))

    # семантика: p.readBytes (процесс) не должен отдавать ядро, rw/pipeReadBytes — должны
    kb = MockKernelBackend()
    kb.write_kernel(0xFFFFFFFF88880000, b"\x11\x22\x33\x44")
    check("process read of kernel addr is NOT kernel data",
          kb.read(0xFFFFFFFF88880000, 4) == b"\x00\x00\x00\x00",
          kb.read(0xFFFFFFFF88880000, 4).hex())
    check("rw/pipe kernel read returns kernel data",
          kb.read_kernel(0xFFFFFFFF88880000, 4) == b"\x11\x22\x33\x44",
          kb.read_kernel(0xFFFFFFFF88880000, 4).hex())
    client.close()
    server.stop()
    print("checks done, RESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1



# --------------------------------------------------------------------------- mock kernel profile
# Воспроизводит ответы dry-run-моков tools/jb1422/kernel/relapse1422.js (makeDryRunMocks),
# чтобы НАША kernel-цепочка, получая p/rw/syscall по TCP, проходила те же 12 стадий.
KERNEL_HI_MASK = 0xFFFFFFFF00000000
KERNEL_HI = 0xFFFFFFFF
OID_KIND_ADDR = 0x028F6F7C                 # oid.cpus + 0x28000 + 0x14 (kind)
RODATA_LO, RODATA_HI = 0x01359D6C, 0x01399D6C


def _kernel_text():
    text = bytearray(0x8000)

    def put(off, arr):
        text[off:off + len(arr)] = bytes(arr)

    put(0x0100, [0x5F, 0xC3]); put(0x0200, [0x5E, 0xC3]); put(0x0300, [0x5A, 0xC3])
    put(0x0400, [0x58, 0xC3]); put(0x0500, [0x48, 0x89, 0x07, 0xC3])
    put(0x0600, [0x48, 0x8B, 0x07, 0xC3]); put(0x0700, [0x0F, 0x01, 0xF8, 0xC3])
    put(0x0800, [0x48, 0xCF]); put(0x0900, [0x48, 0x0F, 0x07])
    put(0x1000, [0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3])
    put(0x1020, [0xB8, 0x04, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3])
    put(0x1040, [0xB8, 0x14, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3])
    put(0x1060, [0x0F, 0x05, 0xC3])
    text[0x2000:0x2000 + 27] = b"_aio_submit_cmd\x00_aio_multi_wait"
    return text


class MockKernelBackend(MockBackend):
    """MockBackend + синтетическая память ядра + syscall-профиль dry-run."""

    def __init__(self):
        MockBackend.__init__(self)
        self.text = _kernel_text()
        self.kstore = {}

    @staticmethod
    def is_kernel(addr):
        return (addr & KERNEL_HI_MASK) == KERNEL_HI_MASK

    def read(self, addr, length):
        # память ПРОЦЕССА: синтетики ядра здесь нет (иначе stage 8 даёт ложный OK)
        return MockBackend.read(self, addr, length)

    def write(self, addr, data):
        return MockBackend.write(self, addr, data)

    def read_kernel(self, addr, length):
        off = addr & 0xFFFFFFFF
        if length == 4:
            if off in self.kstore:
                return struct.pack("<I", self.kstore[off])
            if off == OID_KIND_ADDR:
                return struct.pack("<I", 0x80048002)
            if RODATA_LO <= off <= RODATA_HI:
                base = off % len(self.text)
                return bytes(self.text[base:base + 4])
            return struct.pack("<I", 275)                 # pid
        if length == 8:
            return bytes([0x00, 0x00, 0x88, 0x88, 0xFF, 0xFF, 0xFF, 0xFF])
        base = off % len(self.text)
        return bytes(self.text[base:base + length]) if base + length <= len(self.text) else \
            bytes((self.text[(base + i) % len(self.text)] for i in range(length)))

    def write_kernel(self, addr, data):
        value = 0
        for i in range(min(4, len(data))):
            value |= (data[i] & 0xFF) << (i * 8)
        self.kstore[addr & 0xFFFFFFFF] = value

    def syscall(self, num, args):
        self.syscall_log.append((num, tuple(args)))
        if num == 0x014:                                   # getpid
            return 275
        if num == 0x1E7:                                   # cpuset_getaffinity -> mask 0x1
            if args:
                self.write(int(args[-1]) & 0xFFFFFFFFFFFFFFFF, struct.pack("<I", 1))
            return 0
        if num == 0x061:                                   # socket
            return 3
        if num == 0x062:                                   # connect
            return 0
        if num == 0x004:                                   # write -> len
            return int(args[2]) & 0xFFFFFFFF if len(args) > 2 else 0
        if num == 0x006:                                   # close
            return 0
        if num == 0x1DD:                                   # mmap
            return 0x70000000
        if num == 0x04A:                                   # mprotect
            return 0
        return 0


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="bundle-1422 binary runner: JS chain <-> YARPE primitive")
    ap.add_argument("--mock", action="store_true", help="serve a MockBackend primitive (no console)")
    ap.add_argument("--mock-kernel", action="store_true", help="mock YARPE+NUL+synthetic kernel profile (full-chain demo)")
    ap.add_argument("--in-game", action="store_true", help="serve inside YARPE (Python 2.7 runtime)")
    ap.add_argument("--relay", action="store_true", help="relay binary frames to a line-protocol agent")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9139)
    ap.add_argument("--agent-host", default="127.0.0.1")
    ap.add_argument("--agent-port", type=int, default=9138)
    args = ap.parse_args()

    if args.selftest:
        return _selftest()
    if args.in_game:
        serve_in_game(args.port, P())
        return 0
    if args.relay:
        serve_relay(args.host, args.port, args.agent_host, args.agent_port)
        return 0

    if args.mock_kernel:
        server = BinaryServer(P(MockKernelBackend()), args.host, args.port).start()
        print("READY runner %s:%d profile=mock-kernel" % (args.host, server.port_actual), flush=True)
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            server.stop()
    primitive = P(MockBackend()) if args.mock else P()
    server = BinaryServer(primitive, args.host, args.port).start()
    print("READY runner %s:%d" % (args.host, server.port_actual), flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())