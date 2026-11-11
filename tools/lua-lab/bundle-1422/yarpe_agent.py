# bundle-1422 / yarpe_agent.py — агент ВНУТРИ YARPE (Ren'Py 7.4 / Python 2.7).
#
# Запускается на консоли как stage-2 payload по TCP 9025 (сырой текст Python):
#     python3 - <<'PY'
#     import socket; src=open("yarpe_agent.py","rb").read()
#     s=socket.create_connection(("<PS5_IP>",9025),timeout=10); s.sendall(src)
#     print(s.recv(65536).decode("utf-8","replace"))
#     PY
#
# Затем слушает TCP :9139 на консоли и отдаёт примитив `p` по бинарному протоколу
# kernel-runner.py (JS-цепочка может ходить сюда напрямую, если ей доступен порт консоли,
# либо через `kernel-runner.py --relay` на ПК).
#
# Точные API YARPE (из исходников Helloyunho/yarpe):
#   sc.mem — bytearray на адресное пространство процесса, индекс = addr - 0x1000;
#   utils.etc.alloc(size) -> bytearray, utils.etc.addrof(obj) -> адрес;
#   calls.Syscall(sc, num)(rdi,rsi,rdx,rcx,r8,r9) -> rax;
#   utils.tcp.create_tcp_server(port)/accept_client/read_from_socket/write_to_socket/close_socket.
#
# Протокол — тот же, что в kernel-runner.py:
#   0x01 READ   [addr u64][len u64]                -> [0][data]
#   0x02 WRITE  [addr u64][len u64][data]          -> [0]
#   0x03 MALLOC [size u64][align u64]              -> [0][addr u64]
#   0x04 SYSCALL[num u64][argc u8][args u64*argc]  -> [0][ret i64]
#   0x05 READY  -> [0][1]      0x06 REASON -> [0]["yarpe"]      0x07 PING -> [0]["PONG"]
#
# НЕ проверено на консоли (консоли в этой сессии нет); на ПК проверены протокол (через
# kernel-runner.py --selftest с MockBackend), сам primitive.py (23 проверки) и синтаксис.

from __future__ import print_function

import struct

from sc import sc
from calls import Syscall
from utils.etc import alloc, addrof
from utils.tcp import (  # noqa: F401 - provided by the yarpe runtime
    create_tcp_server, accept_client, read_from_socket, write_to_socket, close_socket,
)

PORT = 9139
CMD_READ, CMD_WRITE, CMD_MALLOC, CMD_SYSCALL = 0x01, 0x02, 0x03, 0x04
CMD_READY, CMD_REASON, CMD_PING = 0x05, 0x06, 0x07
STATUS_OK, STATUS_ERR = 0, 1


def log(line):
    try:
        from utils.rp import log as rp_log
        rp_log(line)
    except Exception:
        print(line)


# --------------------------------------------------------------------- primitive (P)
def mem_read(addr, length):
    base = addr - 0x1000                      # sc.mem indexes by addr-0x1000
    return bytes(sc.mem[base:base + length])


def mem_write(addr, data):
    base = addr - 0x1000
    sc.mem[base:base + len(data)] = data


def mem_alloc(size, align=1):
    return int(addrof(alloc(size)))


def call_syscall(num, args):
    padded = list(args) + [0] * (6 - len(args))
    return int(Syscall(sc, int(num))(*padded[:6]) or 0)


# --------------------------------------------------------------------- binary protocol
def recv_exact(fd, size):
    data = b""
    while len(data) < size:
        chunk = read_from_socket(fd, size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def handle(fd, cursor):
    cmd = cursor[:1]
    if not cmd:
        return None, cursor
    code = bytearray(cmd)[0]
    if code in (CMD_READ, CMD_WRITE, CMD_MALLOC):
        if len(cursor) < 17:
            return "need_more", cursor
        addr, n = struct.unpack("<QQ", cursor[1:17])
        cursor = cursor[17:]
        if code == CMD_READ:
            return struct.pack("<B", STATUS_OK) + mem_read(addr, n), cursor
        if code == CMD_MALLOC:
            return struct.pack("<B", STATUS_OK) + struct.pack("<Q", mem_alloc(addr, n)), cursor
        if len(cursor) < n:
            return "need_more", cursor
        data, cursor = cursor[:n], cursor[n:]
        mem_write(addr, data)
        return struct.pack("<B", STATUS_OK), cursor
    if code == CMD_SYSCALL:
        if len(cursor) < 9:
            return "need_more", cursor
        num = struct.unpack("<Q", cursor[1:9])[0]
        argc = bytearray(cursor[9:10])[0]
        need = 10 + 8 * argc
        if len(cursor) < need:
            return "need_more", cursor
        args = list(struct.unpack("<%dQ" % argc, cursor[10:need])) if argc else []
        ret = call_syscall(num, args)
        return struct.pack("<B", STATUS_OK) + struct.pack("<q", ret), cursor[need:]
    if code == CMD_READY:
        return struct.pack("<BB", STATUS_OK, 1), cursor[1:]
    if code == CMD_REASON:
        return struct.pack("<B", STATUS_OK) + b"yarpe", cursor[1:]
    if code == CMD_PING:
        return struct.pack("<B", STATUS_OK) + b"PONG", cursor[1:]
    return struct.pack("<B", STATUS_ERR) + b"unknown command", cursor[1:]


def main():
    server_fd, _ = create_tcp_server(PORT)
    log("[agent] yarpe binary agent on %d (platform=%s version=%s)" %
        (PORT, getattr(sc, "platform", "?"), getattr(sc, "version", "?")))
    while True:
        client_fd = accept_client(server_fd)
        log("[agent] client fd=%s" % str(client_fd))
        buf = b""
        while True:
            chunk = read_from_socket(client_fd, 4096)
            if not chunk:
                break
            buf += chunk
            while True:
                reply, remainder = handle(client_fd, buf)
                if reply == "need_more":
                    break
                buf = remainder
                write_to_socket(client_fd, reply)
        close_socket(client_fd)


if __name__ == "__main__":
    main()