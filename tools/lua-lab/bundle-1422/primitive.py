#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bundle-1422 / primitive.py — объект `P`: примитив поверх YARPE (Python в игре).

Точные факты из исходников Helloyunho/yarpe (проверено в этой сессии):

  * `sc.mem` — это **bytearray на всё адресное пространство процесса**, где индекс =
    `addr - 0x1000` (src/utils/unsafe.py: `readbuf(addr, n) -> mem[addr-0x1000:...]`,
    `writebuf(addr, data)` — та же срез-запись). Значит чтение/запись произвольного
    адреса — это срез mem, а не отдельный метод.
  * `utils.etc.alloc(size)` -> bytearray (куча процесса), `utils.etc.addrof(obj)` -> int-адрес;
    `utils.ref.get_ref_addr(obj)`/`refbytearray(obj)` — адрес ссылки.
  * `sc.syscalls.<name>(rdi, rsi, rdx, rcx, r8, r9)` -> rax (int); номер берётся из `SYSCALL`
    (src/constants.py) через `SyscallContainer.__getattr__`. Для произвольного номера —
    `from calls import Syscall; Syscall(sc, num)(...)` (src/calls.py: `Syscall.__call__(rdi..r9)`).
  * `sc.functions.<name>(rdi, rsi, rdx, rcx, r8, r9)` -> rax (int) (src/calls.py: Function).
  * `utils.unsafe.fakeobj(addr)` — подделка Python-объекта по адресу.
  * `sc.is_jailbroken` = `getuid()==0 and is_in_sandbox()==0`.

Этот модуль даёт ОДИН интерфейс, который ждёт kernel-цепочка jb1422 (`p.read1/4/8`,
`p.write1/4/8`, `p.malloc`, `p.ready()`, `p.reason()`, плюс hex-варианты `read64/write64/
read32/write32/add` из tools/jb1422/js/primitive.js).

Режимы:
  P()            — внутри YARPE (Ren'Py/Python 2.7): бэкенд = sc.mem.
  P(backend)     — тот же интерфейс поверх произвольного бэкенда (для ПК-тестов): бэкенд
                   должен реализовать read(addr,len)->bytes, write(addr,bytes), alloc(size)->int,
                   syscall(num,args)->int.
  MockBackend()  — словарь страниц + фейковые syscall'ы: mock sc.mem для selftest.
"""

from __future__ import print_function

import struct
import sys

try:                                    # py2 keeps 'long', py3 does not
    _INT_TYPES = (int, long)            # noqa: F821 - py2 only
except NameError:                       # pragma: no cover - py3 path
    _INT_TYPES = (int,)

U64 = 0xFFFFFFFFFFFFFFFF


# --------------------------------------------------------------------------- backends
class MockBackend(object):
    """Словарь страниц 0x1000 + фейковый syscall: стенд-ин для sc.mem на ПК."""

    def __init__(self):
        self.pages = {}
        self.next_alloc = 0x200000
        self.syscall_log = []
        self.syscall_table = {}          # num -> callable(args) -> int

    # -- memory ------------------------------------------------------
    def _page(self, addr):
        base = addr & ~0xFFF
        page = self.pages.get(base)
        if page is None:
            page = bytearray(0x1000)
            self.pages[base] = page
        return page, addr - base

    def read(self, addr, length):
        out = bytearray()
        cur, left = addr, length
        while left > 0:
            page, off = self._page(cur)
            take = min(left, 0x1000 - off)
            out += page[off:off + take]
            cur += take
            left -= take
        return bytes(out)

    def write(self, addr, data):
        cur, idx = addr, 0
        while idx < len(data):
            page, off = self._page(cur)
            take = min(len(data) - idx, 0x1000 - off)
            page[off:off + take] = data[idx:idx + take]
            cur += take
            idx += take

    def alloc(self, size, align=1):
        addr = self.next_alloc
        self.next_alloc += (size + 0x1000 - 1) & ~0xFFF
        self.write(addr, b"\x00" * size)
        return addr

    # -- syscall -----------------------------------------------------
    def syscall(self, num, args):
        self.syscall_log.append((num, tuple(args)))
        handler = self.syscall_table.get(num)
        if handler is not None:
            return handler(tuple(args))
        # default: echo the first argument (lets a test check the return path)
        return args[0] if args else 0


class YarpeBackend(object):
    """Бэкенд поверх реального YARPE-рантайма (sc.mem + calls.Syscall)."""

    def __init__(self, sc=None):
        if sc is None:
            from sc import sc as yarpe_sc          # noqa: F401 - only exists in-game
            sc = yarpe_sc
        self.sc = sc
        self._alloc = None
        self._addrof = None
        self._syscall_cls = None
        try:
            from utils.etc import alloc, addrof
            self._alloc, self._addrof = alloc, addrof
        except Exception:                          # noqa: BLE001 - keep going, alloc() will fail loudly
            pass

    # -- memory (sc.mem index = addr - 0x1000) -----------------------
    def read(self, addr, length):
        base = addr - 0x1000
        return bytes(self.sc.mem[base:base + length])

    def write(self, addr, data):
        base = addr - 0x1000
        self.sc.mem[base:base + len(data)] = data

    def alloc(self, size, align=1):
        if self._alloc is None or self._addrof is None:
            raise RuntimeError("utils.etc.alloc/addrof unavailable in this runtime")
        buf = self._alloc(size)
        return int(self._addrof(buf))

    # -- syscall -----------------------------------------------------
    def syscall(self, num, args):
        if self._syscall_cls is None:
            from calls import Syscall                # noqa: F401 - in-game module
            self._syscall_cls = Syscall
        call_args = list(args) + [0] * (6 - len(args))
        ret = self._syscall_cls(self.sc, num)(*call_args[:6])
        return int(ret or 0)

    def function(self, name, args):
        func = getattr(self.sc.functions, name)
        call_args = list(args) + [0] * (6 - len(args))
        return int(func(*call_args[:6]) or 0)


# --------------------------------------------------------------------------- primitive
class P(object):
    """Интерфейс `p` для kernel-цепочки (совпадает с tools/jb1422/js/primitive.js)."""

    def __init__(self, backend=None):
        self.backend = backend if backend is not None else YarpeBackend()

    # -- status ------------------------------------------------------
    def ready(self):
        return True

    def reason(self):
        return "yarpe"

    # -- raw reads ---------------------------------------------------
    def read1(self, addr):
        return struct.unpack("<B", self._read(addr, 1))[0]

    def read4(self, addr):
        return struct.unpack("<I", self._read(addr, 4))[0]

    def read8(self, addr):
        return struct.unpack("<Q", self._read(addr, 8))[0]

    def read(self, addr, length):
        return self._read(addr, length)

    # -- raw writes --------------------------------------------------
    def write1(self, addr, value):
        self._write(addr, struct.pack("<B", value & 0xFF))

    def write4(self, addr, value):
        self._write(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def write8(self, addr, value):
        self._write(addr, struct.pack("<Q", value & U64))

    def write(self, addr, data):
        self._write(addr, data)

    # -- hex-string aliases (js/primitive.js contract) ---------------
    def _to_int(self, value):
        if isinstance(value, _INT_TYPES):
            return value
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)

    def read64(self, addr):
        return "0x%x" % self.read8(self._to_int(addr))

    def write64(self, addr, value):
        self.write8(self._to_int(addr), self._to_int(value))

    def read32(self, addr, off=0):
        return self.read64(self.add(addr, off))

    def write32(self, addr, off=0, value=0):
        self.write64(self.add(addr, off), value)

    def add(self, addr, off=0):
        return "0x%x" % (self._to_int(addr) + int(off or 0))

    # -- heap --------------------------------------------------------
    def malloc(self, size, align=1):
        return self.backend.alloc(int(size), int(align))

    # -- calls -------------------------------------------------------
    def syscall(self, num, *args):
        return self.backend.syscall(int(num), list(args))

    def syscall_named(self, name, *args):
        return self.backend.syscall(int(self._SYSCALL_NUMBERS[name]), list(args))

    def function(self, name, *args):
        return self.backend.function(name, list(args))

    # -- internals ---------------------------------------------------
    def _read(self, addr, length):
        return self.backend.read(self._to_int(addr), int(length))

    def _write(self, addr, data):
        self.backend.write(self._to_int(addr), data)

    # минимальная карта номеров (FreeBSD/PS5), для удобства payload'ов
    _SYSCALL_NUMBERS = {
        "read": 3, "write": 4, "open": 5, "close": 6, "getpid": 20, "getuid": 24,
        "getppid": 39, "pipe": 42, "kqueue": 362, "socket": 97, "bind": 104,
        "listen": 106, "accept": 30, "mmap": 477, "mprotect": 74,
        "is_in_sandbox": 601, "netgetiflist": 125, "sysctl": 202,
    }


# --------------------------------------------------------------------------- mini selftest
def _selftest():
    """20 операций read/write/syscall на MockBackend — все должны пройти."""
    backend = MockBackend()
    p = P(backend)
    results = []

    def check(name, condition, detail=""):
        results.append((name, bool(condition), detail))
        print(("[PASS] " if condition else "[FAIL] ") + name + (" :: " + detail if detail else ""))

    check("p.ready()", p.ready() is True)
    check("p.reason()", p.reason() == "yarpe", p.reason())

    addr = p.malloc(0x100)
    check("p.malloc(0x100) -> addr", addr > 0, "0x%x" % addr)

    # 1-3: байтовые записи/чтения
    p.write1(addr + 0, 0x5A)
    check("write1/read1", p.read1(addr + 0) == 0x5A, "0x%x" % p.read1(addr))
    p.write4(addr + 4, 0xDEADBEEF)
    check("write4/read4", p.read4(addr + 4) == 0xDEADBEEF)
    p.write8(addr + 8, 0x1122334455667788)
    check("write8/read8", p.read8(addr + 8) == 0x1122334455667788)

    # 4-5: hex-алиасы
    check("read64 (hex string)", p.read64(addr + 8) == "0x1122334455667788", p.read64(addr + 8))
    p.write64(addr + 16, "0xCAFEBABE")
    check("write64 (hex string) -> read32", p.read4(addr + 16) == 0xCAFEBABE)

    # 6-8: add / read32 / write32 со смещением
    check("p.add()", p.add(addr, 0x20) == "0x%x" % (addr + 0x20), p.add(addr, 0x20))
    p.write32(addr, 0x20, 0x41424344)
    check("write32(addr, off, value)", p.read4(addr + 0x20) == 0x41424344)
    check("read32(addr, off)", p.read32(addr, 0x20) == "0x41424344", str(p.read32(addr, 0x20)))

    # 9-10: строковые/байтовые буферы
    p.write(addr + 0x40, b"JB1422")
    check("raw write/read bytes", p.read(addr + 0x40, 6) == b"JB1422")
    check("buffers don't overlap", p.read4(addr) == 0x5A and p.read1(addr + 0x40) == ord("J"),
          "read4(addr)=0x%x" % p.read4(addr))

    # 11-13: syscall без аргументов / с аргументами / именованный
    check("syscall(20) default echo", p.syscall(20) == 0)
    check("syscall(202, 0x1234)", p.syscall(202, 0x1234) == 0x1234)
    backend.syscall_table[24] = lambda args: 1000          # uid != 0 -> is_jailbroken=False
    check("syscalls.getuid()", p.syscall_named("getuid") == 1000)

    # 14-17: границы и перезапись
    p.write1(addr + 0xFF, 0x7F)
    check("last byte of allocation", p.read1(addr + 0xFF) == 0x7F)
    p.write4(addr, 0xFFFFFFFF)
    check("u32 max", p.read4(addr) == 0xFFFFFFFF)
    p.write8(addr + 0x30, U64)
    check("u64 max", p.read8(addr + 0x30) == U64)
    p.write4(addr, 0)
    check("clear dword", p.read4(addr) == 0)

    # 18-20: страницы, второй malloc, журнал syscall'ов
    far = p.malloc(0x10)
    p.write8(far, 0xAABBCCDDEEFF0011)
    check("second malloc is distant page", far != addr and (far & 0xFFF) == 0, "0x%x" % far)
    check("cross-page read8", p.read8(far) == 0xAABBCCDDEEFF0011)
    check("syscall log has 3 entries", len(backend.syscall_log) == 3,
          str(backend.syscall_log))

    failed = [r for r in results if not r[1]]
    print("checks: %d, failed: %d" % (len(results), len(failed)))
    print("RESULT: " + ("PASS" if not failed else "FAIL"))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(_selftest())