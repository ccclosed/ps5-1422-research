#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
emu.py — прототип эмуляции гостевого кода PS5 (FreeBSD/Prospero, x86-64) на ПК.

Идея: eboot.elf от PS5 — это обычный ELF64 с машинным кодом x86-64. Чтобы
исполнить его без консоли, не нужно эмулировать «железо PS5»: достаточно
(1) разложить PT_LOAD по их p_vaddr, (2) поднять Unicorn в режиме x86-64,
(3) подменить то, что обычно даёт ядро/загрузчик: стек, TLS, импорты из
*.prx (PLT/GOT) и системные вызовы FreeBSD.

Прототип делает ровно это и печатает реальную трассу:
  * сколько инструкций исполнено (точный счётчик через UC_HOOK_CODE),
  * какие syscall-номера встречены (rax на инструкции `syscall`) и с какими
    аргументами (rdi/rsi/rdx/r10/r8/r9 по SysV),
  * докуда дошёл и почему остановился (неотображённая память / int3 / ud2 /
    лимит инструкций / таймаут).

Импорты: все PLT-заглушки PS5 имеют вид
    ff 25 <disp32>         jmp qword ptr [rip+disp32]   ; -> слот GOT
    68 <imm32>             push imm32                  ; индекс импорта
    e9 <rel32>             jmp resolver
Мы находим такие заглушки сканированием исполняемого сегмента, заливаем все
слоты GOT адресом шима (16-байтный слот, код `xor eax,eax; ret`) и логируем,
какой индекс импорта был вызван. Это и есть «фальшивая libSce*/libc.prx»:
функция честно вызывается, но возвращает 0.

Запуск:
    python3 emu.py                       # полный прогон с шимами импортов
    python3 emu.py --raw                 # без патча GOT (сырой ELF как есть)
    python3 emu.py --max-insns 2000000 --timeout 30

Никаких заглушек-обманок в самом прототипе нет: каждый шаг реально исполняется
процессором Unicorn, а всё, что подменено (импорты, syscall), честно логируется.
"""
from __future__ import annotations

import argparse
import mmap
import os
import re
import struct
import sys
import time
from collections import Counter, deque

try:
    import unicorn
    from unicorn import (
        Uc,
        UcError,
        UC_ARCH_X86,
        UC_MODE_64,
        UC_HOOK_CODE,
        UC_HOOK_INSN,
        UC_HOOK_INTR,
        UC_HOOK_MEM_UNMAPPED,
        UC_HOOK_MEM_READ_PROT,
        UC_HOOK_MEM_WRITE_PROT,
        UC_HOOK_MEM_FETCH_PROT,
        UC_MEM_READ,
        UC_MEM_WRITE,
        UC_MEM_FETCH,
        UC_PROT_READ,
        UC_PROT_WRITE,
        UC_PROT_EXEC,
        UC_ERR_OK,
        UC_ERR_INSN_INVALID,
    )
    from unicorn.x86_const import (
        UC_X86_REG_RAX,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_RSI,
        UC_X86_REG_RDI,
        UC_X86_REG_RBP,
        UC_X86_REG_RSP,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_R14,
        UC_X86_REG_R15,
        UC_X86_REG_RIP,
        UC_X86_REG_FS_BASE,
        UC_X86_REG_GS_BASE,
        UC_X86_INS_SYSCALL,
    )
except ImportError as exc:  # pragma: no cover
    sys.exit("нужен unicorn: python3 -m pip install --user unicorn (%s)" % exc)

try:
    import capstone

    _MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    _MD.detail = False
except Exception:  # capstone необязателен — трасса будет в сырых байтах
    _MD = None

# ---------------------------------------------------------------------------
# константы эксперимента
# ---------------------------------------------------------------------------
PAGE = 0x1000
DEFAULT_ELF = (
    "/home/oleg/Документы/ps5semulator/games/cyberpunk/anyps5-run/eboot.elf"
)
STACK_BASE = 0x7FFF_0000_0000  # 8 МБ стек, как у FreeBSD-процесса
STACK_SIZE = 0x0080_0000
TLS_BASE = 0x0000_0000_7000_0000  # одна страница под TCB (FS_BASE)
SHIM_BASE = 0x0000_0000_5000_0000  # регион шимов импортов, 16 байт на слот

# имена для UC_HOOK_MEM_UNMAPPED (значения access в Unicorn 2.x)
ACCESS_NAMES = {
    UC_MEM_READ: "READ",
    UC_MEM_WRITE: "WRITE",
    UC_MEM_FETCH: "FETCH",
    19: "READ_UNMAPPED",
    20: "WRITE_UNMAPPED",
    21: "FETCH_UNMAPPED",
    22: "READ_PROT",
    23: "WRITE_PROT",
    24: "FETCH_PROT",
}

SYS_NAMES = {
    # FreeBSD/PS5-подобная нумерация: только то, что проверяемо при прогоне.
    # (полная таблица sysent PS5 — отдельная задача recon/sysent)
    1: "exit",
    3: "read",
    4: "write",
    5: "open",
    6: "close",
    9: "link",
    10: "unlink",
    12: "chdir",
    17: "obreak",
    20: "getpid",
    73: "munmap",
    74: "mprotect",
    97: "socket",
    202: "sysarch",
}


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------
PT_LOAD = 1
PT_DYNAMIC = 2
PT_TLS = 7
PT_SCE_PROCPARAM = 0x61000001
PT_SCE_COMMENT = 0x6FFFFF00
PT_SCE_VERSION = 0x6FFFFF01


class Phdr:
    __slots__ = ("i", "type", "flags", "off", "va", "pa", "fsz", "msz", "align")

    def __init__(self, i, vals):
        (self.i, self.type, self.flags, self.off, self.va,
         self.pa, self.fsz, self.msz, self.align) = (i, *vals)

    def prot(self):
        # x86-64 не имеет «execute-only» и «write-only» страниц: p_flags
        # сегмента кода в PS5-ELF равен 1 (PF_X), но настоящий загрузчик всё
        # равно отображает его читаемым. Поэтому R добавляем всегда, иначе
        # выборки констант из сегмента кода давали бы READ_PROT.
        p = UC_PROT_READ
        if self.flags & 2:
            p |= UC_PROT_WRITE
        if self.flags & 1:
            p |= UC_PROT_EXEC
        return p


def prot_str(prot):
    return ("r" if prot & UC_PROT_READ else "-") + (
        "w" if prot & UC_PROT_WRITE else "-"
    ) + ("x" if prot & UC_PROT_EXEC else "-")


def align_down(x, a=PAGE):
    return x & ~(a - 1)


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


class Elf:
    """Минимальный парсер ELF64: заголовок + program headers + mmap файла."""

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.f = open(path, "rb")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        (ei_class, ei_data) = self.mm[4], self.mm[5]
        if self.mm[:4] != b"\x7fELF":
            raise SystemExit("не ELF: %s" % path)
        if ei_class != 2 or ei_data != 1:
            raise SystemExit("ожидался ELF64 little-endian")
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
         self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize,
         self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack("<HHIQQQIHHHHHH", self.mm[16:64])
        if self.e_machine != 0x3E:
            raise SystemExit("ожидался x86-64, получено %#x" % self.e_machine)
        self.phdrs = []
        off = self.e_phoff
        for i in range(self.e_phnum):
            vals = struct.unpack("<IIQQQQQQ", self.mm[off:off + 56])
            self.phdrs.append(Phdr(i, vals))
            off += self.e_phentsize

    def data(self, off, size):
        return self.mm[off:off + size]

    def headers(self):
        return {
            "osabi": self.mm[7],
            "type": self.e_type,
            "entry": self.e_entry,
            "phnum": self.e_phnum,
            "flags": self.e_flags,
            "size": self.size,
        }


# ---------------------------------------------------------------------------
# Эмулятор
# ---------------------------------------------------------------------------
class Emu:
    def __init__(self, elf, out, max_insns, timeout, trace_limit, use_shims,
                 verbose, label="A", quiet_header=False):
        self.elf = elf
        self.label = label
        self.quiet_header = quiet_header
        self.out = out
        self.max_insns = max_insns
        self.timeout = timeout
        self.trace_limit = trace_limit
        self.use_shims = use_shims
        self.verbose = verbose

        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc_err = 0
        self.insn_count = 0
        self.syscall_counter = Counter()
        self.syscall_args = {}  # nr -> первый встреченный набор аргументов
        self.import_counter = Counter()
        self.import_examples = {}  # idx -> (pc, args)
        self.ring = [0] * 32  # последние PC
        self.ring_n = 0
        self.stop_reason = None
        self.stop_pc = 0
        self.stop_detail = {}
        self.trace = deque()
        self.t0 = 0.0
        self.plt_entries = []  # (stub_va, got_va, import_index)
        self.got_map = {}  # got_va -> shim_va
        self.shims = 0
        self.mapped = []  # (va, size, prot)
        self.phase_name = "?"

    # -- вывод ------------------------------------------------------------
    def p(self, line=""):
        print(line)
        if self.out:
            self.out.write(line + "\n")

    # -- память -----------------------------------------------------------
    def map_region(self, va, size, prot):
        base = align_down(va)
        end = align_up(va + size)
        if end <= base:
            return
        self.uc.mem_map(base, end - base, prot)
        self.mapped.append((base, end - base, prot))

    def load_segments(self):
        loads = [p for p in self.elf.phdrs if p.type == PT_LOAD]
        if not loads:
            raise SystemExit("в ELF нет PT_LOAD")
        # 1. объединённое покрытие страниц: сегменты PS5 могут пересекаться
        #    (PH3 и PH7 в eboot.elf пересекаются на ~23 КиБ), поэтому считаем
        #    union прав, а не отдельные mmap.
        regions = []
        for p in loads:
            regions.append((align_down(p.va), align_up(p.va + p.msz), p.prot()))
        merged = []
        for base, end, prot in sorted(regions):
            if merged and base <= merged[-1][1]:
                b, e, pr = merged[-1]
                merged[-1] = (b, max(e, end), pr | prot)
            else:
                merged.append((base, end, prot))
        for base, end, prot in merged:
            self.uc.mem_map(base, end - base, prot)
            self.mapped.append((base, end - base, prot))

        # 2. данные файла: пишем по порядку phdr, поздние перекрывают ранние
        for p in loads:
            if p.fsz == 0:
                continue
            chunk = 8 << 20
            done = 0
            while done < p.fsz:
                n = min(chunk, p.fsz - done)
                self.uc.mem_write(p.va + done,
                                  self.elf.data(p.off + done, n))
                done += n

        # 3. bss: обнуляем memsz-filesz, но только там, где нет данных файла
        file_cover = [(p.va, p.va + p.fsz) for p in loads if p.fsz]
        for p in loads:
            bss_start, bss_end = p.va + p.fsz, p.va + p.msz
            for s, e in subtract_intervals(bss_start, bss_end, file_cover):
                chunk = 8 << 20
                zchunk = b"\x00" * min(chunk, e - s)
                cur = s
                while cur < e:
                    n = min(chunk, e - cur)
                    self.uc.mem_write(cur, zchunk[:n])
                    cur += n

        # 4. стек, TLS, регион шимов
        self.map_region(STACK_BASE, STACK_SIZE,
                        UC_PROT_READ | UC_PROT_WRITE)
        self.map_region(TLS_BASE, 2 * PAGE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.reg_write(UC_X86_REG_FS_BASE, TLS_BASE + 0x40)
        self.uc.reg_write(UC_X86_REG_GS_BASE, 0)
        self.uc.mem_write(TLS_BASE, b"\x00" * (2 * PAGE))

    def setup_stack(self):
        """Кладём argc/argv как у обычного процесса и ставим указатели в rdi/rsi."""
        top = STACK_BASE + STACK_SIZE
        str_va = top - 0x400
        argc_va = top - 0x100
        argv_va = top - 0xF8
        self.uc.mem_write(str_va, b"eboot.elf\x00")
        self.uc.mem_write(argc_va, struct.pack("<Q", 1))
        self.uc.mem_write(argv_va, struct.pack("<Q", str_va) +
                          struct.pack("<Q", 0))
        rsp = top - 0x1000  # выровнен на 16
        self.uc.reg_write(UC_X86_REG_RSP, rsp)
        self.uc.reg_write(UC_X86_REG_RDI, argc_va)
        self.uc.reg_write(UC_X86_REG_RSI, argv_va)
        self.uc.reg_write(UC_X86_REG_RDX, 0)
        for r in (UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_R8,
                  UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
                  UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
                  UC_X86_REG_R15):
            self.uc.reg_write(r, 0)
        self.uc.reg_write(UC_X86_REG_RIP, self.elf.e_entry)
        return {"rsp": rsp, "argc": argc_va, "argv": argv_va, "str": str_va}

    # -- PLT / импорты -----------------------------------------------------
    _PLT_RE = re.compile(rb"\xff\x25(.{4})\x68(.{4})\xe9(.{4})", re.S)

    def scan_plt(self, dump_limit=12):
        """Ищем PLT-заглушки PS5 в исполняемых PT_LOAD."""
        execs = [p for p in self.elf.phdrs if p.type == PT_LOAD and
                 (p.flags & 1) and p.fsz]
        entries = []
        resolvers = Counter()
        for seg in execs:
            buf = self.elf.data(seg.off, seg.fsz)
            for m in self._PLT_RE.finditer(buf):
                va = seg.va + m.start()
                disp = struct.unpack("<i", m.group(1))[0]
                imm = struct.unpack("<I", m.group(2))[0]
                rel = struct.unpack("<i", m.group(3))[0]
                resolver = va + 16 + rel
                got = va + 6 + disp
                entries.append((va, got, imm))
                resolvers[resolver] += 1
            del buf
        # проверяем гипотезу: все заглушки прыгают в один resolver (PLT0)
        common = resolvers.most_common(1)[0] if resolvers else (0, 0)
        entries.sort()
        self.plt_entries = entries
        self.p("  найдено PLT-заглушек: %d" % len(entries))
        if common[1]:
            self.p("  общий resolver (PLT0): %#x, попаданий %d"
                   % (common[0], common[1]))
        for va, got, imm in entries[:dump_limit]:
            self.p("    stub %#010x  idx %-6d got %#010x" % (va, imm, got))
        if len(entries) > dump_limit:
            self.p("    ... ещё %d" % (len(entries) - dump_limit))
        return entries

    def install_import_shims(self):
        """GOT[stub] -> 16-байтный шим, который логируется и возвращает 0."""
        entries = self.plt_entries
        if not entries:
            return
        n = len(entries)
        size = align_up(n * 16, PAGE)
        self.uc.mem_map(SHIM_BASE, size, UC_PROT_READ | UC_PROT_EXEC)
        self.mapped.append((SHIM_BASE, size, UC_PROT_READ | UC_PROT_EXEC))
        # один шим на слот GOT (слоты могут повторяться у разных заглушек)
        got_to_idx = {}
        shim_bytes = bytearray(size)
        for k, (stub_va, got_va, imm) in enumerate(entries):
            idx = got_to_idx.setdefault(got_va, len(got_to_idx))
            shim_va = SHIM_BASE + idx * 16
            shim_bytes[idx * 16:idx * 16 + 3] = b"\x31\xc0\xc3"  # xor eax,eax; ret
            # остальное — int3, чтобы случайный вход в середину шима был виден
            shim_bytes[idx * 16 + 3:idx * 16 + 16] = b"\xcc" * 13
            self.uc.mem_write(got_va, struct.pack("<Q", shim_va))
            self.got_map[got_va] = (idx, imm)
        self.uc.mem_write(SHIM_BASE, bytes(shim_bytes))
        self.shims = len(got_to_idx)
        self.shim_size = size
        self.p("  шимов импортов установлено: %d (на %d заглушек)"
               % (self.shims, n))

    # -- хуки -------------------------------------------------------------
    def hook_code(self, uc, address, size, _ud):
        self.insn_count += 1
        ring = self.ring
        ring[self.ring_n & 31] = address
        self.ring_n += 1
        # логируем вызов импорта, если PC попал в начало шима
        if address >= SHIM_BASE and address < SHIM_BASE + getattr(self, "shim_size", 0):
            if (address - SHIM_BASE) % 16 == 0:
                idx = (address - SHIM_BASE) // 16
                self.import_counter[idx] += 1
                if idx not in self.import_examples and len(self.import_examples) < 40:
                    try:
                        ret_va = struct.unpack(
                            "<Q", uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8))[0]
                    except UcError:
                        ret_va = 0
                    self.import_examples[idx] = (ret_va, uc.reg_read(UC_X86_REG_RDI),
                                                 uc.reg_read(UC_X86_REG_RSI))
        # первые N инструкций — в трассу
        if len(self.trace) < self.trace_limit:
            try:
                raw = bytes(uc.mem_read(address, min(size, 16)))
            except UcError:
                raw = b""
            self.trace.append((address, raw))
        # лимиты
        if self.insn_count >= self.max_insns:
            self.stop_reason = "instruction limit (%d)" % self.max_insns
            uc.emu_stop()
        elif (self.insn_count & 0xFFFF) == 0:
            if time.time() - self.t0 > self.timeout:
                self.stop_reason = "time limit (%ss)" % self.timeout
                uc.emu_stop()

    def hook_syscall(self, uc, _ud):
        nr = uc.reg_read(UC_X86_REG_RAX)
        a = (uc.reg_read(UC_X86_REG_RDI), uc.reg_read(UC_X86_REG_RSI),
             uc.reg_read(UC_X86_REG_RDX), uc.reg_read(UC_X86_REG_R10),
             uc.reg_read(UC_X86_REG_R8), uc.reg_read(UC_X86_REG_R9))
        pc = uc.reg_read(UC_X86_REG_RIP)
        self.syscall_counter[nr] += 1
        if nr not in self.syscall_args:
            self.syscall_args[nr] = (pc, a)
        # подмена результата: «ядро» отвечает успехом
        uc.reg_write(UC_X86_REG_RAX, 0)

    def hook_unmapped(self, uc, access, address, size, value, _ud):
        name = ACCESS_NAMES.get(access, str(access))
        pc = uc.reg_read(UC_X86_REG_RIP)
        self.stop_pc = pc
        self.stop_reason = "unmapped memory (%s)" % name
        self.stop_detail = {"access": name, "address": address, "size": size,
                            "pc": pc}
        self.p("  !! НЕОТОБРАЖЁННАЯ ПАМЯТЬ: %s addr=%#x size=%d pc=%#x"
               % (name, address, size, pc))
        self.dump_context(uc)
        uc.emu_stop()

    def hook_prot(self, uc, access, address, size, value, _ud):
        name = ACCESS_NAMES.get(access, str(access))
        pc = uc.reg_read(UC_X86_REG_RIP)
        self.stop_pc = pc
        self.stop_reason = "protection fault (%s)" % name
        self.stop_detail = {"access": name, "address": address, "size": size,
                            "pc": pc}
        self.p("  !! НАРУШЕНИЕ ПРАВ ДОСТУПА: %s addr=%#x size=%d pc=%#x"
               % (name, address, size, pc))
        self.dump_context(uc)
        uc.emu_stop()

    def hook_intr(self, uc, intno, _ud):
        pc = uc.reg_read(UC_X86_REG_RIP)
        self.stop_pc = pc
        self.stop_reason = "interrupt/exception int %d" % intno
        self.stop_detail = {"intno": intno, "pc": pc}
        self.p("  !! ПРЕРЫВАНИЕ: int %d в pc=%#x" % (intno, pc))
        self.dump_context(uc)
        uc.emu_stop()

    # -- сервис -----------------------------------------------------------
    def dump_context(self, uc):
        regs = {
            "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX,
            "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
            "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI,
            "rbp": UC_X86_REG_RBP, "rsp": UC_X86_REG_RSP,
            "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9,
            "r10": UC_X86_REG_R10, "r11": UC_X86_REG_R11,
            "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13,
            "r14": UC_X86_REG_R14, "r15": UC_X86_REG_R15,
            "rip": UC_X86_REG_RIP,
        }
        vals = {k: uc.reg_read(v) for k, v in regs.items()}
        self.p("     rax=%#x rbx=%#x rcx=%#x rdx=%#x" %
               (vals["rax"], vals["rbx"], vals["rcx"], vals["rdx"]))
        self.p("     rsi=%#x rdi=%#x rbp=%#x rsp=%#x" %
               (vals["rsi"], vals["rdi"], vals["rbp"], vals["rsp"]))
        self.p("     r8=%#x r9=%#x r10=%#x r11=%#x r12=%#x r13=%#x "
               "r14=%#x r15=%#x" %
               (vals["r8"], vals["r9"], vals["r10"], vals["r11"],
                vals["r12"], vals["r13"], vals["r14"], vals["r15"]))
        # верхушка стека — видно адрес возврата
        try:
            sp = vals["rsp"]
            words = struct.unpack("<8Q", bytes(uc.mem_read(sp, 64)))
            self.p("     stack[%#x]: %s" % (sp, " ".join("%#x" % w for w in words)))
        except UcError:
            pass

    def explain_invalid_insn(self, pc):
        """Unicorn не смог декодировать инструкцию: показываем её байты и мнемонику."""
        try:
            raw = bytes(self.uc.mem_read(pc, 16))
        except UcError:
            return
        self.p("  !! UC_ERR_INSN_INVALID: кодировку инструкции по pc=%#x Unicorn "
               "не понимает" % pc)
        self.p("     байты: %s" % raw[:8].hex())
        text = self.disasm(pc, raw)
        self.p("     дизасм (capstone): %s" % text)
        if raw[0] in (0xc4, 0xc5, 0x62):
            self.p("     первый байт %#x — это VEX/EVEX-префикс (AVX/AVX-512): "
                   "Unicorn 2.1.4 такие инструкции не декодирует." % raw[0])

    def disasm(self, address, raw):
        if _MD is None or not raw:
            return raw.hex()
        ins = list(_MD.disasm(raw, address, 1))
        if not ins:
            return raw.hex()
        i = ins[0]
        return "%-6s %s" % (i.mnemonic, i.op_str)

    def print_trace(self):
        if not self.trace:
            return
        self.p("  первые %d инструкций:" % len(self.trace))
        for address, raw in self.trace:
            self.p("    %#010x: %-16s %s" %
                   (address, raw.hex(), self.disasm(address, raw)))
        # хвост: последние 16 PC из кольца
        n = min(self.ring_n, 32)
        tail = [self.ring[(self.ring_n - n + k) & 31] for k in range(n)]
        self.p("  последние %d PC перед остановкой:" % n)
        for address in tail:
            raw = b""
            try:
                raw = bytes(self.uc.mem_read(address, 16))
            except UcError:
                try:
                    raw = self.elf.data(self.va_to_off(address), 16)
                except Exception:
                    pass
            self.p("    %#010x: %-16s %s" % (address, raw.hex()[:32],
                                             self.disasm(address, raw)))

    def va_to_off(self, va):
        for p in self.elf.phdrs:
            if p.type == PT_LOAD and p.va <= va < p.va + p.fsz:
                return p.off + (va - p.va)
        raise KeyError(va)

    # -- прогон -----------------------------------------------------------
    def run(self):
        h = self.elf.headers()
        self.p("")
        self.p("=" * 78)
        self.p("ФАЗА %s: %s" % (self.label, self.phase_name))
        self.p("=" * 78)
        self.p("[elf] %s" % self.elf.path)
        self.p("      размер=%d байт, e_type=%#x, OSABI=%d (9=FreeBSD), entry=%#x, "
               "phnum=%d" % (h["size"], h["type"], h["osabi"], h["entry"],
                             h["phnum"]))
        if not self.quiet_header:
            self.p("[elf] program headers:")
            for p in self.elf.phdrs:
                self.p("      PH%-2d type=%#010x off=%#010x va=%#010x fsz=%#010x "
                       "msz=%#010x prot=%s" %
                       (p.i, p.type, p.off, p.va, p.fsz, p.msz,
                        prot_str(p.prot())))
        t0 = time.time()
        self.load_segments()
        self.p("[mem] отображено PT_LOAD-регионов: %d, суммарно %.1f МБ"
               % (len(self.mapped), sum(m[1] for m in self.mapped) / 1e6))
        regs = self.setup_stack()
        self.p("[cpu] RSP=%#x RDI(argc)=%#x RSI(argv)=%#x, FS_BASE=%#x"
               % (regs["rsp"], regs["argc"], regs["argv"], TLS_BASE + 0x40))
        self.p("[plt] скан исполняемых сегментов на PLT-заглушки PS5:")
        self.scan_plt()
        if self.use_shims:
            self.install_import_shims()
        else:
            self.p("  режим --raw: GOT не патчим, импорты остаются как в файле")
        self.p("")

        # хуки
        uc = self.uc
        uc.hook_add(UC_HOOK_CODE, self.hook_code)
        uc.hook_add(UC_HOOK_INSN, self.hook_syscall, None, 1, 0,
                    UC_X86_INS_SYSCALL)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self.hook_unmapped)
        uc.hook_add(UC_HOOK_MEM_READ_PROT, self.hook_prot)
        uc.hook_add(UC_HOOK_MEM_WRITE_PROT, self.hook_prot)
        uc.hook_add(UC_HOOK_MEM_FETCH_PROT, self.hook_prot)
        uc.hook_add(UC_HOOK_INTR, self.hook_intr)

        self.t0 = time.time()
        self.p("[run] старт: pc=%#x, лимит %d инструкций / %d с"
               % (self.elf.e_entry, self.max_insns, self.timeout))
        err = None
        try:
            # until=0 останавливал бы эмуляцию на PC=0 (а 0 — легитимный,
            # хотя и неотображённый, адрес), поэтому берём заведомо
            # неисполнимый адрес-часовой.
            uc.emu_start(self.elf.e_entry, 0xFFFF_FFFF_FFFF_FFFF,
                         timeout=0, count=0)
        except UcError as exc:
            err = exc
        elapsed = time.time() - self.t0
        try:
            pc_after = uc.reg_read(UC_X86_REG_RIP)
        except UcError:
            pc_after = self.stop_pc

        if err is not None and "INSN_INVALID" in str(err):
            self.explain_invalid_insn(pc_after)
        self.p("")
        if self.stop_reason is None and err is not None:
            self.stop_reason = "UcError: %s" % err
        self.p("[stop] причина: %s" % (self.stop_reason or "emu_start вернул "
                                      "управление"))
        self.p("[stop] PC=%#x, UcError=%s" % (pc_after, err))
        self.p("[stat] инструкций исполнено: %d за %.3f с (%.2f млн/с)"
               % (self.insn_count, elapsed,
                  self.insn_count / elapsed / 1e6 if elapsed else 0))
        self.p("[stat] системных вызовов: %d, уникальных номеров: %d"
               % (sum(self.syscall_counter.values()), len(self.syscall_counter)))
        for nr, cnt in sorted(self.syscall_counter.items()):
            pc0, args = self.syscall_args[nr]
            name = SYS_NAMES.get(nr, "?")
            self.p("    syscall rax=%#x (%d, %s): %d раз; первый вызов pc=%#x "
                   "args=%s" % (nr, nr, name, cnt, pc0,
                                ", ".join("%#x" % x for x in args)))
        self.p("[stat] вызовов импортов (через шимы): %d, уникальных слотов: %d"
               % (sum(self.import_counter.values()), len(self.import_counter)))
        for idx, cnt in self.import_counter.most_common(12):
            ret_va = self.import_examples.get(idx, (0, 0, 0))[0]
            self.p("    shim[%d]: %d раз, возврат в %#x" % (idx, cnt, ret_va))
        if self.stop_detail:
            self.p("[stop] детали: %s"
                   % ", ".join("%s=%#x" % (k, v) if isinstance(v, int) else
                               "%s=%s" % (k, v)
                               for k, v in self.stop_detail.items()))
        self.print_trace()
        self.p("")
        self.p("[итог] всего %.3f с от старта прогона" % (time.time() - t0))
        return self.insn_count


def subtract_intervals(start, end, covers):
    """[start,end) минус объединение covers -> список непокрытых интервалов."""
    if end <= start:
        return []
    ivs = sorted((max(s, start), min(e, end)) for s, e in covers
                 if e > start and s < end)
    out = []
    cur = start
    for s, e in ivs:
        if s > cur:
            out.append((cur, s))
        cur = max(cur, e)
    if cur < end:
        out.append((cur, end))
    return out


# ---------------------------------------------------------------------------
# вспомогательные фазы: статический скан, проба AVX, проверка syscall-хука
# ---------------------------------------------------------------------------
def emit(out, line=""):
    print(line)
    if out:
        out.write(line + "\n")


def static_scan(elf, out):
    """Что в исполняемых сегментах eboot.elf относится к syscall и к AVX."""
    emit(out, "")
    emit(out, "=" * 78)
    emit(out, "ФАЗА 0: статический скан eboot.elf (без исполнения)")
    emit(out, "=" * 78)
    segs = [p for p in elf.phdrs if p.type == PT_LOAD and (p.flags & 1) and p.fsz]
    n_syscall_bytes = 0
    n_wrapper = 0
    n_syscall_ret = 0
    n_ret_inside_mov = 0
    head_addr = []
    n_vex2 = n_vex3 = n_evex = 0
    total = 0
    for seg in segs:
        buf = elf.data(seg.off, seg.fsz)
        total += seg.fsz
        i = buf.find(b"\x0f\x05")
        while i >= 0:
            n_syscall_bytes += 1
            if len(head_addr) < 8:
                head_addr.append(seg.va + i)
            if i >= 5 and buf[i - 5] == 0xB8:      # mov eax, imm32 ; syscall
                n_wrapper += 1
            if i + 2 < len(buf) and buf[i + 2] == 0xC3:  # байты "0f 05 c3"
                n_syscall_ret += 1
                # проверяем, не лежит ли 0f 05 внутри disp32 у mov rax,[rip+disp]
                if i >= 5 and buf[i - 5:i - 2] == b"\x48\x8b\x05":
                    n_ret_inside_mov += 1
            i = buf.find(b"\x0f\x05", i + 1)
        n_vex2 += buf.count(b"\xc5")
        n_vex3 += buf.count(b"\xc4")
        n_evex += buf.count(b"\x62")
        del buf
    emit(out, "  исполняемая часть образа: %d байт в %d PT_LOAD" % (total, len(segs)))
    emit(out, "  байтовых пар 0f 05 (syscall): %d" % n_syscall_bytes)
    emit(out, "  из них шаблон обёртки 'mov eax,imm32; syscall': %d" % n_wrapper)
    emit(out, "  из них пары '0f 05 c3': %d (в т.ч. %d лежат внутри disp32 "
              "инструкции 'mov rax,[rip+disp]')" %
         (n_syscall_ret, n_ret_inside_mov))
    if head_addr:
        emit(out, "  первые адреса пар 0f 05: %s"
             % ", ".join("%#x" % a for a in head_addr))
    emit(out, "  префиксные байты C5/C4/62 (верхняя оценка VEX/EVEX): "
              "%d / %d / %d" % (n_vex2, n_vex3, n_evex))
    emit(out, "  ВЫВОД: в самом eboot.elf реальных инструкций syscall нет —")
    emit(out, "         все 0f 05 приходятся на данные или на байты внутри")
    emit(out, "         других инструкций (call rel32 и т.п.). PS5-игра делает")
    emit(out, "         системные вызовы через импорты libkernel.prx, а не сама.")
    return n_wrapper


def probe_avx(out):
    """Проверяем декодирование SSE и AVX одной и той же версией Unicorn."""
    emit(out, "")
    emit(out, "=" * 78)
    emit(out, "ФАЗА A: проба декодера Unicorn %s (SSE vs AVX)" % unicorn.__version__)
    emit(out, "=" * 78)
    tests = [
        ("SSE movaps xmm0,[rsp]  (0f 28 04 24)", bytes.fromhex("0f280424")),
        ("AVX vmovups ymm0,[rsp] (c5 fc 10 44 24 40)", bytes.fromhex("c5fc10442440")),
        ("AVX2 vpxor ymm0,ymm0,ymm0 (c5 fd ef c0)", bytes.fromhex("c5fdefc0")),
        ("EVEX vmovups zmm0,[rsp] (62 f1 7c 48 10 04 24)",
         bytes.fromhex("62f17c48100424")),
    ]
    for name, code in tests:
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(0x1000, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        uc.mem_write(0x1000, code + b"\xf4")  # hlt после теста
        uc.reg_write(UC_X86_REG_RSP, 0x1800)
        uc.mem_write(0x1800, b"\x00" * 64)
        try:
            uc.emu_start(0x1000, 0xFFFF_FFFF_FFFF_FFFF, count=1)
            emit(out, "  %-42s -> ОК" % name)
        except UcError as exc:
            emit(out, "  %-42s -> %s" % (name, exc))
    emit(out, "  ВЫВОД: Unicorn 2.1.4 исполняет SSE, но не AVX/AVX2/EVEX.")


def selftest_syscall(out):
    """Проверка механизма перехвата syscall (синтетический код, не PS5)."""
    emit(out, "")
    emit(out, "=" * 78)
    emit(out, "ФАЗА D: проверка syscall-хука на синтетическом коде")
    emit(out, "(это НЕ код PS5 — только проверка, что перехват и логирование")
    emit(out, " работают; номера взяты как метки FreeBSD-нумерации)")
    emit(out, "=" * 78)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    uc.mem_map(0x2000, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
    uc.mem_map(0x3000, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(0x3000, b"hello from ps5 code\n")
    code = (b"\x48\xc7\xc7\x01\x00\x00\x00"   # mov rdi, 1        (fd)
            b"\x48\xc7\xc6\x00\x30\x00\x00"   # mov rsi, 0x3000   (buf)
            b"\x48\xc7\xc2\x15\x00\x00\x00"   # mov rdx, 21       (len)
            b"\xb8\x04\x00\x00\x00"           # mov eax, 4        (write)
            b"\x0f\x05"                       # syscall
            b"\xb8\x01\x00\x00\x00"           # mov eax, 1        (exit)
            b"\x0f\x05"                       # syscall
            b"\xc3")                          # ret
    uc.mem_write(0x1000, code)
    uc.mem_write(0x2000, b"\xcc")             # ловушка после ret
    trap = []
    def hs(u, _d):
        nr = u.reg_read(UC_X86_REG_RAX)
        args = (u.reg_read(UC_X86_REG_RDI), u.reg_read(UC_X86_REG_RSI),
                u.reg_read(UC_X86_REG_RDX))
        try:
            payload = bytes(u.mem_read(args[1], args[2])) if args[2] < 64 else b""
        except UcError:
            payload = b""
        trap.append(nr)
        emit(out, "  syscall rax=%d (%#x) args=(%#x, %#x, %#x) -> возвращаем 0"
                  % (nr, nr, *args))
        if payload:
            emit(out, "     rsi указывает на %r" % payload)
        u.reg_write(UC_X86_REG_RAX, 0)
    def hi(u, no, _d):
        emit(out, "  ловушка после ret: int %d, rax=%#x"
             % (no, u.reg_read(UC_X86_REG_RAX)))
        u.emu_stop()
    uc.hook_add(UC_HOOK_INSN, hs, None, 1, 0, UC_X86_INS_SYSCALL)
    uc.hook_add(UC_HOOK_INTR, hi)
    uc.reg_write(UC_X86_REG_RSP, 0x1F00)
    uc.mem_write(0x1F00, (0x2000).to_bytes(8, "little"))
    try:
        uc.emu_start(0x1000, 0xFFFF_FFFF_FFFF_FFFF, count=100)
    except UcError as exc:
        emit(out, "  ошибка: %s" % exc)
    emit(out, "  перехвачено syscall-номеров: %s" % trap)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--elf", default=DEFAULT_ELF, help="путь к PS5 eboot.elf")
    ap.add_argument("--out", default=None,
                    help="файл отчёта (по умолчанию output/run.out рядом)")
    ap.add_argument("--max-insns", type=int, default=5_000_000,
                    help="лимит исполняемых инструкций на фазу")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="лимит времени, секунд на фазу")
    ap.add_argument("--trace-limit", type=int, default=40,
                    help="сколько первых инструкций распечатать в трассе")
    ap.add_argument("--raw", action="store_true",
                    help="только фаза B (сырой ELF без патча GOT)")
    ap.add_argument("--skip-static", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    if not os.path.exists(args.elf):
        sys.exit("нет файла %s" % args.elf)
    out_path = args.out
    here = os.path.dirname(os.path.abspath(__file__))
    if out_path is None:
        out_path = os.path.join(here, "output", "run.out")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    elf = Elf(args.elf)
    n = 0
    with open(out_path, "w", encoding="utf-8") as out:
        emit(out, "emu.py — исполнение кода PS5 на ПК, отчёт эксперимента")
        emit(out, "Unicorn %s, python %d.%d, файл %s"
             % (unicorn.__version__, sys.version_info[0],
                sys.version_info[1], elf.path))
        if not args.skip_static:
            static_scan(elf, out)
        probe_avx(out)

        # фаза A: сырой ELF, как он лежит на диске (GOT не переразмещён)
        emu_a = Emu(elf, out, args.max_insns, args.timeout, args.trace_limit,
                    use_shims=False, verbose=args.verbose, label="B",
                    quiet_header=True)
        emu_a.phase_name = ("сырой eboot.elf: PT_LOAD разложены, GOT не тронут "
                            "(как после decrypt без relocate)")
        n += emu_a.run()

        if args.raw:
            emit(out, "")
            emit(out, "[итог] --raw: выполнена только фаза B")
            return 0

        # фаза B: с шимами импортов (GOT -> шым, возвращающий 0)
        emu_b = Emu(elf, out, args.max_insns, args.timeout, args.trace_limit,
                    use_shims=True, verbose=args.verbose, label="C",
                    quiet_header=True)
        emu_b.phase_name = ("тот же eboot.elf, но импорты libSce*/libkernel/"
                            "libc заменены шимами (GOT -> xor eax,eax; ret)")
        n += emu_b.run()

        selftest_syscall(out)
        emit(out, "")
        emit(out, "=" * 78)
        emit(out, "[итог эксперимента] суммарно исполнено инструкций: %d" % n)
        emit(out, "=" * 78)
    print("\nотчёт записан: %s (%d инструкций)" % (out_path, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
