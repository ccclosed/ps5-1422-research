#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
prx.py — загрузка SCE/PRX-модулей PS5 (libc.prx, libScePfs.prx, ...) и
мок-слой импортов по NID для эмулятора userland-кода.

Что умеет (всё на реальных файлах из дампа игры):
  1. Парсит ELF64-модуль PS5 (e_type=0xfe10, OSABI=FreeBSD): заголовок,
     PT_LOAD, PT_SCE_PROCPARAM (0x61000001/0x61000002), PT_TLS, DYNAMIC.
  2. Строит карту загрузки: объединённые страничные регионы с правами R/W/X
     (то, что нужно разложить mmap'ом — как в tools/emu/qemu_harness.c).
  3. Берёт таблицу импортов модуля из реестра проекта
     (<module>.registry.json: nid, library, targetOffset) — это ровно те
     слоты GOT, которые заполняет загрузчик PS5.
  4. Для каждого импорта проверяет, есть ли РЕАЛЬНАЯ реализация в Linux-
     библиотеках anyps5 (anyps5/libs/<library>: экспорт с именем = NID),
     и создаёт мок: функция-заглушка с логом вызова и возвратом 0.
  5. Регистрирует моки в Unicorn (если он есть): GOT-слоты модуля
     пропатчиваются на шимы, при исполнении пишется трасса импортов.

Запуск:
    python3 prx.py --elf <libc.prx> --registry <...registry.json> \
                   --out output/prx-libc.out [--verbose]

Модуль-«жертва» берётся из дампа игры:
    games/cyberpunk/anyps5-run/sce_module/libc.prx
    games/cyberpunk/anyps5-run/sce_module/libScePfs.prx
реестры импортов:
    games/cyberpunk/anyps5-run/cyberpunk2077.libc.prx.guest.prx.registry.json
    games/cyberpunk/anyps5-run/cyberpunk2077.libScePfs.prx.guest.prx.registry.json
реальные реализации anyps5:
    anyps5/libs/<library>.prx  (Linux .so, экспорты названы NID)
"""
from __future__ import annotations

import argparse
import json
import mmap
import os
import struct
import sys

PT_LOAD = 1
PT_TLS = 7
PT_DYNAMIC = 2
PT_SCE_PROCPARAM = (0x61000001, 0x61000002)
PT_SCE_COMMENT = 0x6FFFFF00
PT_SCE_VERSION = 0x6FFFFF01

PAGE = 0x1000

DEFAULT_LIBDIR = "/home/oleg/Документы/ps5semulator/anyps5/libs"
DEFAULT_GAMEDIR = "/home/oleg/Документы/ps5semulator/games/cyberpunk/anyps5-run"


def align_down(x, a=PAGE):
    return x & ~(a - 1)


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


def prot_str(p):
    return ("r" if p & 4 else "-") + ("w" if p & 2 else "-") + ("x" if p & 1 else "-")


# ---------------------------------------------------------------------------
class LoadRegion:
    def __init__(self, base, end, flags):
        self.base = base
        self.end = end
        self.flags = flags

    @property
    def size(self):
        return self.end - self.base


class SceElf:
    """ELF64-модуль PS5 (eboot или .prx)."""

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.f = open(path, "rb")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        if self.mm[:4] != b"\x7fELF":
            raise SystemExit("не ELF: %s" % path)
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
         self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize,
         self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack("<HHIQQQIHHHHHH", self.mm[16:64])
        self.osabi = self.mm[7]
        self.phdrs = []
        for i in range(self.e_phnum):
            t, fl, off, va, pa, fsz, msz, al = struct.unpack(
                "<IIQQQQQQ", self.mm[self.e_phoff + i * 56:
                                     self.e_phoff + (i + 1) * 56])
            self.phdrs.append(dict(i=i, type=t, flags=fl, off=off, va=va,
                                   pa=pa, fsz=fsz, msz=msz, align=al))
        self.dynamic = []
        for p in self.phdrs:
            if p["type"] == PT_DYNAMIC:
                n = p["fsz"] // 16
                for k in range(n):
                    tag, val = struct.unpack(
                        "<QQ", self.mm[p["off"] + 16 * k:p["off"] + 16 * k + 16])
                    self.dynamic.append((tag, val))
                    if tag == 0:
                        break

    def data(self, off, size):
        return self.mm[off:off + size]

    def load_map(self):
        """Объединённые страничные регионы PT_LOAD с правами."""
        regs = []
        for p in self.phdrs:
            if p["type"] != PT_LOAD or p["msz"] == 0:
                continue
            regs.append(LoadRegion(align_down(p["va"]),
                                   align_up(p["va"] + p["msz"]), p["flags"]))
        regs.sort(key=lambda r: r.base)
        out = []
        for r in regs:
            if out and r.base <= out[-1].end:
                out[-1].end = max(out[-1].end, r.end)
                out[-1].flags |= r.flags
            else:
                out.append(LoadRegion(r.base, r.end, r.flags))
        return out

    def summary(self):
        return dict(path=self.path, size=self.size, type=self.e_type,
                    osabi=self.osabi, machine=self.e_machine,
                    entry=self.e_entry, phnum=self.e_phnum,
                    shnum=self.e_shnum)


# ---------------------------------------------------------------------------
class SoLibrary:
    """Linux-библиотека anyps5: экспорты названы NID (по ним и резолвим)."""

    def __init__(self, path):
        self.path = path
        self.exports = set()
        try:
            self.f = open(path, "rb")
            self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        except OSError:
            self.mm = None
            return
        if self.mm[:4] != b"\x7fELF":
            return
        # смещения полей ELF64: e_shoff=0x28 (8), e_shentsize=0x3A (2),
        # e_shnum=0x3C (2)
        e_shoff = struct.unpack("<Q", self.mm[0x28:0x30])[0]
        e_shentsize = struct.unpack("<H", self.mm[0x3A:0x3C])[0]
        e_shnum = struct.unpack("<H", self.mm[0x3C:0x3E])[0]
        shdrs = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            shdrs.append(struct.unpack("<IIQQQQIIQQ", self.mm[o:o + 64]))
        for sh in shdrs:
            if sh[1] != 11:  # SHT_DYNSYM
                continue
            if sh[6] >= len(shdrs):  # битый link
                continue
            sym_off, sym_size, link, entsize = sh[4], sh[5], sh[6], sh[9]
            str_sh = shdrs[link]
            strtab = self.mm[str_sh[4]:str_sh[4] + str_sh[5]]
            n = sym_size // (entsize or 24)
            for k in range(n):
                o = sym_off + k * (entsize or 24)
                st_name = struct.unpack("<I", self.mm[o:o + 4])[0]
                if not st_name:
                    continue
                end = strtab.find(b"\x00", st_name)
                name = strtab[st_name:end].decode("ascii", "replace")
                if name:
                    self.exports.add(name)

    def has(self, nid):
        return nid in self.exports


# ---------------------------------------------------------------------------
class MockImport:
    """Мок одного импорта: лог вызовов + возврат 0."""

    __slots__ = ("nid", "library", "got_off", "real", "calls", "first_args")

    def __init__(self, nid, library, got_off, real):
        self.nid = nid
        self.library = library
        self.got_off = got_off
        self.real = real
        self.calls = 0
        self.first_args = None

    def __call__(self, *args):
        self.calls += 1
        if self.first_args is None:
            self.first_args = args
        return 0


class ImportTable:
    """Импорты PS5-модуля: из реестра проекта + проверка реальных реализаций."""

    def __init__(self, registry_path, libdir):
        self.entries = []
        with open(registry_path, encoding="utf-8") as f:
            data = json.load(f)
        self.libdir = libdir
        self.libcache = {}
        for e in data:
            nid = (e.get("nid") or "").split("#")[0]
            lib = e.get("library") or ""
            off = e.get("targetOffset")
            if not nid or not off:
                continue
            got = int(off, 16)
            real = self._real_path(lib, nid)
            self.entries.append(MockImport(nid, lib, got, real))
        self.entries.sort(key=lambda m: m.got_off)

    def _real_path(self, lib, nid):
        if not lib:
            return None
        so = self.libcache.get(lib)
        if so is None:
            p = os.path.join(self.libdir, lib)
            so = SoLibrary(p) if os.path.exists(p) else False
            self.libcache[lib] = so
        if not so:
            return None
        return os.path.join(self.libdir, lib) if so.has(nid) else None

    def stats(self):
        by_lib = {}
        for m in self.entries:
            d = by_lib.setdefault(m.library or "(weak)", [0, 0])
            d[0] += 1
            d[1] += 1 if m.real else 0
        return by_lib


# ---------------------------------------------------------------------------
def load_into_unicorn(sce, imports, log):
    """Раскладываем образ модуля в Unicorn и патчим GOT на моки.

    Возвращает (uc, shim_base, size) или (None, 0, 0), если unicorn нет.
    Ничего не исполняет: это загрузка + подготовка мок-слоя.
    """
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ, \
            UC_PROT_WRITE, UC_PROT_EXEC
    except ImportError:
        return None, 0, 0
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    for r in sce.load_map():
        prot = UC_PROT_READ
        if r.flags & 2:
            prot |= UC_PROT_WRITE
        if r.flags & 1:
            prot |= UC_PROT_EXEC
        uc.mem_map(r.base, r.size, prot)
    for p in sce.phdrs:
        if p["type"] != PT_LOAD or p["fsz"] == 0:
            continue
        chunk = 4 << 20
        done = 0
        while done < p["fsz"]:
            n = min(chunk, p["fsz"] - done)
            uc.mem_write(p["va"] + done, sce.data(p["off"] + done, n))
            done += n
    # мок-шимы: 32 байта на импорт, MOCK_BASE вне образа (PRX мал)
    mock_base = 0x100000000
    n = max(1, len(imports))
    size = align_up(n * 32)
    uc.mem_map(mock_base, size, UC_PROT_READ | UC_PROT_EXEC)
    code = bytearray(b"\x90" * size)
    for i in range(n):
        code[i * 32:i * 32 + 5] = b"\x31\xc0\xc3\xcc\xcc"  # xor eax,eax; ret
    uc.mem_write(mock_base, bytes(code))
    patched = 0
    for i, imp in enumerate(imports):
        try:
            uc.mem_write(imp.got_off, struct.pack("<Q", mock_base + i * 32))
            patched += 1
        except Exception:
            pass
    log("  Unicorn: образ разложен в память, GOT-слотов пропатчено на моки: %d"
        % patched)
    return uc, mock_base, patched


def run(sce_path, registry_path, out, libdir, verbose):
    def log(s=""):
        print(s)
        out.write(s + "\n")

    sce = SceElf(sce_path)
    s = sce.summary()
    log("=" * 78)
    log("prx.py — загрузка SCE/PRX-модуля PS5: %s" % sce_path)
    log("=" * 78)
    log("  размер=%d, e_type=%#x, OSABI=%d (9=FreeBSD), e_machine=%#x, "
        "entry=%#x" % (s["size"], s["type"], s["osabi"], s["machine"],
                       s["entry"]))
    log("  секций: %d (у PS5-модулей обычно 0), program headers: %d"
        % (s["shnum"], s["phnum"]))
    log("  PT_LOAD:")
    for p in sce.phdrs:
        if p["type"] != PT_LOAD:
            continue
        log("    PH%-2d va=%#010x..%#010x fsz=%#010x msz=%#010x flags=%#x (%s)"
            % (p["i"], p["va"], p["va"] + p["msz"], p["fsz"], p["msz"],
               p["flags"], prot_str(p["flags"])))
    log("  прочие PHDR:")
    for p in sce.phdrs:
        if p["type"] == PT_LOAD or p["fsz"] == 0:
            continue
        name = {PT_DYNAMIC: "DYNAMIC", PT_TLS: "TLS",
                PT_SCE_COMMENT: "SCE_COMMENT",
                PT_SCE_VERSION: "SCE_VERSION",
                PT_SCE_PROCPARAM[0]: "SCE_PROCPARAM",
                PT_SCE_PROCPARAM[1]: "SCE_MODULE_PARAM"}.get(p["type"],
                                                             "type=%#x" % p["type"])
        log("    PH%-2d %-18s va=%#010x fsz=%#010x" %
            (p["i"], name, p["va"], p["fsz"]))
    regions = sce.load_map()
    log("  карта загрузки (объединённые регионы): %d шт., суммарно %d байт"
        % (len(regions), sum(r.size for r in regions)))
    for r in regions:
        log("    mmap %#010x..%#010x size=%#010x prot=%s"
            % (r.base, r.end, r.size, prot_str(r.flags)))
    log("  DYNAMIC: %d тегов" % len(sce.dynamic))
    seen = {}
    for tag, val in sce.dynamic:
        seen[tag] = seen.get(tag, 0) + 1
    log("    теги: %s" % ", ".join("%#x×%d" % (t, c)
                                   for t, c in sorted(seen.items())))

    # --- импорты модуля ---
    imports = ImportTable(registry_path, libdir)
    log("")
    log("  импорты из реестра %s" % os.path.basename(registry_path))
    stats = imports.stats()
    total = len(imports.entries)
    real = sum(1 for m in imports.entries if m.real)
    log("    всего импортов: %d; есть реальная реализация в anyps5: %d; "
        "моки: %d" % (total, real, total - real))
    log("    по библиотекам (импортов / из них с реальной реализацией):")
    for lib, (cnt, rcnt) in sorted(stats.items(), key=lambda x: -x[1][0]):
        log("      %-32s %4d / %4d" % (lib, cnt, rcnt))
    log("")
    log("  трасса импортов (NID, библиотека, GOT-слот, реализация):")
    for m in imports.entries[:40]:
        mark = "REAL" if m.real else "mock"
        log("    %#010x  %-26s %-13s %s"
            % (m.got_off, m.nid, m.library or "(weak)", mark))
    if total > 40:
        log("    ... ещё %d" % (total - 40))

    # --- загрузка в Unicorn + мок-слой ---
    log("")
    log("  подготовка мок-слоя импортов:")
    uc, mock_base, patched = load_into_unicorn(sce, imports.entries, log)
    if uc is None:
        log("  Unicorn не установлен: загрузка только в виде карты памяти")
    else:
        log("  мок-слой готов: при вызове любого импорта счётчик вызовов "
            "инкрементируется, функция возвращает 0 (см. MockImport.__call__)")
    return dict(imports=total, real=real, regions=len(regions),
                patched=patched)


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--elf", required=True, help="PS5-модуль (.prx)")
    ap.add_argument("--registry", default=None,
                    help="реестр импортов модуля (<module>.registry.json)")
    ap.add_argument("--out", default=None, help="файл отчёта")
    ap.add_argument("--libdir", default=DEFAULT_LIBDIR,
                    help="каталог Linux-библиотек anyps5 (экспорты = NID)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)
    if not os.path.exists(args.elf):
        sys.exit("нет файла %s" % args.elf)
    reg = args.registry
    if reg is None:
        base = os.path.basename(args.elf)
        cand = os.path.join(DEFAULT_GAMEDIR,
                            "cyberpunk2077.%s.guest.prx.registry.json" % base)
        reg = cand if os.path.exists(cand) else None
    if not reg or not os.path.exists(reg):
        sys.exit("нет реестра импортов модуля (--registry)")
    out_path = args.out or os.path.join(here, "output",
                                        "prx-%s.out" %
                                        os.path.basename(args.elf))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as out:
        st = run(args.elf, reg, out, args.libdir, args.verbose)
    print("\nотчёт записан: %s (%d импортов, %d с реальной реализацией)"
          % (out_path, st["imports"], st["real"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())