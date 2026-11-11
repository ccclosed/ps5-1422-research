#!/usr/bin/env python3
"""extract_imports.py — вытащить интерфейсный профиль PS5 ELF-модуля.

Зачем: у нас есть развёрнутые (plain ELF) модули двух SDK-эпох — Cyberpunk (SDK 8.60)
и Code Violet (SDK 11.00). Нужен машинный профиль каждого модуля: какие библиотеки он
импортирует, какие NID у него есть, какие syscall-обёртки он содержит. Тогда дельту
между эпохами можно считать кодом, а не глазами.

Что извлекается
---------------
1. `build`   — из сегмента PT_SCE_COMMENT (0x6FFFFF00): magic `PATHP`, путь сборки
               (`W:/Build/<BUILDID>/sys/internal/...`) и имя модуля. Это единственный
               достоверный источник «какой SDK/сборка».
2. `libver`  — из PT_SCE_LIBVERSION (0x6FFFFF01): имя библиотеки + 4 версионных поля.
3. `nids`    — закодированные NID-записи PS5. Формат записи — 16 байт:
                   [0x00] 0x00-разделитель
                   [+1..+11] 11 символов base64-подобного алфавита (сам NID)
                   [+12] '#'  [+13] версия библиотеки (буква A..Z)
                   [+14] '#'  [+15] версия модуля (буква A..Z)
               PS5, в отличие от PS4, несёт ДВА версионных суффикса — поэтому запись
               ровно 16 байт. Сканируем по этому шаблону, а не по структуре dynlib:
               структура в перелинкованных модулях смещена, а шаблон устойчив.
4. `libs`    — имена импортируемых библиотек (`lib*.prx` / `lib*`) как NUL-строки.
5. `syscalls`— syscall-обёртки в исполняемых сегментах:
                 a) `b8 <imm32> 0f 05` — mov eax, imm32; syscall
                 b) `0f 05 c3`          — syscall; ret
                 c) `ff 25 <disp32>`    — jmp qword [rip+disp32] (трамплин к импорту)
               Для каждого стаба сохраняем vaddr, размер окна, номер syscall (если
               виден mov eax,imm32), и тип.

Честные границы (важно)
-----------------------
* Привязка NID к библиотеке — **эвристика по близости** к ближайшей строке имени
  библиотеки (`grouping` = "adjacent-name"). Точная привязка требует разбора
  `SceLibEntry`/stub-таблиц, а в перелинкованных модулях их раскладка смещена.
  Поэтому в JSON у каждой группы стоит `confidence`.
* `syscalls` — поиск по байтовым шаблонам; он находит **обёртки**, а не гарантирует,
  что это именно syscall-стаб (может быть обычный вызов). Каждый стаб помечен `kind`.
* Отсутствие PT_SCE_COMMENT = модуль собран без комментария; тогда `build` = null,
  и это не ошибка парсера.

Использование
-------------
    python3 extract_imports.py FILE [FILE ...] --json-out out.json
    python3 extract_imports.py --dir DIR --json-out out.json
    python3 extract_imports.py --selftest
    python3 extract_imports.py --diff profile_a.json profile_b.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field, asdict

PT_LOAD = 1
PT_SCE_COMMENT = 0x6FFFFF00
PT_SCE_LIBVERSION = 0x6FFFFF01
PT_SCE_DYNLIBDATA = 0x61000000
PT_SCE_MODULEPARAM = 0x61000002

# Characters used by the PS5 encoded-NID alphabet. Observed on real modules:
# base64url-ish plus '+' and '-'. We accept a generous set and validate by shape.
NID_CHARS = set(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-_"
)
NID_LEN = 11


# --------------------------------------------------------------------------- #
# ELF
# --------------------------------------------------------------------------- #

@dataclass
class Segment:
    p_type: int
    p_flags: int
    off: int
    vaddr: int
    filesz: int
    memsz: int
    align: int

    @property
    def executable(self) -> bool:
        return bool(self.p_flags & 0x1)


def parse_elf(data: bytes) -> tuple[list[Segment], bool]:
    """Return (segments, is64). Raises ValueError if not an ELF we understand."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF (magic != 7f454c46)")
    is64 = data[4] == 2
    if not is64:
        raise ValueError("only ELF64 is supported")
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    if phentsize != 56:
        raise ValueError(f"unexpected e_phentsize={phentsize}")
    segs = []
    for i in range(phnum):
        base = phoff + i * phentsize
        ph = data[base:base + phentsize]
        if len(ph) < phentsize:
            break
        p_type, p_flags = struct.unpack_from("<II", ph, 0)
        off, vaddr, paddr, filesz, memsz, align = struct.unpack_from("<QQQQQQ", ph, 8)
        segs.append(Segment(p_type, p_flags, off, vaddr, filesz, memsz, align))
    return segs, True


def vaddr_to_off(segs: list[Segment], va: int) -> int | None:
    for s in segs:
        if s.p_type == PT_LOAD and s.vaddr <= va < s.vaddr + s.filesz:
            return s.off + (va - s.vaddr)
    return None


def off_to_vaddr(segs: list[Segment], off: int) -> int | None:
    for s in segs:
        if s.p_type == PT_LOAD and s.off <= off < s.off + s.filesz:
            return s.vaddr + (off - s.off)
    return None


def cstr(data: bytes, off: int, limit: int = 256) -> str:
    end = data.find(b"\x00", off, min(off + limit, len(data)))
    if end < 0:
        end = min(off + limit, len(data))
    return data[off:end].decode("ascii", "replace")


# --------------------------------------------------------------------------- #
# profile extraction
# --------------------------------------------------------------------------- #

@dataclass
class NidRecord:
    nid: str            # 11-char encoded NID
    lib_version: str    # single letter, '' if absent
    mod_version: str
    vaddr: int          # where the record lives (useful for cross-checks)
    dense: bool = False  # True if part of a run of >=3 records 16 bytes apart

    def key(self) -> str:
        return f"{self.nid}#{self.lib_version}#{self.mod_version}"


@dataclass
class ModuleProfile:
    path: str
    size: int
    build_path: str | None = None
    build_id: str | None = None
    module_name: str | None = None
    libvers: list[dict] = field(default_factory=list)
    libs: list[str] = field(default_factory=list)
    nids: list[NidRecord] = field(default_factory=list)
    nid_groups: list[dict] = field(default_factory=list)
    syscall_stubs: list[dict] = field(default_factory=list)
    segments: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def extract_build(data: bytes, segs: list[Segment]) -> tuple[str | None, str | None, str | None]:
    """PT_SCE_COMMENT: magic 'PATHP', then a length and the build path."""
    for s in segs:
        if s.p_type != PT_SCE_COMMENT or s.filesz == 0:
            continue
        blob = data[s.off:s.off + s.filesz]
        if not blob.startswith(b"PATHP"):
            continue
        # PATHP + 3 pad bytes, then u32 length, then the string
        ln = struct.unpack_from("<I", blob, 8)[0] if len(blob) >= 12 else 0
        text = blob[12:12 + ln] if 0 < ln <= len(blob) - 12 else blob[12:]
        text = text.rstrip(b"\x00").decode("ascii", "replace")
        build_id = None
        m = re.search(r"/Build/([^/]+)/", text)
        if m:
            build_id = m.group(1)
        module_name = None
        m2 = re.search(r"/([^/]+\.prx)$", text) or re.search(r"/([^/]+)$", text)
        if m2:
            module_name = m2.group(1)
        return text, build_id, module_name
    return None, None, None


def extract_libvers(data: bytes, segs: list[Segment]) -> list[dict]:
    """PT_SCE_LIBVERSION (0x6FFFFF01): 'libc:' style name + numeric version fields."""
    out = []
    for s in segs:
        if s.p_type != PT_SCE_LIBVERSION or s.filesz == 0:
            continue
        blob = data[s.off:s.off + s.filesz]
        # name is a NUL-terminated string followed by version words; be tolerant
        name = cstr(blob, 0, 64)
        if not name or not name.isprintable():
            continue
        rest = blob[len(name) + 1:]
        words = list(struct.unpack_from("<" + "I" * (len(rest) // 4), rest)) if len(rest) >= 4 else []
        out.append({"name": name, "fields": words,
                    "name_hex": blob[:len(name)].hex()})
    return out


def extract_nids(data: bytes, segs: list[Segment]) -> list[NidRecord]:
    """Scan for 16-byte PS5 encoded-NID records."""
    recs: list[NidRecord] = []
    seen = set()
    n = len(data)
    i = 0
    while True:
        j = data.find(b"\x00", i)
        if j < 0 or j + 16 > n:
            break
        i = j + 1
        chunk = data[j:j + 16]
        if chunk[0] != 0:
            continue
        body = chunk[1:12]
        if not all(c in NID_CHARS for c in body):
            continue
        # require at least one letter and one digit: NIDs are mixed
        if not (any(65 <= c <= 90 or 97 <= c <= 122 for c in body) and
                any(48 <= c <= 57 for c in body)):
            continue
        if chunk[12] != 0x23 or chunk[14] != 0x23:      # '#'
            continue
        lv, mv = chr(chunk[13]), chr(chunk[15])
        if not (lv.isalpha() and mv.isalpha()):
            continue
        va = off_to_vaddr(segs, j)
        if va is None:
            continue
        key = (body, lv, mv)
        if key in seen:
            continue
        seen.add(key)
        recs.append(NidRecord(body.decode("ascii"), lv, mv, va))
    mark_density(recs)
    return recs


def mark_density(recs: list[NidRecord], min_run: int = 3) -> None:
    """A record inside a run of >= min_run records spaced exactly 16 bytes apart is
    part of a real NID table; an isolated hit may be a coincidence in code/data.

    Measured on our modules: libc.prx (SDK 11.00) has 2466/2623 records in such
    runs, libSceNpCppWebApi.prx 33947/36223 - i.e. the tables are contiguous.
    """
    if not recs:
        return
    recs.sort(key=lambda r: r.vaddr)
    run = 1
    for i in range(1, len(recs)):
        if recs[i].vaddr - recs[i - 1].vaddr == 16:
            run += 1
        else:
            if run >= min_run:
                for k in range(i - run, i):
                    recs[k].dense = True
            run = 1
    if run >= min_run:
        for k in range(len(recs) - run, len(recs)):
            recs[k].dense = True


def extract_libs(data: bytes, segs: list[Segment]) -> list[tuple[str, int]]:
    """NUL-terminated library names, with their vaddr."""
    out = []
    for m in re.finditer(rb"lib[A-Za-z0-9_]+(?:\.prx)?\x00", data):
        off = m.start()
        name = m.group(0)[:-1].decode("ascii", "replace")
        # skip absurdly long matches and obvious noise
        if len(name) < 4 or len(name) > 64:
            continue
        va = off_to_vaddr(segs, off)
        if va is None:
            continue
        out.append((name, va))
    # dedupe by (name, va)
    seen = set()
    uniq = []
    for name, va in out:
        if (name, va) in seen:
            continue
        seen.add((name, va))
        uniq.append((name, va))
    return uniq


def group_nids_by_lib(nids: list[NidRecord], libs: list[tuple[str, int]]) -> list[dict]:
    """Heuristic: a NID record belongs to the nearest library name that precedes it.

    Confidence is 'high' when the record sits within 4 KiB after the name and no
    other name is closer; 'low' otherwise. Documented in the module docstring.
    """
    if not libs:
        return [{"lib": None, "confidence": "none", "count": len(nids),
                 "nids": [n.key() for n in nids]}]
    libs_sorted = sorted(libs, key=lambda x: x[1])
    buckets: dict[str, list[dict]] = {}
    for rec in sorted(nids, key=lambda r: r.vaddr):
        prior = [l for l in libs_sorted if l[1] <= rec.vaddr]
        if not prior:
            name, dist = None, None
        else:
            name, lva = prior[-1]
            dist = rec.vaddr - lva
        conf = "high" if (dist is not None and dist <= 4096) else "low"
        if dist is None:
            conf = "none"
        buckets.setdefault(name or "<before-first-lib>", []).append(
            {"key": rec.key(), "vaddr": rec.vaddr, "dist": dist, "confidence": conf})
    groups = []
    for name, items in buckets.items():
        high = sum(1 for i in items if i["confidence"] == "high")
        groups.append({
            "lib": name,
            "count": len(items),
            "high_confidence": high,
            "confidence": "high" if high >= len(items) * 0.8 else
                          ("medium" if high else "low"),
            "nids": [i["key"] for i in items],
        })
    return sorted(groups, key=lambda g: (-g["count"]))


SYSCALL_PATTERNS = [
    # mov eax, imm32 ; syscall
    (re.compile(rb"\xb8(.{4})\x0f\x05", re.S), "mov-eax-syscall"),
    # syscall ; ret
    (re.compile(rb"\x0f\x05\xc3", re.S), "syscall-ret"),
    # jmp qword [rip+disp32]
    (re.compile(rb"\xff\x25(.{4})", re.S), "jmp-rip-import"),
]


def extract_syscall_stubs(data: bytes, segs: list[Segment], limit: int = 4000) -> list[dict]:
    """Pattern-scan executable segments for syscall wrappers / import trampolines."""
    out = []
    for s in segs:
        if not (s.p_type == PT_LOAD and s.executable and s.filesz):
            continue
        blob = data[s.off:s.off + s.filesz]
        for pattern, kind in SYSCALL_PATTERNS:
            for m in pattern.finditer(blob):
                va = s.vaddr + m.start()
                entry = {"vaddr": va, "kind": kind, "seg": f"0x{s.vaddr:x}"}
                if kind == "mov-eax-syscall":
                    num = struct.unpack_from("<I", m.group(1), 0)[0]
                    # a plausible syscall number: small positive
                    if not (0 < num < 0x4000):
                        continue
                    entry["syscall_number"] = num
                if kind == "jmp-rip-import":
                    disp = struct.unpack_from("<i", m.group(1), 0)[0]
                    target = va + 6 + disp
                    entry["import_slot_va"] = target
                    toff = vaddr_to_off(segs, target)
                    if toff is not None and toff + 8 <= len(data):
                        entry["import_slot_value"] = struct.unpack_from("<Q", data, toff)[0]
                out.append(entry)
                if len(out) >= limit:
                    return out
    return out


def profile_file(path: str) -> ModuleProfile:
    data = open(path, "rb").read()
    prof = ModuleProfile(path=path, size=len(data))
    try:
        segs, _ = parse_elf(data)
    except ValueError as exc:
        prof.notes.append(f"не разобран: {exc}")
        return prof

    prof.segments = [{"type": hex(s.p_type), "off": s.off, "vaddr": s.vaddr,
                      "filesz": s.filesz, "flags": s.p_flags} for s in segs]

    bp, bid, mname = extract_build(data, segs)
    prof.build_path, prof.build_id, prof.module_name = bp, bid, mname
    prof.libvers = extract_libvers(data, segs)
    libs = extract_libs(data, segs)
    prof.libs = sorted({n for n, _ in libs})
    prof.nids = extract_nids(data, segs)
    prof.nid_groups = group_nids_by_lib(prof.nids, libs)
    prof.syscall_stubs = extract_syscall_stubs(data, segs)
    return prof


def profile_to_json(p: ModuleProfile) -> dict:
    d = asdict(p)
    d["nid_records"] = len(p.nids)
    d["nid_records_dense"] = sum(1 for n in p.nids if n.dense)
    # `nids` = only table-confirmed records; isolated hits are kept aside.
    d["nids"] = [n.key() for n in p.nids if n.dense]
    d["nids_isolated"] = [n.key() for n in p.nids if not n.dense]
    return d


# --------------------------------------------------------------------------- #
# diff
# --------------------------------------------------------------------------- #

def diff_profiles(a: ModuleProfile, b: ModuleProfile) -> dict:
    """Delta of interface surface between two module profiles."""
    na = {n.key() for n in a.nids if n.dense}
    nb = {n.key() for n in b.nids if n.dense}
    la, lb = set(a.libs), set(b.libs)
    sa = {s.get("syscall_number") for s in a.syscall_stubs if "syscall_number" in s}
    sb = {s.get("syscall_number") for s in b.syscall_stubs if "syscall_number" in s}
    return {
        "a": {"path": a.path, "build_id": a.build_id, "module": a.module_name,
              "nids": len(na), "libs": len(la), "syscalls": len(sa)},
        "b": {"path": b.path, "build_id": b.build_id, "module": b.module_name,
              "nids": len(nb), "libs": len(lb), "syscalls": len(sb)},
        "nids_only_a": sorted(na - nb),
        "nids_only_b": sorted(nb - na),
        "nids_common": len(na & nb),
        "libs_only_a": sorted(la - lb),
        "libs_only_b": sorted(lb - la),
        "libs_common": sorted(la & lb),
        "syscalls_only_a": sorted(x for x in sa - sb if x is not None),
        "syscalls_only_b": sorted(x for x in sb - sa if x is not None),
        "syscalls_common": len(sa & sb),
    }


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

def selftest() -> int:
    """Build a synthetic PS5-ish ELF and require every extractor to find its data."""
    ok = 0
    total = 0

    def check(name, cond, extra=""):
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
            print(f"  [PASS] {name} {extra}")
        else:
            print(f"  [FAIL] {name} {extra}")

    print("SELFTEST: синтетический модуль")
    # --- build a minimal ELF64 with one LOAD segment + PATHP comment ---
    body = bytearray(0x1000)
    off_load = 0x100
    body[off_load:off_load + 3] = b"\x90\x90\x90"
    # encoded NID records at 0x200
    nid_names = [b"gq7cBT0xTSU", b"XmRc0eQ2lQ0", b"9x5Bf4kz1Qo"]
    p = 0x200
    for nm in nid_names:
        rec = b"\x00" + nm + b"#A#B"
        assert len(rec) == 16
        body[p:p + 16] = rec
        p += 16
    # library names
    body[0x300:0x300 + 12] = b"libkernel\x00\x00\x00"
    body[0x318:0x318 + 10] = b"libScePfs\x00"
    # syscall stub: mov eax, 5 ; syscall ; ret
    body[0x400:0x400 + 8] = b"\xb8\x05\x00\x00\x00\x0f\x05\xc3"
    # build path in PATHP comment area
    path = b"W:/Build/J03547016/sys/internal/usermode/src/libc/Prospero_Release/libc.prx"
    pat = b"PATHP\x00\x00\x00" + struct.pack("<I", len(path)) + path + b"\x00"

    phoff = 0x40
    phentsize = 56
    phnum = 2
    ehdr = bytearray(0x40)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2
    struct.pack_into("<Q", ehdr, 0x20, phoff)
    struct.pack_into("<H", ehdr, 0x36, phentsize)
    struct.pack_into("<H", ehdr, 0x38, phnum)
    seg_off = 0x1000
    phs = bytearray(phentsize * phnum)
    # LOAD segment covering body
    struct.pack_into("<II", phs, 0, PT_LOAD, 5)          # R+X
    struct.pack_into("<QQQQQQ", phs, 8, off_load, 0x0, 0, len(body), len(body), 0x10)
    # комментарий дописывается ПОСЛЕ тела, поэтому его смещение вычисляется,
    # а не берётся наугад (первая версия селтеста брала 0x1000 и падала —
    # ровно поэтому селтест и нужен).
    comment_off = len(ehdr) + len(phs) + len(body)
    struct.pack_into("<II", phs, phentsize, PT_SCE_COMMENT, 4)
    struct.pack_into("<QQQQQQ", phs, phentsize + 8, comment_off, 0x200000, 0, len(pat), len(pat), 4)

    image = bytes(ehdr) + bytes(phs) + bytes(body) + pat
    tmp = "/tmp/extract_imports_selftest.elf"
    open(tmp, "wb").write(image)

    prof = profile_file(tmp)
    check("ELF разобран", len(prof.segments) == 2, f"(segments={len(prof.segments)})")
    check("PT_SCE_COMMENT → build_id", prof.build_id == "J03547016", f"(build_id={prof.build_id})")
    check("имя модуля из пути", prof.module_name == "libc.prx", f"({prof.module_name})")
    check("NID-записи найдены", len(prof.nids) == 3, f"(nids={len(prof.nids)})")
    check("NID декодирован верно",
          {n.nid for n in prof.nids} == {b"gq7cBT0xTSU".decode(), b"XmRc0eQ2lQ0".decode(), b"9x5Bf4kz1Qo".decode()})
    check("версии NID распознаны", all(n.lib_version == "A" and n.mod_version == "B" for n in prof.nids))
    check("библиотеки найдены", {"libkernel", "libScePfs"} <= set(prof.libs), f"({prof.libs})")
    sc = [s for s in prof.syscall_stubs if s["kind"] == "mov-eax-syscall"]
    check("syscall-стаб найден", any(s.get("syscall_number") == 5 for s in sc),
          f"(stubs={len(prof.syscall_stubs)})")
    check("группировка NID по библиотекам", len(prof.nid_groups) >= 1)

    os.unlink(tmp)
    print("-" * 70)
    print(f"SELFTEST: {ok}/{total}")
    if ok != total:
        print("SELFTEST: FAIL")
        return 1
    print("SELFTEST: PASSED")
    return 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Профиль интерфейсов PS5 ELF-модуля (импорты/NID/syscall)")
    ap.add_argument("files", nargs="*", help="ELF-модули")
    ap.add_argument("--dir", default="", help="каталог с модулями (*.prx, eboot.bin* — ELF)")
    ap.add_argument("--json-out", default="", help="куда сохранить профили")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--diff", nargs=2, metavar=("A.json", "B.json"),
                    help="дельта двух сохранённых профилей")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if args.diff:
        ja = json.load(open(args.diff[0], encoding="utf-8"))
        jb = json.load(open(args.diff[1], encoding="utf-8"))
        # rebuild minimal profiles for diffing
        def to_prof(j):
            pr = ModuleProfile(path=j["path"], size=j["size"])
            pr.build_id = j.get("build_id")
            pr.module_name = j.get("module_name")
            pr.libs = j.get("libs", [])
            pr.nids = []
            for key in j.get("nids", []):
                parts = key.split("#")
                pr.nids.append(NidRecord(parts[0], parts[1] if len(parts) > 1 else "",
                                          parts[2] if len(parts) > 2 else "", 0))
            pr.syscall_stubs = j.get("syscall_stubs", [])
            return pr
        d = diff_profiles(to_prof(ja), to_prof(jb))
        print(json.dumps(d, ensure_ascii=False, indent=2))
        return 0

    paths = list(args.files)
    if args.dir:
        for name in sorted(os.listdir(args.dir)):
            full = os.path.join(args.dir, name)
            if os.path.isfile(full):
                paths.append(full)
    if not paths:
        print("нечего разбирать: задайте файлы или --dir", file=sys.stderr)
        return 2

    profiles = []
    for p in paths:
        prof = profile_file(p)
        if not args.quiet:
            if prof.notes:
                print(f"{os.path.basename(p):<28} НЕ РАЗОБРАН: {prof.notes[-1]}")
                continue
            dense = sum(1 for n in prof.nids if n.dense)
            sc = sum(1 for s in prof.syscall_stubs if "syscall_number" in s)
            print(f"{os.path.basename(p):<28} build={prof.build_id or '-':<10} "
                  f"nids={dense:<5}(+{len(prof.nids)-dense} изол.) libs={len(prof.libs):<2} "
                  f"tramp={len(prof.syscall_stubs):<4} syscall={sc}")
        profiles.append(profile_to_json(prof))

    if args.json_out:
        json.dump(profiles, open(args.json_out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"\nпрофили: {args.json_out} ({len(profiles)} шт.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))