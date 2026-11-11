#!/usr/bin/env python3
"""
scanner.py - locate FreeBSD/PS5 sysent (system call) tables in kernel images.

A sysent table is an array of fixed-size records.  Every record contains at
least a small argument count and a kernel text pointer to the implementing
function.  The scanner looks for maximal runs of records with a constant
stride, validates every field against structural constraints (argument count
range, canonical kernel pointer, flag bits) and reports the file offset, the
virtual address (when it can be derived from an ELF64 image), the record
stride, the layout name and the number of entries.

The task-specified PS5 record layout is:

    struct sysent {
        uint32_t sy_narg;       /* offset 0  */
        /* 4 bytes padding */
        void    *sy_call;       /* offset 8  */
        void    *sy_auevent;    /* offset 16 */
        uint32_t sy_sysflags;   /* offset 24 */
        /* 4 bytes padding */
    };                          /* sizeof == 32 */

Stock FreeBSD used different layouts; both the 48-byte (FreeBSD 9-12) and the
32-byte (FreeBSD 13+) variants are supported as well, see LAYOUTS below.

Exit status: 0 = at least one table found, 1 = no table found, 2 = error.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

# ---------------------------------------------------------------------------
# tunables
# ---------------------------------------------------------------------------

PTR_LO_DEFAULT = 0xFFFF800000000000
PTR_HI_DEFAULT = 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# record layouts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Field:
    """One member of a sysent record."""

    name: str
    offset: int
    size: int
    kind: str  # "int" or "ptr"

    @property
    def end(self) -> int:
        return self.offset + self.size


class Layout:
    """A concrete in-memory record layout of struct sysent."""

    def __init__(
        self,
        name: str,
        stride: int,
        fmt: str,
        fields: Sequence[Field],
        padding: Sequence[tuple[int, int]],
        description: str,
    ) -> None:
        self.name = name
        self.stride = stride
        self.fmt = fmt
        self.fields = tuple(fields)
        self.padding = tuple(padding)
        self.description = description
        self.st = struct.Struct(fmt)
        self.field_by_name = {f.name: f for f in self.fields}
        self.index = {f.name: i for i, f in enumerate(self.fields)}
        if self.st.size != stride:
            raise ValueError(
                f"layout {name}: format size {self.st.size} != stride {stride}"
            )

    def unpack(self, buf, offset: int):
        return self.st.unpack_from(buf, offset)


# The layout named in the task.  Natural C alignment on x86-64 gives stride 32
# and four bytes of padding after sy_narg and after sy_sysflags.
PS5 = Layout(
    "ps5",
    32,
    "<I4xQQI4x",
    (
        Field("narg", 0, 4, "int"),
        Field("call", 8, 8, "ptr"),
        Field("auevent", 16, 8, "ptr"),
        Field("flags", 24, 4, "int"),
    ),
    ((4, 8), (28, 32)),
    "task-specified PS5 layout: u32 sy_narg, ptr sy_call, ptr sy_auevent, "
    "u32 sy_sysflags; sizeof=32",
)

# Same as PS5 but without sy_sysflags (useful if a firmware build dropped it).
PS5_NOFLAGS = Layout(
    "ps5-nof",
    24,
    "<I4xQQ",
    (
        Field("narg", 0, 4, "int"),
        Field("call", 8, 8, "ptr"),
        Field("auevent", 16, 8, "ptr"),
    ),
    ((4, 8),),
    "PS5 variant without sy_sysflags: u32 sy_narg, ptr sy_call, "
    "ptr sy_auevent; sizeof=24",
)

# Fully packed variant (unaligned 64-bit pointers).  Only used when requested
# explicitly; no normal compiler emits it.
PS5_PACKED = Layout(
    "ps5-packed",
    24,
    "<IQQI",
    (
        Field("narg", 0, 4, "int"),
        Field("call", 4, 8, "ptr"),
        Field("auevent", 12, 8, "ptr"),
        Field("flags", 20, 4, "int"),
    ),
    (),
    "packed PS5 variant: u32 sy_narg, ptr sy_call, ptr sy_auevent, "
    "u32 sy_sysflags; sizeof=24, unaligned pointers",
)

# Stock FreeBSD 9.x .. 12.x, sys/sys/sysent.h.
FREEBSD9 = Layout(
    "freebsd9",
    48,
    "<I4xQH6xQIIII",
    (
        Field("narg", 0, 4, "int"),       # int
        Field("call", 8, 8, "ptr"),       # sy_call_t *
        Field("auevent", 16, 2, "int"),   # au_event_t (u_int16_t)
        Field("systrace", 24, 8, "ptr"),  # systrace_args_func_t
        Field("entry", 32, 4, "int"),     # u_int32_t DTrace entry id
        Field("return", 36, 4, "int"),    # u_int32_t DTrace return id
        Field("flags", 40, 4, "int"),     # u_int32_t
        Field("thrcnt", 44, 4, "int"),    # u_int32_t
    ),
    ((4, 8), (18, 24)),
    "stock FreeBSD 9.3-12.4: int sy_narg, ptr sy_call, u16 sy_auevent, "
    "ptr sy_systrace_args_func, u32 sy_entry/sy_return/sy_flags/sy_thrcnt; "
    "sizeof=48",
)

# Stock FreeBSD 13.x .. 15.x, sys/sys/sysent.h.
FREEBSD13 = Layout(
    "freebsd13",
    32,
    "<QQBBHIII",
    (
        Field("call", 0, 8, "ptr"),       # sy_call_t *
        Field("systrace", 8, 8, "ptr"),   # systrace_args_func_t
        Field("narg", 16, 1, "int"),      # u_int8_t
        Field("flags", 17, 1, "int"),     # u_int8_t
        Field("auevent", 18, 2, "int"),   # au_event_t
        Field("entry", 20, 4, "int"),     # u_int32_t
        Field("return", 24, 4, "int"),    # u_int32_t
        Field("thrcnt", 28, 4, "int"),    # u_int32_t
    ),
    (),
    "stock FreeBSD 13.x-15.x: ptr sy_call, ptr sy_systrace_args_func, "
    "u8 sy_narg, u8 sy_flags, u16 sy_auevent, u32 sy_entry/sy_return/"
    "sy_thrcnt; sizeof=32",
)

LAYOUTS: dict[str, Layout] = {
    layout.name: layout
    for layout in (PS5, PS5_NOFLAGS, PS5_PACKED, FREEBSD9, FREEBSD13)
}

DEFAULT_LAYOUTS = ("ps5", "ps5-nof", "freebsd9", "freebsd13")


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    min_entries: int = 24
    max_narg: int = 24
    max_flags: int = 0xFFFF
    ptr_min: int = PTR_LO_DEFAULT
    ptr_max: int = PTR_HI_DEFAULT
    step: int = 4
    max_tables: int = 8
    allow_null_call: bool = False
    auevent_any: bool = False

    def validate(self) -> None:
        if self.min_entries < 1:
            raise ValueError("--min-entries must be >= 1")
        if self.max_narg < 0 or self.max_narg > 255:
            raise ValueError("--max-narg must be in 0..255")
        if self.step not in (1, 2, 4, 8):
            raise ValueError("--step must be one of 1,2,4,8")
        if self.ptr_min > self.ptr_max:
            raise ValueError("--ptr-min must be <= --ptr-max")
        if self.max_tables < 1:
            raise ValueError("--max-tables must be >= 1")


# ---------------------------------------------------------------------------
# ELF64
# ---------------------------------------------------------------------------

@dataclass
class Segment:
    p_type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)  # PF_X


@dataclass
class Section:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    entsize: int


class Elf64:
    """Minimal little-endian ELF64 reader (program headers, sections, symbols)."""

    def __init__(self, data: bytes, path: str = "<memory>") -> None:
        if len(data) < 64 or data[:4] != b"\x7fELF":
            raise ValueError(f"{path}: not an ELF file")
        if data[4] != 2 or data[5] != 1:
            raise ValueError(
                f"{path}: only little-endian ELF64 is supported "
                f"(EI_CLASS={data[4]}, EI_DATA={data[5]})"
            )
        (
            _ident,
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)

        self.segments: list[Segment] = []
        if self.e_phnum and self.e_phentsize >= 56:
            for i in range(self.e_phnum):
                off = self.e_phoff + i * self.e_phentsize
                if off + 56 > len(data):
                    break
                (
                    p_type,
                    p_flags,
                    p_offset,
                    p_vaddr,
                    p_paddr,
                    p_filesz,
                    p_memsz,
                    p_align,
                ) = struct.unpack_from("<IIQQQQQQ", data, off)
                if p_type == 1:  # PT_LOAD
                    self.segments.append(
                        Segment(
                            p_type, p_flags, p_offset, p_vaddr, p_paddr,
                            p_filesz, p_memsz, p_align,
                        )
                    )

        self.sections: list[Section] = []
        if self.e_shoff and self.e_shnum and self.e_shentsize >= 64:
            raw_sections = []
            for i in range(self.e_shnum):
                off = self.e_shoff + i * self.e_shentsize
                if off + 64 > len(data):
                    break
                raw_sections.append(
                    struct.unpack_from("<IIQQQQIIQQ", data, off)
                )
            shstr = b""
            if 0 <= self.e_shstrndx < len(raw_sections):
                s = raw_sections[self.e_shstrndx]
                shstr = data[s[4]: s[4] + s[5]]
            for (
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                sh_link, _sh_info, _sh_addralign, sh_entsize,
            ) in raw_sections:
                name = _cstr(shstr, sh_name) if shstr else ""
                self.sections.append(
                    Section(
                        name, sh_type, sh_flags, sh_addr, sh_offset,
                        sh_size, sh_link, sh_entsize,
                    )
                )

        self.symbols = _parse_symbols(data, self.sections)

    def segment_for_offset(self, offset: int) -> Optional[Segment]:
        for seg in self.segments:
            if seg.offset <= offset < seg.offset + seg.filesz:
                return seg
        return None

    def vaddr_for_offset(self, offset: int) -> Optional[int]:
        seg = self.segment_for_offset(offset)
        if seg is None:
            return None
        return seg.vaddr + (offset - seg.offset)


class SymbolTable:
    """Address -> symbol name lookup, tolerant to size-less symbols/aliases."""

    def __init__(self, symbols: Iterable[tuple[int, int, str]]) -> None:
        # (value, size, name)
        table = sorted(set(symbols), key=lambda x: (x[0], -x[1], x[2]))
        self.values = [s[0] for s in table]
        self.sizes = [s[1] for s in table]
        self.names = [s[2] for s in table]

    def __len__(self) -> int:
        return len(self.values)

    def lookup(self, addr: int, max_backtrack: int = 32) -> Optional[str]:
        if not self.values:
            return None
        i = bisect.bisect_right(self.values, addr) - 1
        if i < 0:
            return None
        nearest: Optional[tuple[int, str]] = None
        for j in range(i, max(-1, i - max_backtrack), -1):
            value = self.values[j]
            size = self.sizes[j]
            name = self.names[j]
            if size and value <= addr < value + size:
                return name
            if nearest is None:
                nearest = (value, name)
        if nearest is None:
            return None
        value, name = nearest
        delta = addr - value
        return name if delta == 0 else f"{name}+0x{delta:x}"


def _cstr(blob: bytes, offset: int, limit: int = 65536) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\0", offset, min(len(blob), offset + limit))
    if end < 0:
        end = min(len(blob), offset + limit)
    return blob[offset:end].decode("utf-8", "replace")


def _parse_symbols(data: bytes, sections: Sequence[Section]) -> SymbolTable:
    syms: list[tuple[int, int, str]] = []
    for sec in sections:
        if sec.sh_type != 2 or not sec.entsize:  # SHT_SYMTAB
            continue
        if sec.link >= len(sections):
            continue
        strtab = sections[sec.link]
        if strtab.offset + strtab.size > len(data):
            continue
        count = sec.size // sec.entsize
        for j in range(count):
            off = sec.offset + j * sec.entsize
            if off + 24 > len(data):
                break
            name_off, info, _other, shndx, value, size = struct.unpack_from(
                "<IBBHQQ", data, off
            )
            if shndx == 0:  # SHN_UNDEF
                continue
            st_type = info & 0xF
            if st_type in (3, 4):  # STT_SECTION, STT_FILE
                continue
            if not name_off:
                continue
            if name_off >= strtab.size:
                continue
            name = _cstr(data, strtab.offset + name_off,
                         strtab.size - name_off)
            if name:
                syms.append((value, size, name))
    return SymbolTable(syms)


# ---------------------------------------------------------------------------
# image container
# ---------------------------------------------------------------------------

class Image:
    def __init__(self, path: str, base: Optional[int] = None) -> None:
        self.path = str(path)
        p = Path(path)
        with p.open("rb") as f:
            self.data = f.read()
        self.size = len(self.data)
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        self.base = base
        self.elf: Optional[Elf64] = None
        if self.data[:4] == b"\x7fELF":
            self.kind = "elf64"
            self.elf = Elf64(self.data, self.path)
        else:
            self.kind = "raw"

    @property
    def symbols(self) -> SymbolTable:
        if self.elf is None:
            return SymbolTable(())
        return self.elf.symbols

    def vaddr_for_offset(self, offset: int) -> Optional[int]:
        if self.elf is not None:
            return self.elf.vaddr_for_offset(offset)
        if self.base is not None:
            return self.base + offset
        return None

    def metadata(self) -> dict:
        meta = {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "format": self.kind,
        }
        if self.elf is not None:
            meta["elf"] = {
                "type": self.elf.e_type,
                "machine": self.elf.e_machine,
                "entry": f"0x{self.elf.e_entry:x}",
                "segments": [
                    {
                        "offset": f"0x{s.offset:x}",
                        "vaddr": f"0x{s.vaddr:x}",
                        "filesz": s.filesz,
                        "memsz": s.memsz,
                        "flags": s.flags,
                    }
                    for s in self.elf.segments
                ],
                "symbols": len(self.elf.symbols),
            }
        elif self.base is not None:
            meta["base"] = f"0x{self.base:x}"
        return meta


# ---------------------------------------------------------------------------
# scanner
# ---------------------------------------------------------------------------

def _entry_is_valid(
    layout: Layout,
    values: tuple,
    cfg: ScanConfig,
    *,
    auevent_is_ptr: bool,
    has_systrace: bool,
) -> bool:
    """Validate one record.  Kept for explicit use; hot loop is inlined below."""
    call = values[layout.index["call"]]
    if call == 0:
        if not cfg.allow_null_call:
            return False
        if values[layout.index["narg"]] != 0:
            return False
        if "flags" in layout.index and values[layout.index["flags"]] != 0:
            return False
        if auevent_is_ptr and values[layout.index["auevent"]] != 0:
            return False
        if has_systrace and values[layout.index["systrace"]] != 0:
            return False
        return True
    if not (cfg.ptr_min <= call <= cfg.ptr_max) or call == cfg.ptr_max:
        return False
    if values[layout.index["narg"]] > cfg.max_narg:
        return False
    if "flags" in layout.index:
        flags = values[layout.index["flags"]]
        if flags > cfg.max_flags:
            return False
    if auevent_is_ptr and not cfg.auevent_any:
        av = values[layout.index["auevent"]]
        if av and not (cfg.ptr_min <= av <= cfg.ptr_max):
            return False
    if has_systrace:
        st = values[layout.index["systrace"]]
        if st and not (cfg.ptr_min <= st <= cfg.ptr_max):
            return False
    return True


def _padding_zero_ratio(
    buf, offset: int, layout: Layout, count: int
) -> float:
    if not layout.padding:
        return 1.0
    total = 0
    zero = 0
    for i in range(min(count, 64)):
        base = offset + i * layout.stride
        for start, end in layout.padding:
            chunk = buf[base + start: base + end]
            total += len(chunk)
            zero += chunk.count(0)
    return zero / total if total else 1.0


def _call_in_image_ratio(
    buf: bytes, start: int, layout: Layout, count: int, base: Optional[int]
) -> Optional[float]:
    """Fraction of sy_call pointers that land inside the loaded image.

    A real sysent table points into the kernel image; a random run of records does not.
    Returns None when the image base is unknown (then the check is skipped).
    """
    if base is None:
        return None
    unpack = layout.st.unpack_from
    call_i = layout.index["call"]
    lo, hi = base, base + len(buf)
    inside = 0
    for i in range(count):
        v = unpack(buf, start + i * layout.stride)[call_i]
        if lo <= v < hi:
            inside += 1
    return inside / count


def scan_layout(
    buf: bytes,
    layout: Layout,
    cfg: ScanConfig,
    verbose: bool = False,
    base: Optional[int] = None,
) -> list[dict]:
    """Return maximal record runs for one layout."""
    stride = layout.stride
    if len(buf) < stride:
        return []

    unpack = layout.st.unpack_from
    call_i = layout.index["call"]
    narg_i = layout.index["narg"]
    flags_i = layout.index.get("flags")
    auevent_i = layout.index.get("auevent")
    systrace_i = layout.index.get("systrace")
    auevent_is_ptr = (
        auevent_i is not None
        and layout.field_by_name["auevent"].kind == "ptr"
    )
    has_systrace = systrace_i is not None
    max_narg = cfg.max_narg
    max_flags = cfg.max_flags
    lo = cfg.ptr_min
    hi = cfg.ptr_max
    step = cfg.step
    allow_null = cfg.allow_null_call
    auevent_any = cfg.auevent_any
    limit = len(buf) - stride + 1

    valid_offsets: list[int] = []
    append = valid_offsets.append

    if not allow_null:
        # Fast path: a sysent entry always has a non-NULL kernel text pointer.
        for off in range(0, limit, step):
            values = unpack(buf, off)
            call = values[call_i]
            if call < lo or call >= hi:
                continue
            if values[narg_i] > max_narg:
                continue
            if flags_i is not None and values[flags_i] > max_flags:
                continue
            if auevent_is_ptr and not auevent_any:
                av = values[auevent_i]
                if av and not (lo <= av < hi):
                    continue
            if has_systrace:
                st = values[systrace_i]
                if st and not (lo <= st < hi):
                    continue
            append(off)
    else:
        for off in range(0, limit, step):
            values = unpack(buf, off)
            call = values[call_i]
            if call == 0:
                if values[narg_i] != 0:
                    continue
                if flags_i is not None and values[flags_i] != 0:
                    continue
                if auevent_is_ptr and values[auevent_i] != 0:
                    continue
                if has_systrace and values[systrace_i] != 0:
                    continue
                append(off)
                continue
            if call < lo or call >= hi:
                continue
            if values[narg_i] > max_narg:
                continue
            if flags_i is not None and values[flags_i] > max_flags:
                continue
            if auevent_is_ptr and not auevent_any:
                av = values[auevent_i]
                if av and not (lo <= av < hi):
                    continue
            if has_systrace:
                st = values[systrace_i]
                if st and not (lo <= st < hi):
                    continue
            append(off)

    if verbose:
        print(
            f"[scanner] layout {layout.name}: {len(valid_offsets)} valid "
            f"record offsets",
            file=sys.stderr,
        )
    if not valid_offsets:
        return []

    valid = set(valid_offsets)
    starts = [off for off in valid_offsets if (off - stride) not in valid]

    results: list[dict] = []
    for start in starts:
        count = 0
        pos = start
        while pos in valid:
            count += 1
            pos += stride
        if count < cfg.min_entries:
            continue

        null_calls = 0
        if allow_null:
            for i in range(count):
                if unpack(buf, start + i * stride)[call_i] == 0:
                    null_calls += 1
            # Zero-filled memory must not be mistaken for a syscall table.
            if null_calls * 5 > count:
                continue

        pad_ratio = _padding_zero_ratio(buf, start, layout, count)
        in_image = _call_in_image_ratio(buf, start, layout, count, base)
        score = count * 100.0
        if start % 16 == 0:
            score += 25.0
        elif start % 8 == 0:
            score += 12.0
        score += 5.0 * pad_ratio
        # A genuine table has its handlers inside the image; a long run of look-alike
        # records does not. This is what separates 677/735 real entries from a 69 455-record
        # coincidence in a 100 MB dump.
        if in_image is not None:
            score *= 0.05 + in_image

        results.append(
            {
                "offset": start,
                "layout": layout.name,
                "stride": stride,
                "entries": count,
                "first_syscall": 0,
                "last_syscall": count - 1,
                "score": round(score, 3),
                "padding_zero_ratio": round(pad_ratio, 4),
                "null_calls": null_calls,
                "call_in_image_ratio": None if in_image is None else round(in_image, 4),
                "fields": {
                    f.name: {
                        "offset": f.offset,
                        "size": f.size,
                        "kind": f.kind,
                    }
                    for f in layout.fields
                },
            }
        )
    return results


def _overlap_ratio(a: dict, b: dict) -> float:
    a0, a1 = a["offset"], a["offset"] + a["entries"] * a["stride"]
    b0, b1 = b["offset"], b["offset"] + b["entries"] * b["stride"]
    inter = max(0, min(a1, b1) - max(a0, b0))
    if inter == 0:
        return 0.0
    smaller = min(a1 - a0, b1 - b0)
    return inter / smaller if smaller else 0.0


def scan_image(
    image: Image, cfg: ScanConfig, layouts: Sequence[Layout],
    verbose: bool = False,
) -> list[dict]:
    candidates: list[dict] = []
    for layout in layouts:
        candidates.extend(scan_layout(image.data, layout, cfg, verbose=verbose, base=image.base))

    candidates.sort(
        key=lambda t: (-t["score"], -t["entries"], t["offset"], t["layout"])
    )
    kept: list[dict] = []
    for cand in candidates:
        if any(_overlap_ratio(cand, other) > 0.5 for other in kept):
            continue
        cand["vaddr"] = image.vaddr_for_offset(cand["offset"])
        kept.append(cand)
        if len(kept) >= cfg.max_tables:
            break

    for i, table in enumerate(kept):
        table["index"] = i
    return kept


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def _fmt_addr(value: Optional[int]) -> str:
    return "n/a" if value is None else f"0x{value:x}"


def _print_human(image: Image, tables: Sequence[dict]) -> None:
    print(f"image : {image.path}")
    print(f"format: {image.kind}")
    print(f"size  : {image.size} bytes ({image.size / (1024 * 1024):.2f} MiB)")
    print(f"sha256: {image.sha256}")
    if image.elf is not None:
        print(f"elf   : {len(image.elf.segments)} PT_LOAD, "
              f"{len(image.elf.symbols)} symbols")
    elif image.base is not None:
        print(f"base  : 0x{image.base:x} (raw image load address)")
    print()

    if not tables:
        print("no sysent table found")
        return

    for table in tables:
        layout = LAYOUTS[table["layout"]]
        print(
            f"[{table['index']}] layout={table['layout']} "
            f"stride={table['stride']} entries={table['entries']}"
        )
        print(
            f"    file_offset=0x{table['offset']:x} "
            f"vaddr={_fmt_addr(table['vaddr'])} "
            f"syscalls={table['first_syscall']}..{table['last_syscall']}"
        )
        print(
            f"    score={table['score']} "
            f"padding_zero_ratio={table['padding_zero_ratio']} "
            f"null_calls={table['null_calls']}"
        )
        for pos in (0, table["entries"] - 1):
            off = table["offset"] + pos * table["stride"]
            values = layout.unpack(image.data, off)
            fields = " ".join(
                f"{f.name}={values[i] if f.kind == 'int' else hex(values[i])}"
                for i, f in enumerate(layout.fields)
            )
            print(f"    [{table['first_syscall'] + pos}] {fields}")
        print()

    print(f"found {len(tables)} table(s)")


def resolve_layouts(names: str) -> list[Layout]:
    wanted: list[str] = []
    for item in names.split(","):
        item = item.strip()
        if not item:
            continue
        if item == "auto":
            wanted.extend(DEFAULT_LAYOUTS)
        elif item in LAYOUTS:
            wanted.append(item)
        else:
            raise ValueError(
                f"unknown layout {item!r}; known: auto, {', '.join(LAYOUTS)}"
            )
    seen = set()
    result = []
    for name in wanted:
        if name not in seen:
            seen.add(name)
            result.append(LAYOUTS[name])
    if not result:
        raise ValueError("no layouts selected")
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Find sysent (syscall) tables in a FreeBSD/PS5 kernel image.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("image", help="raw kernel image or ELF64 kernel")
    p.add_argument(
        "--layout", default="auto",
        help="comma separated layouts: auto, ps5, ps5-nof, ps5-packed, "
             "freebsd9, freebsd13",
    )
    p.add_argument("--min-entries", type=int, default=24,
                   help="minimum number of consecutive records")
    p.add_argument("--max-narg", type=int, default=24,
                   help="maximum accepted sy_narg value")
    p.add_argument("--max-flags", type=lambda s: int(s, 0), default=0xFFFF,
                   help="maximum accepted sy_sysflags value")
    p.add_argument("--ptr-min", type=lambda s: int(s, 0),
                   default=PTR_LO_DEFAULT,
                   help="minimum accepted kernel pointer")
    p.add_argument("--ptr-max", type=lambda s: int(s, 0),
                   default=PTR_HI_DEFAULT,
                   help="maximum accepted kernel pointer (exclusive)")
    p.add_argument("--step", type=int, default=4, choices=(1, 2, 4, 8),
                   help="record start search granularity in bytes")
    p.add_argument("--max-tables", type=int, default=8,
                   help="maximum number of tables to report")
    p.add_argument("--allow-null-call", action="store_true",
                   help="accept zero sy_call records (reserved syscalls); "
                        "runs with >20%% null records are still rejected")
    p.add_argument("--auevent-any", action="store_true",
                   help="do not require sy_auevent to be a kernel pointer")
    p.add_argument("--base", type=lambda s: int(s, 0), default=None,
                   help="load address of a raw image (for vaddr reporting)")
    p.add_argument("--json", metavar="PATH", default=None,
                   help="write machine-readable results to PATH")
    p.add_argument("--verbose", action="store_true")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = ScanConfig(
            min_entries=args.min_entries,
            max_narg=args.max_narg,
            max_flags=args.max_flags,
            ptr_min=args.ptr_min,
            ptr_max=args.ptr_max,
            step=args.step,
            max_tables=args.max_tables,
            allow_null_call=args.allow_null_call,
            auevent_any=args.auevent_any,
        )
        cfg.validate()
        layouts = resolve_layouts(args.layout)
        image = Image(args.image, base=args.base)
    except (OSError, ValueError) as exc:
        print(f"scanner: error: {exc}", file=sys.stderr)
        return 2

    tables = scan_image(image, cfg, layouts, verbose=args.verbose)
    answer = {
        "tool": "sysent-scanner",
        "version": 1,
        "image": image.metadata(),
        "config": {
            "layouts": [layout.name for layout in layouts],
            "min_entries": cfg.min_entries,
            "max_narg": cfg.max_narg,
            "max_flags": cfg.max_flags,
            "ptr_min": f"0x{cfg.ptr_min:x}",
            "ptr_max": f"0x{cfg.ptr_max:x}",
            "step": cfg.step,
            "allow_null_call": cfg.allow_null_call,
            "auevent_any": cfg.auevent_any,
        },
        "tables": [
            {
                **table,
                "vaddr_hex": _fmt_addr(table["vaddr"]),
                "offset_hex": f"0x{table['offset']:x}",
            }
            for table in tables
        ],
    }

    if args.json:
        Path(args.json).write_text(
            json.dumps(answer, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    _print_human(image, tables)
    return 0 if tables else 1


if __name__ == "__main__":
    sys.exit(main())