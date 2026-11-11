#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ps5bin.py -- minimal PS4/PS5 ELF reader (and SELF container probe) plus a
byte-pattern engine with wildcards.

Why not pyelftools: the toolbox runs on a locked-down box where the only
guaranteed interpreter is python3; this module has zero third-party imports.
It understands exactly what the PS4/PS5 payload formats need:

  * ELF64, little endian, e_machine == EM_X86_64 (62)
  * machine types ET_SCE_EXEC / ET_SCE_PRX / ET_SCE_RELEXEC / ET_SCE_DYNEXEC
  * PT_LOAD segment map  <->  file offset / virtual address translation
  * PT_DYNAMIC tag table, including the SCE specific 0x61xxxxxx tags
  * detection of an encrypted SELF container (magic 0x4F153D1D), which cannot
    be scanned without the platform crypto keys

Public API:
    Image(path)                      -- parsed image, lazy mmap
    Image.load(path)                 -- same, returns Image
    ImageError                       -- parse failure with a human message
    SelfContainerNotReadable         -- encrypted SELF; carries the header dict
    Pattern("48 89 ?? c3")           -- wildcard byte pattern
    Image.scan(pattern)              -- yields file offsets of matches
"""

from __future__ import annotations

import mmap
import os
import struct

ELF_MAGIC = b"\x7fELF"
SELF_MAGIC_LE = b"\x1d\x3d\x15\x4f"          # 0x4F153D1D, little endian
SELF_MAGIC = 0x4F153D1D
FSELF_MAGIC = 0x5414F5EE                      # community name "fSELF"

EM_X86_64 = 62
EI_CLASS_64 = 2
EI_DATA_LE = 1

PT_NAMES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
    0x61000001: "PT_SCE_RELA",
    0x6FFFFF00: "PT_SCE_COMMENT",
    0x6FFFFF01: "PT_SCE_META",
}

E_TYPE_NAMES = {
    0: "ET_NONE",
    1: "ET_REL",
    2: "ET_EXEC",
    3: "ET_DYN",
    4: "ET_CORE",
    0xFE04: "ET_SCE_RELEXEC",
    0xFE10: "ET_SCE_EXEC",
    0xFE18: "ET_SCE_PRX",
    0xFE20: "ET_SCE_DYNEXEC",
    0xFE24: "ET_SCE_DYNAMIC",
}

DT_NAMES = {
    1: "DT_NEEDED",
    2: "DT_PLTRELSZ",
    3: "DT_PLTGOT",
    4: "DT_HASH",
    5: "DT_STRTAB",
    6: "DT_SYMTAB",
    7: "DT_RELA",
    8: "DT_RELASZ",
    9: "DT_RELAENT",
    10: "DT_STRSZ",
    11: "DT_SYMENT",
    12: "DT_INIT",
    13: "DT_FINI",
    14: "DT_SONAME",
    15: "DT_RPATH",
    16: "DT_SYMBOLIC",
    17: "DT_REL",
    18: "DT_RELSZ",
    19: "DT_RELENT",
    20: "DT_PLTREL",
    21: "DT_DEBUG",
    22: "DT_TEXTREL",
    23: "DT_JMPREL",
    0x6FFFFEF5: "DT_GNU_HASH",
    0x6FFFFFF9: "DT_RELACOUNT",
    0x6FFFFFFA: "DT_RELCOUNT",
}

# SCE tag numbers. Names follow the de-facto community mapping (ps4/ps5 tooling
# such as `elf.py` in ps4-payload-sdk / orbis-pub-cmd dumps). Only the ones this
# tool actually uses are resolved; everything else is reported raw.
SCE_TAGS = {}   # names deliberately not guessed; see REPORT.md


PF_X, PF_W, PF_R = 1, 2, 4


class ImageError(Exception):
    """Raised when a file cannot be treated as a scannable PS4/PS5 ELF."""


class SelfContainerNotReadable(ImageError):
    """Raised for an encrypted SELF container."""

    def __init__(self, path, header):
        self.path = path
        self.header = header
        super().__init__(
            "%s: encrypted SELF container (magic 0x%08X) - payload is encrypted "
            "and compressed, scanning requires the PS5 platform keys which are "
            "not available on this host" % (path, SELF_MAGIC)
        )


class Segment:
    __slots__ = ("index", "p_type", "p_type_name", "offset", "vaddr", "paddr",
                 "filesz", "memsz", "flags", "align")

    def __init__(self, index, p_type, offset, vaddr, paddr, filesz, memsz, flags, align):
        self.index = index
        self.p_type = p_type
        self.p_type_name = PT_NAMES.get(p_type, "0x%08x" % p_type)
        self.offset = offset
        self.vaddr = vaddr
        self.paddr = paddr
        self.filesz = filesz
        self.memsz = memsz
        self.flags = flags
        self.align = align

    @property
    def is_load(self):
        return self.p_type == 1

    @property
    def perms(self):
        if not self.flags:
            return "---"
        return ("r" if self.flags & PF_R else "-") + \
               ("w" if self.flags & PF_W else "-") + \
               ("x" if self.flags & PF_X else "-")

    @property
    def end_offset(self):
        return self.offset + self.filesz

    @property
    def end_vaddr(self):
        return self.vaddr + max(self.filesz, self.memsz)

    def as_dict(self):
        return {
            "index": self.index,
            "type": self.p_type_name,
            "offset": self.offset,
            "vaddr": self.vaddr,
            "filesz": self.filesz,
            "memsz": self.memsz,
            "flags": self.flags,
            "perms": self.perms,
            "align": self.align,
        }

    def __repr__(self):
        return "<%s off=0x%x vaddr=0x%x filesz=0x%x %s>" % (
            self.p_type_name, self.offset, self.vaddr, self.filesz, self.perms)


def _elf_type_name(t):
    return E_TYPE_NAMES.get(t, "0x%04x" % t)


_MODULE_NAME_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyz"
                               b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def _looks_like_module_name(raw):
    """True for things like 'libSceAjm', 'libSceAjm.native.prx', 'cpLauncher'.

    Obfuscated dynamic symbols ('P330P3dFF68#S#R') and numeric attribute blobs
    are rejected, so the caller never labels a tag with a string that is not a
    plausible library/module name.
    """
    if not raw or not (3 <= len(raw) <= 80):
        return False
    if any(c not in _MODULE_NAME_CHARS for c in raw):
        return False
    if b"#" in raw:
        return False
    first = raw[0]
    if not (65 <= first <= 90 or 97 <= first <= 122):
        return False
    return True


class Image:
    """A PS4/PS5 ELF image with offset <-> address translation."""

    def __init__(self, path, keep_data=False):
        self.path = os.path.abspath(path)
        self.name = os.path.basename(self.path)
        try:
            self.size = os.path.getsize(self.path)
        except OSError as exc:
            raise ImageError("%s: %s" % (path, exc)) from exc
        self._fh = open(self.path, "rb")
        self.data = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        self.segments = []
        self.dynamic = []
        self.dyn_strtab = None      # (file_off, size)
        self.e_type = 0
        self.entry = 0
        self.base = 0
        self._parse()

    # -- context manager / cleanup -------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        try:
            if not self.data.closed:
                self.data.close()
        finally:
            if not self._fh.closed:
                self._fh.close()

    # -- parsing -------------------------------------------------------
    def _parse(self):
        d = self.data
        if len(d) < 64:
            raise ImageError("%s: file too small for ELF64 (%d bytes)" % (self.path, len(d)))
        if bytes(d[0:4]) == SELF_MAGIC_LE:
            raise SelfContainerNotReadable(self.path, probe_self_header(d))
        if bytes(d[0:4]) != ELF_MAGIC:
            raise ImageError("%s: not an ELF (magic %s)" % (self.path, bytes(d[0:4]).hex()))
        ei_class = d[4]
        ei_data = d[5]
        if ei_class != EI_CLASS_64 or ei_data != EI_DATA_LE:
            raise ImageError("%s: unsupported ELF class/data (%d/%d)" % (self.path, ei_class, ei_data))
        (self.e_type, e_machine, _version, self.entry, e_phoff, e_shoff, _flags,
         _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx) = struct.unpack_from(
            "<HHIQQQIHHHHHH", d, 16)
        if e_machine != EM_X86_64:
            raise ImageError("%s: unsupported machine %d (want x86-64=%d)" % (self.path, e_machine, EM_X86_64))
        self.machine = e_machine
        self.e_phoff = e_phoff
        self.e_shoff = e_shoff
        self.e_phnum = e_phnum
        self.e_shnum = e_shnum
        self.type_name = _elf_type_name(self.e_type)
        if e_phentsize != 56:
            raise ImageError("%s: unexpected phentsize %d" % (self.path, e_phentsize))
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + 56 > len(d):
                raise ImageError("%s: program header %d beyond EOF" % (self.path, i))
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from("<IIQQQQQQ", d, off)
            self.segments.append(Segment(i, p_type, p_offset, p_vaddr, p_paddr,
                                         p_filesz, p_memsz, p_flags, p_align))
        loads = [s for s in self.segments if s.is_load and s.filesz]
        if not loads:
            raise ImageError("%s: no non-empty PT_LOAD segment" % self.path)
        self.base = min(s.vaddr for s in loads)
        self._loads_by_off = sorted(loads, key=lambda s: s.offset)
        self._loads_by_va = sorted(loads, key=lambda s: s.vaddr)
        self._parse_dynamic()

    def _parse_dynamic(self):
        for seg in self.segments:
            if seg.p_type != 2:
                continue
            off = seg.offset
            end = min(seg.offset + seg.filesz, len(self.data))
            while off + 16 <= end:
                tag, val = struct.unpack_from("<QQ", self.data, off)
                off += 16
                if tag == 0:
                    break
                self.dynamic.append((tag, val))
        tags = {}
        for tag, val in self.dynamic:
            tags.setdefault(tag, []).append(val)
        self.dyn_tags = tags
        if 5 in tags and 10 in tags:
            self.dyn_strtab = (self.vaddr_to_offset(tags[5][0]), tags[10][0])

    # -- translation ---------------------------------------------------
    def offset_to_vaddr(self, off):
        for seg in self._loads_by_off:
            if seg.offset <= off < seg.offset + seg.filesz:
                return seg.vaddr + (off - seg.offset), seg
        return None, None

    def vaddr_to_offset(self, va):
        for seg in self._loads_by_va:
            span = max(seg.filesz, seg.memsz)
            if seg.vaddr <= va < seg.vaddr + span:
                delta = va - seg.vaddr
                if delta < seg.filesz:
                    return seg.offset + delta
                return None          # in .bss: mapped but not backed by the file
        return None

    def segment_of_offset(self, off):
        for seg in self._loads_by_off:
            if seg.offset <= off < seg.offset + seg.filesz:
                return seg
        return None

    def segment_of_vaddr(self, va):
        for seg in self._loads_by_va:
            if seg.vaddr <= va < seg.vaddr + max(seg.filesz, seg.memsz):
                return seg
        return None

    def exec_segments(self):
        return [s for s in self._loads_by_off if s.flags & PF_X]

    def readable_bytes(self, off, length):
        return bytes(self.data[off:off + length])

    # -- dynamic helpers ----------------------------------------------
    def dyn_str(self, index):
        """Read a NUL terminated string from DT_STRTAB at the given byte index."""
        if not self.dyn_strtab:
            return None
        base, size = self.dyn_strtab
        if base is None or index >= size:
            return None
        start = base + index
        stop = self.data.find(b"\0", start, base + size)
        if stop < 0:
            stop = base + size
        return bytes(self.data[start:stop])

    def dyn_names(self):
        """[(tag, value, name, file_off, vaddr)] for string valued dynamic tags.

        DT_NEEDED / DT_SONAME / DT_RPATH values are byte offsets into DT_STRTAB.
        On real PS4/PS5 payloads the SCE 0x61xxxxxx tags also carry a DT_STRTAB
        byte offset in their low 32 bits - observed on eboot.bin where
        0x61000045 value 0x1010100003b46 -> 0x3b46 -> "libSceAjm".  That is an
        empirical observation, so a candidate is only accepted when it looks
        like a library/module name; anything else stays raw instead of being
        reported as a name we cannot prove.
        """
        out = []
        known = {1, 14, 15}
        for tag, val in self.dynamic:
            name = None
            if tag in known:
                name = self.dyn_str(val)
            elif 0x61000000 <= tag <= 0x61FFFFFF:
                cand = self.dyn_str(val & 0xFFFFFFFF)
                if cand and _looks_like_module_name(cand):
                    name = cand
            if not name:
                continue
            try:
                text = name.decode("latin-1")
            except Exception:
                continue
            if not text.isprintable():
                continue
            if tag in known:
                off = self.dyn_strtab[0] + val if self.dyn_strtab else None
            else:
                off = self.dyn_strtab[0] + (val & 0xFFFFFFFF) if self.dyn_strtab else None
            va, _seg = self.offset_to_vaddr(off) if off is not None else (None, None)
            out.append({
                "tag": tag,
                "tag_name": DT_NAMES.get(tag) or "SCE_0x%08x" % tag,
                "value": val,
                "name": text,
                "file_off": off,
                "vaddr": va,
            })
        return out

    # -- scanning ------------------------------------------------------
    def scan(self, pattern, segments=None):
        """Yield (file_off, vaddr, segment) for each match inside the segments."""
        if segments is None:
            segments = self._loads_by_off
        for seg in segments:
            if not seg.filesz:
                continue
            for rel in pattern.find_in(self.data, seg.offset, seg.offset + seg.filesz):
                yield rel, seg.vaddr + (rel - seg.offset), seg

    def read_cstr(self, off, maxlen=256):
        stop = self.data.find(b"\0", off, off + maxlen)
        if stop < 0:
            stop = off + maxlen
        return bytes(self.data[off:stop])

    def printable_context(self, off, before=16, after=48):
        start = max(0, off - before)
        raw = bytes(self.data[start:off + after])
        return "".join(chr(c) if 32 <= c < 127 else "." for c in raw)

    def info(self):
        return {
            "path": self.path,
            "name": self.name,
            "size": self.size,
            "e_type": self.e_type,
            "type_name": self.type_name,
            "entry": self.entry,
            "base": self.base,
            "phnum": self.e_phnum,
            "segments": [s.as_dict() for s in self.segments],
        }


def probe_self_header(data):
    """Best-effort SELF header probe. Fields are reported raw; the layout below
    follows the publicly documented SCE SELF header for PS4 (same family on PS5)
    and is NOT validated against a decrypted key set on this host."""
    hdr = {}
    try:
        hdr["magic"] = "0x%08X" % struct.unpack_from("<I", data, 0)[0]
        hdr["version"] = "0x%08X" % struct.unpack_from("<I", data, 4)[0]
        hdr["header_len"] = struct.unpack_from("<H", data, 0x18)[0]
        hdr["meta_len"] = struct.unpack_from("<H", data, 0x1A)[0]
        hdr["file_len"] = struct.unpack_from("<Q", data, 0x1C)[0]
        hdr["num_entries"] = struct.unpack_from("<H", data, 0x24)[0]
        hdr["interpretation"] = "unverified (field layout from public PS4 SELF docs)"
    except struct.error as exc:
        hdr["error"] = str(exc)
    return hdr


class Pattern:
    """A byte pattern with '??' wildcards, e.g. Pattern('48 89 07 c3')."""

    __slots__ = ("text", "pid", "tokens", "length", "anchor_off", "anchor_bytes")

    def __init__(self, text, pid=None):
        self.text = text.strip()
        self.pid = pid
        toks = []
        for part in self.text.split():
            if part in ("??", "?"):
                toks.append(None)
            else:
                if len(part) != 2:
                    raise ValueError("bad pattern token %r in %r" % (part, text))
                toks.append(int(part, 16))
        if not toks:
            raise ValueError("empty pattern")
        self.tokens = toks
        self.length = len(toks)
        self.anchor_off, self.anchor_bytes = self._longest_literal()

    def _longest_literal(self):
        best_off, best_len, cur_off, cur_len = 0, 0, 0, 0
        for i, t in enumerate(self.tokens):
            if t is None:
                if cur_len > best_len:
                    best_off, best_len = cur_off, cur_len
                cur_len = 0
            else:
                if cur_len == 0:
                    cur_off = i
                cur_len += 1
        if cur_len > best_len:
            best_off, best_len = cur_off, cur_len
        if best_len == 0:
            return None, b""
        return best_off, bytes(self.tokens[best_off:best_off + best_len])

    def matches_at(self, data, off):
        for i, t in enumerate(self.tokens):
            if t is not None and data[off + i] != t:
                return False
        return True

    def find_in(self, data, start, end):
        """Yield absolute file offsets of matches in data[start:end]."""
        n = self.length
        if n == 0:
            return
        anchor_off, anchor = self.anchor_off, self.anchor_bytes
        if anchor and len(anchor) >= 2:
            pos = start - anchor_off
            limit = end - n
            while True:
                hit = data.find(anchor, max(start - anchor_off, 0) if pos < 0 else pos, end)
                if hit < 0:
                    return
                cand = hit - anchor_off
                pos = hit + 1
                if cand < start or cand > limit:
                    if pos > limit + anchor_off:
                        return
                    continue
                if self.matches_at(data, cand):
                    yield cand
        else:
            first = next((i for i, t in enumerate(self.tokens) if t is not None), None)
            if first is None:
                return
            byte = self.tokens[first]
            limit = end - n
            pos = start + first
            while True:
                hit = data.find(bytes([byte]), pos, end)
                if hit < 0:
                    return
                cand = hit - first
                pos = hit + 1
                if start <= cand <= limit and self.matches_at(data, cand):
                    yield cand


def load_images(paths):
    """Load several images, returning (images, errors)."""
    images, errors = [], []
    for p in paths:
        try:
            images.append(Image(p))
        except ImageError as exc:
            errors.append({"path": os.path.abspath(p), "error": str(exc),
                           "header": getattr(exc, "header", None)})
    return images, errors