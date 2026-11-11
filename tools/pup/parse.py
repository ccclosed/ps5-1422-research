#!/usr/bin/env python3
"""parse.py - forensic parser for PlayStation 5 PUP update files (SCEUF family).

What it does, without any console and without any key material:

  1. Detects the outer container.  A retail PS5UPDATE.PUP is an SLB2/BLS
     archive ("SLB2" magic) that stores one or two PUP fragments
     (PS5UPDATE1.PUP = system, PS5UPDATE2.PUP = recovery).
  2. Parses the 0x20-byte PUP header of every fragment: magic, version,
     flags, header_size, metadata_size, and - when the header is plaintext -
     file_size, entry_count, metadata_count.
  3. Prints the record table as JSON.  For a decrypted PUP that is the
     segment table (id/offset/sizes/flags).  For a retail PUP the segment
     table is ciphertext: the parser says so explicitly, reports the entry
     count derived from the plaintext header_size, and still prints the real
     SLB2 file records (name/offset/size).
  4. Scans the file for known magics and computes SHA-256.

No decryption is attempted and no key is invented.  The console-side
decrypter (zecoxao/ps5-pup-decrypt, idc/ps4-pup_decrypt) hands buffers to
/dev/pup_update0, i.e. the keys live in the console, not in the package.

Usage:
    python3 parse.py FILE [--out OUT.json] [--no-scan] [--scan-bytes N]
    python3 parse.py --selftest [--out OUT.json]

Exit codes: 0 success, 1 unreadable/unsupported input, 2 usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SLB2_MAGIC = b"SLB2"
PS5_PUP_MAGIC = 0xEEF51454
PS4_PUP_MAGIC = 0x1D3D154F

BLS_HEADER_SIZE = 0x20
BLS_ENTRY_SIZE = 0x30
PUP_HEADER_SIZE = 0x20
PUP_ENTRY_SIZE = 0x20
PUP_HEADER_TRAILER = 0x10

# Magic patterns scanned in the file.  weak=True patterns are 2 bytes long
# and therefore produce random hits in ciphertext; they are counted but not
# treated as evidence.
MAGICS = [
    ("SLB2", b"SLB2", "BLS/SLB2 container (outer PS5UPDATE.PUP)"),
    ("PS5_PUP", b"\x54\x14\xf5\xee", "PS5 PUP fragment header (SCEUF family)"),
    ("PS4_PUP", b"\x4f\x15\x3d\x1d", "PS4 PUP fragment header (SCEUF family)"),
    ("SCEUF_ASCII", b"SCEUF", "ASCII SCEUF (PS3-era PUP)"),
    ("ELF", b"\x7fELF", "ELF executable"),
    ("PKG", b"\x7fPKG", "PS4/PS5 PKG package"),
    ("ZIP", b"PK\x03\x04", "ZIP archive"),
    ("GZIP", b"\x1f\x8b\x08", "gzip stream"),
    ("XZ", b"\xfd7zXZ\x00", "xz stream"),
    ("SEVENZ", b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    ("FAT32", b"FAT32   ", "FAT32 boot sector"),
    ("EXFAT", b"EXFAT   ", "exFAT boot sector"),
    ("ZLIB_9C", b"\x78\x9c", "zlib stream (weak: 2-byte magic)"),
    ("ZLIB_DA", b"\x78\xda", "zlib stream (weak: 2-byte magic)"),
]

WEAK_MAGICS = {name for name, pat, _ in MAGICS if len(pat) <= 2}

FLAG_BITS = [
    (0, "is_info"),
    (1, "is_encrypted"),
    (2, "is_signed"),
    (3, "is_compressed"),
    (11, "has_blocks"),
    (16, "has_digests"),
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def read_at(f, off: int, size: int) -> bytes:
    f.seek(off)
    data = f.read(size)
    if len(data) != size:
        raise ValueError(f"short read at 0x{off:x}: want {size}, got {len(data)}")
    return data


def entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def sha256_file(path: str, chunk: int = 8 << 20) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            size += len(block)
            h.update(block)
    return h.hexdigest(), size


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def hex32(v: int) -> str:
    return f"0x{v:08X}"


def flag_list(flags: int) -> dict:
    out = {}
    for bit, name in FLAG_BITS:
        out[name] = bool(flags & (1 << bit))
    out["id"] = flags >> 20
    out["block_size_shift"] = ((flags >> 12) & 0xF) + 12
    out["block_size"] = 1 << out["block_size_shift"]
    return out


# ---------------------------------------------------------------------------
# SLB2 / BLS outer container
# ---------------------------------------------------------------------------

def parse_slb2(f, file_size: int) -> dict:
    head = read_at(f, 0, BLS_HEADER_SIZE)
    magic = head[0:4]
    if magic != SLB2_MAGIC:
        raise ValueError(f"not an SLB2 container: magic {magic!r}")

    version = u32(head, 0x04)
    flags = u32(head, 0x08)
    file_count = u32(head, 0x0C)
    block_count = u32(head, 0x10)
    unknown = head[0x14:0x20]

    result = {
        "type": "SLB2/BLS",
        "magic": magic.decode("ascii"),
        "version": version,
        "flags": flags,
        "flags_hex": hex32(flags),
        "file_count": file_count,
        "block_count": block_count,
        "block_count_implied_size": block_count * 512,
        "unknown_14": unknown.hex(),
        "files": [],
        "warnings": [],
    }

    if not (1 <= file_count <= 64):
        result["warnings"].append(f"implausible file_count={file_count} (expected 1..64)")
        return result

    table_size = BLS_ENTRY_SIZE * file_count
    if BLS_HEADER_SIZE + table_size > file_size:
        result["warnings"].append("entry table extends past end of file")
        return result

    table = read_at(f, BLS_HEADER_SIZE, table_size)
    prev_end = BLS_HEADER_SIZE + table_size
    for i in range(file_count):
        base = i * BLS_ENTRY_SIZE
        block_offset = u32(table, base + 0x00)
        size = u32(table, base + 0x04)
        reserved = table[base + 0x08:base + 0x10]
        raw_name = table[base + 0x10:base + 0x30]
        name = raw_name.split(b"\x00", 1)[0]
        try:
            name_s = name.decode("ascii")
            name_ok = all(0x20 <= ord(c) < 0x7F for c in name_s)
        except UnicodeDecodeError:
            name_s = name.hex()
            name_ok = False
        offset = block_offset * 512
        end = offset + size
        pad = (512 - (size % 512)) % 512
        rec = {
            "index": i,
            "name": name_s,
            "name_ascii_valid": name_ok,
            "block_offset": block_offset,
            "offset": offset,
            "size": size,
            "end": end,
            "padding_to_512": pad,
            "reserved": reserved.hex(),
        }
        if offset < prev_end:
            result["warnings"].append(f"file[{i}] starts before end of previous record")
        if offset + size > file_size:
            result["warnings"].append(
                f"file[{i}] 0x{offset:x}+0x{size:x} exceeds file size 0x{file_size:x}"
            )
        if not name_ok:
            result["warnings"].append(f"file[{i}] name is not printable ASCII")
        result["files"].append(rec)
        prev_end = ceil_div(end, 512) * 512

    implied = block_count * 512
    result["block_count_matches_file_size"] = implied == file_size
    if implied != file_size:
        delta = implied - file_size
        result["block_count_delta"] = delta
        result["warnings"].append(
            "SLB2 block_count*512 != file size "
            f"(delta {delta:+d} bytes); either the file is truncated or "
            "block_count is a volume/partition figure rather than a file length"
        )

    return result


# ---------------------------------------------------------------------------
# PUP fragment header + segment table
# ---------------------------------------------------------------------------

def parse_pup_header(buf: bytes) -> dict:
    magic = u32(buf, 0x00)
    if magic == PS5_PUP_MAGIC:
        kind = "ps5"
        magic_name = "PS5 PUP (0xEEF51454)"
    elif magic == PS4_PUP_MAGIC:
        kind = "ps4"
        magic_name = "PS4 PUP (0x1D3D154F)"
    elif buf[0:5] == b"SCEUF":
        kind = "sceuf"
        magic_name = "ASCII SCEUF"
    else:
        kind = "unknown"
        magic_name = f"0x{magic:08X}"

    flags = u16(buf, 0x0A)
    plaintext = bool(flags & 1)

    # Only 0x00..0x10 is plaintext in a retail package.  When bit 0 of flags
    # is clear, file_size / entry_count / metadata_count / unknown_1c are
    # ciphertext: report them as null instead of pretending they are fields.
    return {
        "kind": kind,
        "magic": hex32(magic),
        "magic_name": magic_name,
        "version": u16(buf, 0x04),
        "unknown_06": u16(buf, 0x06),
        "unknown_08": u16(buf, 0x08),
        "flags": flags,
        "flags_hex": f"0x{flags:04X}",
        "header_already_decrypted": plaintext,
        "header_size": u16(buf, 0x0C),
        "metadata_size": u16(buf, 0x0E),
        "file_size": u64(buf, 0x10) if plaintext else None,
        "entry_count": u16(buf, 0x18) if plaintext else None,
        "metadata_count": u16(buf, 0x1A) if plaintext else None,
        "unknown_1c": u32(buf, 0x1C) if plaintext else None,
        "ciphertext_0x10_0x20": None if plaintext else buf[0x10:0x20].hex(),
    }


def entry_count_candidates(header_size: int) -> list[dict]:
    """Candidate segment counts from the plaintext header_size.

    The PS4 formula is verified on retail packages (PUPPRE, idc):
        header_size = 0x20 header + n*0x20 entries + 0x10 trailer
    PS5 retail fragments do not all fit it, so every exact fit is listed and
    nothing is promoted to a fact.
    """
    cands = []
    formulas = [
        (0x10, "header_size = 0x20 + n*0x20 + 0x10 (PS4-verified)"),
        (0x00, "header_size = 0x20 + n*0x20"),
        (0x20, "header_size = 0x20 + n*0x20 + 0x20"),
    ]
    for trailer, label in formulas:
        rem = header_size - PUP_HEADER_SIZE - trailer
        if rem >= 0 and rem % PUP_ENTRY_SIZE == 0:
            cands.append({"formula": label, "trailer": trailer,
                          "count": rem // PUP_ENTRY_SIZE})
    if header_size % PUP_ENTRY_SIZE == 0:
        cands.append({"formula": "header_size = n*0x20 (table only)",
                      "trailer": None, "count": header_size // PUP_ENTRY_SIZE})
    seen = set()
    unique = []
    for c in cands:
        if c["count"] not in seen:
            seen.add(c["count"])
            unique.append(c)
    return unique


def metadata_count_candidates(metadata_size: int) -> list[dict]:
    """Candidate counts of 0x50-byte metadata entries from metadata_size."""
    cands = []
    for trailer, label in (
        (0x20, "metadata_size = 0x20 + n*0x50 (PS5 fit)"),
        (0xB0, "metadata_size = 0xB0 + n*0x50 (PS4, per PUPPRE)"),
        (0x00, "metadata_size = n*0x50"),
    ):
        rem = metadata_size - trailer
        if rem >= 0 and rem % 0x50 == 0:
            cands.append({"formula": label, "trailer": trailer,
                          "count": rem // 0x50})
    seen = set()
    unique = []
    for c in cands:
        if c["count"] not in seen:
            seen.add(c["count"])
            unique.append(c)
    return unique


def parse_entries(f, pup_off: int, pup_size: int, count: int, kind: str) -> list[dict]:
    if count <= 0 or count > 4096:
        raise ValueError(f"implausible entry_count={count}")
    need = count * PUP_ENTRY_SIZE
    table_off = pup_off + PUP_HEADER_SIZE
    if PUP_HEADER_SIZE + need > pup_size:
        raise ValueError("entry table does not fit inside the PUP fragment")
    table = read_at(f, table_off, need)

    entries = []
    for i in range(count):
        base = i * PUP_ENTRY_SIZE
        flags = u32(table, base + 0x00)
        flags2 = u32(table, base + 0x04)
        offset = u64(table, base + 0x08)
        comp = u64(table, base + 0x10)
        uncomp = u64(table, base + 0x18)
        info = flag_list(flags)
        rec = {
            "index": i,
            "id": info["id"],
            "flags": hex32(flags),
            "flags2": hex32(flags2),
            "offset": offset,
            "offset_absolute": pup_off + offset,
            "compressed_size": comp,
            "uncompressed_size": uncomp,
            "is_info": info["is_info"],
            "is_encrypted": info["is_encrypted"],
            "is_signed": info["is_signed"],
            "is_compressed": info["is_compressed"],
            "has_blocks": info["has_blocks"],
            "has_digests": info["has_digests"],
            "block_size": info["block_size"],
        }
        if kind == "ps5":
            rec["block_align_mask"] = 0x1FF if (flags2 & 1) else 0xF
        if offset + comp > pup_size:
            rec["warning"] = (
                f"offset+compressed_size 0x{offset + comp:x} exceeds fragment size 0x{pup_size:x}"
            )
        entries.append(rec)
    return entries


def probe_entry_layouts(f, pup_off: int, pup_size: int, header: dict) -> list[dict]:
    """Try several plausible entry-table layouts and report what each one yields.

    This is the "several table layouts" requirement: a layout is only called
    readable/credible when the bytes actually decode into a sane table
    (low entropy, in-range and aligned offsets, plausible compressed sizes).
    For a retail fragment the table is ciphertext, so every layout must come
    back as "not credible" - that is a result, not a failure of the parser.
    """
    header_size = header.get("header_size") or 0
    probes: list[dict] = []
    layouts = [
        (PUP_HEADER_SIZE, 0x10, "0x20 header + n*0x20 entries + 0x10 trailer (PS4 formula)"),
        (PUP_HEADER_SIZE, 0x00, "0x20 header + n*0x20 entries, no trailer"),
        (PUP_HEADER_SIZE, 0x20, "0x20 header + n*0x20 entries + 0x20 trailer"),
        (PUP_HEADER_SIZE, 0x10, "0x20 header + n*0x30 entries + 0x10 trailer"),
        (0x00, 0x10, "header_size = n*0x20 + 0x10 (table starts at file offset 0)"),
    ]
    entry_sizes = [PUP_ENTRY_SIZE, PUP_ENTRY_SIZE, PUP_ENTRY_SIZE, 0x30, PUP_ENTRY_SIZE]
    for (base, trailer, label), esize in zip(layouts, entry_sizes):
        probe: dict = {
            "layout": label,
            "entry_size": esize,
            "trailer": trailer,
            "table_offset": pup_off + base,
            "fits_header_size": False,
            "entry_count": None,
            "readable_bytes": 0,
            "entropy": None,
            "metrics": {},
            "credible": False,
            "verdict": "",
        }
        rem = header_size - base - trailer
        if base + trailer > header_size or rem < 0 or rem % esize:
            probe["verdict"] = (
                f"rejected: header_size {header_size:#x} is not "
                f"{base:#x} + n*{esize:#x} + {trailer:#x}"
            )
            probes.append(probe)
            continue
        count = rem // esize
        probe["entry_count"] = count
        need = count * esize
        if count <= 0 or count > 4096 or base + need + trailer > pup_size:
            probe["verdict"] = "rejected: table does not fit inside the fragment"
            probes.append(probe)
            continue
        probe["fits_header_size"] = True
        table = read_at(f, pup_off + base, min(need, 0x10000))
        probe["readable_bytes"] = len(table)
        probe["entropy"] = round(entropy(table), 4)
        in_range = monotonic = aligned = plausible_sizes = 0
        examined = 0
        prev_off = -1
        for i in range(min(count, len(table) // esize)):
            b = i * esize
            if b + PUP_ENTRY_SIZE > len(table):
                break
            offset = u64(table, b + 0x08)
            comp = u64(table, b + 0x10)
            examined += 1
            if offset <= pup_size and offset + comp <= pup_size:
                in_range += 1
            if offset >= prev_off:
                monotonic += 1
            if offset % 0x10 == 0:
                aligned += 1
            if 0 < comp <= pup_size:
                plausible_sizes += 1
            prev_off = offset
        n = max(1, examined)
        probe["metrics"] = {
            "entries_examined": examined,
            "offset_in_range_fraction": round(in_range / n, 4),
            "monotonic_offset_fraction": round(monotonic / n, 4),
            "aligned_offset_fraction": round(aligned / n, 4),
            "plausible_compressed_size_fraction": round(plausible_sizes / n, 4),
        }
        credible = (
            probe["entropy"] is not None
            and probe["entropy"] < 7.0
            and examined > 0
            and probe["metrics"]["offset_in_range_fraction"] > 0.95
            and probe["metrics"]["aligned_offset_fraction"] > 0.95
            and probe["metrics"]["plausible_compressed_size_fraction"] > 0.95
        )
        probe["credible"] = credible
        probe["verdict"] = (
            "readable: entries decode into a sane table"
            if credible
            else (
                "not credible: bytes do not decode into a sane table "
                f"(entropy {probe['entropy']}, metrics {probe['metrics']})"
            )
        )
        probes.append(probe)
    return probes


def parse_pup_fragment(f, rec: dict, file_size: int) -> dict:
    pup_off = rec["offset"]
    pup_size = rec["size"]
    if pup_off + PUP_HEADER_SIZE > file_size:
        raise ValueError("PUP fragment header lies past end of file")

    head = read_at(f, pup_off, PUP_HEADER_SIZE)
    header = parse_pup_header(head)
    kind = header["kind"]
    header_size = header["header_size"]
    metadata_size = header["metadata_size"]

    plaintext = header["header_already_decrypted"]
    out = {
        "name": rec["name"],
        "offset": pup_off,
        "size": pup_size,
        "header": header,
        "header_region": {
            "plaintext_bytes": 0x10,
            "ciphertext_bytes": max(0, header_size - 0x10),
            "entropy_prefix": round(entropy(head[0:0x10]), 4),
            "entropy_suffix": None,
        },
        "entry_table": {
            "offset": pup_off + PUP_HEADER_SIZE,
            "offset_relative": PUP_HEADER_SIZE,
            "entry_size": PUP_ENTRY_SIZE,
            "readable": False,
            "reason": None,
        },
        "metadata_area": {
            "offset": pup_off + header_size,
            "size": metadata_size,
            "entropy": None,
            "readable": False,
        },
        "entry_count_candidates": entry_count_candidates(header_size),
        "derived_entry_count": next(
            (c["count"] for c in entry_count_candidates(header_size)
             if c["formula"].endswith("(PS4-verified)")), None),
        "derived_entry_count_confidence": "hypothesis",
        "entries": [],
        "warnings": [],
    }

    if header_size == 0 or header_size > pup_size:
        out["warnings"].append(
            f"header_size 0x{header_size:x} is not within the fragment (0x{pup_size:x})"
        )
        header_size = min(max(header_size, PUP_HEADER_SIZE), pup_size)

    if header_size > 0x10:
        tail_len = min(header_size - 0x10, 0x10000)
        tail = read_at(f, pup_off + 0x10, tail_len)
        out["header_region"]["entropy_suffix"] = round(entropy(tail), 4)

    if metadata_size and header_size + metadata_size <= pup_size:
        meta_len = min(metadata_size, 0x10000)
        meta = read_at(f, pup_off + header_size, meta_len)
        out["metadata_area"]["entropy"] = round(entropy(meta), 4)

    meta_cands = metadata_count_candidates(metadata_size)
    out["metadata_count_candidates"] = meta_cands
    out["derived_metadata_count"] = meta_cands[0]["count"] if len(meta_cands) == 1 else None
    out["derived_metadata_count_confidence"] = "hypothesis"

    # Probe every plausible entry-table layout and record what each one yields
    # (for retail ciphertext: an explicit "not credible", never an invented table).
    out["layout_probes"] = probe_entry_layouts(
        f, pup_off, pup_size, dict(header, header_size=header_size))

    if plaintext:
        out["entry_table"]["readable"] = True
        count = header["entry_count"]
        if count == 0 or count > 4096:
            out["warnings"].append(
                f"header says entry_count={count}, falling back to derived value"
            )
            count = out["derived_entry_count"] or 0
        try:
            out["entries"] = parse_entries(f, pup_off, pup_size, count, kind)
            out["entry_table"]["count"] = len(out["entries"])
        except ValueError as exc:
            out["warnings"].append(f"entry table unreadable: {exc}")
            out["entry_table"]["reason"] = str(exc)
        expected = PUP_HEADER_SIZE + count * PUP_ENTRY_SIZE + PUP_HEADER_TRAILER
        if expected != header_size:
            out["warnings"].append(
                f"header_size 0x{header_size:x} != 0x20 + {count}*0x20 + 0x10 = 0x{expected:x}"
            )
    else:
        out["entry_table"]["count"] = 0
        out["entry_table"]["reason"] = (
            "flags bit 0 is clear: bytes 0x10..0x10+header_size (including the "
            "entry table and the metadata area) are ciphertext; no PC key is public"
        )
        out["warnings"].append(
            "PUP entry table is encrypted; only the 0x10-byte plaintext header prefix "
            "and the derived entry count are available"
        )
        out["header"]["raw_0x10_0x20_note"] = (
            "these 16 bytes are ciphertext and are reported only as hex"
        )

    return out


# ---------------------------------------------------------------------------
# Magic scan
# ---------------------------------------------------------------------------

def scan_magics(path: str, patterns, max_bytes: int | None,
                chunk: int = 8 << 20, overlap: int = 64) -> dict:
    result = {
        name: {"description": desc, "pattern": pat.hex(), "weak": name in WEAK_MAGICS,
               "count": 0, "first_offsets": []}
        for name, pat, desc in patterns
    }
    seen_limit = 8
    total = 0
    prev_tail = b""
    base = 0
    with open(path, "rb") as f:
        while True:
            want = chunk
            if max_bytes is not None:
                left = max_bytes - total
                if left <= 0:
                    break
                want = min(want, left)
            data = f.read(want)
            if not data:
                break
            buf = prev_tail + data
            buf_base = base - len(prev_tail)
            limit_hit = False
            for name, pat, _desc in patterns:
                info = result[name]
                if info["weak"] and info["count"] > 100000:
                    continue
                start = 0
                while True:
                    i = buf.find(pat, start)
                    if i < 0:
                        break
                    pos = buf_base + i
                    if pos >= base:
                        info["count"] += 1
                        if len(info["first_offsets"]) < seen_limit:
                            info["first_offsets"].append(pos)
                    start = i + 1
                    if info["count"] > 200000:
                        limit_hit = True
                        break
            total += len(data)
            base += len(data)
            prev_tail = buf[-overlap:]
            if limit_hit:
                break
    return {"bytes_scanned": total, "patterns": result}


# ---------------------------------------------------------------------------
# Whole-file report
# ---------------------------------------------------------------------------

def annotate_pup_magic_hits(path: str, scan: dict, size: int) -> None:
    """Mark magic hits that actually look like a PUP header.

    A 4-byte magic occurs about once per 4 GiB of random data, so a hit inside
    ciphertext is not evidence.  A real header has a plausible header_size /
    metadata_size pair at 0x0C / 0x0E.
    """
    for key in ("PS5_PUP", "PS4_PUP"):
        info = scan["patterns"].get(key)
        if not info:
            continue
        plausible = []
        with open(path, "rb") as f:
            for off in info["first_offsets"]:
                if off + PUP_HEADER_SIZE > size:
                    continue
                f.seek(off)
                buf = f.read(PUP_HEADER_SIZE)
                hs = u16(buf, 0x0C)
                ms = u16(buf, 0x0E)
                aligned = ((hs - 0x30) % PUP_ENTRY_SIZE == 0
                           or hs % PUP_ENTRY_SIZE == 0)
                if (PUP_HEADER_SIZE < hs <= 0x4000 and 0x50 <= ms <= 0x4000
                        and aligned):
                    plausible.append({
                        "offset": off,
                        "header_size": hs,
                        "metadata_size": ms,
                        "flags": u16(buf, 0x0A),
                    })
        info["plausible_headers"] = plausible


def sample_entropy(path: str, size: int, samples: int = 32, sample_size: int = 65536) -> dict:
    if size == 0:
        return {"samples": 0}
    n = min(samples, max(1, size // sample_size))
    step = max(sample_size, size // n)
    values = []
    with open(path, "rb") as f:
        for i in range(n):
            off = min(i * step, max(0, size - sample_size))
            f.seek(off)
            data = f.read(min(sample_size, size - off))
            values.append((off, round(entropy(data), 4)))
    return {
        "sample_size": sample_size,
        "samples": len(values),
        "min": min(v for _, v in values),
        "max": max(v for _, v in values),
        "mean": round(sum(v for _, v in values) / len(values), 4),
        "first": [{"offset": o, "entropy": e} for o, e in values[:8]],
    }


def build_report(path: str, do_scan: bool = True, scan_bytes: int | None = None,
                 synthetic: bool = False) -> dict:
    t0 = time.time()
    file_size = os.path.getsize(path)
    report = {
        "tool": "tools/pup/parse.py",
        "file": os.path.abspath(path),
        "size": file_size,
        "sha256": None,
        "sha256_scope": "whole file",
        "synthetic_fixture": synthetic,
        "container": None,
        "pups": [],
        "magic_scan": None,
        "entropy": None,
        "verdict": {},
        "warnings": [],
    }

    sha, sha_size = sha256_file(path)
    if sha_size != file_size:
        report["warnings"].append("file changed while hashing")
    report["sha256"] = sha

    with open(path, "rb") as f:
        magic = read_at(f, 0, 4)

        if magic == SLB2_MAGIC:
            try:
                container = parse_slb2(f, file_size)
            except ValueError as exc:
                report["warnings"].append(f"SLB2 parse failed: {exc}")
                container = None
            report["container"] = container
            if container:
                for rec in container["files"]:
                    if rec["name_ascii_valid"] and rec["offset"] + PUP_HEADER_SIZE <= file_size:
                        try:
                            report["pups"].append(parse_pup_fragment(f, rec, file_size))
                        except ValueError as exc:
                            report["warnings"].append(f"{rec['name']}: {exc}")
        else:
            head = read_at(f, 0, PUP_HEADER_SIZE)
            header = parse_pup_header(head)
            if header["kind"] == "unknown":
                report["warnings"].append(
                    f"unrecognised magic {header['magic']}; not an SLB2 container or PUP"
                )
            else:
                rec = {"name": os.path.basename(path), "offset": 0, "size": file_size}
                try:
                    report["pups"].append(parse_pup_fragment(f, rec, file_size))
                except ValueError as exc:
                    report["warnings"].append(f"PUP parse failed: {exc}")

    if do_scan:
        report["magic_scan"] = scan_magics(path, MAGICS, scan_bytes)
        annotate_pup_magic_hits(path, report["magic_scan"], file_size)
    report["entropy"] = sample_entropy(path, file_size)

    readable = sum(1 for p in report["pups"] if p["entry_table"]["readable"])
    total_entries = sum(len(p["entries"]) for p in report["pups"])
    encrypted = sum(1 for p in report["pups"] if not p["entry_table"]["readable"])

    report["verdict"] = {
        "container": report["container"]["type"] if report["container"] else "bare PUP",
        "pup_fragments": len(report["pups"]),
        "entry_tables_readable": readable,
        "entry_tables_encrypted": encrypted,
        "entries_parsed": total_entries,
        "entry_count_hypotheses": {
            p["name"]: p["entry_count_candidates"] for p in report["pups"]
        },
        "fully_parseable_on_pc": bool(report["pups"]) and encrypted == 0,
    }
    report["elapsed_seconds"] = round(time.time() - t0, 2)
    return report


# ---------------------------------------------------------------------------
# Human-readable summary and multi-file comparison
# ---------------------------------------------------------------------------

def _short_candidates(pup: dict) -> str:
    """Compact one-line form of the entry-count hypotheses."""
    parts = []
    for cand in pup.get("entry_count_candidates", []):
        trailer = cand.get("trailer")
        if trailer == 0x10 and cand.get("formula", "").startswith("header_size = 0x20"):
            tag = "PS4 formula"
        elif trailer == 0x00:
            tag = "no trailer"
        elif trailer == 0x20:
            tag = "0x20 trailer"
        elif trailer is None:
            tag = "table only"
        else:
            tag = f"trailer {trailer:#x}"
        parts.append(f"n={cand['count']} ({tag})")
    return "; ".join(parts) if parts else "-"


def render_summary(report: dict) -> str:
    """Multi-line human-readable dump of one parsed PUP."""
    lines: list[str] = []
    size = report["size"]
    lines.append(f"FILE      : {report['file']}")
    lines.append(f"size      : {size} bytes ({size / 2**30:.3f} GiB)")
    lines.append(f"sha256    : {report['sha256']}")
    container = report.get("container")
    if container:
        matches = "matches file size" if container.get("block_count_matches_file_size") else "does NOT match file size"
        lines.append(
            f"container : SLB2 version={container['version']} flags={container['flags_hex']} "
            f"file_count={container['file_count']} block_count={container['block_count']} "
            f"-> block_count*512={container['block_count_implied_size']} bytes ({matches})"
        )
        for rec in container.get("files", []):
            lines.append(
                f"  file[{rec['index']}] name={rec['name']} block_offset={rec['block_offset']} "
                f"offset={rec['offset']} size={rec['size']} end={rec['end']} "
                f"padding_to_512={rec['padding_to_512']}"
            )
        for warning in container.get("warnings", []):
            lines.append(f"  WARNING: {warning}")
    else:
        lines.append("container : none (bare PUP)")
    for pup in report.get("pups", []):
        header = pup["header"]
        lines.append(f"PUP fragment: {pup['name']} @ offset {pup['offset']} size {pup['size']}")
        lines.append(
            f"  header   : magic={header['magic']} ({header['magic_name']}) "
            f"version={header['version']} u16@0x06={header['unknown_06']} "
            f"u16@0x08={header['unknown_08']} flags@0x0A={header['flags_hex']} "
            f"header_size={header['header_size']} metadata_size={header['metadata_size']}"
        )
        lines.append(
            f"  plaintext: {header['header_already_decrypted']} "
            f"({0x10 if not header['header_already_decrypted'] else header['header_size']} "
            f"visible bytes of {header['header_size']})"
        )
        table = pup["entry_table"]
        reason = f" reason={table['reason']}" if table.get("reason") else ""
        lines.append(
            f"  entries  : readable={table['readable']} count={table.get('count', 0)}{reason}"
        )
        for cand in pup.get("entry_count_candidates", []):
            lines.append(f"    count hypothesis: n={cand['count']} via {cand['formula']}")
        for probe in pup.get("layout_probes", []):
            lines.append(
                f"    layout probe: entry_size={probe['entry_size']:#x} trailer={probe['trailer']:#x} "
                f"-> {probe['verdict']}"
            )
        region = pup.get("header_region", {})
        meta = pup.get("metadata_area", {})
        lines.append(
            f"  entropy  : header prefix(0x00-0x10)={region.get('entropy_prefix')} "
            f"header tail(0x10+)={region.get('entropy_suffix')} "
            f"metadata_area={meta.get('entropy')}"
        )
    whole = report.get("entropy") or {}
    if whole:
        lines.append(
            f"entropy   : {whole.get('samples')} samples of {whole.get('sample_size')} bytes, "
            f"min={whole.get('min')} max={whole.get('max')} mean={whole.get('mean')}"
        )
    scan = (report.get("magic_scan") or {}).get("patterns") or {}
    ps5 = scan.get("PS5_PUP") or {}
    if scan:
        parts = []
        for name, info in scan.items():
            weak = " (weak, random hits expected)" if info.get("weak") else ""
            parts.append(f"{name}={info.get('count')}{weak}")
        lines.append("magic scan: " + " ".join(parts))
        lines.append(
            f"magic scan: PS5 PUP plausible headers="
            f"{len(ps5.get('plausible_headers') or [])} of {ps5.get('count')} raw hits"
        )
    for warning in report.get("warnings", []):
        lines.append(f"WARNING   : {warning}")
    return "\n".join(lines)


def _field_values(report: dict) -> dict:
    """Flat dict of the fields worth comparing between firmware versions."""
    container = report.get("container") or {}
    pups = report.get("pups") or []
    pup = pups[0] if pups else {}
    header = pup.get("header") or {}
    table = pup.get("entry_table") or {}
    region = pup.get("header_region") or {}
    meta = pup.get("metadata_area") or {}
    whole = report.get("entropy") or {}
    scan = (report.get("magic_scan") or {}).get("patterns") or {}
    ps5 = scan.get("PS5_PUP") or {}
    files = container.get("files") or []
    return {
        "size": report.get("size"),
        "sha256": report.get("sha256"),
        "container_magic": container.get("magic"),
        "slb2_version": container.get("version"),
        "slb2_flags": container.get("flags_hex"),
        "slb2_file_count": container.get("file_count"),
        "slb2_block_count": container.get("block_count"),
        "slb2_implied_size": container.get("block_count_implied_size"),
        "fragment_name": pup.get("name"),
        "fragment_offset": pup.get("offset"),
        "fragment_size": pup.get("size"),
        "fragment_end": (files[0].get("end") if files else None),
        "fragment_padding": (files[0].get("padding_to_512") if files else None),
        "pup_kind": header.get("kind"),
        "pup_magic": header.get("magic"),
        "pup_version": header.get("version"),
        "pup_unk06": header.get("unknown_06"),
        "pup_unk08": header.get("unknown_08"),
        "pup_flags": header.get("flags_hex"),
        "header_size": header.get("header_size"),
        "metadata_size": header.get("metadata_size"),
        "header_plaintext": header.get("header_already_decrypted"),
        "entry_candidates": _short_candidates(pup),
        "entry_table_readable": table.get("readable"),
        "header_tail_entropy": region.get("entropy_suffix"),
        "metadata_entropy": meta.get("entropy"),
        "entropy_mean": whole.get("mean"),
        "ps5_magic_hits": ps5.get("count"),
        "ps5_plausible_headers": len(ps5.get("plausible_headers") or []),
    }


COMPARE_FIELDS = [
    ("size", "file size (bytes)"),
    ("sha256", "sha256"),
    ("container_magic", "outer magic"),
    ("slb2_version", "SLB2 version"),
    ("slb2_flags", "SLB2 flags"),
    ("slb2_file_count", "SLB2 file_count"),
    ("slb2_block_count", "SLB2 block_count"),
    ("slb2_implied_size", "SLB2 block_count*512"),
    ("fragment_name", "fragment name"),
    ("fragment_offset", "fragment offset"),
    ("fragment_size", "fragment size"),
    ("fragment_end", "fragment end"),
    ("fragment_padding", "fragment padding to 512"),
    ("pup_kind", "PUP kind"),
    ("pup_magic", "PUP magic"),
    ("pup_version", "PUP header version"),
    ("pup_unk06", "PUP u16@0x06"),
    ("pup_unk08", "PUP u16@0x08"),
    ("pup_flags", "PUP flags@0x0A"),
    ("header_size", "PUP header_size"),
    ("metadata_size", "PUP metadata_size"),
    ("header_plaintext", "header already plaintext"),
    ("entry_candidates", "entry-count hypotheses"),
    ("entry_table_readable", "entry table readable"),
    ("header_tail_entropy", "header tail entropy (bits/byte)"),
    ("metadata_entropy", "metadata area entropy (bits/byte)"),
    ("entropy_mean", "whole-file entropy, sampled mean"),
    ("ps5_magic_hits", "PS5 PUP magic byte hits"),
    ("ps5_plausible_headers", "PS5 headers that look real"),
]


def render_compare(reports: list[dict], labels: list[str]) -> str:
    """Per-file summaries plus a field-by-field comparison table."""
    out: list[str] = []
    out.append("PS5 PUP structural comparison - parse.py --compare")
    out.append(f"files : {len(reports)}")
    out.append("")
    for label, report in zip(labels, reports):
        out.append(f"### per-file dump: {label} ({os.path.basename(report['file'])})")
        out.append(render_summary(report))
        out.append("")

    maps = [_field_values(report) for report in reports]
    header_row = ["field"] + list(labels) + ["changed"]
    rows: list[list[str]] = []
    changed_titles: list[str] = []
    for key, title in COMPARE_FIELDS:
        cells = []
        for fieldmap in maps:
            value = fieldmap.get(key)
            cells.append("-" if value is None else str(value))
        changed = "yes" if len(set(cells)) > 1 else "no"
        if changed == "yes":
            changed_titles.append(title)
        rows.append([title] + cells + [changed])
    table = [header_row] + rows
    widths = [max(len(row[i]) for row in table) for i in range(len(header_row))]

    def fmt(row: list[str]) -> str:
        return "  ".join(cell.ljust(width) for cell, width in zip(row, widths))

    out.append("### field-by-field comparison")
    out.append(fmt(header_row))
    out.append(fmt(["-" * width for width in widths]))
    for row in rows:
        out.append(fmt(row))
    out.append("")
    out.append(f"fields that differ between the {len(reports)} files: {len(changed_titles)}")
    for title in changed_titles:
        out.append(f"  * {title}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Self-test: a synthetic, decrypted PS5 PUP exercising the record table path
# ---------------------------------------------------------------------------

def make_selftest_fixture(path: str) -> None:
    """Build a tiny plaintext PS5 PUP inside an SLB2 container.

    This is a test vector, not firmware: it proves the record-table branch
    (id/offset/size/flags) works.  Retail PUPs have this table encrypted.
    """
    entries = []
    payloads = []
    data_off = 0x20 + 3 * PUP_ENTRY_SIZE + 0x10  # header + table + trailer
    specs = [
        (0x00500000, 0x001000, 0x001000, False),   # id 5, plain
        (0x00700008, 0x002000, 0x004000, True),    # id 7, compressed
        (0x00800800, 0x003000, 0x003000, True),    # id 8, blocked
    ]
    cursor = data_off
    for flags, comp, uncomp, payload in specs:
        payloads.append(bytes([0xAB]) * comp if payload else bytes(comp))
        entries.append(struct.pack("<IIQQQ", flags, 0, cursor, comp, uncomp))
        cursor += comp

    header_size = data_off
    metadata_size = 0x20 + 3 * 0x50
    file_size = cursor + metadata_size
    header = struct.pack(
        "<IHHHHHHQHHI",
        PS5_PUP_MAGIC, 0x0110, 0x3201, 0x0004, 0x0001,
        header_size, metadata_size, file_size, 3, 3, 0,
    )
    assert len(header) == 0x20, len(header)
    # header + record table + 0x10 trailer + real payloads + metadata + tail.
    # The payloads must actually be present: the record offsets are checked
    # against the fragment size by the layout probes.
    pup = header + b"".join(entries) + b"\x00" * 0x10
    pup += b"".join(payloads)
    pup += b"\x5A" * metadata_size
    pup += b"\xCC" * 0x100  # payload tail
    # fix file_size to actual fragment length
    file_size = len(pup)
    header = struct.pack(
        "<IHHHHHHQHHI",
        PS5_PUP_MAGIC, 0x0110, 0x3201, 0x0004, 0x0001,
        header_size, metadata_size, file_size, 3, 3, 0,
    )
    pup = header + pup[0x20:]

    name = b"TEST.PUP" + b"\x00" * 24
    bls = struct.pack("<4sIIII12s", SLB2_MAGIC, 3, 0x00010000, 1, ceil_div(0x400 + len(pup), 512), b"\x00" * 12)
    bls += struct.pack("<II8s32s", 2, len(pup), b"\x00" * 8, name)
    blob = bls + b"\x00" * (0x400 - len(bls)) + pup
    blob += b"\x00" * (ceil_div(len(blob), 512) * 512 - len(blob))
    with open(path, "wb") as f:
        f.write(blob)


def run_selftest() -> int:
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "SELFTEST.PUP")
        make_selftest_fixture(path)
        report = build_report(path, do_scan=True, synthetic=True)
    report["file"] = "synthetic://SELFTEST.PUP (generated test vector, not firmware)"
    report["sha256_scope"] = "whole generated fixture"
    ok = (
        report["synthetic_fixture"] is True
        and len(report["pups"]) == 1
        and report["pups"][0]["entry_table"]["readable"] is True
        and len(report["pups"][0]["entries"]) == 3
        and [e["id"] for e in report["pups"][0]["entries"]] == [5, 7, 8]
        and report["pups"][0]["entries"][1]["is_compressed"] is True
        and report["pups"][0]["entries"][2]["has_blocks"] is True
        and any(
            probe["credible"]
            and probe["entry_size"] == PUP_ENTRY_SIZE
            and probe["trailer"] == 0x10
            and probe["entry_count"] == 3
            for probe in report["pups"][0]["layout_probes"]
        )
    )
    report["selftest_passed"] = ok
    if not ok:
        report["warnings"].append("self-test assertions failed")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Parse PS5 PUP (SCEUF) containers without a console.",
    )
    ap.add_argument("files", nargs="*", metavar="FILE",
                    help="PS5UPDATE.PUP or a .pup.dec fragment; several files with --compare")
    ap.add_argument("--out", help="write JSON here instead of stdout (single file)")
    ap.add_argument("--no-scan", action="store_true", help="skip the magic scan")
    ap.add_argument("--scan-bytes", type=int, default=None,
                    help="scan only the first N bytes (default: whole file)")
    ap.add_argument("--compact", action="store_true", help="single-line JSON")
    ap.add_argument("--summary", action="store_true",
                    help="human-readable dump instead of JSON (single file)")
    ap.add_argument("--compare", action="store_true",
                    help="parse 2+ files, print a field-by-field comparison table")
    ap.add_argument("--labels", default=None,
                    help="comma-separated labels for --compare (default: file names)")
    ap.add_argument("--selftest", action="store_true",
                    help="run the built-in plaintext-PUP test vector")
    args = ap.parse_args(argv)

    if args.selftest:
        if args.files:
            ap.error("--selftest takes no FILE")
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                old = sys.stdout
                sys.stdout = f
                try:
                    code = run_selftest()
                finally:
                    sys.stdout = old
            # run_selftest already printed to the file; mirror status to stderr
            print(f"self-test {'PASSED' if code == 0 else 'FAILED'}; wrote {args.out}", file=sys.stderr)
            return code
        return run_selftest()

    if not args.files:
        ap.error("FILE is required (or use --selftest)")

    if args.compare:
        if len(args.files) < 2:
            ap.error("--compare needs at least two files")
        labels = ([lab.strip() for lab in args.labels.split(",")] if args.labels
                  else [os.path.basename(path) for path in args.files])
        if len(labels) != len(args.files):
            ap.error(f"--labels has {len(labels)} entries for {len(args.files)} files")
        reports = []
        for path in args.files:
            if not os.path.isfile(path):
                print(f"error: no such file: {path}", file=sys.stderr)
                return 1
            try:
                reports.append(build_report(path, do_scan=not args.no_scan,
                                            scan_bytes=args.scan_bytes))
            except Exception as exc:  # noqa: BLE001 - CLI must report, not traceback
                print(f"error: {path}: {exc}", file=sys.stderr)
                return 1
        text = render_compare(reports, labels)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            print(f"wrote {args.out} ({len(text)} bytes)", file=sys.stderr)
        else:
            print(text)
        return 0

    if len(args.files) > 1:
        ap.error("several files given: use --compare")
    path = args.files[0]
    if not os.path.isfile(path):
        print(f"error: no such file: {path}", file=sys.stderr)
        return 1

    try:
        report = build_report(path, do_scan=not args.no_scan,
                              scan_bytes=args.scan_bytes)
    except Exception as exc:  # noqa: BLE001 - CLI must report, not traceback
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.summary:
        text = render_summary(report)
    else:
        text = json.dumps(report, indent=None if args.compact else 2,
                          ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"wrote {args.out} ({len(text)} bytes)", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))