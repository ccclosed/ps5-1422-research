#!/usr/bin/env python3
"""scan_self_classes.py - classify every PS5 SELF-like file in a tree, read-only.

For each file (and for SELF members inside SLB2 PUP containers and ZIPs) it
reports: SELF header fields (magic/version/mode/endian/attributes/key_type/
header_size/metadata_size), whether the header is plaintext or ciphertext,
segment-record count, per-segment entropy, presence of a plaintext inner ELF,
and finally the class:

    DECRYPTED  (fSELF)  header readable, records parse, plaintext inner ELF,
                        segments flagged not-encrypted, entropy < 7.5
    MIXED               some segment records flagged encrypted, some not
                        (the hypothetical third class)
    ENCRYPTED_SEGMENTS  header readable but segments flagged encrypted
    RETAIL              header itself is ciphertext (firmware PUP SELF)
    ELF                 already-unpacked ET_SCE_DYNAMIC module (not a SELF)
    OTHER               anything else

Also prints PT_SCE_COMMENT build path and SCE version segment for ELF modules,
so the code era can be read from real bytes.

No keys, no decryption, no writes: only header/record reads and small entropy
samples (64 KiB per segment), safe on multi-GB files.

Usage:
    scan_self_classes.py PATH [PATH ...] [--json OUT] [--max-read-mb N]
"""

from __future__ import annotations

import argparse
import io
import json
import math
import os
import re
import struct
import sys
import zipfile

SELF_MAGICS = {0x1D3D154F: "SELF-ORBIS", 0xEEF51454: "SELF-PROSPERO"}
SLB2_MAGIC = b"SLB2"
ELF_MAGIC = b"\x7fELF"
RECORD_OFFSET = 0x40
RECORD_SIZE = 0x20
FIRST_REGION = 0x400
SEG_ENTROPY_LIMIT = 7.5
SEG_SAMPLE = 64 << 10
INNER_ELF_WINDOW = 1 << 20          # bounded inner-ELF search (real offset is 0x1A0)
ZIP_MEMBER_MAX = 64 << 20
BUILD_RE = re.compile(r"([A-Za-z]:/Build/(J\d+)/[^\\x00]*)")


# ---------------------------------------------------------------------------
# readers
# ---------------------------------------------------------------------------

class FileReader:
    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "rb")

    def read(self, offset: int, size: int) -> bytes:
        self.f.seek(offset)
        return self.f.read(size)

    def close(self):
        self.f.close()


class BytesReader:
    def __init__(self, data: bytes):
        self.data = data

    def read(self, offset: int, size: int) -> bytes:
        return self.data[offset:offset + size]

    def close(self):
        pass


def entropy(data: bytes) -> float:
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


def random_entropy_expected(n: int) -> float:
    """Expected entropy of n uniformly random bytes (finite-sample bias)."""
    if n <= 1:
        return 0.0
    m = min(256, max(2, n))
    return math.log2(m) - (m - 1) / (2.0 * n * math.log(2.0))


# ---------------------------------------------------------------------------
# classifiers
# ---------------------------------------------------------------------------

def read_self_header(reader, base: int) -> dict | None:
    head = reader.read(base, 0x20)
    if len(head) < 0x20:
        return None
    magic = struct.unpack_from("<I", head, 0)[0]
    if magic not in SELF_MAGICS:
        return None
    return {
        "magic": f"{magic:#010x}",
        "magic_name": SELF_MAGICS[magic],
        "version": head[4],
        "mode": head[5],
        "endian": head[6],
        "attributes": head[7],
        "key_type": struct.unpack_from("<I", head, 0x08)[0],
        "header_size": struct.unpack_from("<H", head, 0x0C)[0],
        "metadata_size": struct.unpack_from("<H", head, 0x0E)[0],
        "head_hex": head.hex(),
    }


def read_records(reader, base: int, file_size: int) -> list[dict]:
    data = reader.read(base, FIRST_REGION)
    records = []
    offset = RECORD_OFFSET
    while offset + RECORD_SIZE <= len(data):
        flags, segment, rec_size, size_again = struct.unpack_from("<QQQQ", data, offset)
        if rec_size == 0 or rec_size != size_again:
            break
        if segment >= file_size or segment < 0x350 or segment % 0x10 != 0:
            break
        if rec_size > file_size:
            break
        records.append({"flags": flags, "encrypted_flag": bool(flags & 0x2),
                        "compressed_flag": bool(flags & 0x8),
                        "segment_index": flags >> 20,
                        "offset": segment, "size": rec_size})
        offset += RECORD_SIZE
    return records


def classify_self(reader, base: int, size: int, label: str) -> dict:
    h = read_self_header(reader, base)
    if not h:
        return {"label": label, "kind": "other", "class": "OTHER"}
    tail_len = max(0, min(h["header_size"], 0x1000) - 0x10)
    tail = reader.read(base + 0x10, tail_len) if tail_len else b""
    tail_ent = entropy(tail)
    tail_exp = random_entropy_expected(len(tail))
    header_readable = bool(tail) and tail_ent < tail_exp - 0.25
    records = read_records(reader, base, size) if header_readable else []
    inner_elf = -1
    if header_readable and size > 0:
        window = reader.read(base, min(size, INNER_ELF_WINDOW))
        inner_elf = window.find(ELF_MAGIC)
    seg_entropies = []
    for rec in records[:64]:
        sample = reader.read(base + rec["offset"], min(rec["size"], SEG_SAMPLE))
        rec["entropy"] = round(entropy(sample), 3)
        seg_entropies.append(rec["entropy"])
    payload_offset = base + (h["header_size"] or FIRST_REGION)
    payload_sample = reader.read(payload_offset, min(size - (h["header_size"] or FIRST_REGION), SEG_SAMPLE)) \
        if size > (h["header_size"] or FIRST_REGION) else b""
    payload_entropy = round(entropy(payload_sample), 3)

    enc_flags = [r["encrypted_flag"] for r in records]
    all_clear = bool(records) and not any(enc_flags)
    mixed = any(enc_flags) and not all(enc_flags)
    high = sum(1 for e in seg_entropies if e >= SEG_ENTROPY_LIMIT)
    if not header_readable:
        klass = "RETAIL"          # header ciphertext: firmware SELF
    elif mixed:
        klass = "MIXED"           # hypothetical third class
    elif all_clear and high == 0 and inner_elf >= 0:
        klass = "DECRYPTED"       # fSELF: unwrap_self.py can unwrap
    elif all_clear:
        klass = "DECRYPTED_HIGH_ENTROPY"
    elif enc_flags and all(enc_flags):
        klass = "ENCRYPTED_SEGMENTS"
    else:
        klass = "UNKNOWN"
    return {
        "label": label,
        "kind": h["magic_name"],
        "class": klass,
        "magic": h["magic"],
        "version": h["version"],
        "attributes": f"{h['attributes']:#04x}",
        "key_type": h["key_type"],
        "header_size": h["header_size"],
        "metadata_size": h["metadata_size"],
        "header_readable": header_readable,
        "header_tail_entropy": round(tail_ent, 3),
        "header_tail_random_expected": round(tail_exp, 3),
        "records": len(records),
        "encrypted_flags_true": sum(1 for x in enc_flags if x),
        "mixed_flags": mixed,
        "inner_elf_offset": inner_elf,
        "seg_entropy_min": min(seg_entropies) if seg_entropies else None,
        "seg_entropy_max": max(seg_entropies) if seg_entropies else None,
        "seg_entropy_high_count": high,
        "payload_entropy": payload_entropy,
        "unwrap_possible": klass == "DECRYPTED",
        "key_type_is_4": h["key_type"] == 4,
        "head_hex": h["head_hex"],
    }


def classify_elf(reader, base: int, size: int, label: str) -> dict:
    head = reader.read(base, 0x40)
    if len(head) < 0x40:
        return {"label": label, "kind": "elf", "class": "OTHER"}
    e_type = struct.unpack_from("<H", head, 0x10)[0]
    phoff = struct.unpack_from("<Q", head, 0x20)[0]
    phentsize = struct.unpack_from("<H", head, 0x36)[0]
    phnum = struct.unpack_from("<H", head, 0x38)[0]
    comments: list[str] = []
    versions: list[str] = []
    for i in range(min(phnum, 64)):
        o = base + phoff + i * phentsize
        ph = reader.read(o, 56)
        if len(ph) < 56:
            break
        p_type, _flags = struct.unpack_from("<II", ph, 0)
        p_offset, p_filesz = struct.unpack_from("<Q", ph, 0x08)[0], struct.unpack_from("<Q", ph, 0x20)[0]
        if p_type == 0x6FFFFF00 and p_filesz and p_filesz < 0x1000:
            raw = reader.read(base + p_offset, min(p_filesz, 0x1000))
            if raw[:4] == b"PATH":
                ln = struct.unpack_from("<I", raw, 8)[0]
                comments.append(raw[12:12 + ln].decode("latin-1", "replace").rstrip("\0"))
        elif p_type == 0x6FFFFF01 and p_filesz and p_filesz < 0x100:
            versions.append(reader.read(base + p_offset, p_filesz).hex())
    build_id = None
    comment = comments[0] if comments else None
    if comment:
        m = BUILD_RE.search(comment)
        build_id = m.group(2) if m else None
    return {
        "label": label,
        "kind": "elf",
        "class": "ELF",
        "e_type": f"{e_type:#06x}",
        "osabi": head[7],
        "phnum": phnum,
        "build_id": build_id,
        "comment": comment,
        "sce_version": versions[0][:64] if versions else None,
        "size": size,
    }


def classify_slb2(reader, size: int, label: str) -> list[dict]:
    head = reader.read(0, 0x20)
    if len(head) < 0x20 or head[0:4] != SLB2_MAGIC:
        return []
    file_count = struct.unpack_from("<I", head, 0x0C)[0]
    block_count = struct.unpack_from("<I", head, 0x10)[0]
    if not (1 <= file_count <= 16):
        return []
    table = reader.read(0x20, 0x30 * file_count)
    rows = []
    for i in range(file_count):
        b = i * 0x30
        block_off, rec_size = struct.unpack_from("<II", table, b)
        name = table[b + 16:b + 0x30].split(b"\0")[0].decode("latin-1", "replace")
        off = block_off * 512
        rows.append(classify_self(reader, off, rec_size,
                                  f"{label}::SLB2[{i}]/{name} @0x{off:x} ({rec_size})"))
    # container itself as a row too
    rows.insert(0, {"label": label, "kind": "SLB2", "class": "CONTAINER",
                    "file_count": file_count,
                    "block_count": block_count,
                    "block_count_matches": block_count * 512 == size,
                    "payloads": [r["label"] for r in rows]})
    return rows


def classify_zip(path: str, max_read_mb: int) -> list[dict]:
    rows = []
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return [{"label": path, "kind": "zip", "class": "OTHER", "note": "unreadable zip"}]
    limit = max_read_mb << 20
    for info in z.infolist():
        if info.is_dir() or info.file_size > limit:
            continue
        try:
            data = z.read(info)
        except (RuntimeError, OSError, zipfile.BadZipFile):
            continue
        if len(data) < 0x20:
            continue
        magic = struct.unpack_from("<I", data, 0)[0]
        label = f"{os.path.basename(path)}::{info.filename}"
        if magic in SELF_MAGICS:
            rows.append(classify_self(BytesReader(data), 0, len(data), label))
        elif data[:4] == ELF_MAGIC:
            rows.append(classify_elf(BytesReader(data), 0, len(data), label))
    return rows


def classify_path(path: str, max_read_mb: int) -> list[dict]:
    size = os.path.getsize(path)
    label = path
    # container types first
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return [{"label": label, "kind": "?", "class": "OTHER", "note": "unreadable"}]
    if head == SLB2_MAGIC:
        fr = FileReader(path)
        try:
            return classify_slb2(fr, size, label)
        finally:
            fr.close()
    if path.lower().endswith(".zip") or head[:2] == b"PK":
        return classify_zip(path, max_read_mb)
    if head == ELF_MAGIC:
        fr = FileReader(path)
        try:
            return [classify_elf(fr, 0, size, label)]
        finally:
            fr.close()
    if size >= 0x20:
        try:
            magic = struct.unpack_from("<I", open(path, "rb").read(0x20), 0)[0]
        except OSError:
            magic = 0
        if magic in SELF_MAGICS:
            fr = FileReader(path)
            try:
                return [classify_self(fr, 0, size, label)]
            finally:
                fr.close()
    return [{"label": label, "kind": "other", "class": "OTHER", "size": size}]


# ---------------------------------------------------------------------------
# table
# ---------------------------------------------------------------------------

SELF_COLUMNS = ["class", "magic", "ver", "attrs", "key_type", "hdr", "meta",
                "recs", "enc", "innerELF", "seg_entropy", "unwrap"]


def render(rows: list[dict]) -> str:
    out = []
    out.append(f"{'label':60} {'kind':16} {'class':14} {'magic':10} {'ver':>3} {'attrs':>5} "
               f"{'key_type':>8} {'hdr':>5} {'meta':>5} {'recs':>4} {'innerELF':>8} "
               f"{'seg_ent min/max':>15} {'unwrap':>6}")
    out.append("-" * 170)
    for r in rows:
        if r["class"] == "CONTAINER":
            out.append(f"{r['label']:60} {'SLB2':16} {'CONTAINER':14} "
                       f"file_count={r['file_count']} block_count={r['block_count']} "
                       f"matches_size={r['block_count_matches']}")
            continue
        if r["kind"] == "elf":
            out.append(f"{r['label']:60} {'ELF':16} {'ELF':14} e_type={r['e_type']} osabi={r['osabi']} "
                       f"phnum={r['phnum']} build={r['build_id']} sce_ver={str(r['sce_version'])[:18]}")
            continue
        if r["class"] == "OTHER":
            out.append(f"{r['label']:60} {r.get('kind','other'):16} {'OTHER':14} size={r.get('size','?')}")
            continue
        seg = ("-" if r["seg_entropy_min"] is None
               else f"{r['seg_entropy_min']:.2f}/{r['seg_entropy_max']:.2f}")
        out.append(f"{r['label']:60} {r['kind']:16} {r['class']:14} {r['magic']:10} "
                   f"{r['version']:>3} {r['attributes']:>5} {r['key_type']:>8} "
                   f"{r['header_size']:>5} {r['metadata_size']:>5} {r['records']:>4} "
                   f"{r['inner_elf_offset']:>8} {seg:>15} {str(r['unwrap_possible']):>6}")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", help="write full results as JSON")
    ap.add_argument("--max-read-mb", type=int, default=64,
                    help="skip ZIP members larger than this (MiB)")
    ap.add_argument("--summary", action="store_true", default=True)
    args = ap.parse_args(argv)

    rows: list[dict] = []
    files = 0
    for root in args.paths:
        if os.path.isfile(root):
            targets = [root]
        else:
            targets = []
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames.sort()
                for fn in sorted(filenames):
                    targets.append(os.path.join(dirpath, fn))
        for path in targets:
            if os.path.islink(path) and not os.path.exists(path):
                continue
            try:
                if not os.path.isfile(path):
                    continue
                files += 1
                rows.extend(classify_path(path, args.max_read_mb))
            except (OSError, struct.error, ValueError) as exc:
                rows.append({"label": path, "kind": "?", "class": "OTHER",
                             "note": f"error: {exc}"})
    print(render(rows))

    print()
    print("=" * 170)
    print(f"SUMMARY: files read={files}, rows={len(rows)}")
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["class"]] = counts.get(r["class"], 0) + 1
    for cls, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  class {cls:24}: {n}")
    kt4 = [r for r in rows if r.get("key_type_is_4")]
    print(f"\n  SELF/container entries with key_type=4: {len(kt4)}")
    for r in kt4:
        print(f"    {r['class']:14} unwrap_possible={r.get('unwrap_possible')} "
              f"inner_elf={r.get('inner_elf_offset')} {r['label']}")
    mixed = [r for r in rows if r["class"] == "MIXED"]
    print(f"\n  MIXED (partially encrypted) entries: {len(mixed)}")
    for r in mixed:
        print(f"    {r['label']} enc_flags={r['encrypted_flags_true']}/{r['records']} "
              f"seg_entropy={r['seg_entropy_min']}..{r['seg_entropy_max']}")
    dec = [r for r in rows if r["class"] == "DECRYPTED"]
    print(f"\n  DECRYPTED/fSELF (unwrap_self.py can unwrap): {len(dec)}")
    for r in dec[:25]:
        print(f"    key_type={r['key_type']} ver={r['version']} attrs={r['attributes']} "
              f"recs={r['records']} seg_entropy={r['seg_entropy_min']}..{r['seg_entropy_max']} {r['label']}")
    if len(dec) > 25:
        print(f"    ... and {len(dec) - 25} more")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=1, ensure_ascii=False)
        print(f"\n  json written: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))