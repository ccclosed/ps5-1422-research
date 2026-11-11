#!/usr/bin/env python3
"""self_probe.py - SELF (ProSPERO) / SLB2 probe for PS5 firmware containers.

Works without any key material.  Uses the sce_self_header layout from etaHEN's
self.h (SELF_PROSPERO_MAGIC = 0xEEF51454):

    0x00 u32 magic
    0x04 u8  version
    0x05 u8  mode
    0x06 u8  endian
    0x07 u8  attributes
    0x08 u32 key_type
    0x0C u16 header_size
    0x0E u16 metadata_size
    0x10 u64 file_size          (ciphertext in a retail PS5 SELF)
    0x18 u16 segment_count      (ciphertext)
    0x1A u16 flags              (ciphertext)
    0x1C 4-byte pad             (ciphertext)

Only 0x00..0x10 is plaintext in a retail PS5 SELF; everything after is
encrypted.  The tool reports that explicitly instead of inventing values, and
probes several plausible segment-table layouts (they are expected to fail on
ciphertext - a negative result is a result).

Usage:
    self_probe.py extract  SLB2_PUP OUTDIR          # dump SLB2 records, sha256
    self_probe.py header   FILE                      # SELF header + entropy map
    self_probe.py compare  FILE_A FILE_B             # field-by-field
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import struct
import sys

SLB2_MAGIC = b"SLB2"
SELF_PROSPERO_MAGIC = 0xEEF51454
SELF_ORBIS_MAGIC = 0x1D3D154F
SELF_HEADER_SIZE = 0x20
SEGMENT_HEADER_SIZE = 0x20
RECORD_OFFSET = 0x40      # SELF segment-record table (per unwrap_self.py)
RECORD_SIZE = 0x20
FIRST_REGION = 0x400

# The attribute byte has no public, authoritative bit-name table in self.h;
# report raw bit numbers instead of guessing names.
# Segment flag bits (from etaHEN self.h)
SEG_FLAG_BITS = [
    (1, "is_encrypted"),
    (2, "is_signed"),
    (3, "is_compressed"),
    (11, "has_blocks"),
    (16, "has_digests"),
    (17, "has_blockinfo"),
]


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def entropy(bs: bytes) -> float:
    if not bs:
        return 0.0
    counts = [0] * 256
    for x in bs:
        counts[x] += 1
    n = len(bs)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h



def random_entropy_expected(n: int, alphabet: int = 256) -> float:
    """Expected Shannon entropy of n uniformly random bytes (finite-sample bias).

    For n=256 bytes this is ~7.28, for n=1440 ~7.87 - i.e. a "random-looking"
    256-byte block never reaches 8.0.  Needed so we do not mistake small-sample
    entropy for structure.
    """
    if n <= 1:
        return 0.0
    m = min(alphabet, max(2, n))
    return math.log2(m) - (m - 1) / (2.0 * n * math.log(2.0))


def encryption_verdict(bs: bytes) -> dict:
    """Compare region entropy against the random expectation for that length."""
    obs = entropy(bs)
    exp = random_entropy_expected(len(bs))
    return {"length": len(bs), "entropy": round(obs, 4),
            "random_expected": round(exp, 4),
            "delta": round(obs - exp, 4),
            "looks_random": obs > exp - 0.25}


def sha256_file(path: str, chunk: int = 8 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# SLB2
# ---------------------------------------------------------------------------

def parse_slb2(path: str) -> dict:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        h = f.read(0x20)
        magic = h[0:4]
        if magic != SLB2_MAGIC:
            raise SystemExit(f"not an SLB2 container: magic {magic!r}")
        version, flags, file_count, block_count = struct.unpack_from("<IIII", h, 4)
        reserved = h[0x14:0x20]
        if not (1 <= file_count <= 16):
            raise SystemExit(f"implausible file_count={file_count}")
        table = f.read(0x30 * file_count)
        records = []
        for i in range(file_count):
            b = i * 0x30
            block_off, rec_size = struct.unpack_from("<II", table, b)
            rec_reserved = table[b + 8:b + 16]
            name = table[b + 16:b + 0x30].split(b"\0")[0].decode("latin-1")
            records.append({
                "index": i,
                "name": name,
                "block_offset": block_off,
                "offset": block_off * 512,
                "size": rec_size,
                "end": block_off * 512 + rec_size,
                "reserved": rec_reserved.hex(),
            })
    return {
        "path": path,
        "size": size,
        "magic": magic.decode("latin-1"),
        "version": version,
        "flags": flags,
        "file_count": file_count,
        "block_count": block_count,
        "block_count_implied_size": block_count * 512,
        "reserved": reserved.hex(),
        "records": records,
    }


def cmd_extract(args: argparse.Namespace) -> int:
    info = parse_slb2(args.pup)
    os.makedirs(args.outdir, exist_ok=True)
    print(f"SLB2 : {info['path']}")
    print(f"size : {info['size']}  version={info['version']} flags={info['flags']:#010x} "
          f"file_count={info['file_count']} block_count={info['block_count']} "
          f"(={info['block_count_implied_size']}, matches_size="
          f"{info['block_count_implied_size'] == info['size']})")
    print(f"reserved 0x14..0x20: {info['reserved']}")
    for rec in info["records"]:
        pad = 0
        print(f"  [{rec['index']}] {rec['name']}: block_offset={rec['block_offset']} "
              f"offset={rec['offset']} size={rec['size']} end={rec['end']} "
              f"reserved={rec['reserved']}")
        dest = os.path.join(args.outdir, f"1422-{rec['name']}")
        with open(args.pup, "rb") as f, open(dest, "wb") as o:
            f.seek(rec["offset"])
            left = rec["size"]
            while left:
                b = f.read(min(8 << 20, left))
                if not b:
                    raise SystemExit("short read while extracting")
                o.write(b)
                left -= len(b)
        print(f"      extracted -> {dest} ({os.path.getsize(dest)} bytes)")
        print(f"      sha256    = {sha256_file(dest)}")
        with open(dest, "rb") as f:
            print(f"      first0x20 = {f.read(0x20).hex()}")
    return 0


# ---------------------------------------------------------------------------
# SELF
# ---------------------------------------------------------------------------


def find_inner_elf(path: str) -> int:
    """Offset of the first plaintext "\\x7fELF" anywhere in the file, or -1.

    This is exactly the first gate of unwrap_self.py (line 111,
    `inner = data.find(b"\\x7fELF")`): a *decrypted* SELF carries a plaintext
    inner ELF, a retail-encrypted SELF does not.
    """
    import mmap
    size = os.path.getsize(path)
    if size == 0:
        return -1
    with open(path, "rb") as f:
        try:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            return f.read().find(b"\x7fELF")
        try:
            return mm.find(b"\x7fELF")
        finally:
            mm.close()


def read_self_records(path: str, size: int) -> list[dict]:
    """Parse the decrypted-SELF segment-record table at 0x40 (unwrap_self layout).

    For a retail-encrypted SELF the bytes there are ciphertext and no record
    passes the structural checks, so the list comes back empty.  That is the
    second thing unwrap_self.py relies on (read_records, lines 97-110).
    """
    with open(path, "rb") as f:
        data = f.read(FIRST_REGION)
    records = []
    offset = RECORD_OFFSET
    while offset + RECORD_SIZE <= len(data):
        flags, segment, rec_size, size_again = struct.unpack_from("<QQQQ", data, offset)
        if rec_size == 0 or rec_size != size_again:
            break
        if segment >= size or segment < 0x350 or segment % 0x10 != 0:
            break
        if rec_size > size:
            break
        records.append({"flags": flags, "flag_has_segment": bool(flags & 0x800),
                        "segment_index_from_flags": flags >> 20,
                        "offset": segment, "size": rec_size})
        offset += RECORD_SIZE
    return records


def parse_self_header(path: str) -> dict:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        buf = f.read(0x4000)
    magic = u32(buf, 0)
    if magic == SELF_PROSPERO_MAGIC:
        kind = "SELF-PROSPERO (PS5)"
    elif magic == SELF_ORBIS_MAGIC:
        kind = "SELF-ORBIS (PS4)"
    else:
        kind = f"unknown magic {magic:#010x}"
    plain = buf[0x00:0x10]
    enc_probe = buf[0x10:0x20]
    header_size = u16(buf, 0x0C)
    metadata_size = u16(buf, 0x0E)
    attributes = buf[0x07]
    # determine encryption from a *large enough* region: header bytes after 0x10
    # (bounded by header_size) and the metadata area.
    hdr_tail_len = max(0, min(header_size, len(buf)) - 0x10)
    hdr_verdict = encryption_verdict(buf[0x10:0x10 + hdr_tail_len]) if hdr_tail_len else None
    meta_off = header_size
    meta_verdict = (encryption_verdict(buf[meta_off:meta_off + metadata_size])
                    if metadata_size and meta_off + metadata_size <= len(buf) else None)
    encrypted = bool(hdr_verdict and hdr_verdict["looks_random"])
    flags = {
        "magic": f"{magic:#010x}",
        "kind": kind,
        "version": buf[0x04],
        "mode": buf[0x05],
        "endian": buf[0x06],
        "attributes": f"{attributes:#04x}",
        "attribute_bits": [bit for bit in range(8) if attributes & (1 << bit)],
        "key_type": u32(buf, 0x08),
        "header_size": header_size,
        "metadata_size": metadata_size,
        "file_size_field_0x10": None if encrypted else u64(buf, 0x10),
        "segment_count_field_0x18": None if encrypted else u16(buf, 0x18),
        "flags_field_0x1A": None if encrypted else f"{u16(buf, 0x1A):#06x}",
        "pad_0x1C": None if encrypted else buf[0x1C:0x20].hex(),
        "plaintext_bytes_0x00_0x10": plain.hex(),
        "bytes_0x10_0x20": enc_probe.hex(),
        "header_tail_verdict": hdr_verdict,
        "metadata_area_verdict": meta_verdict,
        "header_encrypted": encrypted,
        "self_records": read_self_records(path, size),
        "self_records_count": len(read_self_records(path, size)),
        "inner_elf_offset": find_inner_elf(path),
        "size": size,
    }
    flags["verdict"] = (
        "decrypted SELF (fSELF): plaintext inner ELF present, record table readable -> unwrap_self.py can unwrap"
        if (not flags["header_encrypted"] and flags["inner_elf_offset"] >= 0
            and flags["self_records_count"] > 0)
        else "retail-encrypted SELF: no plaintext inner ELF and/or record table unreadable "
             "-> unwrap_self.py refuses (\"no inner ELF header\" / \"every load segment looks encrypted\")"
    )
    flags["entropy_map_256B_first4K"] = [
        round(entropy(buf[i:i + 256]), 4) for i in range(0, min(0x1000, len(buf)), 256)
    ]
    return flags


def segment_table_probes(path: str, header_size: int, max_bytes: int = 0x1000) -> list[dict]:
    """Try plausible segment-table layouts; report what decodes (expected: nothing)."""
    with open(path, "rb") as f:
        buf = f.read(max(0x4000, max_bytes))
    size = os.path.getsize(path)
    probes = []
    layouts = [
        (0x00, "header_size = 0x20 + n*0x20 (no trailer)"),
        (0x10, "header_size = 0x20 + n*0x20 + 0x10 (PS4 formula)"),
        (0x20, "header_size = 0x20 + n*0x20 + 0x20"),
        (0x30, "header_size = 0x20 + n*0x20 + 0x30"),
    ]
    for trailer, label in layouts:
        rem = header_size - SELF_HEADER_SIZE - trailer
        if rem < 0 or rem % SEGMENT_HEADER_SIZE:
            probes.append({"layout": label, "fits": False, "count": None,
                           "verdict": f"rejected: {header_size} != 0x20 + n*0x20 + {trailer:#x}"})
            continue
        count = rem // SEGMENT_HEADER_SIZE
        probe = {"layout": label, "fits": True, "count": count, "verdict": ""}
        if count <= 0 or SELF_HEADER_SIZE + count * SEGMENT_HEADER_SIZE + trailer > len(buf):
            probe["verdict"] = "rejected: table does not fit header area"
            probes.append(probe)
            continue
        table = buf[SELF_HEADER_SIZE:SELF_HEADER_SIZE + count * SEGMENT_HEADER_SIZE]
        mono = aligned = plausible = within = 0
        prev = -1
        for i in range(count):
            b = i * SEGMENT_HEADER_SIZE
            flags = u64(table, b)
            off = u64(table, b + 8)
            comp = u64(table, b + 0x10)
            uncomp = u64(table, b + 0x18)
            if off >= prev:
                mono += 1
            if off % 0x10 == 0:
                aligned += 1
            if 0 < comp <= size and 0 < uncomp <= (1 << 40):
                plausible += 1
            if off < size and off + comp <= size:
                within += 1
            prev = off
        probe["metrics"] = {
            "entries": count,
            "entropy": round(entropy(table), 4),
            "monotonic_fraction": round(mono / count, 4),
            "aligned_fraction": round(aligned / count, 4),
            "plausible_sizes_fraction": round(plausible / count, 4),
            "within_file_fraction": round(within / count, 4),
        }
        credible = (
            probe["metrics"]["entropy"] < 7.0
            and probe["metrics"]["monotonic_fraction"] > 0.95
            and probe["metrics"]["aligned_fraction"] > 0.95
            and probe["metrics"]["within_file_fraction"] > 0.95
        )
        probe["credible"] = credible
        probe["verdict"] = ("readable: segment table decodes" if credible
                            else "not credible: bytes do not decode into a segment table")
        probes.append(probe)
    return probes


def cmd_header(args: argparse.Namespace) -> int:
    h = parse_self_header(args.file)
    print(f"SELF : {args.file} ({h['size']} bytes)")
    for key in ("kind", "magic", "version", "mode", "endian", "attributes",
                "attribute_bits", "key_type", "header_size", "metadata_size",
                "plaintext_bytes_0x00_0x10", "bytes_0x10_0x20",
                "header_tail_verdict", "metadata_area_verdict", "header_encrypted",
                "file_size_field_0x10", "segment_count_field_0x18",
                "flags_field_0x1A", "pad_0x1C", "self_records_count",
                "inner_elf_offset", "verdict"):
        print(f"  {key:26}: {h[key]}")
    print(f"  entropy per 256 B, first 4 KiB: {h['entropy_map_256B_first4K']}")
    print("  segment-table layout probes:")
    for p in segment_table_probes(args.file, h["header_size"]):
        print(f"    {p['layout']}: fits={p['fits']} count={p['count']} "
              f"credible={p.get('credible')} -> {p['verdict']}")
        if "metrics" in p:
            print(f"      metrics={p['metrics']}")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    a = parse_self_header(args.a)
    b = parse_self_header(args.b)
    keys = ["kind", "magic", "version", "mode", "endian", "attributes",
            "attribute_bits", "key_type", "header_size", "metadata_size",
            "plaintext_bytes_0x00_0x10", "bytes_0x10_0x20",
            "header_tail_verdict", "metadata_area_verdict", "header_encrypted",
            "self_records_count", "inner_elf_offset", "verdict"]
    print(f"compare: A={args.a}  B={args.b}")
    print(f"{'field':28} {'A':>24} {'B':>24}  changed")
    for k in keys:
        va, vb = str(a[k]), str(b[k])
        print(f"{k:28} {va:>24} {vb:>24}  {'YES' if va != vb else 'no'}")
    print(f"\nA header hex 0x00-0x20: {a['plaintext_bytes_0x00_0x10']}{a['bytes_0x10_0x20']}")
    print(f"B header hex 0x00-0x20: {b['plaintext_bytes_0x00_0x10']}{b['bytes_0x10_0x20']}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("extract")
    p.add_argument("pup")
    p.add_argument("outdir")
    p.set_defaults(func=cmd_extract)
    p = sub.add_parser("header")
    p.add_argument("file")
    p.set_defaults(func=cmd_header)
    p = sub.add_parser("compare")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(func=cmd_compare)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))