#!/usr/bin/env python3
"""delta1422.py - what can be learned from the 14.20 -> 14.22 PUP pair without keys.

The inner image is ciphertext, so this tool does not pretend to diff code.  It
answers the questions that *are* answerable on a PC:

  1. Is 14.22 a delta patch against 14.20 at container level?
     (record table, base-version references, delta magics, plaintext tokens)
  2. What lives in the PUP header area (header_size=1456) and metadata area
     (metadata_size=3552) - entropy, self-repetition, cross-version equality,
     any readable fields?
  3. A byte/sector/page map of differences over the whole file: where do the
     versions coincide, where do they differ, and does comparison under a
     4096-byte shift reveal an insertion point (i.e. stream-preserving data)?
  4. Can the changed subsystem be localised from the container alone?

All measurements are exact (numpy byte comparisons) or statistical, and every
number printed here can be reproduced with the commands in the report.

Usage:
    python3 tools/pup/delta1422.py A.PUP B.PUP [--label-a 14.20] [--label-b 14.22]
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import sys

try:
    import numpy as np
except ImportError:  # pragma: no cover
    sys.exit("error: numpy is required (pip install --user numpy)")

PAGE = 4096
SECTOR = 512
WINDOW = 1 << 20          # 1 MiB diff-map cell
CHUNK = 256 << 20         # sector-digest chunk
STRUCT_END = 0x410        # end of the plaintext PUP header prefix (0x400..0x410)
PUP_OFF = 0x400
HEADER_SIZE = 1456
METADATA_SIZE = 3552
HEADER_AREA = (PUP_OFF + 0x10, PUP_OFF + HEADER_SIZE)          # 0x410..0x9B0
METADATA_AREA = (PUP_OFF + HEADER_SIZE, PUP_OFF + HEADER_SIZE + METADATA_SIZE)  # 0x9B0..0x1790


def entropy(bs: bytes) -> float:
    if not bs:
        return 0.0
    counts = [0] * 256
    for b in bs:
        counts[b] += 1
    n = len(bs)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def printable_runs(bs: bytes, minlen: int = 4) -> list[bytes]:
    runs, cur = [], bytearray()
    for b in bs:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                runs.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= minlen:
        runs.append(bytes(cur))
    return runs


def xor_sector_digests(path: str) -> np.ndarray:
    """One uint64 digest per 512-byte sector (XOR fold of its 64 words).

    Equal sectors always give equal digests; for random ciphertext the chance
    of a false positive is ~2^-64 per pair, i.e. negligible.
    """
    parts: list[np.ndarray] = []
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            usable = (len(block) // SECTOR) * SECTOR
            arr = np.frombuffer(block[:usable], dtype=np.uint64).reshape(-1, SECTOR // 8)
            parts.append(np.bitwise_xor.reduce(arr, axis=1).astype(np.uint64))
            if usable < len(block):  # partial trailing sector (not expected for PUP)
                parts.append(np.frombuffer(
                    hashlib.blake2b(block[usable:], digest_size=8).digest(), dtype=np.uint64))
    return np.concatenate(parts)


def pairwise_maps(path_a: str, path_b: str) -> dict:
    """Exact per-byte / per-16B-block / per-4K-page comparison over the common part."""
    size_a, size_b = os.path.getsize(path_a), os.path.getsize(path_b)
    n = min(size_a, size_b)
    common = n - (n % WINDOW)
    per_window: list[dict] = []
    blocks16_equal = 0
    blocks16_equal_offsets: list[int] = []
    pages_equal = 0
    pages_equal_offsets: list[int] = []
    equal_bytes = 0
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        base = 0
        while base < n:
            want = min(WINDOW, n - base)
            A = np.frombuffer(fa.read(want), dtype=np.uint8)
            B = np.frombuffer(fb.read(want), dtype=np.uint8)
            eqb = A == B
            equal_bytes += int(eqb.sum())
            m16 = (want // 16) * 16
            eq16 = np.all(A[:m16].reshape(-1, 16) == B[:m16].reshape(-1, 16), axis=1)
            idx16 = np.flatnonzero(eq16)
            blocks16_equal += int(idx16.size)
            if len(blocks16_equal_offsets) < 400:
                blocks16_equal_offsets.extend((base + idx16 * 16)[:400].tolist())
            mp = (want // PAGE) * PAGE
            eqp = np.all(A[:mp].reshape(-1, PAGE) == B[:mp].reshape(-1, PAGE), axis=1)
            idxp = np.flatnonzero(eqp)
            pages_equal += int(idxp.size)
            if len(pages_equal_offsets) < 200:
                pages_equal_offsets.extend((base + idxp * PAGE)[:200].tolist())
            per_window.append({
                "offset": base,
                "diff_bytes": int(want - eqb.sum()),
                "equal_pages": int(idxp.size),
                "pages": int(mp // PAGE),
            })
            base += want
        # trailing part of the longer file (only meaningful for the size delta)
        tail_a = fa.read()
        tail_b = fb.read()
    return {
        "common_bytes": n,
        "common_bytes_window_aligned": common,
        "equal_bytes": equal_bytes,
        "equal_byte_fraction": equal_bytes / n if n else 0.0,
        "blocks16_equal": blocks16_equal,
        "blocks16_equal_offsets": blocks16_equal_offsets,
        "pages_equal": pages_equal,
        "pages_equal_offsets": pages_equal_offsets,
        "per_window": per_window,
        "tail_a_bytes": len(tail_a),
        "tail_b_bytes": len(tail_b),
        "size_a": size_a,
        "size_b": size_b,
    }


def region_report(name: str, region: bytes) -> dict:
    blocks16 = [region[i:i + 16] for i in range(0, len(region) - 15, 16)]
    block_entropies = [entropy(b) for b in blocks16]
    return {
        "name": name,
        "len": len(region),
        "entropy": round(entropy(region), 4),
        "zero_bytes": region.count(0),
        "byte_values": len(set(region)),
        "blocks16": len(blocks16),
        "unique_blocks16": len(set(blocks16)),
        "block16_entropy_min": round(min(block_entropies), 4) if block_entropies else None,
        "block16_entropy_mean": round(sum(block_entropies) / len(block_entropies), 4) if block_entropies else None,
        "block16_entropy_max": round(max(block_entropies), 4) if block_entropies else None,
        "printable_runs": [r.decode("latin-1") for r in printable_runs(region)][:12],
        "hex_first64": region[:64].hex(),
    }


def region_compare(a: bytes, b: bytes) -> dict:
    n = min(len(a), len(b))
    equal = sum(1 for i in range(n) if a[i] == b[i])
    blocks_a = [a[i:i + 16] for i in range(0, n - 15, 16)]
    blocks_b = [b[i:i + 16] for i in range(0, n - 15, 16)]
    eq_blocks = sum(1 for x, y in zip(blocks_a, blocks_b) if x == y)
    return {
        "common_len": n,
        "equal_bytes": equal,
        "equal_byte_fraction": equal / n if n else 0.0,
        "equal_blocks16": eq_blocks,
        "blocks16": len(blocks_a),
        "identical": a[:n] == b[:n],
    }



def structural_diff(path_a: str, path_b: str, end: int = STRUCT_END) -> dict:
    """Byte diff of the readable structural region (SLB2 header + plaintext PUP prefix)."""
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        a, b = fa.read(end), fb.read(end)
    n = min(len(a), len(b))
    diffs = [i for i in range(n) if a[i] != b[i]]
    ranges: list[tuple[int, int]] = []
    start = prev = None
    for i in diffs:
        if start is None:
            start = prev = i
        elif i == prev + 1:
            prev = i
        else:
            ranges.append((start, prev))
            start = prev = i
    if start is not None:
        ranges.append((start, prev))
    return {
        "len": n,
        "differing_bytes": len(diffs),
        "ranges": ranges,
        "plaintext_prefix_equal": a[0x400:0x410] == b[0x400:0x410],
        "reserved_equal": a[0x14:0x20] == b[0x14:0x20],
        "field_0x200_a": a[0x200:0x220].hex(),
        "field_0x200_b": b[0x200:0x220].hex(),
        "field_0x3e0_a": a[0x3e0:0x400].hex(),
        "field_0x3e0_b": b[0x3e0:0x400].hex(),
    }



def digest_field_tests(path: str) -> dict:
    """Can the 32-byte fields @0x200 / @0x3E0 be SHA-256 of a *readable* area?"""
    import struct
    with open(path, "rb") as f:
        head = f.read(0x400)
        boff = struct.unpack_from("<I", head, 0x20)[0]
        rsize = struct.unpack_from("<I", head, 0x24)[0]
        frag_off = boff * SECTOR
        frag_end = frag_off + rsize
        f.seek(0)
        whole = hashlib.sha256()
        frag = hashlib.sha256()
        frag_padded = hashlib.sha256()
        pos = 0
        while True:
            b = f.read(8 << 20)
            if not b:
                break
            whole.update(b)
            lo = max(0, frag_off - pos)
            hi = min(len(b), frag_end - pos)
            if hi > lo:
                frag.update(b[lo:hi])                 # fragment only
            if len(b) > lo:
                frag_padded.update(b[lo:])            # fragment + trailing padding
            pos += len(b)
        f.seek(HEADER_AREA[0]); header_area = f.read(HEADER_AREA[1] - HEADER_AREA[0])
        f.seek(METADATA_AREA[0]); metadata_area = f.read(METADATA_AREA[1] - METADATA_AREA[0])
    field_200 = head[0x200:0x220]
    field_3e0 = head[0x3e0:0x400]
    cands = {
        "sha256(whole file)": whole.hexdigest(),
        "sha256(fragment)": frag.hexdigest(),
        "sha256(fragment+padding)": frag_padded.hexdigest(),
        "sha256(bytes[0:0x200])": hashlib.sha256(head[:0x200]).hexdigest(),
        "sha256(bytes[0:0x400])": hashlib.sha256(head).hexdigest(),
        "sha256(bytes[0x200:0x400])": hashlib.sha256(head[0x200:0x400]).hexdigest(),
        "sha256(header_area 0x410..0x9B0)": hashlib.sha256(header_area).hexdigest(),
        "sha256(metadata_area 0x9B0..0x1790)": hashlib.sha256(metadata_area).hexdigest(),
        "sha256(header_area+metadata_area)": hashlib.sha256(header_area + metadata_area).hexdigest(),
        "sha256(bytes[0x400:0x1790])": hashlib.sha256(head[0x400:] + header_area + metadata_area).hexdigest(),
    }
    matches = [name for name, dig in cands.items()
               if dig == field_200.hex() or dig == field_3e0.hex()]
    return {"field_0x200": field_200.hex(), "field_0x3e0": field_3e0.hex(),
            "candidates": cands, "matches": matches}


def shift_scan(dig_a: np.ndarray, dig_b: np.ndarray, max_shift: int = 256) -> list[tuple[int, int]]:
    """Count equal 512-byte sectors under a shift of `s` sectors (A[i] vs B[i+s])."""
    n = min(dig_a.size, dig_b.size)
    results = []
    for s in range(-max_shift, max_shift + 1):
        if s >= 0:
            a, b = dig_a[:n - s], dig_b[s:n]
        else:
            a, b = dig_a[-s:n], dig_b[:n + s]
        if a.size == 0:
            continue
        results.append((s, int(np.count_nonzero(a == b))))
    return results


def digest_intersection(dig_a: np.ndarray, dig_b: np.ndarray) -> list[tuple[int, int, int]]:
    """Sector digests present in both files -> (digest, sector_a, sector_b)."""
    common, ia, ib = np.intersect1d(dig_a, dig_b, return_indices=True)
    return [(int(v), int(x), int(y)) for v, x, y in zip(common, ia, ib)]


def duplicate_digests(dig: np.ndarray) -> dict:
    uniq, counts = np.unique(dig, return_counts=True)
    dup = counts > 1
    return {
        "sectors": int(dig.size),
        "distinct_digests": int(uniq.size),
        "digests_repeated": int(dup.sum()),
        "extra_occurrences": int(counts[dup].sum() - dup.sum()) if dup.any() else 0,
        "top": [(int(uniq[i]), int(counts[i])) for i in np.flatnonzero(dup)[:10]],
    }


def token_scan(path: str, tokens: list[bytes]) -> dict:
    hits: dict[bytes, list[int]] = {t: [] for t in tokens}
    with open(path, "rb") as f:
        base = 0
        prev = b""
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            buf = prev + block
            buf_base = base - len(prev)
            for tok in tokens:
                start = 0
                while True:
                    i = buf.find(tok, start)
                    if i < 0:
                        break
                    pos = buf_base + i
                    if pos >= base and len(hits[tok]) < 20:
                        hits[tok].append(pos)
                    start = i + 1
            base += len(block)
            prev = buf[-64:]
    return {t.decode("latin-1"): v for t, v in hits.items() if v}


def common_prefix(a_path: str, b_path: str) -> int:
    n = 0
    with open(a_path, "rb") as fa, open(b_path, "rb") as fb:
        while True:
            a, b = fa.read(WINDOW), fb.read(WINDOW)
            if a != b:
                for i in range(min(len(a), len(b))):
                    if a[i] != b[i]:
                        return n + i
                return n + min(len(a), len(b))
            n += len(a)
            if not a:
                return n


def common_suffix(a_path: str, b_path: str, limit: int = 8 << 20) -> int:
    sa, sb = os.path.getsize(a_path), os.path.getsize(b_path)
    n = 0
    with open(a_path, "rb") as fa, open(b_path, "rb") as fb:
        while n < min(sa, sb, limit):
            want = min(WINDOW, sa - n, sb - n)
            fa.seek(sa - n - want)
            fb.seek(sb - n - want)
            a, b = fa.read(want), fb.read(want)
            if a != b:
                for i in range(want - 1, -1, -1):
                    if a[i] != b[i]:
                        return n + (want - 1 - i)
                return n + want
            n += want
    return n


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file_a", help="older PUP (e.g. 14.20)")
    ap.add_argument("file_b", help="newer PUP (e.g. 14.22)")
    ap.add_argument("--label-a", default=os.path.basename(argv[0]) if len(argv) > 0 else "A")
    ap.add_argument("--label-b", default=os.path.basename(argv[1]) if len(argv) > 1 else "B")
    ap.add_argument("--map-out", help="write the per-1MiB diff map here")
    ap.add_argument("--max-shift", type=int, default=256)
    args = ap.parse_args(argv)

    A, B = args.label_a, args.label_b
    for p in (args.file_a, args.file_b):
        if not os.path.isfile(p):
            return print(f"error: no such file: {p}") or 1

    size_a, size_b = os.path.getsize(args.file_a), os.path.getsize(args.file_b)
    print("=" * 100)
    print(f"delta1422.py: {A} ({args.file_a}) vs {B} ({args.file_b})")
    print(f"sizes: {A}={size_a}  {B}={size_b}  delta={size_b - size_a:+d} bytes "
          f"({(size_b - size_a) // 1024:+d} KiB, {(size_b - size_a) // PAGE:+d} x 4096-byte page(s))")
    print("=" * 100)

    # ---------------------------------------------------------------- 1. container
    print("\n### 1. Container-level check: delta patch or full image?")
    def slb2_head(path):
        with open(path, "rb") as f:
            h = f.read(0x50)
        import struct
        magic = h[0:4].decode("latin-1", "replace")
        ver, flags, fc, bc = struct.unpack_from("<IIII", h, 4)
        boff, rsize = struct.unpack_from("<II", h, 0x20)
        return {"magic": magic, "version": ver, "flags": flags, "file_count": fc,
                "block_count": bc, "record_block_offset": boff, "record_size": rsize,
                "record_name": h[0x30:0x50].split(b"\0")[0].decode("latin-1", "replace")}
    ha, hb = slb2_head(args.file_a), slb2_head(args.file_b)
    for key in ha:
        mark = "same" if ha[key] == hb[key] else "DIFF"
        print(f"  SLB2 {key:20}: {A}={ha[key]!r:>20}  {B}={hb[key]!r:>20}  [{mark}]")
    print(f"  -> single record, no delta/base record, no extra file: "
          f"{'YES' if ha['file_count'] == 1 and hb['file_count'] == 1 else 'NO'}")
    sd = structural_diff(args.file_a, args.file_b)
    print(f"  structural region 0x000..0x{STRUCT_END:x}: differing_bytes={sd['differing_bytes']}/{sd['len']}")
    for start, end in sd["ranges"]:
        print(f"    differs 0x{start:03x}-0x{end:03x} ({end - start + 1} bytes)")
    print(f"  PUP plaintext header 0x400..0x410 identical: {sd['plaintext_prefix_equal']}; "
          f"SLB2 reserved 0x14..0x20 identical: {sd['reserved_equal']}")
    print(f"  digest field 0x200: {A}={sd['field_0x200_a']}  {B}={sd['field_0x200_b']}")
    print(f"  digest field 0x3E0: {A}={sd['field_0x3e0_a']}  {B}={sd['field_0x3e0_b']}")

    tokens = [b"14.20", b"14.22", b"PS5UPDATE2.PUP", b"PS5UPDATE1.PUP", b"SCEUF",
              b"SLB2", b"base_version", b"DELTA", b"delta", b"PATCH", b"patch",
              b"KERNEL", b"kernel.elf", b"SceSysCore", b"bsdiff", b"BSDIFF",
              b"zchunk", b"ZCHUNK", b"OPATCH", b"DPATCH"]
    print("\n  plaintext token scan (full file; exact byte strings):")
    tok_a = token_scan(args.file_a, tokens)
    tok_b = token_scan(args.file_b, tokens)
    for tok in sorted(set(tok_a) | set(tok_b), key=lambda t: (t not in tok_a, t)):
        if tok in ("SLB2", "PS5UPDATE1.PUP"):
            continue
        print(f"    {tok!r}: {A}={tok_a.get(tok, [])}  {B}={tok_b.get(tok, [])}")
    print(f"    structural tokens: SLB2 seen in {A}={len(tok_a.get('SLB2', []))} place(s), "
          f"{B}={len(tok_b.get('SLB2', []))}; PS5UPDATE1.PUP={len(tok_a.get('PS5UPDATE1.PUP', []))}"
          f"/{len(tok_b.get('PS5UPDATE1.PUP', []))}")

    # ---------------------------------------------------------------- 2. areas
    print("\n### 2. PUP header area (header_size=1456) and metadata area (metadata_size=3552)")
    def read_area(path, span):
        with open(path, "rb") as f:
            f.seek(span[0])
            return f.read(span[1] - span[0])
    areas = {}
    for label, path in ((A, args.file_a), (B, args.file_b)):
        ha_ = read_area(path, HEADER_AREA)
        ma_ = read_area(path, METADATA_AREA)
        areas[label] = {"header": ha_, "metadata": ma_}
        for name, blob in (("header_area", ha_), ("metadata_area", ma_)):
            r = region_report(name, blob)
            print(f"  {label} {name}: len={r['len']} entropy={r['entropy']} zeros={r['zero_bytes']} "
                  f"byte_values={r['byte_values']} unique16={r['unique_blocks16']}/{r['blocks16']} "
                  f"block16_entropy(min/mean/max)={r['block16_entropy_min']}/{r['block16_entropy_mean']}/{r['block16_entropy_max']}")
            print(f"      first64: {r['hex_first64']}")
            if r["printable_runs"]:
                print(f"      printable runs>=4: {r['printable_runs']}")
    for name in ("header", "metadata"):
        c = region_compare(areas[A][name], areas[B][name])
        print(f"  {A} vs {B} {name}_area: identical={c['identical']} equal_bytes={c['equal_bytes']}"
              f"/{c['common_len']} ({c['equal_byte_fraction']:.2%}) equal_blocks16={c['equal_blocks16']}/{c['blocks16']}")

    print("\n  digest fields @0x200 / @0x3E0: is either a SHA-256 of a readable area?")
    for label, path in ((A, args.file_a), (B, args.file_b)):
        dt = digest_field_tests(path)
        print(f"    {label} @0x200={dt['field_0x200']}")
        print(f"    {label} @0x3E0={dt['field_0x3e0']}")
        for name, dig in dt["candidates"].items():
            print(f"      {name:38}: {dig}")
        print(f"      matches with either field: {dt['matches'] or 'NONE'}")

    # ---------------------------------------------------------------- 3. whole-file map
    print("\n### 3. Whole-file difference map (exact, common part only)")
    maps = pairwise_maps(args.file_a, args.file_b)
    print(f"  common bytes: {maps['common_bytes']} (window-aligned {maps['common_bytes_window_aligned']});"
          f" tail {A}={maps['tail_a_bytes']} {B}={maps['tail_b_bytes']}")
    print(f"  equal bytes: {maps['equal_bytes']} = {maps['equal_byte_fraction']:.4%} "
          f"(random-ciphertext expectation 1/256 = 0.3906%)")
    print(f"  fully equal 16-byte blocks: {maps['blocks16_equal']} offsets={maps['blocks16_equal_offsets'][:24]}")
    print(f"  fully equal 4 KiB pages   : {maps['pages_equal']} offsets={maps['pages_equal_offsets'][:24]}")
    diffs = [w["diff_bytes"] for w in maps["per_window"]]
    print(f"  1 MiB windows: {len(diffs)}; diff_bytes min={min(diffs)} max={max(diffs)} "
          f"mean={sum(diffs) / len(diffs):.1f}")
    full_windows = sum(1 for w in maps["per_window"] if w["equal_pages"] == w["pages"])
    print(f"  windows whose every page is equal: {full_windows}/{len(maps['per_window'])}")
    if args.map_out:
        with open(args.map_out, "w", encoding="utf-8") as f:
            f.write(f"# diff map {A} vs {B}: offset_hex offset_dec diff_bytes equal_pages pages_4k\n")
            for w in maps["per_window"]:
                f.write(f"0x{w['offset']:08x} {w['offset']:>9} {w['diff_bytes']:>7} "
                        f"{w['equal_pages']:>4} {w['pages']:>4}\n")
        print(f"  map written: {args.map_out}")

    # ---------------------------------------------------------------- 3b. shifts
    print("\n### 3b. Sector-digest comparison and shift scan (insertion test)")
    dig_a = xor_sector_digests(args.file_a)
    dig_b = xor_sector_digests(args.file_b)
    print(f"  sectors: {A}={dig_a.size} {B}={dig_b.size} (512 B each)")
    n = min(dig_a.size, dig_b.size)
    align_equal = int(np.count_nonzero(dig_a[:n] == dig_b[:n]))
    print(f"  aligned (shift 0) equal sector digests: {align_equal}/{n}")
    scanned = shift_scan(dig_a, dig_b, args.max_shift)
    best = sorted(scanned, key=lambda x: -x[1])[:8]
    print(f"  best shifts in +/-{args.max_shift} sectors (shift_sectors, equal_digests): {best}")
    for s in (8, -8):
        hit = [v for k, v in scanned if k == s]
        if hit:
            print(f"    shift {s:+d} sectors ({s * SECTOR:+d} bytes): {hit[0]} equal digests")
    du_a, du_b = duplicate_digests(dig_a), duplicate_digests(dig_b)
    print(f"  within-file repeated sector digests: {A}={du_a['digests_repeated']} "
          f"(extra occurrences {du_a['extra_occurrences']}), {B}={du_b['digests_repeated']} "
          f"(extra occurrences {du_b['extra_occurrences']})")
    if du_a["top"] or du_b["top"]:
        print(f"    top repeated: {A}={du_a['top'][:5]} {B}={du_b['top'][:5]}")
    inter = digest_intersection(dig_a, dig_b)
    print(f"  cross-file sector digests present in both: {len(inter)}")
    for dig, sa, sb in inter[:20]:
        with open(args.file_a, "rb") as f:
            f.seek(sa * SECTOR)
            ba = f.read(SECTOR)
        with open(args.file_b, "rb") as f:
            f.seek(sb * SECTOR)
            bb = f.read(SECTOR)
        print(f"    sector {A}#{sa} (0x{sa * SECTOR:x}) vs {B}#{sb} (0x{sb * SECTOR:x}): "
              f"bytes_equal={ba == bb} all_zero={not any(ba)}")
    if not inter:
        print("    -> no 512-byte sector (at any offset) occurs in both builds: "
              "the encrypted payload shares no data at sector granularity")

    # ---------------------------------------------------------------- boundaries
    print("\n### 4. Prefix/suffix and size delta")
    print(f"  common prefix: 0x{common_prefix(args.file_a, args.file_b):x} bytes")
    print(f"  common suffix: {common_suffix(args.file_a, args.file_b)} bytes (searched up to 8 MiB)")
    print(f"  size delta: {size_b - size_a:+d} bytes = {(size_b - size_a) // PAGE} page of 4096 "
          f"= {(size_b - size_a) // SECTOR} sectors of 512")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))