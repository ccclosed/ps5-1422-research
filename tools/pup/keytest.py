#!/usr/bin/env python3
"""keytest.py - try candidate AES keys against the first KiB(s) of a PS5 SELF header.

Purpose
-------
The inner object of a retail PS5 PUP is a SELF (ProSPERO, magic 0xEEF51454) whose
header is encrypted from offset 0x10 onward.  Only bytes 0x00..0x0F are plaintext:

    0x00 u32 magic          0xEEF51454
    0x04 u8  version
    0x05 u8  mode
    0x06 u8  endian
    0x07 u8  attributes
    0x08 u32 key_type
    0x0C u16 header_size
    0x0E u16 metadata_size

Everything after that - the rest of the fixed header, the segment table, the
metadata area - is ciphertext in any retail PS5 SELF.  This tool takes candidate
keys (from `keys.py`, a JSON file, or the command line), decrypts the first N
bytes under several AES modes, and *scores* the result.  It never invents a
verdict: a candidate that only "looks less random" is reported as inconclusive.

Modes tried per candidate
------------------------
  ecb            AES-128/256-ECB, decrypted from offset 0x10 block by block
  cbc:<ivd>      AES-128/256-CBC, IV derived from <ivd>:
                   zero   - zero IV
                   key    - IV = first 16 bytes of the AES key
                   sect   - IV = 128-bit little-endian sector number of 0x10 (0)
                   crlf   - IV = b"\\r\\n" * 8 (a historic SCE quirk seen in
                            some tools; included because it costs nothing)
  xts:<split>    AES-XTS (IEEE 1619), tweak = 128-bit LE sector number of each
                   512-byte sector; <split> is one of:
                   half   - key1 = first half, key2 = second half
                   same   - key1 = key2 = whole candidate (lengthened/truncated)

Sector size is 512 bytes throughout, matching the PS5 storage sector, so the
tweak for any offset inside the first 4 KiB is simply offset // 512.

Scoring (why a match is believable)
-----------------------------------
Each attempt is scored on independent criteria, and the verdict is derived from
how many *hard* criteria pass, never from a single signal:

  HARD  H1 plaintext fields sane : after decryption the header must still show a
                                   recognised magic at 0x00 (it is not encrypted,
                                   so this only catches self-inflicted bugs) and
                                   header_size/metadata_size within sane ranges
        H2 file_size plausible    : u64 at 0x10 <= file length, > 0
        H3 segment_count plausible: u16 at 0x18 in 1..64
  SOFT  S1 entropy drop          : entropy of 0x10..0x400 well below ciphertext
        S2 segment table decodes : n records of 0x20 at header_size with flags,
                                   offsets and sizes that stay inside the file
        S3 ASCII strings appear   : printable runs >= 6 in the decrypted area

A candidate is reported PLAUSIBLE only if H1+H2+H3 pass and at least two of
S1..S3 pass.  PARTIAL if some HARD pass.  Otherwise NEGATIVE.  Contradictory
results (entropy drop but no valid fields) are reported as INCONCLUSIVE, which
is the honest label for "something changed but nothing decodes".

Self-test
---------
`--selftest` builds a synthetic-but-realistic SELF header from the *actual*
plaintext prefix of a real target file, encrypts a chosen test key under every
supported mode, and requires the tool to recover exactly that key with a
PLAUSIBLE verdict.  This proves the crypto, the tweak arithmetic, the field
parser and the scorer work end-to-end.  Run it before trusting any real run.

Usage
-----
    python3 keytest.py --selftest
    python3 keytest.py --target fw/inner/1422-PS5UPDATE2.pup --keys keys.txt
    python3 keytest.py --target ... --key-hex <hex> --label demo
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from dataclasses import dataclass, field

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    print("FATAL: нужен пакет cryptography (pip install cryptography)", file=sys.stderr)
    raise SystemExit(3)

SELF_MAGIC_PROSPERO = 0xEEF51454
SELF_MAGIC_ORBIS = 0x1D3D154F
MAGICS = {SELF_MAGIC_PROSPERO: "SELF-PROSPERO (PS5)", SELF_MAGIC_ORBIS: "SELF-ORBIS (PS4/FSELF)"}

PLAINTEXT_PREFIX = 0x10          # bytes 0x00..0x0F are not encrypted
DEFAULT_SPAN = 4096              # we decrypt/evaluate the first 4 KiB
SECTOR = 512
SEGMENT_RECORD = 0x20
MAX_SEGMENTS = 64

CRLF_IV = b"\r\n" * 8


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    result = 0.0
    for c in counts:
        if c:
            p = c / n
            result -= p * math.log2(p)
    return result


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def printable_runs(data: bytes, minimum: int = 6) -> list[str]:
    """Return printable ASCII runs of at least `minimum` bytes."""
    runs, cur = [], bytearray()
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= minimum:
                runs.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= minimum:
        runs.append(cur.decode("ascii", "replace"))
    return runs


def parse_plaintext_prefix(data: bytes) -> dict:
    """The 16 bytes that are *not* encrypted in a retail SELF."""
    if len(data) < PLAINTEXT_PREFIX:
        return {}
    magic = u32(data, 0)
    return {
        "magic": magic,
        "magic_name": MAGICS.get(magic, "unknown"),
        "version": data[4],
        "mode": data[5],
        "endian": data[6],
        "attributes": data[7],
        "key_type": u32(data, 8),
        "header_size": u16(data, 12),
        "metadata_size": u16(data, 14),
    }


# --------------------------------------------------------------------------- #
# decryption modes
# --------------------------------------------------------------------------- #

def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    algo = algorithms.AES(key)
    dec = Cipher(algo, modes.ECB()).decryptor()
    return dec.update(data) + dec.finalize()


def _aes_cbc_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    algo = algorithms.AES(key)
    dec = Cipher(algo, modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def _xts_tweak(sector: int) -> bytes:
    return sector.to_bytes(16, "little")


def _aes_xts_decrypt(key1: bytes, key2: bytes, data: bytes, start_offset: int) -> bytes:
    """XTS over `data`, where data[0] sits at absolute offset start_offset.

    Implemented manually (two-block-per-tweak) so that the tweak follows the
    *absolute* sector number, which is what a disk-level encryption layer does.
    `data` must be a multiple of 16 and every 512-byte sector must be complete.
    """
    out = bytearray()
    sector_size = SECTOR
    for base in range(0, len(data), sector_size):
        chunk = data[base:base + sector_size]
        abs_off = start_offset + base
        sector_no = abs_off // sector_size
        tweak = _xts_tweak(sector_no)
        # encrypt tweak with key2
        tweak_enc = Cipher(algorithms.AES(key2), modes.ECB()).encryptor()
        t = tweak_enc.update(tweak) + tweak_enc.finalize()
        for block_index in range(0, len(chunk), 16):
            block = chunk[block_index:block_index + 16]
            if len(block) < 16:
                out += block          # tail shorter than a block: left as is
                continue
            x = bytes(a ^ b for a, b in zip(block, t))
            dec = Cipher(algorithms.AES(key1), modes.ECB()).decryptor()
            y = dec.update(x) + dec.finalize()
            out += bytes(a ^ b for a, b in zip(y, t))
            # advance tweak: multiply by alpha (x) in GF(2^128), little-endian
            carry = 0
            t_list = bytearray(t)
            for i in range(16):
                new_carry = t_list[i] >> 7
                t_list[i] = ((t_list[i] << 1) & 0xFF) | carry
                carry = new_carry
            if carry:
                t_list[0] ^= 0x87
            t = bytes(t_list)
    return bytes(out)


def decrypt_candidate(key: bytes, ciphertext: bytes, start_offset: int, mode_spec: str) -> bytes | None:
    """Decrypt `ciphertext` (starting at absolute `start_offset`) or return None."""
    try:
        if mode_spec == "ecb":
            if len(key) not in (16, 32):
                return None
            body = ciphertext[: len(ciphertext) // 16 * 16]
            return _aes_ecb_decrypt(key, body)

        if mode_spec.startswith("cbc:"):
            if len(key) not in (16, 32):
                return None
            ivd = mode_spec.split(":", 1)[1]
            if ivd == "zero":
                iv = b"\x00" * 16
            elif ivd == "key":
                iv = key[:16]
            elif ivd == "sect":
                iv = _xts_tweak(start_offset // SECTOR)
            elif ivd == "crlf":
                iv = CRLF_IV
            else:
                return None
            body = ciphertext[: len(ciphertext) // 16 * 16]
            return _aes_cbc_decrypt(key, body, iv)

        if mode_spec.startswith("xts:"):
            split = mode_spec.split(":", 1)[1]
            if split == "half":
                if len(key) not in (32, 64):
                    return None
                half = len(key) // 2
                k1, k2 = key[:half], key[half:]
            elif split == "same":
                if len(key) not in (16, 32):
                    return None
                k1 = k2 = key
            else:
                return None
            usable = (len(ciphertext) // SECTOR) * SECTOR
            if usable < SECTOR:
                return None
            return _aes_xts_decrypt(k1, k2, ciphertext[:usable], start_offset)

        return None
    except Exception:
        return None


SUPPORTED_MODES = ["ecb", "cbc:zero", "cbc:key", "cbc:sect", "cbc:crlf", "xts:half", "xts:same"]


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #

@dataclass
class Verdict:
    label: str
    mode: str
    key_id: str
    hard: dict = field(default_factory=dict)
    soft: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    score: float = 0.0
    verdict: str = "NEGATIVE"

    def as_dict(self) -> dict:
        return {
            "key": self.key_id, "mode": self.mode, "verdict": self.verdict,
            "score": round(self.score, 3), "hard": self.hard, "soft": self.soft,
            "notes": self.notes,
        }


def evaluate(decrypted: bytes, prefix: dict, file_len: int) -> tuple[dict, dict, list[str]]:
    """Score a decrypted header. Returns (hard, soft, notes).

    `decrypted` is the plaintext of offset 0x10 onward (may be shorter than 4 KiB).
    """
    hard, soft, notes = {}, {}, []

    # ---- H1: fixed header fields sane -------------------------------------
    # header_size / metadata_size come from the plaintext prefix, so this checks
    # that the prefix itself is a sane SELF header (guards against bad inputs).
    hs = prefix.get("header_size", 0)
    ms = prefix.get("metadata_size", 0)
    h1 = (
        prefix.get("magic") in MAGICS
        and 0x20 <= hs <= 0x2000
        and rev_ok(ms)
    )
    hard["H1_header_fields_sane"] = bool(h1)
    if not h1:
        notes.append(f"префикс не похож на SELF: magic={prefix.get('magic')!r} header_size={hs} metadata_size={ms}")

    # ---- H2: file_size plausible ------------------------------------------
    file_size = u64(decrypted, 0) if len(decrypted) >= 8 else 0
    h2 = 0 < file_size <= file_len and file_size >= file_len // 4
    hard["H2_file_size_plausible"] = bool(h2)
    hard["H2_value"] = file_size
    if not h2:
        notes.append(f"file_size={file_size} не согласуется с длиной файла {file_len}")

    # ---- H3: segment count plausible --------------------------------------
    seg_count = u16(decrypted, 8) if len(decrypted) >= 10 else 0
    h3 = 1 <= seg_count <= MAX_SEGMENTS
    hard["H3_segment_count_plausible"] = bool(h3)
    hard["H3_value"] = seg_count

    # ---- S1: entropy drop -------------------------------------------------
    sample = decrypted[: min(len(decrypted), 0x400)]
    ent = entropy(sample)
    soft["S1_entropy"] = round(ent, 4)
    soft["S1_entropy_drop"] = ent < 7.0        # ciphertext sits near 7.7-8.0
    if ent >= 7.5:
        notes.append(f"энтропия {ent:.2f} — по-прежнему шум")

    # ---- S2: segment table decodes ---------------------------------------
    table_ok, table_detail = check_segment_table(decrypted, prefix.get("header_size", 0), file_len)
    soft["S2_segment_table"] = table_ok
    soft["S2_detail"] = table_detail

    # ---- S3: ASCII strings ------------------------------------------------
    strings = printable_runs(decrypted, 6)
    soft["S3_ascii_runs"] = len(strings)
    soft["S3_sample"] = strings[:5]
    if strings:
        notes.append("ASCII: " + ", ".join(repr(s) for s in strings[:3]))

    return hard, soft, notes


def rev_ok(ms: int) -> bool:
    """metadata_size sanity: either 0 or a small multiple of 0x10 <= 0x4000."""
    return ms == 0 or (0x10 <= ms <= 0x4000 and ms % 0x10 == 0)


def check_segment_table(decrypted: bytes, header_size: int, file_len: int) -> tuple[bool, str]:
    """Validate a segment-record table located at `header_size` in the plaintext.

    `decrypted` starts at absolute 0x10, so a table at absolute `header_size`
    lives at offset header_size - 0x10.
    """
    if header_size < PLAINTEXT_PREFIX:
        return False, f"header_size {header_size} < 0x10"
    off = header_size - PLAINTEXT_PREFIX
    if off < 0 or off + SEGMENT_RECORD > len(decrypted):
        return False, "таблица за пределами расшифрованного окна"
    flags = u64(decrypted, off)
    offset = u64(decrypted, off + 8)
    size = u64(decrypted, off + 16)
    if flags == 0 and offset == 0 and size == 0:
        return False, "первая запись нулевая"
    # A real segment record must sit inside the file and be non-trivial.
    if not (0 < offset < file_len):
        return False, f"offset {offset} вне файла"
    if not (0 < size <= file_len):
        return False, f"size {size} вне файла"
    # Very weak distribution check: an all-FF or all-00 record is almost
    # certainly wrong-key output.
    if size in (0xFFFFFFFFFFFFFFFF,):
        return False, "size = all-ones"
    return True, f"flags=0x{flags:x} offset={offset} size={size}"


def classify(hard: dict, soft: dict) -> tuple[str, float]:
    hard_pass = sum(1 for k, v in hard.items() if k.endswith(("sane", "plausible")) and v)
    soft_keys = ["S1_entropy_drop", "S2_segment_table", "S3_ascii_runs"]
    soft_pass = 0
    if soft.get("S1_entropy_drop"):
        soft_pass += 1
    if soft.get("S2_segment_table"):
        soft_pass += 1
    if soft.get("S3_ascii_runs", 0) > 0:
        soft_pass += 1
    score = hard_pass * 1.0 + soft_pass * 0.5
    if hard_pass == 3 and soft_pass >= 2:
        return "PLAUSIBLE", score
    if hard_pass >= 2:
        return "PARTIAL", score
    if soft_pass >= 2:
        return "INCONCLUSIVE", score
    return "NEGATIVE", score


# --------------------------------------------------------------------------- #
# key loading
# --------------------------------------------------------------------------- #

def load_keys(path: str) -> list[dict]:
    """Load candidates from a text/JSON file.

    Text format (one per line, '#' comments and blank lines ignored):
        <label> | <source> | <hex key>
    JSON format: [{"label":..., "source":..., "key_hex":...}, ...]
    """
    if not os.path.exists(path):
        return []
    text = open(path, "r", encoding="utf-8", errors="replace").read()
    if text.lstrip().startswith("["):
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            print(f"ключи: JSON не разобрался: {exc}", file=sys.stderr)
            return []
        out = []
        for row in raw:
            key_hex = (row.get("key_hex") or "").strip().replace(" ", "")
            try:
                key = bytes.fromhex(key_hex)
            except ValueError:
                print(f"ключи: пропущен битый hex у {row.get('label')}", file=sys.stderr)
                continue
            out.append({"label": row.get("label", "unnamed"),
                        "source": row.get("source", "?"),
                        "key": key})
        return out

    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3:
            print(f"ключи:{lineno}: ожидалось 'label | source | hex', пропущено", file=sys.stderr)
            continue
        label, source, key_hex = parts
        try:
            key = bytes.fromhex(key_hex.replace(" ", ""))
        except ValueError:
            print(f"ключи:{lineno}: битый hex, пропущено", file=sys.stderr)
            continue
        out.append({"label": label, "source": source, "key": key})
    return out


def key_fingerprint(key: bytes) -> str:
    return f"{len(key) * 8}b:{hashlib.sha256(key).hexdigest()[:16]}"


# --------------------------------------------------------------------------- #
# target loading
# --------------------------------------------------------------------------- #

def load_target(path: str, span: int) -> tuple[bytes, int]:
    with open(path, "rb") as f:
        data = f.read(span)
    size = os.path.getsize(path)
    return data, size


# --------------------------------------------------------------------------- #
# real run
# --------------------------------------------------------------------------- #

def run_target(target: str, keys: list[dict], span: int, verbose: bool) -> list[Verdict]:
    data, file_len = load_target(target, span)
    prefix = parse_plaintext_prefix(data)
    if prefix.get("magic") not in MAGICS:
        print(f"ВНИМАНИЕ: {target} не похож на SELF (magic=0x{u32(data,0):08x})", file=sys.stderr)

    ciphertext = data[PLAINTEXT_PREFIX:]
    base_entropy = entropy(ciphertext[: 0x400 - PLAINTEXT_PREFIX])
    print(f"Цель: {target}")
    print(f"  размер файла      : {file_len}")
    print(f"  магия             : 0x{u32(data,0):08X} ({prefix.get('magic_name')})")
    print(f"  key_type          : 0x{prefix.get('key_type', 0):08X}")
    print(f"  header_size       : 0x{prefix.get('header_size', 0):X}")
    print(f"  metadata_size     : 0x{prefix.get('metadata_size', 0):X}")
    print(f"  открытый префикс  : {data[:PLAINTEXT_PREFIX].hex()}")
    print(f"  энтропия шифртекста (0x10..0x400): {base_entropy:.4f}")
    print(f"  кандидатов        : {len(keys)}  x  режимов {len(SUPPORTED_MODES)}"
          f" = {len(keys) * len(SUPPORTED_MODES)} попыток")
    print()

    verdicts: list[Verdict] = []
    for cand in keys:
        key = cand["key"]
        for mode_spec in SUPPORTED_MODES:
            plain = decrypt_candidate(key, ciphertext, PLAINTEXT_PREFIX, mode_spec)
            if plain is None:
                continue
            hard, soft, notes = evaluate(plain, prefix, file_len)
            verdict, score = classify(hard, soft)
            v = Verdict(label=cand["label"], mode=mode_spec,
                        key_id=f"{cand['label']}/{key_fingerprint(key)}",
                        hard=hard, soft=soft, notes=notes, score=score, verdict=verdict)
            verdicts.append(v)
            if verbose or verdict != "NEGATIVE":
                mark = {"PLAUSIBLE": "!!!", "PARTIAL": " ? ", "INCONCLUSIVE": " ~ "}.get(verdict, "   ")
                print(f"{mark} {cand['label']:<28} {mode_spec:<12} {verdict:<12} score={score:.2f} "
                      f"ent={soft.get('S1_entropy','?')} seg={hard.get('H3_value','?')} "
                      f"fs={hard.get('H2_value','?')}")
    return verdicts


# --------------------------------------------------------------------------- #
# self test: prove the tester can find a key it is supposed to find
# --------------------------------------------------------------------------- #

def build_synthetic_self(prefix16: bytes, file_len: int) -> bytes:
    """Build a realistic plaintext SELF header (>= 0x400 bytes) to encrypt.

    Uses the real plaintext prefix (magic/version/.../header_size/metadata_size)
    and fills the encrypted region with plausible values: file_size, segment
    count, flags, a segment table of 0x20-byte records and an ASCII version tag.
    """
    header_size = u16(prefix16, 12)
    metadata_size = u16(prefix16, 14)
    buf = bytearray(0x1000)
    buf[0:PLAINTEXT_PREFIX] = prefix16
    # encrypted fixed header
    struct.pack_into("<Q", buf, 0x10, file_len)        # file_size
    struct.pack_into("<H", buf, 0x18, 3)               # segment_count
    struct.pack_into("<H", buf, 0x1A, 0x2)             # flags
    # a couple of realistic-looking fields
    struct.pack_into("<I", buf, 0x20, header_size)
    struct.pack_into("<I", buf, 0x24, metadata_size)
    # segment table at header_size: 3 records of 0x20 bytes
    for i in range(3):
        off = header_size + i * SEGMENT_RECORD
        struct.pack_into("<Q", buf, off + 0x00, 0x800 | (i << 20))   # flags
        struct.pack_into("<Q", buf, off + 0x08, 0x200 + i * 0x100)    # offset, inside image
        struct.pack_into("<Q", buf, off + 0x10, 0x100)                # size
        struct.pack_into("<Q", buf, off + 0x18, 0x100)                # size again
    # an ASCII marker, like a build/version tag
    tag = b"PS5UPDATE1.PUP\x00" + b"build 26.07-14.22.00\x00"
    buf[0x300:0x300 + len(tag)] = tag
    return bytes(buf)


def encrypt_with(key: bytes, plaintext: bytes, mode_spec: str) -> bytes | None:
    """Encrypt `plaintext` (which sits at absolute offset 0x10) under mode_spec."""
    try:
        if mode_spec == "ecb":
            if len(key) not in (16, 32):
                return None
            enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            return enc.update(plaintext) + enc.finalize()
        if mode_spec.startswith("cbc:"):
            if len(key) not in (16, 32):
                return None
            ivd = mode_spec.split(":", 1)[1]
            iv = {"zero": b"\x00" * 16, "key": key[:16],
                  "sect": _xts_tweak(0), "crlf": CRLF_IV}.get(ivd)
            if iv is None:
                return None
            enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            return enc.update(plaintext) + enc.finalize()
        if mode_spec.startswith("xts:"):
            split = mode_spec.split(":", 1)[1]
            if split == "half":
                if len(key) not in (32, 64):
                    return None
                half = len(key) // 2
                k1, k2 = key[:half], key[half:]
            elif split == "same":
                if len(key) not in (16, 32):
                    return None
                k1 = k2 = key
            else:
                return None
            # encrypt = run the same XTS transform with the E function; emulate by
            # running decrypt on ciphertext produced by an inverse implementation.
            return _xts_encrypt(k1, k2, plaintext, PLAINTEXT_PREFIX)
        return None
    except Exception:
        return None


def _xts_encrypt(key1: bytes, key2: bytes, data: bytes, start_offset: int) -> bytes:
    out = bytearray()
    for base in range(0, len(data), SECTOR):
        chunk = data[base:base + SECTOR]
        sector_no = (start_offset + base) // SECTOR
        tweak_enc = Cipher(algorithms.AES(key2), modes.ECB()).encryptor()
        t = tweak_enc.update(_xts_tweak(sector_no)) + tweak_enc.finalize()
        for bi in range(0, len(chunk), 16):
            block = chunk[bi:bi + 16]
            if len(block) < 16:
                out += block
                continue
            x = bytes(a ^ b for a, b in zip(block, t))
            enc = Cipher(algorithms.AES(key1), modes.ECB()).encryptor()
            y = enc.update(x) + enc.finalize()
            out += bytes(a ^ b for a, b in zip(y, t))
            carry = 0
            tl = bytearray(t)
            for i in range(16):
                nc = tl[i] >> 7
                tl[i] = ((tl[i] << 1) & 0xFF) | carry
                carry = nc
            if carry:
                tl[0] ^= 0x87
            t = bytes(tl)
    return bytes(out)


def selftest(target: str) -> int:
    """Require recovery of a known key for every supported mode."""
    if os.path.exists(target):
        head, file_len = load_target(target, DEFAULT_SPAN)
        prefix = parse_plaintext_prefix(head)
        if prefix.get("magic") not in MAGICS:
            print(f"selftest: {target} не SELF, использую синтетический префикс", file=sys.stderr)
            prefix = {}
            head = b"\x54\x14\xf5\xee\x10\x01\x01\x32" + b"\x04\x00\x00\x00" + b"\x40\x02" + b"\xa0\x05"
            file_len = 1266091008
    else:
        print(f"selftest: {target} отсутствует, использую синтетический префикс", file=sys.stderr)
        head = b"\x54\x14\xf5\xee\x10\x01\x01\x32" + b"\x04\x00\x00\x00" + b"\x40\x02" + b"\xa0\x05"
        file_len = 1266091008
        prefix = {}

    prefix = prefix or parse_plaintext_prefix(head)
    # The synthetic image is exactly 0x1000 bytes, and file_size inside it must
    # describe *that* image, otherwise H2 can never pass (this was a real bug:
    # the first version wrote a 4 KiB file carrying the 157 MB field).
    SYNTH_SIZE = 0x1000
    plaintext_full = build_synthetic_self(head[:PLAINTEXT_PREFIX], SYNTH_SIZE)
    plain_body = plaintext_full[PLAINTEXT_PREFIX:]

    test_keys = {
        "ecb": bytes(range(16)),
        "cbc:zero": bytes(range(16, 32)),
        "cbc:key": bytes(range(32, 48)),
        "cbc:sect": bytes(range(48, 64)),
        "cbc:crlf": bytes(range(64, 80)),
        "xts:half": bytes(range(32)),
        "xts:same": bytes(range(16, 48)),
    }

    print("=" * 78)
    print("SELFTEST: синтетический SELF -> шифрование известным ключом -> поиск")
    print("=" * 78)
    ok_count = 0
    for mode_spec, key in test_keys.items():
        ct = encrypt_with(key, plain_body, mode_spec)
        if ct is None:
            print(f"  [SKIP] {mode_spec}: ключ не подходит")
            continue
        # assemble a file-like image: plaintext prefix + ciphertext
        image = head[:PLAINTEXT_PREFIX] + ct
        tmp = f"/tmp/keytest-selftest-{mode_spec.replace(':', '-')}.bin"
        with open(tmp, "wb") as f:
            f.write(image)

        cands = [{"label": "selftest-known", "source": "selftest", "key": key}]
        verdicts = run_target(tmp, cands, DEFAULT_SPAN, verbose=False)
        expected_mode = mode_spec
        hit = [v for v in verdicts if v.verdict == "PLAUSIBLE" and v.mode == expected_mode]
        os.unlink(tmp)
        if hit:
            ok_count += 1
            print(f"  [PASS] {mode_spec:<12} ключ найден, вердикт PLAUSIBLE")
        else:
            best = max(verdicts, key=lambda v: v.score) if verdicts else None
            print(f"  [FAIL] {mode_spec:<12} ключ НЕ распознан"
                  f"{' (лучший: ' + best.verdict + ' ' + best.mode + ')' if best else ''}")

    total = len(test_keys)
    print("-" * 78)
    print(f"SELFTEST: {ok_count}/{total} режимов прошли")
    if ok_count != total:
        print("SELFTEST: FAIL — тестеру нельзя доверять, реальные прогоны бессмысленны")
        return 1
    print("SELFTEST: PASSED — крипто, tweak-арифметика, парсер полей и скорер работают")
    return 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Проверка ключей-кандидатов на SELF-заголовке PS5/PS4")
    ap.add_argument("--target", default="fw/inner/1422-PS5UPDATE2.pup",
                    help="файл-SELF (первые N байт берутся)")
    ap.add_argument("--keys", default="", help="файл с кандидатами (text или JSON)")
    ap.add_argument("--key-hex", default="", help="одиночный кандидат в hex")
    ap.add_argument("--label", default="cli", help="метка для --key-hex")
    ap.add_argument("--source", default="cli", help="источник для --key-hex")
    ap.add_argument("--span", type=int, default=DEFAULT_SPAN, help="сколько байт разбирать")
    ap.add_argument("--selftest", action="store_true", help="проверить сам тестер")
    ap.add_argument("--verbose", action="store_true", help="печатать и отрицательные результаты")
    ap.add_argument("--json-out", default="", help="куда сохранить журнал (JSON)")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest(args.target)

    keys: list[dict] = []
    if args.keys:
        keys += load_keys(args.keys)
    if args.key_hex:
        try:
            keys.append({"label": args.label, "source": args.source,
                         "key": bytes.fromhex(args.key_hex.replace(" ", ""))})
        except ValueError:
            print(f"битый hex в --key-hex: {args.key_hex}", file=sys.stderr)
            return 2
    if not keys:
        print("нет кандидатов: задайте --keys и/или --key-hex (или --selftest)", file=sys.stderr)
        return 2
    if not os.path.exists(args.target):
        print(f"цель не найдена: {args.target}", file=sys.stderr)
        return 2

    verdicts = run_target(args.target, keys, args.span, args.verbose)
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
    print()
    print("Итог: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "попыток не было")
    plausible = [v for v in verdicts if v.verdict == "PLAUSIBLE"]
    if plausible:
        print("\n*** ЕСТЬ PLAUSIBLE-КАНДИДАТ(Ы) — проверить вручную! ***")
        for v in plausible:
            print(f"  {v.key_id}  режим={v.mode} score={v.score:.2f}")
    else:
        print("Рабочий ключ среди кандидатов НЕ найден (ожидаемо, если ключа нет в публичном доступе).")

    if args.json_out:
        payload = {
            "target": args.target,
            "span": args.span,
            "candidates": len(keys),
            "attempts": len(verdicts),
            "counts": counts,
            "results": [v.as_dict() for v in verdicts],
        }
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"журнал: {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))