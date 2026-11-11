#!/usr/bin/env python3
"""ps4scheme.py — порт схемы расшифровки PS4-PUP на контейнер PS5 (наш 14.22).

Схема взята из публичных источников (см. recon/pup-decrypt-attempt.md):
  * idc/ps4-pup_decrypt      — payload, который ВЫЗЫВАЕТ ЯДРО PS4 через /dev/pup_update0
  * idc/ps4-pup_unpack       — распаковка УЖЕ расшифрованного пакета (без ключей)
  * Ar1sto/PUPPRE            — PC-реверс: восстановленная схема сегментов

Восстановленная схема (PUPPRE, docs/offline-decryption.md):
  внутренний PUP = [0x10 открытых байт][header_size байт][hash_size байт][сегменты]
  metadata-запись (0x50): aes128_key(16) | aes128_iv(16) | hmac_sha256(32) | digest_key(16)
  сегмент: AES-128-CBC(key, iv), сверка HMAC-SHA256(digest_key, plaintext)

Единственный шаг, закрытый консолью, — расшифровать header+metadata.
Этот файл:
  1) реализует весь путь целиком (метаданные -> сегменты);
  2) строит СИНТЕТИЧЕСКИЙ пакет с читаемыми метаданными и проходит его насквозь
     (положительный контроль: если контроль не проходит — тест ничего не стоит);
  3) применяет к реальному fw/PS5UPDATE-sys-2026_1027.PUP все найденные ключи и режимы
     и печатает точку отказа.

Запуск:
    python3 tools/pup/ps4scheme.py --control          # только контроль
    python3 tools/pup/ps4scheme.py --attack <pup>     # атака на реальный файл
    python3 tools/pup/ps4scheme.py --all              # и то, и другое
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import struct
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception as exc:  # pragma: no cover
    sys.exit(f"нужен пакет cryptography: {exc}")

MAGIC_PUP = 0xEEF51454          # внутренний PUP/SELF-заголовок (PS4 и PS5 совпадают)
META_ENTRY = 0x50               # key16 + iv16 + digest32 + digest_key16
ENTRY_DESC = 0x10               # flags u32 | offset u32 | csize u32 | usize u32


# ---------------------------------------------------------------- AES-примитивы
def aes_cbc_dec(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return c.update(data) + c.finalize()


def aes_cbc_enc(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return c.update(data) + c.finalize()


def aes_ecb_dec(key: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return c.update(data) + c.finalize()


def aes_ctr_dec(key: bytes, nonce: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
    return c.update(data) + c.finalize()


def aes_xts_dec(key: bytes, tweak: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.XTS(tweak)).decryptor()
    return c.update(data) + c.finalize()


def pad16(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 16)


# ------------------------------------------------------- парсинг внутреннего PUP
def parse_inner_header(buf: bytes, off: int = 0x400) -> dict:
    """0x10 открытых байт: magic, version, key_type, header_size, hash_size."""
    h = buf[off:off + ENTRY_DESC]
    magic, ver_keytype = struct.unpack("<II", h[0:8])
    # 8..12 — u16 unknown08 + u16 unknown0A; 12..16 — header_size + hash_size
    header_size, hash_size = struct.unpack("<HH", h[12:16])
    return {
        "magic": magic,
        "magic_ok": magic == MAGIC_PUP,
        "version": ver_keytype & 0xFF,
        "key_type": (ver_keytype >> 8) & 0xFF,
        "version_full": ver_keytype,
        "header_size": header_size,
        "hash_size": hash_size,
        "plaintext_len": ENTRY_DESC,
        "encrypted_len": header_size + hash_size - ENTRY_DESC,
        "meta_entries": hash_size // META_ENTRY,
        "raw16": h.hex(),
    }


def split_meta(meta: bytes) -> list[dict]:
    out = []
    for i in range(0, len(meta) - META_ENTRY + 1, META_ENTRY):
        e = meta[i:i + META_ENTRY]
        out.append({
            "aes_key": e[0:16],
            "aes_iv": e[16:32],
            "digest": e[32:64],
            "digest_key": e[64:80],
        })
    return out


def validate_header_region(dec: bytes, file_size: int, n_desc: int) -> dict:
    """Правдоподобна ли расшифровка header-области: N описателей записей по 0x10."""
    if len(dec) < n_desc * ENTRY_DESC:
        return {"ok": False, "why": "мало байт"}
    offs, ok = [], True
    for i in range(n_desc):
        flags, off, csize, usize = struct.unpack("<IIII", dec[i * ENTRY_DESC:(i + 1) * ENTRY_DESC])
        if off == 0 and csize == 0 and usize == 0:
            continue
        if off > file_size or csize > file_size or usize > file_size:
            ok = False
            break
        if csize and usize and usize < csize // 4:      # несжатое не может быть вчетверо меньше
            ok = False
            break
        offs.append(off)
    monotonic = all(b >= a for a, b in zip(offs, offs[1:])) if offs else False
    return {"ok": ok and monotonic and len(offs) > 0, "entries": len(offs), "monotonic": monotonic}


def decrypt_segment(meta: dict, ciphertext: bytes) -> tuple[bytes, bool]:
    plain = aes_cbc_dec(meta["aes_key"], meta["aes_iv"], pad16(ciphertext))[:len(ciphertext)]
    mac_plain = hmac.new(meta["digest_key"], plain, hashlib.sha256).digest()
    mac_cipher = hmac.new(meta["digest_key"], ciphertext, hashlib.sha256).digest()
    return plain, (mac_plain == meta["digest"] or mac_cipher == meta["digest"])


# ------------------------------------------------------------------- КОНТРОЛЬ
def build_synthetic(n_seg: int = 2, seg_len: int = 0x400) -> bytes:
    """Строим пакет по той же схеме, но с ЧИТАЕМЫМИ метаданными (как PS4UPDATE.PUP.dec)."""
    metas, segs_enc, descs = [], [], []
    header_size = ENTRY_DESC + n_seg * ENTRY_DESC
    hash_size = n_seg * META_ENTRY
    body_off = header_size + hash_size
    cur = body_off
    for i in range(n_seg):
        prefix = f"SEGMENT-{i}-".encode()
        plain = (prefix * (seg_len // len(prefix) + 2))[:seg_len]
        plain = plain + b"\x00" * (-len(plain) % 16)   # CBC требует кратность 16
        key = bytes([0x10 + i]) * 16
        iv = bytes([0x20 + i]) * 16
        dkey = bytes([0x30 + i]) * 16
        ct = aes_cbc_enc(key, iv, plain)
        digest = hmac.new(dkey, plain, hashlib.sha256).digest()
        metas.append(key + iv + digest + dkey)
        descs.append(struct.pack("<IIII", 0x80000000 | i, cur, len(ct), len(plain)))
        segs_enc.append(ct)
        cur += len(ct)
    hdr16 = struct.pack("<IIHHHH", MAGIC_PUP, 0x32010110, 4, 0, header_size, hash_size)
    return hdr16 + b"".join(descs) + b"".join(metas) + b"".join(segs_enc)


def run_control() -> bool:
    print("=== КОНТРОЛЬ 1: NIST AES-128 известный ответ ===")
    # FIPS-197 / NIST SP800-38A: AES-128 ECB, ключ 2b7e1516..., блок 6bc1bee2...
    kat_key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    kat_ct = bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97")
    got = aes_ecb_dec(kat_key, kat_ct)
    exp = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    print(f"  AES-128-ECB decrypt: {'OK' if got==exp else 'FAIL'}  ({got.hex()})")
    if got != exp:
        return False

    print("\n=== КОНТРОЛЬ 2: синтетический пакет по схеме PS4 (метаданные читаемы) ===")
    pkg = build_synthetic()
    info = parse_inner_header(pkg, 0)
    print(f"  header: magic_ok={info['magic_ok']} header_size=0x{info['header_size']:X} "
          f"hash_size=0x{info['hash_size']:X} meta_entries={info['meta_entries']}")
    if not info["magic_ok"]:
        return False
    n_desc = (info["header_size"] - ENTRY_DESC) // ENTRY_DESC
    hdr_region = pkg[ENTRY_DESC:ENTRY_DESC + info["header_size"] - ENTRY_DESC]
    v = validate_header_region(hdr_region, len(pkg), n_desc)
    print(f"  описатели записей: {v}")
    if not v["ok"]:
        return False
    meta = split_meta(pkg[ENTRY_DESC + info["header_size"] - ENTRY_DESC:][:info["hash_size"]])
    print(f"  metadata-записей: {len(meta)} (по {META_ENTRY} байт)")
    ok_all = True
    for i, m in enumerate(meta):
        flags, off, csize, usize = struct.unpack("<IIII", hdr_region[i * ENTRY_DESC:(i + 1) * ENTRY_DESC])
        plain, mac_ok = decrypt_segment(m, pkg[off:off + csize])
        good = plain.startswith(f"SEGMENT-{i}-".encode()) and mac_ok
        print(f"    сегмент {i}: plaintext={'да' if plain.startswith(f'SEGMENT-{i}-'.encode()) else 'НЕТ'} "
              f"HMAC={'OK' if mac_ok else 'FAIL'}")
        ok_all &= good
    print(f"  ИТОГ КОНТРОЛЯ: {'ПРОЙДЕН — путь metadata→AES-CBC→HMAC работает' if ok_all else 'ПРОВАЛЕН'}")
    return ok_all


# ---------------------------------------------------------------------- АТАКА
def candidate_keys(hdr16: bytes) -> dict[str, bytes]:
    """Все статические кандидаты, которые можно честно собрать без консоли."""
    h = hashlib.sha256
    c = {
        "zeros16": b"\x00" * 16,
        "zeros32": b"\x00" * 32,
        "header16": hdr16,
        "sha256(hdr16)": hashlib.sha256(hdr16).digest(),
        "sha256(magic)": h(struct.pack("<I", MAGIC_PUP)).digest(),
        "seq16": bytes(range(16)),
        "seq32": bytes(range(32)),
    }
    return c


def attack(path: str) -> None:
    buf = open(path, "rb").read(0x4000)
    size = os.path.getsize(path)
    print(f"=== АТАКА на {path} ({size} байт) ===")
    info = parse_inner_header(buf)
    print(f"  внутренний PUP @0x400: {info}")
    print(f"  открыто: {info['plaintext_len']} байт = {info['raw16']}")
    print(f"  под шифром: {info['encrypted_len']} байт "
          f"(header_size 0x{info['header_size']:X} + hash_size 0x{info['hash_size']:X} - 0x10)")
    print(f"  ожидаемо metadata-записей по 0x50: {info['meta_entries']} "
          f"(хвост {info['hash_size'] % META_ENTRY} байт)")

    enc_off = 0x400 + ENTRY_DESC
    enc = buf[enc_off:enc_off + info["encrypted_len"]]
    n_desc = (info["header_size"] - ENTRY_DESC) // ENTRY_DESC
    print(f"  кандидатов-описателей в header-области: {n_desc}")

    keys = candidate_keys(buf[0x400:0x410])
    print(f"\n  кандидатов ключей: {len(keys)} -> {', '.join(keys)}")
    failures = []
    for kname, key in keys.items():
        for klen in (16, 32):
            kk = (key * 2)[:klen]
            for mode in ("ECB", "CBC0", "CBCiv", "CTR0", "XTS"):
                try:
                    if mode == "ECB":
                        dec = aes_ecb_dec(kk, enc[: (len(enc) // 16) * 16])
                    elif mode == "CBC0":
                        dec = aes_cbc_dec(kk, b"\x00" * 16, enc[: (len(enc) // 16) * 16])
                    elif mode == "CBCiv":
                        dec = aes_cbc_dec(kk, buf[0x400:0x410] + b"\x00" * 0, enc[: (len(enc) // 16) * 16])
                    elif mode == "CTR0":
                        dec = aes_ctr_dec(kk, b"\x00" * 16, enc[: (len(enc) // 16) * 16])
                    else:
                        kxts = (kk * 4)[:64]
                        if kxts[:32] == kxts[32:]:
                            continue
                        dec = aes_xts_dec(kxts, b"\x00" * 16, enc[: (len(enc) // 16) * 16])
                except Exception as e:
                    failures.append((kname, klen, mode, type(e).__name__))
                    continue
                v = validate_header_region(dec, size, n_desc)
                if v["ok"]:
                    print(f"  !!! УСПЕХ: key={kname} len={klen} mode={mode} entries={v['entries']}")
                    open(f"/tmp/DECRYPTED-{kname}-{mode}.bin", "wb").write(dec)
                    return
                failures.append((kname, klen, mode, "нет структуры"))
    print(f"\n  попыток: {len(failures)}; ни одна не дала валидной таблицы записей.")
    from collections import Counter
    cnt = Counter(f[3] for f in failures)
    print(f"  распределение исходов: {dict(cnt)}")
    print("\n  ТОЧКА ОТКАЗА: шаг 'расшифровать header+metadata' — нет ключа.")
    print("  Сегментный путь (AES-128-CBC + HMAC) при этом полностью реализован")
    print("  и подтверждён контролем, т.е. после получения метаданных распаковка пойдёт.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--control", action="store_true")
    ap.add_argument("--attack")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--pup", default="fw/PS5UPDATE-sys-2026_1027.PUP")
    a = ap.parse_args()
    if a.all or a.control:
        ok = run_control()
        print()
        if a.all:
            attack(a.pup)
        sys.exit(0 if ok else 1)
    if a.attack:
        attack(a.attack)
        return
    ap.print_help()


if __name__ == "__main__":
    main()