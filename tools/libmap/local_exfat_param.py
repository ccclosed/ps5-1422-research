#!/usr/bin/env python3
"""local_exfat_param.py — прочитать sce_sys/param.json из ЛОКАЛЬНОГО .exfat-образа PS5.

Зачем: у нас на диске лежит `games/cyberpunk/PPSA04029.exfat` (260 519 755 776 байт,
реальный exFAT-образ PS5-дампа). Он не смонтирован (и не может быть без root/fuse),
но нам из него нужен один файл — `sce_sys/param.json`, чтобы документально подтвердить
эпоху Cyberpunk (SDK/FW) и закрыть оговорку №8 из sdk-delta-860-vs-1100.md.

`fw/game-modules/tools/exfat_remote.py` умеет ходить по exFAT по HTTP Range, но требует
объект-читатель с интерфейсом `size` / `verbose` / `fetch(off, length)`. Здесь подставляется
локальный файловый читатель — сеть не нужна, весь образ не читается (только VBR, FAT,
каталоги и кластеры нужного файла).

Декодер версии — по recon/module-era-decoding.md (правило из KytyPS5):
    requiredSystemSoftwareVersion = "0x" + MMmmpp(6 ДЕСЯТИЧНЫХ цифр) + 10 hex
    → major = первые 2 цифры, minor = следующие 2, patch = последние 2 (если != "00")
    sdkVersion кодируется так же (BCD-подобно): 0x1100000000000000 → 11.00

Использование
-------------
    python3 local_exfat_param.py IMAGE.exfat
    python3 local_exfat_param.py IMAGE.exfat --list /            # что в корне
    python3 local_exfat_param.py IMAGE.exfat --list sce_sys
    python3 local_exfat_param.py IMAGE.exfat --read sce_sys/param.json --out /tmp/p.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import struct
import sys

EXFAT_TOOL = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "fw", "game-modules", "tools", "exfat_remote.py",
)


def load_exfat_module():
    path = os.path.abspath(EXFAT_TOOL)
    if not os.path.exists(path):
        raise SystemExit(f"не найден {path}")
    spec = importlib.util.spec_from_file_location("exfat_remote", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LocalFile:
    """Читатель локального файла с тем же интерфейсом, что Remote из exfat_remote."""

    def __init__(self, path: str, verbose: bool = False):
        self.path = path
        self.size = os.path.getsize(path)
        self.verbose = verbose
        self.bytes_fetched = 0
        self.requests = 0
        self._f = open(path, "rb")

    def fetch(self, off: int, length: int) -> bytes:
        if off >= self.size or length <= 0:
            return b""
        length = int(min(length, self.size - off))
        self._f.seek(off)
        data = self._f.read(length)
        self.bytes_fetched += len(data)
        self.requests += 1
        return data

    def close(self):
        self._f.close()


def decode_version(value) -> str:
    """Декодировать requiredSystemSoftwareVersion / sdkVersion по правилу KytyPS5.

    Принимает int, строку '0x...' или '0X...'. Возвращает 'MM.mm' / 'MM.mm.pp'.
    """
    if value is None:
        return "—"
    if isinstance(value, int):
        raw = f"0x{value:016x}"
    else:
        raw = str(value).strip()
    if not raw.lower().startswith("0x"):
        return f"не распознано ({raw!r})"
    digits = raw[2:]
    # ровно 16 hex-цифр; первые 6 — ДЕСЯТИЧНЫЕ цифры версии
    if len(digits) < 16:
        digits = digits.rjust(16, "0")
    head = digits[:6]
    if not head.isdigit():
        return f"не распознано ({raw!r})"
    major, minor, patch = head[0:2], head[2:4], head[4:6]
    out = f"{major}.{minor}"
    if patch != "00":
        out += f".{patch}"
    return out


def find_in_dir(ex, entries, name):
    low = name.lower()
    for e in entries:
        if e["name"].lower() == low:
            return e
    return None


def list_dir(ex, path: str, verbose=False):
    """Пройти путь вида 'sce_sys' или '/' и напечатать содержимое."""
    parts = [p for p in path.replace("\\", "/").split("/") if p and p != "."]
    first = ex.root_cluster
    cur_name = "/"
    for part in parts:
        data = ex.read_dir(first)
        entries = ex.parse_dir(data)
        e = find_in_dir(ex, entries, part)
        if not e:
            raise SystemExit(f"нет '{part}' в '{cur_name}'. Есть: "
                             + ", ".join(x["name"] for x in entries[:20]))
        if not e["is_dir"]:
            raise SystemExit(f"'{part}' — не каталог")
        first = e["first"]
        cur_name = part
    data = ex.read_dir(first)
    entries = ex.parse_dir(data)
    for e in entries:
        kind = "DIR " if e["is_dir"] else "FILE"
        print(f"  {kind} {e['size']:>14}  {e['name']}")
    return entries


def read_file(ex, path: str) -> bytes:
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    first = ex.root_cluster
    target = None
    for i, part in enumerate(parts):
        data = ex.read_dir(first)
        entries = ex.parse_dir(data)
        e = find_in_dir(ex, entries, part)
        if not e:
            raise SystemExit(f"нет '{part}' при разборе пути {path}")
        if i == len(parts) - 1:
            target = e
        else:
            if not e["is_dir"]:
                raise SystemExit(f"'{part}' — не каталог")
            first = e["first"]
    assert target is not None
    return ex.read_chain(target["first"], target["size"], no_fat_chain=target["no_fat_chain"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Чтение файлов из локального .exfat-образа PS5")
    ap.add_argument("image")
    ap.add_argument("--list", metavar="DIR", default=None)
    ap.add_argument("--read", metavar="PATH", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--param", action="store_true", help="найти sce_sys/param.json и декодировать")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    mod = load_exfat_module()
    lf = LocalFile(args.image, verbose=args.verbose)
    if args.verbose:
        print(f"[local] {args.image}  {lf.size} байт")
    ex = mod.ExFat(lf)

    if args.list:
        list_dir(ex, args.list, args.verbose)
        return 0

    if args.param or args.read:
        path = args.read or "sce_sys/param.json"
        blob = read_file(ex, path)
        if args.out:
            open(args.out, "wb").write(blob)
            print(f"сохранено {len(blob)} байт → {args.out}")
        if args.read and not args.param:
            return 0
        try:
            d = json.loads(blob.decode("utf-8", "replace"))
        except Exception as exc:
            print(f"param.json не разобрался как JSON: {exc}", file=sys.stderr)
            return 1
        print(f"\n=== {path} ({len(blob)} байт) ===")
        for key in ("contentVersion", "masterVersion", "originContentVersion",
                    "targetContentVersion", "sdkVersion",
                    "requiredSystemSoftwareVersion", "pubtools"):
            if key not in d:
                continue
            v = d[key]
            if key == "pubtools" and isinstance(v, dict):
                print(f"  {key}.toolVersion = {v.get('toolVersion')}")
                continue
            if key in ("sdkVersion", "requiredSystemSoftwareVersion"):
                print(f"  {key} = {v} → {decode_version(v)}")
            else:
                print(f"  {key} = {v}")
        print(f"\nВЕРДИКТ ЭПОХИ: SDK {decode_version(d.get('sdkVersion'))}, "
              f"требуемая прошивка {decode_version(d.get('requiredSystemSoftwareVersion'))}")
        return 0

    print("нечего делать: задайте --list, --read и/или --param", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())