#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ffpfsc.py — чтение `.ffpfsc` (PS5-дамп игры) по HTTP Range, без скачивания всего образа.

Формат (по phantomptr/ps5upload: payload/src/ffpfsc_unpack.c + engine/crates/ps5upload-fpkg/src/ffpfsc.rs):

  PFS-обёртка (MkPFS, unsigned PFS v2):
    block 0  PFS header: u64 version=2 @0, u64 magic=20130315 @8
    block 1  таблица inode'ов, шаг 0xA8; inode 3 — единственный файл:
             flags(u32 @+4, bit0=compressed), stored u64 @+8, raw u64 @+16,
             first_block u32 @+0x64
    block 5  uroot: dirent'ы ".", "..", имя файла; dirent: u32 nlen @+8,
             u32 step @+12, имя @+16
    block 6+ содержимое файла (PFSC-контейнер или сырой exFAT/PFS образ)

  PFSC-контейнер (0x30-байтный заголовок):
    @0x00 u32 magic 0x43534650 ("PFSC")
    @0x10 u64 block_size = 0x10000
    @0x18 u64 table_at   (относительно начала контейнера, обычно 0x400)
    @0x20 u64 data_at
    @0x28 u64 logical_size (несжатый размер внутреннего образа)
    table_at: n+1 u64 смещений блоков (относительно начала контейнера), n = ceil(logical/0x10000)
    data_at+: блоки; каждый блок — zlib-поток, если его длина < 0x10000, иначе сырые 0x10000.

Использование:
  python3 ps5jb/tools/ffpfsc.py --url "<archive.org_url>" --param
  python3 ps5jb/tools/ffpfsc.py --url ... --list sce_sys
  python3 ps5jb/tools/ffpfsc.py --url ... --read sce_sys/param.json --out /tmp/param.json
  python3 ps5jb/tools/ffpfsc.py --url ... --info
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import time
import zlib
from collections import OrderedDict

BLOCK = 0x10000
PFS_VERSION = 2
PFS_MAGIC = 20130315
PFSC_MAGIC = 0x43534650
INODE_LEN = 0xA8
TABLE_WINDOW = 8192          # записей таблицы (по 8 байт) на один Range-запрос
CHUNK = 1 << 20              # кэш сырых чтений, 1 МиБ


def _le64(b, o=0):
    return struct.unpack_from("<Q", b, o)[0]


def _le32(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


class HTTPRange:
    """Читает диапазоны файла по HTTP; кэширует куски по 1 МиБ."""

    def __init__(self, url, proxy=None, verbose=False, retries=5):
        self.url = url
        self.proxy = proxy
        self.verbose = verbose
        self.retries = retries
        self.requests = 0
        self.bytes = 0
        self.cache = OrderedDict()          # chunk_index -> bytes
        self.cache_limit = 256              # 256 МиБ
        self.size = None                    # заполняется из Content-Range

    def _curl(self, off, length):
        cmd = ["curl", "-sSL", "--fail", "--max-time", "300",
               "-r", f"{off}-{off + length - 1}"]
        if self.proxy:
            cmd += ["-x", self.proxy]
        cmd.append(self.url)
        last = ""
        for attempt in range(self.retries):
            out = subprocess.run(cmd, capture_output=True)
            if out.returncode == 0:
                body = out.stdout
                if len(body) == length:
                    self.requests += 1
                    self.bytes += len(body)
                    return body
                last = f"short read {len(body)}/{length}"
            else:
                last = out.stderr.decode("utf-8", "replace").strip()[:200]
            time.sleep(0.4 * (attempt + 1))
        raise IOError(f"range {off}+{length} failed: {last}")

    def read(self, off, length):
        if length == 0:
            return b""
        out = bytearray()
        pos = off
        end = off + length
        while pos < end:
            ci = pos // CHUNK
            chunk = self.cache.get(ci)
            if chunk is None:
                need = min(CHUNK, (end - (ci * CHUNK)) if False else CHUNK)
                chunk = self._curl(ci * CHUNK, need)
                self.cache[ci] = chunk
                if len(self.cache) > self.cache_limit:
                    self.cache.popitem(last=False)
            else:
                self.cache.move_to_end(ci)
            rel = pos - ci * CHUNK
            take = min(end - pos, CHUNK - rel, len(chunk) - rel)
            if take <= 0:
                raise IOError(f"chunk {ci} short at rel {rel}")
            out += chunk[rel:rel + take]
            pos += take
        return bytes(out)


class BlockTable:
    """Таблица PFSC: n+1 u64 смещений блоков; читается окнами по 8192 записей."""

    def __init__(self, rf, base, table_at, blocks, verbose=False):
        self.rf = rf
        self.base = base
        self.table_at = table_at
        self.blocks = blocks
        self.verbose = verbose
        self.windows = {}

    def _window(self, wi):
        w = self.windows.get(wi)
        if w is None:
            first = wi * TABLE_WINDOW
            count = min(TABLE_WINDOW + 1, self.blocks + 1 - first)
            w = self.rf.read(self.base + self.table_at + first * 8, count * 8)
            self.windows[wi] = w
            if len(self.windows) > 64:
                self.windows.pop(next(iter(self.windows)))
        return w

    def offsets(self, i, j):
        """смещения блоков [i..j] относительно начала контейнера (j+1 значений -> j-i+2)."""
        out = []
        for k in range(i, j + 2):
            wi = k // TABLE_WINDOW
            rel = k - wi * TABLE_WINDOW
            out.append(_le64(self._window(wi), rel * 8))
        return out


class Ffpfsc:
    """Внутренний образ (exFAT/PFS) из `.ffpfsc` по HTTP Range."""

    def __init__(self, url, proxy=None, verbose=False, cache_limit=512):
        self.rf = HTTPRange(url, proxy=proxy, verbose=verbose)
        self.verbose = verbose
        head = self.rf.read(0, 6 * BLOCK)
        self.pfs_version = _le64(head, 0)
        self.pfs_magic = _le64(head, 8)
        if self.pfs_version != PFS_VERSION or self.pfs_magic != PFS_MAGIC:
            raise ValueError(f"not a PFS wrapper: version={self.pfs_version} magic={self.pfs_magic}")
        node = head[BLOCK + 3 * INODE_LEN: BLOCK + 4 * INODE_LEN]
        flags = _le32(node, 4)
        self.stored = _le64(node, 8)
        self.raw = _le64(node, 16) if (flags & 1) else self.stored
        self.first_block = _le32(node, 0x64)
        self.compressed = bool(flags & 1)
        if self.first_block < 6:
            raise ValueError(f"bad first_block {self.first_block}")
        # имя файла из uroot
        uroot = head[5 * BLOCK:6 * BLOCK]
        at, names = 0, []
        for _ in range(3):
            nlen = _le32(uroot, at + 8)
            step = _le32(uroot, at + 12)
            names.append(uroot[at + 16:at + 16 + nlen].decode("utf-8", "replace"))
            if step == 0:
                break
            at += step
        self.inner_name = names[-1]
        self.base = self.first_block * BLOCK               # начало контейнера/файла
        # PFSC-заголовок
        ph = self.rf.read(self.base, 0x30)
        if _le32(ph, 0) != PFSC_MAGIC:
            raise ValueError(f"PFSC magic not found at {self.base:#x}: {ph[:4]!r}")
        self.pfsc_version = _le32(ph, 4)
        self.block_size = _le64(ph, 0x10)
        self.table_at = _le64(ph, 0x18)
        self.data_at = _le64(ph, 0x20)
        self.logical_size = _le64(ph, 0x28)
        self.blocks = (self.logical_size + self.block_size - 1) // self.block_size
        self.table = BlockTable(self.rf, self.base, self.table_at, self.blocks, verbose)
        self.block_cache = OrderedDict()
        self.block_cache_limit = cache_limit
        if verbose:
            print(f"[ffpfsc] inner={self.inner_name!r} stored={self.stored} raw={self.raw} "
                  f"compressed={self.compressed} block={self.block_size} blocks={self.blocks} "
                  f"table_at={self.table_at:#x} data_at={self.data_at:#x}")

    # ---------- доступ к несжатому внутреннему образу ----------
    def read(self, off, length):
        """Читает диапазон несжатого образа; недостающие блоки тянет одним Range-запросом."""
        if off < 0 or length < 0 or off + length > self.logical_size:
            raise ValueError(f"range {off}+{length} outside image ({self.logical_size})")
        out = bytearray()
        pos = off
        end = off + length
        while pos < end:
            bi = pos // self.block_size
            # найдём, сколько блоков подряд ещё нужно докачать
            if bi not in self.block_cache:
                last = min((end - 1) // self.block_size, bi + 4096)
                self._fetch_blocks(bi, last)
            blk = self.block_cache[bi]
            self.block_cache.move_to_end(bi)
            rel = pos - bi * self.block_size
            take = min(end - pos, self.block_size - rel, len(blk) - rel)
            if take <= 0:
                raise IOError(f"block {bi} short")
            out += blk[rel:rel + take]
            pos += take
        return bytes(out)

    def _fetch_blocks(self, i, j):
        """качает блоки [i..j] одним диапазоном и раскладывает по кэшу."""
        from collections import OrderedDict as _OD
        offs = self.table.offsets(i, j)
        span = offs[-1] - offs[0]
        if span > (64 << 20):                       # не тянем гигантский диапазон одним куском
            mid = (i + j) // 2
            self._fetch_blocks(i, mid)
            self._fetch_blocks(mid + 1, j)
            return
        raw = self.rf.read(self.base + offs[0], span)
        for k in range(i, j + 1):
            a, b = offs[k - i], offs[k - i + 1]
            ln = b - a
            data = raw[a - offs[0]:b - offs[0]]
            if ln < self.block_size:
                try:
                    blk = zlib.decompress(data)
                except zlib.error as e:
                    raise IOError(f"zlib fail at block {k}: {e}")
            else:
                blk = data
            self.block_cache[k] = blk
        while len(self.block_cache) > self.block_cache_limit:
            self.block_cache.popitem(last=False)

    def _block(self, i):
        blk = self.block_cache.get(i)
        if blk is not None:
            self.block_cache.move_to_end(i)
            return blk
        offs = self.table.offsets(i, i)
        start, stop = offs[0], offs[1]
        ln = stop - start
        if ln <= 0 or ln > self.block_size:
            raise IOError(f"corrupt block table at {i}: {start}..{stop}")
        # смещения в таблице абсолютны внутри контейнера (`offs[0] == data_at`)
        raw = self.rf.read(self.base + start, ln)
        if ln < self.block_size:
            try:
                blk = zlib.decompress(raw)
            except zlib.error as e:
                raise IOError(f"zlib fail at block {i}: {e}")
        else:
            blk = raw
        self.block_cache[i] = blk
        if len(self.block_cache) > self.block_cache_limit:
            self.block_cache.popitem(last=False)
        return blk

    def read_blocks(self, i, j, workers=1):
        """последовательное чтение блоков [i..j] (для больших диапазонов)."""
        return b"".join(self._block(k) for k in range(i, j + 1))


# ----------------------------------------------------------------------------
# Минимальный exFAT-ридер поверх произвольного читающего объекта (image.read)
# ----------------------------------------------------------------------------
class ExFat:
    def __init__(self, image, verbose=False):
        self.img = image
        self.verbose = verbose
        vbr = image.read(0, 512)
        if vbr[3:11] != b"EXFAT   ":
            raise ValueError(f"not exFAT: {vbr[3:11]!r}")
        self.part_off = _le64(vbr, 0x40)
        self.vol_len = _le64(vbr, 0x48)
        self.fat_off = _le32(vbr, 0x50)
        self.fat_len = _le32(vbr, 0x54)
        self.heap_off = _le32(vbr, 0x58)
        self.cluster_count = _le32(vbr, 0x5C)
        self.root_cluster = _le32(vbr, 0x60)
        self.sector_shift = vbr[0x6C]
        self.spc_shift = vbr[0x6D]
        self.sector_size = 1 << self.sector_shift
        self.cluster_size = self.sector_size << self.spc_shift
        if verbose:
            print(f"[exfat] cluster={self.cluster_size} root={self.root_cluster} "
                  f"clusters={self.cluster_count} fat@{self.fat_off}")

    def _cluster_off(self, n):
        # ClusterHeapOffset в VBR задан в СЕКТОРАХ, не в байтах
        return (self.heap_off * self.sector_size + (n - 2) * self.cluster_size)

    def _fat(self, n):
        off = self.fat_off * self.sector_size + 4 * n
        return _le32(self.img.read(off, 4))

    def _chain(self, first, max_bytes=None):
        """возвращает список кластеров цепочки (с валидацией номеров)."""
        out, n, guard = [], first, 0
        hi = self.cluster_count + 2
        while 2 <= n < hi and guard < 1_000_000:
            out.append(n)
            if max_bytes is not None and len(out) * self.cluster_size >= max_bytes:
                break
            n = self._fat(n)
            guard += 1
        return out

    def read_clusters(self, first, length, nofat=False):
        out = bytearray()
        if nofat:
            left = length
            n = first
            while left > 0:
                chunk = min(self.cluster_size, left)
                out += self.img.read(self._cluster_off(n), chunk)
                left -= chunk
                n += 1
            return bytes(out)
        for n in self._chain(first, length):
            need = min(self.cluster_size, length - len(out))
            out += self.img.read(self._cluster_off(n), need)
            if len(out) >= length:
                break
        return bytes(out[:length])

    def _dir_entries(self, cluster):
        """Читает каталог (цепочку кластеров) и разбирает записи exFAT по правилам спеки:
        файл = 0x85 (атрибуты) + 0xC0 (stream: flags/name len/first cluster/size) + 0xC1 (имя)."""
        cache = getattr(self, "_dircache", None)
        if cache is None:
            cache = self._dircache = {}
        if cluster in cache:
            return cache[cluster]
        data = b"".join(self.img.read(self._cluster_off(n), self.cluster_size)
                        for n in self._chain(cluster))
        entries, at, n = [], 0, len(data)
        while at + 32 <= n:
            etype = data[at]
            if etype == 0x00:
                break
            if etype == 0x85 and at + 32 * (1 + data[at + 1]) <= n:
                sec = data[at + 1]
                attrs = struct.unpack_from("<H", data, at + 4)[0]
                stream = None
                name_len = 0
                name = ""
                # вторичные записи: stream 0xC0 и name 0xC1
                j = at + 32
                while j < at + 32 * (1 + sec):
                    t = data[j]
                    if t == 0xC0 and j + 32 <= n:
                        name_len = data[j + 3]
                        flags2 = data[j + 1]
                        first = struct.unpack_from("<I", data, j + 20)[0]
                        size = struct.unpack_from("<Q", data, j + 24)[0]
                        stream = dict(name_len=name_len, nofat=bool(flags2 & 0x02),
                                      first=first, size=size)
                    elif t & 0x40 and j + 32 <= n:      # 0xC1.. name entries
                        name += data[j + 2:j + 32].decode("utf-16-le", "ignore")
                    j += 32
                if stream and stream["name_len"]:
                    name = name[:stream["name_len"]]
                    entries.append(dict(name=name, attrs=attrs,
                                        first=stream["first"], size=stream["size"],
                                        is_dir=bool(attrs & 0x10),
                                        nofat=stream["nofat"]))
                at += 32 * (1 + sec)
                continue
            at += 32
        cache[cluster] = entries
        return entries

    @staticmethod
    def _read_name(data, at, name_len):
        chars = []
        while len(chars) < name_len and at + 32 <= len(data):
            etype = data[at]
            if etype & 0x40:                       # last name entry
                pass
            chunk = data[at + 2:at + 32]
            chars.extend(chunk.decode("utf-16-le", "ignore"))
            at += 32
        return "".join(chars).rstrip("\x00")

    def listdir(self, path):
        ent = self.resolve(path, want_dir=True)
        cluster = self.root_cluster if ent is None else ent["first"]
        return self._dir_entries(cluster)

    def resolve(self, path, want_dir=False):
        parts = [p for p in path.replace("\\", "/").split("/") if p]
        cur = self.root_cluster
        ent = None
        for i, p in enumerate(parts):
            entries = self._dir_entries(cur)
            ent = next((e for e in entries if e["name"].lower() == p.lower()), None)
            if ent is None:
                return None
            if i < len(parts) - 1:
                if not ent["is_dir"]:
                    return None
                cur = ent["first"]
        return ent

    def read_file(self, path, limit=None):
        ent = self.resolve(path)
        if ent is None or ent["is_dir"]:
            return None
        size = ent["size"] if limit is None else min(ent["size"], limit)
        return self.read_clusters(ent["first"], size, ent.get("nofat", False))

    def walk(self, path="", depth=0, max_depth=4):
        entries = self.listdir(path)
        for e in entries:
            p = f"{path}/{e['name']}" if path else e["name"]
            yield p, e
            if e["is_dir"] and depth < max_depth:
                yield from self.walk(p, depth + 1, max_depth)


# ----------------------------------------------------------------------------
# Версия из param.json — правило из recon/module-era-decoding.md (декадер KytyPS5)
# ----------------------------------------------------------------------------
VER_RE = re.compile(r"^0[xX]([0-9]{6})[0-9A-Fa-f]{10}$")


def decode_version(encoded):
    """0x1270000000000000 -> '12.70' (FW), 0x1100000000000000 -> '11.00' (SDK)."""
    if not isinstance(encoded, str):
        return None
    m = VER_RE.match(encoded.strip())
    if not m:
        return None
    d = m.group(1)
    major, minor, patch = d[0:2], d[2:4], d[4:6]
    out = f"{int(major)}.{minor}"
    if patch != "00":
        out += f".{patch}"
    return out


def summarize_param(raw):
    try:
        j = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None
    keys = ["titleId", "contentId", "contentVersion", "requiredSystemSoftwareVersion",
            "sdkVersion", "titleName", "applicationDataFreeSpace"]
    out = {k: j.get(k) for k in keys if k in j}
    for k in ("requiredSystemSoftwareVersion", "sdkVersion"):
        if k in j:
            out[k + "_decoded"] = decode_version(j[k])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Читать .ffpfsc (PS5-дамп) по HTTP Range")
    ap.add_argument("--url", required=True, help="URL файла .ffpfsc (archive.org/download/...)")
    ap.add_argument("--proxy", default=os.environ.get("FFPFSC_PROXY", "socks5h://127.0.0.1:10810"))
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--file-size", type=int, default=None, help="размер файла (для контроля)")
    ap.add_argument("--info", action="store_true", help="показать метаданные PFS/PFSC")
    ap.add_argument("--list", metavar="PATH", default=None, help="листинг каталога внутри образа")
    ap.add_argument("--path", default=None, help="найти файл и напечатать его размер")
    ap.add_argument("--read", metavar="PATH", default=None, help="скачать файл из образа")
    ap.add_argument("--out", default=None, help="куда сохранить (--read)")
    ap.add_argument("--param", action="store_true", help="найти sce_sys/param.json и декодировать версию")
    ap.add_argument("--param-path", default="sce_sys/param.json")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args(argv)

    proxy = None if a.no_proxy else a.proxy
    t0 = time.time()
    fs = Ffpfsc(a.url, proxy=proxy, verbose=a.verbose)
    print(f"[pfs] inner={fs.inner_name!r} compressed={fs.compressed} stored={fs.stored} raw={fs.raw}")
    print(f"[pfsc] block={fs.block_size} logical={fs.logical_size} blocks={fs.blocks} "
          f"table_at={fs.table_at:#x} data_at={fs.data_at:#x}")
    print(f"[http] запросов={fs.rf.requests} байт={fs.rf.bytes} "
          f"({fs.rf.bytes/1048576:.2f} МиБ) за {time.time()-t0:.1f}с")
    if a.info:
        return 0

    ex = ExFat(fs, verbose=a.verbose)
    print(f"[exfat] cluster={ex.cluster_size} root={ex.root_cluster}")

    if a.list is not None:
        for p, e in ex.walk(a.list.strip("/"), max_depth=2):
            print(f"{'D' if e['is_dir'] else 'F'} {e['size']:>12} {p}")
        return 0

    if a.path:
        e = ex.resolve(a.path)
        print(json.dumps({"path": a.path, "found": bool(e),
                          **(e or {})}, ensure_ascii=False))
        return 0

    if a.read:
        data = ex.read_file(a.read, limit=a.file_size)
        if data is None:
            print(f"[!] не найден: {a.read}", file=sys.stderr)
            return 2
        out = a.out or os.path.basename(a.read)
        with open(out, "wb") as f:
            f.write(data)
        print(f"[ok] {a.read} -> {out} ({len(data)} байт)")
        return 0

    if a.param:
        # param.json бывает и в корне образа, и внутри app0/sce_sys
        for cand in (a.param_path, "app0/" + a.param_path, "PPSA34015/sce_sys/param.json"):
            e = ex.resolve(cand)
            if e and not e["is_dir"]:
                raw = ex.read_file(cand)
                info = summarize_param(raw)
                print(f"[param] {cand}: {e['size']} байт")
                print(json.dumps(info, ensure_ascii=False, indent=2))
                r = (info or {}).get("requiredSystemSoftwareVersion_decoded")
                s = (info or {}).get("sdkVersion_decoded")
                print(f"[version] requiredSystemSoftwareVersion -> FW {r}; sdkVersion -> SDK {s}")
                return 0
        print("[!] param.json не найден по известным путям", file=sys.stderr)
        return 2

    # по умолчанию: показать корень
    for p, e in ex.walk("", max_depth=1):
        print(f"{'D' if e['is_dir'] else 'F'} {e['size']:>12} {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())