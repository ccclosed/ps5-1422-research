#!/usr/bin/env python3
"""PS5 official firmware (PUP) resolver / downloader — works from a PC, no console.

Source of truth: the community mirror of Sony's own updatelist.xml
  https://github.com/MewX/ps5-official-firmware-list
Each file updatelists/updatelist.<YYYY_MMDD>.<version>.xml is a verbatim copy of what the
console's update client receives; it contains the label, the image size and the official
download URL, and the URL itself carries the image's SHA-256 in the path segment "sys_<hash>".

Usage:
    fetch.py list                     # versions present in the mirror
    fetch.py resolve 14.22            # -> label, size, sha256, official URL
    fetch.py verify FILE 14.22        # compare a local PUP against Sony's metadata
    fetch.py download 14.22 [--out DIR] [--jobs N]

Exit codes: 0 ok, 1 error, 2 mismatch.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import urllib.request

MIRROR_API = "https://api.github.com/repos/MewX/ps5-official-firmware-list/contents/updatelists"
MIRROR_RAW = "https://raw.githubusercontent.com/MewX/ps5-official-firmware-list/main/updatelists"

PUP_RE = re.compile(
    r'<system_pup[^>]*label="(?P<label>[^"]+)"[^>]*sdk_version="(?P<sdk>[^"]+)"[^>]*>'
    r'.*?<image size="(?P<size>\d+)">(?P<url>[^<]+)</image>',
    re.S,
)
HASH_RE = re.compile(r"/sys_([0-9a-f]{64})/", re.I)


def _get(url: str, timeout: int = 40) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ps5jb-pup-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as fh:
        return fh.read()


CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".updatelists.cache")


def _via_gh() -> list[str]:
    """Authenticated listing through the gh CLI (avoids the anonymous rate limit)."""
    out = subprocess.run(
        ["gh", "api", "repos/MewX/ps5-official-firmware-list/contents/updatelists", "--jq", ".[].name"],
        capture_output=True, text=True, timeout=60,
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip()[:200])
    return [l.strip() for l in out.stdout.splitlines() if l.strip().startswith("updatelist.")]


def _via_html() -> list[str]:
    """Scrape the GitHub tree page — works without a token."""
    html = _get("https://github.com/MewX/ps5-official-firmware-list/tree/main/updatelists").decode("utf-8", "replace")
    return sorted(set(re.findall(r"updatelist\.[0-9_]+\.\d+\.\d+\.\d+\.xml", html)))


def _via_api() -> list[str]:
    import json

    data = json.loads(_get(MIRROR_API).decode())
    return sorted(e["name"] for e in data if e["name"].startswith("updatelist."))


def list_versions(refresh: bool = False) -> list[str]:
    """Return mirror file names, e.g. updatelist.2026_1027.14.22.00.xml."""
    if not refresh and os.path.isfile(CACHE):
        names = [l.strip() for l in open(CACHE, encoding="utf-8") if l.strip()]
        if names:
            return names
    for fn in (_via_gh, _via_html, _via_api):
        try:
            names = sorted(set(fn()))
            if names:
                with open(CACHE, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(names) + "\n")
                return names
        except Exception as exc:  # noqa: BLE001 - try the next source
            print(f"note: {fn.__name__} failed: {exc}", file=sys.stderr)
    raise SystemExit("error: cannot list mirror files (no gh, no html, no api, no cache)")


def _find_file(version: str) -> str:
    """Match a user version like '14.22' or '14.22.00' against the mirror listing."""
    want = version.strip().rstrip(".")
    if not want.endswith(".00") and want.count(".") == 1:
        want += ".00"
    names = list_versions()
    for name in names:
        if name.endswith(f"{want}.xml"):
            return name
    raise SystemExit(f"error: version {version!r} not found in mirror ({len(names)} files)")


def resolve(version: str) -> dict:
    name = _find_file(version)
    xml = _get(f"{MIRROR_RAW}/{name}").decode("utf-8", "replace")
    m = PUP_RE.search(xml)
    if not m:
        raise SystemExit(f"error: no <system_pup> entry in {name}")
    url, size, label, sdk = m.group("url"), int(m.group("size")), m.group("label"), m.group("sdk")
    h = HASH_RE.search(url)
    return {
        "file": name,
        "version": sdk.split("-")[0],
        "label": label,
        "sdk_version": sdk,
        "size": size,
        "sha256": h.group(1).lower() if h else None,
        "url": url,
    }


def sha256_of(path: str, chunk: int = 8 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def verify(path: str, version: str) -> int:
    meta = resolve(version)
    if not os.path.isfile(path):
        print(f"error: no such file: {path}")
        return 1
    size = os.path.getsize(path)
    print(f"file      : {path}")
    print(f"metadata  : {meta['label']} ({meta['file']})")
    print(f"size      : {size} (sony says {meta['size']}) {'OK' if size == meta['size'] else 'MISMATCH'}")
    if meta["sha256"]:
        got = sha256_of(path)
        print(f"sha256    : {got}")
        print(f"sony path : {meta['sha256']} {'OK' if got == meta['sha256'] else 'MISMATCH'}")
        if got != meta["sha256"]:
            return 2
    return 0 if size == meta["size"] else 2


def download(version: str, out_dir: str, jobs: int = 8, resume: bool = True) -> int:
    meta = resolve(version)
    os.makedirs(out_dir, exist_ok=True)
    name = f"PS5UPDATE-{meta['version']}-{meta['file'].split('.')[1]}.PUP"
    dest = os.path.join(out_dir, name)
    print(f"version : {meta['label']}")
    print(f"size    : {meta['size']} bytes")
    print(f"sha256  : {meta['sha256']}")
    print(f"url     : {meta['url']}")
    print(f"dest    : {dest}")
    if os.path.exists(dest) and os.path.getsize(dest) == meta["size"]:
        print("already downloaded with the right size; verifying hash")
        return verify(dest, version)
    cmd = [
        "curl", "-L", "--fail", "--retry", "5", "--retry-delay", "3",
        "-C", "-" if resume else "0",
        "--parallel", "--parallel-max", str(jobs),
        "-o", dest, meta["url"],
    ]
    print("+ " + " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        print(f"error: curl exited {rc}")
        return 1
    return verify(dest, version)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    p_res = sub.add_parser("resolve"); p_res.add_argument("version")
    p_ver = sub.add_parser("verify"); p_ver.add_argument("file"); p_ver.add_argument("version")
    p_dl = sub.add_parser("download"); p_dl.add_argument("version")
    p_dl.add_argument("--out", default=".")
    p_dl.add_argument("--jobs", type=int, default=8)
    a = ap.parse_args()

    if a.cmd == "list":
        for n in list_versions():
            print(n)
        return 0
    if a.cmd == "resolve":
        m = resolve(a.version)
        for k in ("version", "label", "size", "sha256", "url", "file"):
            print(f"{k:12}: {m[k]}")
        return 0
    if a.cmd == "verify":
        return verify(a.file, a.version)
    if a.cmd == "download":
        return download(a.version, a.out, a.jobs)
    return 1


if __name__ == "__main__":
    sys.exit(main())
