#!/usr/bin/env python3
"""Compile the research probe corpus with Lua 5.1 (lupa), like the upstream gate.

Mirrors `PS5-14.10-Research/tools/check_lua_syntax.py`: every `probes/**/*.lua`
source is compiled with `loadstring` under a real Lua 5.1 VM (lupa), without
executing it.  Catches Lua 5.2+ syntax (`goto`, `::labels::`), BOM problems and
truncated files before a probe ever reaches the console.

Requires: `python3 -m pip install --user lupa==2.6` (wheel, no root needed).

    python3 syntax_lua51.py                      # auto-detects the checkout
    python3 syntax_lua51.py --probes /path/probes
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent
DEFAULT_ROOTS = [
    LAB_DIR.parents[1] / "recon" / "_src" / "lua" / "zz",       # ps5jb/recon/_src/lua/zz
    Path("/home/oleg/Документы/ps5semulator/ps5jb/recon/_src/lua/zz"),
]


def find_probes(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    for root in DEFAULT_ROOTS:
        probes = root / "probes"
        if probes.is_dir():
            return probes
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Lua 5.1 syntax gate over the probe corpus")
    ap.add_argument("--probes", help="path to a probes/ directory")
    ap.add_argument("--limit", type=int, default=0, help="only check the first N files (debug)")
    args = ap.parse_args()

    probes = find_probes(args.probes)
    if probes is None:
        print("[FAIL] probes/ not found; run: git clone --depth 1 "
              "https://github.com/ZigZagBoi1/PS5-14.10-Research ps5jb/recon/_src/lua/zz")
        return 2

    try:
        from lupa.lua51 import LuaRuntime
    except ImportError:
        print("[FAIL] lupa is not installed. Install it with:")
        print("       python3 -m pip install --user lupa==2.6")
        print("       (if PyPI is blocked: curl -x socks5h://127.0.0.1:10810 -O <wheel-url>)")
        return 2

    compiler = LuaRuntime().eval("loadstring")
    files = sorted(probes.rglob("*.lua"))
    if args.limit:
        files = files[: args.limit]

    started = time.time()
    failures: list[tuple[str, str]] = []
    for probe in files:
        try:
            source = probe.read_text(encoding="utf-8-sig")   # BOM is invalid Lua 5.1
        except (OSError, UnicodeDecodeError) as exc:
            failures.append((str(probe.relative_to(probes)), f"read error: {exc}"))
            continue
        try:
            result = compiler(source, str(probe.relative_to(probes)))
        except UnicodeDecodeError:
            failures.append((str(probe.relative_to(probes)), "Lua error text was not valid UTF-8"))
            continue
        # loadstring returns (nil, msg) on a syntax error and a function otherwise
        if isinstance(result, tuple) and result[0] is None:
            failures.append((str(probe.relative_to(probes)), str(result[1])))

    elapsed = time.time() - started
    print(f"# probes root: {probes}")
    print(f"Compiled {len(files)} Lua 5.1 probe sources; failures={len(failures)}")
    for name, error in failures[:20]:
        print(f"  {name}: {error}")
    print(f"# elapsed {elapsed:.2f}s")
    if failures:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())