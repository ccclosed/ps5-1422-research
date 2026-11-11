#!/usr/bin/env python3
"""Wrapper around the research checkout's hardware-free test suite.

Runs `tools/verify_offline.py` from the cloned PS5-14.10-Research tree (356
tests, stdlib only, no console, no network) and reduces its output to one
summary line, so `run.sh` has a machine-checkable result.

    python3 offline_suite.py                        # auto-detects the checkout
    python3 offline_suite.py --repo /path/to/checkout
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent
DEFAULT_ROOTS = [
    LAB_DIR.parents[1] / "recon" / "_src" / "lua" / "zz",
    Path("/home/oleg/Документы/ps5semulator/ps5jb/recon/_src/lua/zz"),
]


def find_repo(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    for root in DEFAULT_ROOTS:
        if (root / "tools" / "verify_offline.py").is_file():
            return root
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Run tools/verify_offline.py from the research checkout")
    ap.add_argument("--repo", help="path to the PS5-14.10-Research checkout")
    ap.add_argument("--tail", type=int, default=6, help="lines of runner output to show")
    args = ap.parse_args()

    repo = find_repo(args.repo)
    if repo is None:
        print("[FAIL] research checkout not found; run: git clone --depth 1 "
              "https://github.com/ZigZagBoi1/PS5-14.10-Research ps5jb/recon/_src/lua/zz")
        return 2

    started = time.time()
    proc = subprocess.run(
        [sys.executable, "tools/verify_offline.py"],
        cwd=repo, capture_output=True, text=True, timeout=900,
    )
    elapsed = time.time() - started
    out = (proc.stdout or "") + (proc.stderr or "")

    match_ran = re.search(r"Ran (\d+) tests? in ([\d.]+)s", out)
    ok = proc.returncode == 0 and bool(re.search(r"^OK", out, re.MULTILINE))
    ran = match_ran.group(1) if match_ran else "?"

    print(f"# checkout: {repo}")
    for line in out.strip().splitlines()[-args.tail:]:
        print(f"  {line}")
    print(f"Ran {ran} tests, exit={proc.returncode}, wall={elapsed:.2f}s, status={'OK' if ok else 'FAILED'}")
    print("RESULT: PASS" if ok else "RESULT: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())