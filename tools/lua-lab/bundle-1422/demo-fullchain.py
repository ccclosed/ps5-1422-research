#!/usr/bin/env python3
"""bundle-1422 / demo-fullchain.py — доказательство интеграции: наша kernel-цепочка
целиком проходит через НАШ примитив по TCP.

Схема:
    node tools/jb1422/kernel/relapse1422.js   (наша цепочка, не трогаем)
                    |  p.read*/write*/malloc (sync), chain.syscall, rw.read/write (async)
                    v  TCP
    kernel-runner.py --mock-kernel            (Python: mock YARPE + синтетическое ядро,
                    |                          как в dry-run-моках kernel-модуля)
                    v
    профиль ответов 1:1 с tools/jb1422/kernel/relapse1422.js makeDryRunMocks()

Запуск одной командой:
    python3 demo-fullchain.py                 # поднимет runner, прогонит node, напечатает таблицу
    python3 demo-fullchain.py --verbose       # плюс лог runner'а
Код возврата 0 — цепочка дошла до конца (12 стадий, done=true).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE / "output"
LOG = OUT_DIR / "fullchain-over-tcp.log"
EXPECTED_STAGES = int(__import__("os").environ.get("EXPECTED_STAGES", "13"))  # регрессия: меньше — exit != 0


def start_runner(verbose: bool) -> tuple[subprocess.Popen, int]:
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "kernel-runner.py"), "--mock-kernel",
         "--host", "127.0.0.1", "--port", "0"],
        cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                raise RuntimeError("kernel-runner exited before READY")
            continue
        line = line.strip()
        if verbose:
            print("[runner] " + line)
        match = re.search(r"READY runner ([^:]+):(\d+)", line)
        if match:
            return proc, int(match.group(2))
    proc.kill()
    raise RuntimeError("no READY line from kernel-runner in 15s")


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the jb1422 kernel chain over the bundle-1422 TCP primitive")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    OUT_DIR.mkdir(exist_ok=True)

    runner, port = start_runner(args.verbose)
    print(f"kernel-runner (--mock-kernel) на 127.0.0.1:{port}")
    try:
        cmd = ["node", str(HERE / "run-relapse-over-tcp.mjs"), f"--addr=127.0.0.1:{port}"]
        print("$ " + " ".join(cmd) + "\n")
        proc = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True, timeout=300)
        output = proc.stdout + (proc.stderr or "")
        LOG.write_text(
            f"# demo-fullchain {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"# runner port: {port}\n$ {' '.join(cmd)}\n\n{output}",
            encoding="utf-8",
        )
        print(output)
        m = re.search(r"ИТОГ: done=(\w+), стадий=(\d+), OK=(\d+), DEGRADED=(\d+), FAIL=(\d+)", output)
        if not m:
            print("[REGRESSION] в выводе нет строки ИТОГ — цепочка не дошла до отчёта")
            print(f"[log] {LOG}")
            return 1
        done, stages, ok, degraded, failed = m.group(1), *map(int, m.groups()[1:])
        print(f"\n[summary] full-chain через YARPE-примитив: стадий={stages}, OK={ok}, "
              f"DEGRADED={degraded}, FAIL={failed}")
        print(f"[log] {LOG}")
        # строгая регрессия: полный набор стадий и все зелёные
        regressions = []
        if done != "true":
            regressions.append("done != true")
        if stages < EXPECTED_STAGES:
            regressions.append(f"стадий {stages} < {EXPECTED_STAGES}")
        if ok < EXPECTED_STAGES:
            regressions.append(f"OK {ok} < {EXPECTED_STAGES}")
        if degraded:
            regressions.append(f"DEGRADED={degraded}")
        if failed:
            regressions.append(f"FAIL={failed}")
        if regressions or proc.returncode != 0:
            print("[REGRESSION] " + "; ".join(regressions or [f"node exit={proc.returncode}"]))
            return 1
        print("[OK] full-chain зелёный: все стадии OK, деградаций нет")
        return 0
    finally:
        runner.terminate()
        try:
            runner.wait(timeout=5)
        except subprocess.TimeoutExpired:
            runner.kill()


if __name__ == "__main__":
    raise SystemExit(main())