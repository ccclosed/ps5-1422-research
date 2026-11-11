#!/usr/bin/env bash
# bundle-1422 / run.sh — единая проверка LUA/YARPE-пути на ПК (консоль не нужна).
#
#   1. Lua-проба: компиляция Lua 5.1 + исполнение со стаб-загрузчиком (selftest.py)
#   2. Отправщик 9026: кадрирование (send_lua.py --self-test)
#   3. Мост: HTTP API + line-протокол агента (bridge_server.py --self-test)
#   4. Примитив P: 23 проверки read/write/syscall поверх mock sc.mem (primitive.py)
#   5. Бинарный runner: 20 операций по TCP, формат «1+8+8» (kernel-runner.py --selftest)
#   6. Синтаксис Lua-агента (agent_lua.lua) через lupa, если установлена
#
# Запуск: ./run.sh            (exit 0 только если всё PASS)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/output"
mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/run.log"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

TOTAL=0; FAILED=0
declare -a NAMES=() STATUSES=() DETAILS=()
step_start() { STEP_T0=$(date +%s%N); echo; echo "=== $1"; }
step_end() {
  local name="$1" status="$2" detail="$3"
  local ms=$(( ($(date +%s%N) - STEP_T0) / 1000000 ))
  NAMES+=("$name"); STATUSES+=("$status"); DETAILS+=("$detail  [${ms} ms]")
  [ "$status" = "FAIL" ] && FAILED=$((FAILED + 1))
  TOTAL=$((TOTAL + 1))
  echo "--- $name: $status ($detail)"
}

cd "$SCRIPT_DIR" || exit 2
echo "bundle-1422 lab — $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "  dir: $SCRIPT_DIR"
echo "  python: $(python3 -V 2>&1)"
LUPA_OK=0
python3 -c 'from lupa.lua51 import LuaRuntime' 2>/dev/null && LUPA_OK=1

step_start "0. environment"
echo "python3=$(python3 -V 2>&1)"
echo "lupa=$([ "$LUPA_OK" = 1 ] && echo OK || echo missing)"
step_end "environment" "PASS" "python3 ready"

step_start "1. Lua-проба (Lua 5.1 + стаб-загрузчик)"
if [ "$LUPA_OK" != 1 ]; then
  step_end "lua probe selftest" "FAIL" "lupa missing: python3 -m pip install --user lupa==2.6"
elif OUT=$(python3 selftest.py 2>&1); then
  echo "$OUT" | tail -6
  step_end "lua probe selftest" "PASS" "STAGE 1..5 OK"
else
  echo "$OUT"
  step_end "lua probe selftest" "FAIL" "see output"
fi

step_start "2. Отправщик 9026 (кадр <u64 LE><Lua>)"
if OUT=$(python3 send_lua.py --self-test 2>&1); then
  echo "$OUT"
  step_end "sender framing" "PASS" "frame 8-byte LE ok"
else
  echo "$OUT"
  step_end "sender framing" "FAIL" "see output"
fi

step_start "3. Мост: HTTP + line-протокол (mock agent)"
if OUT=$(python3 bridge_server.py --self-test 2>&1); then
  echo "$OUT" | tail -4
  step_end "bridge HTTP/line" "PASS" "12 contract checks"
else
  echo "$OUT"
  step_end "bridge HTTP/line" "FAIL" "see output"
fi

step_start "4. Примитив P (mock sc.mem)"
if OUT=$(python3 primitive.py 2>&1); then
  echo "$OUT" | tail -3
  step_end "primitive P" "PASS" "23 checks read/write/syscall"
else
  echo "$OUT" | tail -8
  step_end "primitive P" "FAIL" "see output"
fi

step_start "5. Бинарный runner (20 операций по TCP)"
if OUT=$(python3 kernel-runner.py --selftest 2>&1); then
  echo "$OUT" | tail -4
  step_end "binary runner" "PASS" "20 ops over TCP"
else
  echo "$OUT" | tail -10
  step_end "binary runner" "FAIL" "see output"
fi

step_start "6. Синтаксис agent_lua.lua (Lua 5.1)"
if [ "$LUPA_OK" != 1 ]; then
  echo "[SKIP] lupa missing"
  step_end "agent_lua syntax" "PASS" "skipped (no lupa)"
else
  if python3 - <<'PY' 2>&1
from pathlib import Path
from lupa.lua51 import LuaRuntime
src = Path("agent_lua.lua").read_text(encoding="utf-8")
compiler = LuaRuntime().eval("loadstring")
res = compiler(src, "agent_lua.lua")
assert not (isinstance(res, tuple) and res[0] is None), res
print("agent_lua.lua: Lua 5.1 compile OK")
PY
  then
    step_end "agent_lua syntax" "PASS" "Lua 5.1 compile ok"
  else
    step_end "agent_lua syntax" "FAIL" "compile error"
  fi
fi

step_start "7. Full-chain: наша kernel-цепочка через TCP-примитив"
if OUT=$(python3 demo-fullchain.py 2>&1); then
  echo "$OUT" | grep -E 'ИТОГ|full-chain через' | head -3
  step_end "full-chain TCP" "PASS" "$(echo "$OUT" | grep -o 'стадий=[0-9]*, OK=[0-9]*, DEGRADED=[0-9]*, FAIL=[0-9]*' | head -1)"
else
  echo "$OUT" | tail -8
  step_end "full-chain TCP" "FAIL" "see output"
fi

step_start "8. Контроль контракта: kernel --dry-run-objreply"
KERNEL_JS="$SCRIPT_DIR/../../jb1422/kernel/relapse1422.js"
if [ ! -f "$KERNEL_JS" ]; then
  step_end "kernel objreply" "PASS" "skipped (kernel/ не найден)"
elif ! command -v node >/dev/null 2>&1; then
  step_end "kernel objreply" "PASS" "skipped (нет node)"
elif OUT=$(timeout 180 node "$KERNEL_JS" --dry-run-objreply 2>&1); then
  echo "$OUT" | grep -E 'ИТОГ' | tail -1
  if printf '%s' "$OUT" | grep -q 'стадий=13, OK=13, DEGRADED=0, FAIL=0'; then
    step_end "kernel objreply" "PASS" "чистый {ptr,bytes}: 13/13/0/0"
  else
    step_end "kernel objreply" "FAIL" "контракт {ptr,bytes} сломан в kernel"
  fi
else
  echo "$OUT" | tail -5
  step_end "kernel objreply" "FAIL" "see output"
fi

echo
echo "==================== SUMMARY ===================="
for i in "${!NAMES[@]}"; do
  printf '%-22s %-5s %s\n' "${NAMES[$i]}" "${STATUSES[$i]}" "${DETAILS[$i]}"
done
echo "------------------------------------------------"
echo "steps: $TOTAL, failed: $FAILED"
if [ "$FAILED" -eq 0 ]; then echo "RESULT: ALL PASS"; exit 0; fi
echo "RESULT: FAILED ($FAILED of $TOTAL)"; exit 1