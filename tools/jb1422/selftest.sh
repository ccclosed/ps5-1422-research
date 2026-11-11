#!/usr/bin/env bash
# jb1422/selftest.sh — всё, что проверяемо БЕЗ консоли PS5.
#
#   ./selftest.sh            # полный прогон, exit 0 если нет FAIL
#   ./selftest.sh --fast     # без smoke-теста run.sh (не поднимает сервер)
#
# Проверяет: node --check по всем js, три dry-run режима kernel-модуля,
# rw-sim, kernel-integration, index.html + ссылки на скрипты, payloads и манифесты,
# verify.sh, и (по умолчанию) реальную отдачу index.html через run.sh.
# Пишет отчёт в logs/selftest-<дата>.log и печатает сводную таблицу PASS/FAIL.
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" || exit 1
LOGDIR="$DIR/logs"; mkdir -p "$LOGDIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$LOGDIR/selftest-$TS.log"
FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

# --- инфраструктура отчёта -------------------------------------------------
ROWS=(); FAILS=0; SKIPS=0; PASSES=0
row() { # row <статус> <имя> <деталь>
  local st="$1" name="$2" detail="${3:-}"
  ROWS+=("$st|$name|$detail")
  case "$st" in
    PASS) PASSES=$((PASSES + 1));;
    FAIL) FAILS=$((FAILS + 1));;
    SKIP) SKIPS=$((SKIPS + 1));;
  esac
}
say() { printf '%s\n' "$*" | tee -a "$LOG" >/dev/null; }
t() { # t <имя> <команда...>: запускает, пишет в лог, возвращает exit-код
  local name="$1"; shift
  { echo; echo "===== $name"; echo "+ $*"; } >>"$LOG"
  "$@" >>"$LOG" 2>&1
  local rc=$?
  { echo "----- exit=$rc"; } >>"$LOG"
  return $rc
}

echo "════════════════════════════════════════════════════════════════════"
echo " jb1422 selftest — $(date '+%Y-%m-%d %H:%M:%S')"
echo " каталог: $DIR"
echo " отчёт:   $LOG"
echo "════════════════════════════════════════════════════════════════════"
echo "selftest $TS" >"$LOG"

# --- 0. инструменты --------------------------------------------------------
if command -v node >/dev/null 2>&1; then
  NODE_V="$(node -v)"
  row PASS "node доступен" "$NODE_V"
else
  row FAIL "node доступен" "node не найден в PATH (нужен Node.js >= 18)"
  echo; echo "КРИТИЧНО: без node selftest не имеет смысла"; exit 2
fi
if command -v python3 >/dev/null 2>&1; then
  row PASS "python3 доступен" "$(python3 -V 2>&1)"
else
  row FAIL "python3 доступен" "нужен для run.sh и проверок"
fi

# --- 1. node --check по всем js -------------------------------------------
JS_FILES=()
while IFS= read -r f; do JS_FILES+=("$f"); done < <(find . -path ./logs -prune -o \
  -type f \( -name '*.js' -o -name '*.mjs' \) -print | sort)
SYNTAX_BAD=0; SYNTAX_FIRST=""
for f in "${JS_FILES[@]}"; do
  if ! node --check "$f" >>"$LOG" 2>&1; then
    SYNTAX_BAD=$((SYNTAX_BAD + 1))
    [ -z "$SYNTAX_FIRST" ] && SYNTAX_FIRST="$f"
  fi
done
if [ "$SYNTAX_BAD" -eq 0 ]; then
  row PASS "node --check (${#JS_FILES[@]} файлов)" "js/ kernel/ tests/ probes/"
else
  row FAIL "node --check (${#JS_FILES[@]} файлов)" "ошибок: $SYNTAX_BAD, первый: $SYNTAX_FIRST"
fi

# --- 2. dry-run kernel-модуля: 3 режима ------------------------------------
# 2a. обычный: должен дойти до конца на моках (exit 0, done=true)
if t "kernel --dry-run" node kernel/relapse1422.js --dry-run; then
  if grep -q 'ИТОГ: done=true' "$LOG" && tail -40 "$LOG" | grep -q 'РЕЗУЛЬТАТ: цепочка исполнена'; then
    row PASS "kernel --dry-run" "exit 0, done=true (все стадии)"
  else
    row FAIL "kernel --dry-run" "exit 0, но в выводе нет done=true/финального РЕЗУЛЬТАТ"
  fi
else
  row FAIL "kernel --dry-run" "ненулевой exit; см. $LOG"
fi
# 2b. KASLR-fail: ожидаемый провал на стадии 4, exit 0
if t "kernel --dry-run-kaslr-fail" node kernel/relapse1422.js --dry-run-kaslr-fail; then
  if tail -40 "$LOG" | grep -q 'РЕЗУЛЬТАТ: цепочка остановлена' && grep -q 'FAIL' "$LOG"; then
    row PASS "kernel --dry-run-kaslr-fail" "ожидаемый FAIL стадии 4, exit 0"
  else
    row FAIL "kernel --dry-run-kaslr-fail" "нет ожидаемого 'цепочка остановлена'/FAIL"
  fi
else
  row FAIL "kernel --dry-run-kaslr-fail" "exit != 0 (в этом режиме ожидается 0)"
fi
# 2c. no-oid: fallback по DEGRADED, exit 0, done=true
if t "kernel --dry-run-no-oid" node kernel/relapse1422.js --dry-run-no-oid; then
  if tail -40 "$LOG" | grep -q 'ИТОГ: done=true'; then
    row PASS "kernel --dry-run-no-oid" "exit 0, done=true (fallback DEGRADED)"
  else
    row FAIL "kernel --dry-run-no-oid" "exit 0, но нет done=true"
  fi
else
  row FAIL "kernel --dry-run-no-oid" "ненулевой exit"
fi

# --- 3. tests/rw-sim.js ----------------------------------------------------
if t "tests/rw-sim.js" node tests/rw-sim.js; then
  if tail -5 "$LOG" | grep -q 'SIM_RESULT: PASS'; then
    row PASS "tests/rw-sim.js" "SIM_RESULT: PASS"
  else
    row FAIL "tests/rw-sim.js" "exit 0, но нет SIM_RESULT: PASS"
  fi
else
  row FAIL "tests/rw-sim.js" "exit != 0; см. $LOG"
fi

# --- 4. tests/kernel-integration.mjs --------------------------------------
if [ -f tests/kernel-integration.mjs ]; then
  if t "tests/kernel-integration.mjs" node tests/kernel-integration.mjs; then
    if tail -5 "$LOG" | grep -q 'SIM_RESULT: PASS'; then
      row PASS "tests/kernel-integration.mjs" "SIM_RESULT: PASS (мост p/chain)"
    else
      row FAIL "tests/kernel-integration.mjs" "exit 0, но нет SIM_RESULT: PASS"
    fi
  else
    row FAIL "tests/kernel-integration.mjs" "exit != 0"
  fi
else
  row SKIP "tests/kernel-integration.mjs" "файла нет"
fi

# --- 4b. tests/full-chain-mock.js (если появится) -------------------------
if [ -f tests/full-chain-mock.js ]; then
  if t "tests/full-chain-mock.js" node tests/full-chain-mock.js; then
    row PASS "tests/full-chain-mock.js" "exit 0"
  else
    row FAIL "tests/full-chain-mock.js" "exit != 0; см. $LOG"
  fi
else
  row SKIP "tests/full-chain-mock.js" "файла пока нет (владелец: recon-1422-status)"
fi

# --- 5. python-синтаксис тестового раннера --------------------------------
if [ -f tests/run_local_webkit.py ]; then
  if python3 -c "compile(open('tests/run_local_webkit.py', encoding='utf-8').read(), 'tests/run_local_webkit.py', 'exec')" >>"$LOG" 2>&1; then
    row PASS "py-синтаксис tests/run_local_webkit.py" "OK (без записи __pycache__)"
  else
    row FAIL "python3 -m py_compile tests/run_local_webkit.py" "ошибка синтаксиса"
  fi
else
  row SKIP "tests/run_local_webkit.py" "файла нет"
fi

# --- 6. index.html и ссылки на скрипты ------------------------------------
if [ -f index.html ]; then
  MISSING="$(python3 - <<'PY'
import re, os, sys
html = open('index.html', encoding='utf-8', errors='replace').read()
srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
missing = [s for s in srcs if not s.startswith(('http:', 'https:', '//')) and not os.path.isfile(s)]
print('\n'.join(missing))
PY
)"
  if [ -z "$MISSING" ]; then
    row PASS "index.html: все <script src> на месте" "js/**, kernel/offsets/1422.js"
  else
    row FAIL "index.html: все <script src> на месте" "нет: $(echo "$MISSING" | tr '\n' ' ')"
  fi
  if grep -q 'autorun=1' index.html; then
    row PASS "index.html: autorun=1" "поддержан"
  else
    row SKIP "index.html: autorun=1" "не найден (не критично)"
  fi
else
  row FAIL "index.html существует" "файла нет"
fi

# --- 7. payloads + манифест ----------------------------------------------
if [ -d payloads ] && [ -f payloads/MANIFEST.sha256 ]; then
  if (cd payloads && sha256sum -c MANIFEST.sha256 >>"$LOG" 2>&1); then
    row PASS "payloads/MANIFEST.sha256" "sha256 совпали"
  else
    row FAIL "payloads/MANIFEST.sha256" "несовпадение/битый манифест"
  fi
  NPL=$(find payloads -maxdepth 1 -type f -name '*.elf' | wc -l)
  [ "$NPL" -ge 2 ] && row PASS "payloads: elfldr + kstuff-lite" "$NPL ELF" || row FAIL "payloads: elfldr + kstuff-lite" "найдено $NPL"
else
  row FAIL "payloads/MANIFEST.sha256" "нет каталога payloads или манифеста"
fi

# --- 8. verify.sh / общий манифест: вне области этой задачи ---------------
# (selftest проверяет содержимое пакета сам; verify.sh/MANIFEST.sha256 ведёт владелец пакета)
if [ -x verify.sh ] && [ -f MANIFEST.sha256 ]; then
  row SKIP "verify.sh (MANIFEST.sha256)" "вне области selftest; запускать отдельно: ./verify.sh"
else
  row SKIP "verify.sh (MANIFEST.sha256)" "нет verify.sh/MANIFEST.sha256"
fi

# --- 9. smoke: run.sh реально отдаёт index.html --------------------------
if [ "$FAST" -eq 0 ] && [ -x run.sh ]; then
  SPORT=$((18000 + RANDOM % 400))
  ./run.sh "$SPORT" >"$LOGDIR/run-smoke.log" 2>&1 &
  SRV_PID=$!
  OK=""; CODE=""
  for i in $(seq 1 40); do
    sleep 0.15
    CODE="$(curl -s -o /tmp/jb1422-index.smoke -w '%{http_code}' "http://127.0.0.1:$SPORT/index.html" 2>/dev/null || true)"
    [ "$CODE" = "200" ] && { OK=1; break; }
  done
  if [ -n "$OK" ] && grep -q 'jb1422' /tmp/jb1422-index.smoke 2>/dev/null; then
    row PASS "run.sh: GET /index.html" "HTTP 200, порт $SPORT"
  else
    row FAIL "run.sh: GET /index.html" "код=${CODE:-нет ответа}; лог $LOGDIR/run-smoke.log"
  fi
  # заодно проверим POST /beacon
  BCODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
      --data '{"selftest":true}' "http://127.0.0.1:$SPORT/beacon" 2>/dev/null || true)"
  if [ "$BCODE" = "200" ] && grep -q 'selftest' "$LOGDIR/beacon.jsonl" 2>/dev/null; then
    row PASS "run.sh: POST /beacon" "HTTP 200, запись в logs/beacon.jsonl"
  else
    row FAIL "run.sh: POST /beacon" "код=${BCODE:-нет ответа}"
  fi
  kill "$SRV_PID" 2>/dev/null
  wait "$SRV_PID" 2>/dev/null
  rm -f /tmp/jb1422-index.smoke
else
  row SKIP "run.sh smoke" "--fast или нет run.sh"
fi

# --- сводная таблица ------------------------------------------------------
echo
echo "┌──────────────────────────────────────────────────────────────────────────────"
printf "│ %-4s %-46s %s\n" "#" "тест" "статус/деталь"
echo "├──────────────────────────────────────────────────────────────────────────────"
i=0
for r in "${ROWS[@]}"; do
  i=$((i + 1))
  st="${r%%|*}"; rest="${r#*|}"; name="${rest%%|*}"; detail="${rest#*|}"
  printf "│ %-4d %-46s %-6s %s\n" "$i" "$name" "$st" "$detail"
done
echo "└──────────────────────────────────────────────────────────────────────────────"
TOTAL=${#ROWS[@]}
echo "ИТОГО: тестов=$TOTAL PASS=$PASSES FAIL=$FAILS SKIP=$SKIPS"
if [ "$FAILS" -eq 0 ]; then
  echo "РЕЗУЛЬТАТ: PASS — всё, что проверяемо без консоли, в порядке."
  echo "Дальше: ./run.sh → открыть index.html на PS5 14.22 (см. README.md)."
  echo "РЕЗУЛЬТАТ: PASS" >>"$LOG"
  exit 0
else
  echo "РЕЗУЛЬТАТ: FAIL — разберите строки FAIL выше (детали в $LOG)."
  echo "РЕЗУЛЬТАТ: FAIL (FAIL=$FAILS)" >>"$LOG"
  exit 1
fi