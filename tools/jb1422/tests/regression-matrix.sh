#!/usr/bin/env bash
# jb1422/tests/regression-matrix.sh — матрица регрессий kernel-цепочки.
#
# Зачем: сломанная цепочка должна падать здесь, а не на консоли. Прогоняет все
# поддерживаемые режимы kernel-модуля + сквозной TCP-прогон через наш примитив и
# сверяет ФАКТ с ОЖИДАНИЕМ. exit 0 — только если совпало всё.
#
#   ./regression-matrix.sh            # полная матрица
#   ./regression-matrix.sh --fast     # без demo-fullchain.py (не поднимает TCP)
#
# Ожидания (зафиксированы по текущему поведению; менять только осознанно):
#   --dry-run             exit 0, done=true            (все стадии исполнены)
#   --dry-run-full        exit 0, done=true
#   --dry-run-no-oid      exit 0, done=true            (oid нет → DEGRADED-fallback)
#   --dry-run-kaslr-fail  exit 0, «остановлена»        (self-DoS guard, стадия 4 FAIL)
#   demo-fullchain.py     exit 0, «[OK] full-chain зелёный»
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
LOGDIR="$ROOT/logs"; mkdir -p "$LOGDIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="$LOGDIR/regression-matrix-$TS.log"
FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

ROWS=(); FAILS=0
say() { printf '%s\n' "$*" | tee -a "$LOG"; }

# run_mode <имя> <ожидание-текст> <проверка-тип> <команда...>
# типы проверки: done | stopped | okline
run_mode() {
  local name="$1" expect="$2" kind="$3"; shift 3
  { echo; echo "===== $name"; echo "+ $*"; } >>"$LOG"
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  printf '%s\n' "$out" >>"$LOG"; echo "----- exit=$rc" >>"$LOG"
  local fact="exit=$rc" verdict=FAIL why=""
  case "$kind" in
    done)
      if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'done=true'; then verdict=PASS; fact="exit=0, done=true"
      else
        printf '%s' "$out" | grep -q 'done=true' || why="нет done=true"
        [ "$rc" -ne 0 ] && why="${why:+$why; }exit=$rc"
        fact="exit=$rc${why:+, $why}"
      fi ;;
    stopped)
      if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'остановлена'; then verdict=PASS; fact="exit=0, остановлена на стадии"
      else fact="exit=$rc, нет 'остановлена'"; fi ;;
    okline)
      if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q '\[OK\] full-chain зелёный'; then verdict=PASS; fact="exit=0, full-chain зелёный"
      else fact="exit=$rc, нет '[OK] full-chain зелёный'"; fi ;;
  esac
  [ "$verdict" = FAIL ] && FAILS=$((FAILS + 1))
  ROWS+=("$verdict|$name|$expect|$fact")
  echo "$out" >"$LOGDIR/last-$name.log"
}

echo "════════════════════════════════════════════════════════════════════"
echo " jb1422 regression-matrix — $(date '+%Y-%m-%d %H:%M:%S')"
echo " отчёт: $LOG"
echo "════════════════════════════════════════════════════════════════════"

cd "$ROOT" || exit 2

run_mode "--dry-run"            "exit 0, done=true"     done    node kernel/relapse1422.js --dry-run
run_mode "--dry-run-full"       "exit 0, done=true"     done    node kernel/relapse1422.js --dry-run-full
run_mode "--dry-run-no-oid"     "exit 0, done=true"     done    node kernel/relapse1422.js --dry-run-no-oid
run_mode "--dry-run-kaslr-fail" "exit 0, остановлена"   stopped node kernel/relapse1422.js --dry-run-kaslr-fail

if [ "$FAST" -eq 0 ]; then
  DEMO="$ROOT/../lua-lab/bundle-1422/demo-fullchain.py"
  if [ -f "$DEMO" ]; then
    run_mode "demo-fullchain"     "exit 0, full-chain зелёный" okline python3 "$DEMO"
  else
    ROWS+=("SKIP|demo-fullchain|exit 0|нет $DEMO")
  fi
else
  ROWS+=("SKIP|demo-fullchain|—|пропущен (--fast)")
fi

echo
printf "│ %-20s │ %-22s │ %-34s │ %s\n" "режим" "ожидание" "факт" "итог"
printf "├%s┼%s┼%s┼%s\n" "──────────────────────" "────────────────────────" "────────────────────────────────────" "───────"
for r in "${ROWS[@]}"; do
  IFS='|' read -r st name expect fact <<<"$r"
  printf "│ %-20s │ %-22s │ %-34s │ %s\n" "$name" "$expect" "$fact" "$st"
done
TOTAL=${#ROWS[@]}
PASSES=$(printf '%s\n' "${ROWS[@]}" | grep -c '^PASS|' || true)
SKIPS=$(printf '%s\n' "${ROWS[@]}" | grep -c '^SKIP|' || true)
echo
echo "ИТОГО: режимов=$TOTAL PASS=$PASSES FAIL=$FAILS SKIP=$SKIPS"
echo "лог: $LOG"
if [ "$FAILS" -eq 0 ]; then
  echo "REGRESSION_MATRIX: PASS"
  exit 0
fi
echo "REGRESSION_MATRIX: FAIL — поведение разошлось с ожиданием"
exit 1