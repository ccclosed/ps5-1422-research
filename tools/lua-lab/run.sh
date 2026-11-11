#!/usr/bin/env bash
# Lua-lab: run every PC-side check of the Lua/9026 vector in one command.
#
#   1. protocol self-test   mock loader on 127.0.0.1:9026 + client frame/decoder checks
#   2. Lua 5.1 syntax gate  lupa compiles the whole research probe corpus
#   3. offline suite        the research checkout's 356 hardware-free tests
#
# Usage:
#   ./run.sh                 # all three, summary at the end
#   ./run.sh --install-deps  # install lupa==2.6 first (pip --user, no root)
#   ./run.sh --repo PATH     # use another PS5-14.10-Research checkout
#   ./run.sh --port 9026     # preferred mock-loader port
#
# Exit code 0 only when every step passed.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PS5JB_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_DEFAULT="$PS5JB_DIR/recon/_src/lua/zz"
OUT_DIR="$SCRIPT_DIR/output"

REPO="$REPO_DEFAULT"
PORT=9026
INSTALL_DEPS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --install-deps) INSTALL_DEPS=1; shift ;;
    --repo) REPO="${2:?--repo needs a path}"; shift 2 ;;
    --port) PORT="${2:?--port needs a number}"; shift 2 ;;
    -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/run.log"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

TOTAL=0
FAILED=0
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

echo "PS5 Lua vector lab — $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "  lab:  $SCRIPT_DIR"
echo "  repo: $REPO"
echo "  log:  $LOG"
echo "  python: $(python3 -V 2>&1)"

# ---------------------------------------------------------------- step 0: env
step_start "0. environment"
ENV_OK=1
if [ ! -d "$REPO" ]; then
  echo "[warn] research checkout not found at $REPO (steps 2-3 will be skipped)"
  ENV_OK=0
fi
python3 -c 'import sys; print("python", sys.version.split()[0])'
if python3 -c 'from lupa.lua51 import LuaRuntime; LuaRuntime().eval("_VERSION")' 2>/dev/null; then
  LUPA_OK=1
  echo "lupa: OK ($(python3 -c 'from lupa.lua51 import LuaRuntime; print(LuaRuntime().eval("_VERSION"))'))"
else
  LUPA_OK=0
  echo "lupa: MISSING"
  if [ "$INSTALL_DEPS" = "1" ]; then
    echo "installing lupa==2.6 ..."
    python3 -m pip install --user lupa==2.6 >/dev/null 2>&1 && LUPA_OK=1
    [ "$LUPA_OK" = "1" ] && echo "lupa: installed"
  fi
fi
if [ "$LUPA_OK" = "1" ]; then step_end "environment" "PASS" "python+lupa ready"; else step_end "environment" "FAIL" "lupa missing: ./run.sh --install-deps"; fi

# ------------------------------------------------------- step 1: mock protocol
step_start "1. mock loader 9026 (frames 8-byte LE / 0xFFFFFFFF+cmd / 0x13371337+mcontext)"
if python3 "$SCRIPT_DIR/protocol_selftest.py" --port "$PORT" --quiet; then
  step_end "protocol self-test" "PASS" "mock 9026 answered all frame kinds"
else
  step_end "protocol self-test" "FAIL" "see output above"
fi

# --------------------------------------------------------- step 2: Lua 5.1 gate
step_start "2. Lua 5.1 syntax gate over probes/ (lupa)"
if [ "$LUPA_OK" != "1" ]; then
  step_end "lua 5.1 syntax" "FAIL" "lupa missing"
elif [ "$ENV_OK" != "1" ]; then
  step_end "lua 5.1 syntax" "FAIL" "checkout missing"
else
  SYNTAX_OUT=$(python3 "$SCRIPT_DIR/syntax_lua51.py" --probes "$REPO/probes" 2>&1)
  echo "$SYNTAX_OUT"
  if printf '%s' "$SYNTAX_OUT" | grep -q 'failures=0'; then
    CNT=$(printf '%s' "$SYNTAX_OUT" | sed -n 's/^Compiled \([0-9]*\) .*/\1/p')
    step_end "lua 5.1 syntax" "PASS" "${CNT} probes compiled, 0 failures"
  else
    step_end "lua 5.1 syntax" "FAIL" "compile failures"
  fi
fi

# ------------------------------------------------------------ step 3: offline
step_start "3. hardware-free suite (checkout tools/verify_offline.py)"
if [ "$ENV_OK" != "1" ]; then
  step_end "offline suite" "FAIL" "checkout missing"
else
  SUITE_OUT=$(python3 "$SCRIPT_DIR/offline_suite.py" --repo "$REPO" 2>&1)
  echo "$SUITE_OUT"
  if printf '%s' "$SUITE_OUT" | grep -q 'RESULT: PASS'; then
    STEP_LINE=$(printf '%s' "$SUITE_OUT" | grep -m1 '^Ran ')
    step_end "offline suite" "PASS" "${STEP_LINE}"
  else
    step_end "offline suite" "FAIL" "see output above"
  fi
fi

# ---------------------------------------------------------------- summary
echo
echo "==================== SUMMARY ===================="
for i in "${!NAMES[@]}"; do
  printf '%-22s %-5s %s\n' "${NAMES[$i]}" "${STATUSES[$i]}" "${DETAILS[$i]}"
done
echo "------------------------------------------------"
echo "steps: $TOTAL, failed: $FAILED"
if [ "$FAILED" -eq 0 ]; then
  echo "RESULT: ALL PASS"
  exit 0
else
  echo "RESULT: FAILED ($FAILED of $TOTAL)"
  exit 1
fi