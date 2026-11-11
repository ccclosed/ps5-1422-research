#!/bin/bash
# run_qemu.sh — воспроизводимый прогон PS5-кода на QEMU TCG (AVX) с моками импортов.
# Использование: ./run_qemu.sh [--real-nid] [--vtable]
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
GAME=/home/oleg/Документы/ps5semulator/games/cyberpunk/anyps5-run
ELF="$GAME/eboot.elf"
MODE="${1:-}"

# 1. манифест импортов: stub -> GOT -> library:NID (из реестра проекта)
python3 - "$GAME/cyberpunk2077.registry.json" "$HERE/output/imports.tsv" <<'PY'
import json, sys
reg = json.load(open(sys.argv[1]))
rows = []
for e in reg:
    if e.get('relocationType') != 'R_X86_64_JUMP_SLOT':
        continue
    cs = e.get('callSites') or []
    if not cs:
        continue
    lib = e.get('library') or '-'
    nid = (e.get('nid') or '-').split('#')[0] or '-'
    got = int(e['targetOffset'], 16); rel = int(e['relocationOffset'], 16)
    weak = 1 if e.get('weak') else 0
    for stub in cs:
        rows.append((int(stub, 16), got, rel, lib, nid, weak))
rows.sort()
with open(sys.argv[2], 'w') as f:
    f.write('# stub_va\tgot_va\trelocation_va\tlibrary\tnid\tweak\n')
    for r in rows:
        f.write('%#x\t%#x\t%#x\t%s\t%s\t%d\n' % r)
print('imports.tsv:', len(rows), 'строк')
PY

# 2. харнесс
gcc -O2 -fPIE -pie -o "$HERE/qemu_harness" "$HERE/qemu_harness.c"

# 3. прогон под qemu TCG с подсчётом инструкций в диапазоне образа
LOG="$HERE/output/qemu-run.log"
rm -f "$LOG"
case "$MODE" in
  --real-nid) EXTRA_ENV="" ;;
  --vtable)   EXTRA_ENV="PS5_NO_REAL=1 PS5_MOCK_PTR=1 PS5_SEED_VTABLE=1" ;;
  *)          EXTRA_ENV="PS5_NO_REAL=1 PS5_MOCK_PTR=1" ;;
esac
env $EXTRA_ENV qemu-x86_64 -B 0x4000000000 -one-insn-per-tb \
    -d exec -dfilter 0x0+0xafb7470 -D "$LOG" \
    "$HERE/qemu_harness" "$ELF" entry "$HERE/output/imports.tsv" || true
echo "инструкций в диапазоне образа PS5: $(grep -c '^Trace' "$LOG")"
echo "AVX-инструкция 0xcb0c5c исполнена: $(grep -c 'cb0c5c' "$LOG")"
