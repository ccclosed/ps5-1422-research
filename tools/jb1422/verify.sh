#!/usr/bin/env bash
# jb1422/verify.sh — сверка sha256 всех файлов пакета с MANIFEST.sha256.
#
#   ./verify.sh              # проверить целостность (exit 0 = всё совпало)
#   ./verify.sh --quiet      # только итог (для selftest.sh)
#   ./verify.sh --rebuild    # пересобрать MANIFEST.sha256 по текущим файлам
#   ./verify.sh --list       # показать, что покрыто манифестом
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" || exit 1
MAN="MANIFEST.sha256"
MODE="check"; [ "${1:-}" = "--quiet" ] && MODE="quiet"; [ "${1:-}" = "--rebuild" ] && MODE="rebuild"; [ "${1:-}" = "--list" ] && MODE="list"

# набор файлов пакета: всё, кроме логов и самого манифеста
collect() {
  find . \( -path ./logs -o -path ./MANIFEST.sha256 \) -prune -o -type f -print \
    | sed 's|^\./||' | LC_ALL=C sort
}

if [ "$MODE" = "rebuild" ]; then
  { collect | while IFS= read -r f; do sha256sum "$f"; done; } >"$MAN.$$" \
    && mv "$MAN.$$" "$MAN"
  echo "[verify] манифест пересобран: $MAN ($(wc -l <"$MAN") файлов)"
  exit 0
fi

if [ ! -f "$MAN" ]; then
  echo "[verify] НЕТ $MAN — пересоберите: ./verify.sh --rebuild" >&2
  exit 2
fi

if [ "$MODE" = "list" ]; then
  echo "[verify] манифест покрывает $(wc -l <"$MAN") файлов:"
  awk '{print "  " $2}' "$MAN" | head -200
  exit 0
fi

OUT="$(sha256sum -c "$MAN" 2>&1)"; RC=$?
TOTAL="$(printf '%s\n' "$OUT" | grep -c ': OK$')"
BADLINES="$(printf '%s\n' "$OUT" | grep -v ': OK$' | grep -v '^$')"
BADN="$(printf '%s\n' "$BADLINES" | grep -c . )"
if [ "$RC" -eq 0 ] && [ -z "$BADLINES" ]; then
  [ "$MODE" = "quiet" ] || echo "[verify] OK: $TOTAL файлов, sha256 совпали"
  exit 0
fi
echo "[verify] FAIL: OK=$TOTAL, проблем=$BADN" >&2
printf '%s\n' "$BADLINES" | head -40 >&2
echo "[verify] подсказка: если файлы пакета менялись намеренно — ./verify.sh --rebuild" >&2
exit 1