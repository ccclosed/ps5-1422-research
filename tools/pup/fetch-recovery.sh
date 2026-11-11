#!/usr/bin/env bash
# Скачивание recovery-образа 14.22 (~1.42 ГБ) с серверов Sony.
set -uo pipefail
cd /home/oleg/Документы/ps5semulator/ps5jb

SUPPORT="https://www.playstation.com/en-us/support/hardware/ps5/system-software/"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0"

echo "== 1. достаю URL recovery со страницы поддержки =="
curl -s -m 60 -A "$UA" "$SUPPORT" -o /tmp/support.html -w "support page: %{http_code} %{size_download} байт\n"
grep -oE 'https?://[^"<> ]*(rec_|sys_)[0-9a-f]{16,}[^"<> ]*PS5UPDATE\.PUP' /tmp/support.html | sort -u > /tmp/urls.txt || true
echo "найдено ссылок: $(wc -l < /tmp/urls.txt)"
head -4 /tmp/urls.txt

REC="$(grep -m1 'rec_' /tmp/urls.txt || true)"
if [ -z "$REC" ]; then
  echo "!! rec-ссылка на странице не найдена (страница могла быть отдана без JS)"
  exit 1
fi
echo "== 2. recovery URL: $REC =="
curl -sI -m 30 "$REC" | head -6

echo "== 3. качаю =="
curl -L --fail --retry 5 --retry-delay 3 -C - -o fw/PS5UPDATE-rec-2026_1027.PUP "$REC" \
     -w "curl: http=%{http_code} скачано=%{size_download} за %{time_total}s скорость=%{speed_download}B/s\n"

echo "== 4. хеши =="
ls -la fw/PS5UPDATE-rec-2026_1027.PUP
md5sum fw/PS5UPDATE-rec-2026_1027.PUP
sha256sum fw/PS5UPDATE-rec-2026_1027.PUP
xxd -l 32 fw/PS5UPDATE-rec-2026_1027.PUP
