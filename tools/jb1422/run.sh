#!/usr/bin/env bash
# jb1422/run.sh — одна команда: поднять локальный стенд для цепочки PS5 14.22.
#
#   ./run.sh            # порт 8080
#   PORT=9000 ./run.sh  # другой порт
#   ./run.sh 9000       # порт аргументом
#
# Печатает адрес, который надо открыть на консоли, и что должно появиться в логе.
# Служит index.html, js/**, kernel/**, probes/**, payloads/** и принимает POST /beacon
# (пишет в logs/beacon.jsonl). Остановка — Ctrl-C.
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-${PORT:-8080}}"
LOGDIR="$DIR/logs"
BEACON="$LOGDIR/beacon.jsonl"
mkdir -p "$LOGDIR" || { echo "не могу создать $LOGDIR" >&2; exit 1; }

# --- локальные IP (что печатать консоли) ---
IPS=""
if command -v hostname >/dev/null 2>&1; then
  IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | head -5)"
fi
if [ -z "$IPS" ] && command -v ip >/dev/null 2>&1; then
  IPS="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
fi
[ -z "$IPS" ] && IPS="127.0.0.1"

cat <<EOF
════════════════════════════════════════════════════════════════════════
 jb1422 — стенд цепочки PS5 14.22 (userland R/W → kernel R/W)
════════════════════════════════════════════════════════════════════════
 Каталог : $DIR
 Порт    : $PORT
 Логи    : $LOGDIR/beacon.jsonl (POST /beacon), logs/selftest-*.log
EOF
echo " Открыть на PS5 14.22 (User's Guide / браузер):"
for ip in $IPS; do
  echo "   ▶  http://$ip:$PORT/index.html"
  echo "      с автозапуском: http://$ip:$PORT/index.html?autorun=1"
done
echo "   ▶  локально (ПК, WebKitGTK): http://127.0.0.1:$PORT/index.html"
cat <<EOF

 Что должно появиться в логе (на консоли 14.22):
   STAGE 0: OK  ...            — окружение/UA
   STAGE 1: OK  ...            — контроли canvas
   STAGE H: OK  ...            — harness self-test (12/12)
   STAGE 2: OK  ...            — Canvas getContext UAF жив (главный признак входа)
   STAGE 3-5: OK ...           — same-type reclaim + alias R/W
   STAGE 9: BLOCKED ...        — ожидаемо: нет leak адреса на публичной поверхности
   STAGE 10-11: BLOCKED ...    — kernel-часть ждёт leak/oid (см. kernel/relapse1422.js)
 На ПК (WebKitGTK 2.52.5) STAGE 2 ожидаемо FAIL — движок уже с фиксом, это не ошибка пакета.

 Кнопки: [▶ Run full chain] [🧪 Harness self-test] [☰ Kernel candidates] [Copy log]
 Проверка перед консолью:  ./selftest.sh   (exit 0 = всё, что проверяемо без консоли, PASS)
 Целостность пакета:       ./verify.sh
 Скопировать payload'ы на консоль (если нужно): payloads/ — elfldr/kstuff-lite + MANIFEST.sha256

 Остановка: Ctrl-C
════════════════════════════════════════════════════════════════════════
EOF

# --- HTTP-сервер: статика + POST /beacon (пишет логи в logs/beacon.jsonl) ---
# Код сервера живёт в here-doc: в самом пакете не появляется временных файлов.
exec python3 - "$DIR" "$PORT" "$BEACON" <<'PY'
import http.server
import json
import os
import posixpath
import sys
import time
import urllib.parse

root, port, beacon = sys.argv[1], int(sys.argv[2]), sys.argv[3]
root = os.path.abspath(root)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=root, **kw)

    def log_message(self, fmt, *args):
        line = "%s %s\n" % (time.strftime("%H:%M:%S"), fmt % args)
        try:
            with open(os.path.join(root, "logs", "requests.log"), "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path not in ("/beacon", "/beacon/"):
            self.send_error(404, "only /beacon accepts POST")
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        body = self.rfile.read(min(n, 4 << 20)) if n else b""
        rec = {"ts": time.time(), "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "remote": self.client_address[0], "bytes": len(body)}
        text = body.decode("utf-8", "replace")
        rec["body"] = text
        try:
            with open(beacon, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass
        # печатаем первую строку beacon'а, чтобы она попала в консоль стенда
        first = text.strip().splitlines()[0][:200] if text.strip() else "(empty)"
        print("[beacon] %s: %s" % (self.client_address[0], first), flush=True)
        payload = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def translate_path(self, path):
        # без выхода за корень пакета
        path = urllib.parse.urlparse(path).path
        path = posixpath.normpath(urllib.parse.unquote(path))
        parts = [p for p in path.split("/") if p and p not in (".", "..")]
        return os.path.join(root, *parts)


class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


try:
    httpd = Server(("0.0.0.0", port), Handler)
except OSError as e:
    print("[!] не удалось занять порт %d: %s" % (port, e), flush=True)
    sys.exit(2)
print("[+] сервер слушает 0.0.0.0:%d, корень=%s" % (port, root), flush=True)
print("[+] журнал beacon: %s" % beacon, flush=True)
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\n[+] остановлено", flush=True)
finally:
    httpd.server_close()
PY