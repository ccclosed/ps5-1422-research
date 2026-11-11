#!/usr/bin/env bash
# Serve the entry-1422 bundle over HTTPS with the project's probe server.
# Reuses tools/probe/serve.py (self-signed cert, /beacon endpoint, JSONL logs).
#
#   ./run.sh              -> https://0.0.0.0:8443/  (logs in tools/probe/logs/)
#   PORT=9443 ./run.sh    -> другой порт
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8443}"
exec python3 "$HERE/../../serve.py" --root "$HERE" --port "$PORT" "$@"