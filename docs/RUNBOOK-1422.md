# RUNBOOK — PS5 14.22 под рукой: вход → kernel-цепочка → проверка JB

> Конкретные шаги на день, когда консоль с 14.22 окажется под рукой. Все пути/команды — из
> реальных файлов пакета (`tools/jb1422`, `tools/lua-lab/bundle-1422`), проверены `selftest.sh`.
> Честный статус: **userland-вход на 14.22 подтверждён**, kernel R/W публично не поднят —
> браузерный путь дойдёт до `STAGE 9 BLOCKED`, путь через YARPE/Lua — до kernel-стадий с
> `DEGRADED`. RUNBOOK фиксирует именно это, а не «готовый джейлбрейк».

## 0. Что нужно и что уже настроено

- Консоль **PS5 14.22**, ПК в той же LAN (без изоляции клиентов); `node -v` ≥18, `python3`.
- Перед выездом: `cd ps5jb/tools/jb1422 && ./selftest.sh` → `EXIT=0`; `cd ps5jb/tools/lua-lab && ./run.sh` → `ALL PASS` (7/7).
- Порты: **8080** стенд, **9026** Lua-loader, **9025** YARPE stage-2, **9139** агент, **9140**
  релей, **9021** elfldr, **1337** ftpsrv, **2323** shsrv.

## 1. Вход A — браузер (Canvas/WebKit, основной)

```bash
cd ps5jb/tools/jb1422
./run.sh                  # PORT=8080 по умолчанию; печатает IP:порт
# на консоли открыть: http://<IP_ПК>:8080/index.html?autorun=1
```
Ожидаемый лог на экране: `STAGE 0: OK` (окружение/UA) → `STAGE 1: OK` (canvas) →
`STAGE H: OK` (harness 12/12) → **`STAGE 2: OK`** (UAF жив = вход есть) → `STAGE 3–5: OK`
(reclaim + alias R/W + self-test) → `STAGE 9: BLOCKED` (нет leak — ожидаемо) →
`STAGE 11: BLOCKED` (kernel ждёт R/W). На ПК `STAGE 2` = `FAIL` (WebKitGTK уже с фиксом) — норма.

Beacon (каждая стадия уходит POST `/beacon`):
```bash
tail -f logs/beacon.jsonl | grep -o 'STAGE-[0-9H]*'   # какие стадии дошли
grep -a 'STAGE-2' logs/beacon.jsonl | tail -1         # статус входа
tail -f logs/requests.log                             # запросы консоли
```
**Вход сработал**, если `STAGE 2: OK` и затем `STAGE 5: OK`.

## 2. Вход B — YARPE (save-эксплойт, даёт `p` в процессе игры)

Нужно: PSN-профиль; игра Ren'Py — **A YEAR OF SPRINGS** (CUSA30428–31) или **Arcade Spirits: The
New Challengers** (CUSA32096/97), PS4-издание; сейв `save.zip` **v3.3.0**
(`https://github.com/Helloyunho/yarpe/releases/tag/v3.3.0`), вставленный через **взломанную PS4 +
Apollo** (hex PSN Account ID должен совпадать).

```bash
# 1) консоль: запустить игру и загрузить сейв -> "Listening on port 9025 for stage 2 payload..."
# 2) ПК: отправить агента (сырой Python, без длины)
python3 - <<'PY'
import socket
src = open("ps5jb/tools/lua-lab/bundle-1422/yarpe_agent.py","rb").read()
s = socket.create_connection(("<IP_PS5>", 9025), timeout=10); s.sendall(src)
print(s.recv(65536).decode("utf-8","replace"))
PY
# в игре: "[agent] yarpe binary agent on 9139"
```
`STAGE`-логов в YARPE нет: успех = READY=1 на :9139 и `p.reason()="yarpe"`.

## 3. Вход B2 — Lua через сохранение (TCP 9026, резерв)

Нужно: **Hamidashi Creative Demo** (CUSA27390, JP-PSN) + сейв, собранный/перешифрованный через
**взломанную PS4 + Apollo** с тем же hex PSN Account ID (`recon/lua-vector.md` §4.1).

```bash
# после загрузки сейва: чёрный экран + "lua loader is loaded" / "Listening on TCP 9026"
cd ps5jb/tools/lua-lab/bundle-1422
python3 bridge_server.py --lua-host <IP_PS5>   # зайдёт на 9026, отправит agent_lua.lua
# мост: HTTP 127.0.0.1:9137, line-агент :9138
```
`agent_lua.lua` на консоли не проверялся (только компиляция Lua 5.1) — это резервный путь.

## 4. Как понять, какой вход сработал

| Признак | Браузер | YARPE | Lua 9026 |
|---|---|---|---|
| Экран/лог | `STAGE 2: OK` в index.html | `[agent] ... on 9139` | `Listening on TCP 9026` + мост READY |
| ПК-проверка | `grep -a 'STAGE-2' logs/beacon.jsonl` | READY=1 на :9139 | `bridge_server.py` без ошибок |
| Что даёт | `p`/`chain` после reclaim | `p` сразу (без leak) | `p` через мост |

## 5. Kernel-цепочка после успешного входа

**A. Браузер:** стартует сам на `STAGE 11` (handoff в `kernel/relapse1422.js`); без leak
останавливается раньше — смотрите `STAGE 9/11` detail.

**B. YARPE (реальный прогон kernel-стадий через TCP-примитив):**
```bash
cd ps5jb/tools/lua-lab/bundle-1422
# терминал 1 — релей ПК -> агент на консоли:
python3 kernel-runner.py --relay --port 9140 --agent-host <IP_PS5> --agent-port 9139
# терминал 2 — наша kernel-цепочка поверх примитива:
node run-relapse-over-tcp.mjs --addr=127.0.0.1:9140
```
Payload берётся сам: `ps5jb/tools/payload/payloads/elfldr-ps5-v0.27.elf` (394 568 Б);
AIO-триггер: `ps5jb/tools/jb1422/payloads/triggers/t1_aio_wait_race.elf`.

Ожидаемая таблица (13 стадий; дома сверять с `node kernel/relapse1422.js --dry-run`):
| n | стадия | ожидание на консоли |
|---|---|---|
| 1 | KASLR candidates (RTM_GET) | OK |
| 2 | pin to single core | OK |
| 3 | arm kernel R/W (waiter+oid/external) | OK/DEGRADED |
| 4 | verify kbase (allproc) | OK |
| 5 | discover gadgets + syscall stubs | OK/DEGRADED |
| 6 | find current process (allproc) | OK |
| 7 | locate pipes | OK |
| 8 | cross pipes (fast R/W) | DEGRADED (fallback) |
| 9 | defuse aio groups | OK |
| 10 | escalate (ucred + security_flags) | OK |
| 11 | launch payload (elfldr :9021 / mmap+launch) | OK если elfldr слушает, иначе DEGRADED |
| 12 | final report (kbase/curproc/ucred/payload) | OK |
| 13 | AIO sanity check (t1 trigger) | OK если триггер приложен, иначе DEGRADED |

Норма: `ИТОГ: done=true, стадий=13, FAIL=0` (DEGRADED 1–2 = fallback, не ошибка).

## 6. Как проверить, что джейлбрейк поднялся

```bash
nc -vz <IP_PS5> 9021                                   # elfldr слушает -> можно слать payload
curl -s --max-time 5 "ftp://<IP_PS5>:1337/" | head      # ftpsrv (листинг)
nc -v <IP_PS5> 2323                                     # shsrv (telnet-шелл), если поднят
# маркеры триггеров (через ftpsrv/shsrv): cat /data/kexpl-t1.log -> DOUBLE-CANCEL-ACCEPTED
```
Порядок триггеров от безопасного: `t5 → t2 → t1 → t3 → t4`. При панике вместо лога — klog/серийная
консоль. Нет файла = триггер не доставлен (не «дыра закрыта»).

## 7. Если упало: причина → что делать

| Где | Типичная причина | Что делать |
|---|---|---|
| STAGE 0 FAIL | не та страница/нет JS | открыть `http://<IP>:8080/index.html`, повторить с `?v=2` |
| STAGE 2 FAIL (консоль) | движок не уязвим/обновлён | сверить FW в STAGE 0; идти через YARPE/Lua (§2–3) |
| STAGE 3/5 DEGRADED | иная раскладка heap, zero-at-free | повторить Run 2–3 раза; пробы `probes/p553`, `p554d` |
| STAGE 9 BLOCKED | нет leak адреса (ожидаемо) | зафиксировать лог; YARPE обходит этот блокер |
| STAGE 11 BLOCKED/DEGRADED | kernel R/W не поднят / elfldr не слушает | поднять elfldr, повторить; браузеру нужен leak |
| kernel 1 FAIL | RTM_GET недоступен | проверить сеть/права, повторить 2 раза |
| kernel 3/4 FAIL | oid/external R/W не вооружён | подать `p` из YARPE (§5B), не браузерный BLOCKED |
| kernel 11 DEGRADED | нет elfldr на :9021 | `nc -vz <IP> 9021`; payload слать после старта elfldr |
| kernel 13 DEGRADED | триггер t1 не приложен | передать `payloads/triggers/t1_aio_wait_race.elf` |
| всё OK, JB не работает | payload не запустился | `cat /data/kexpl-*.log`, проверить :1337/:2323, klog |

## 8. Сбор логов — что присылать

```bash
cd ps5jb/tools/jb1422
# 1) браузерный лог: кнопка «Copy log» в index.html -> /tmp/jb-browser.log
cp logs/beacon.jsonl logs/requests.log /tmp/
node kernel/relapse1422.js --dry-run  > /tmp/kernel-dry-run.log 2>&1
node tests/kernel-integration.mjs     > /tmp/kernel-integration.log 2>&1
for p in 8080 9026 9025 9139 9140 9021 1337 2323; do nc -vz <IP_PS5> $p; done > /tmp/ports.log 2>&1
tar -czf /tmp/jb1422-logs-$(date +%Y%m%d-%H%M).tgz /tmp/jb-browser.log /tmp/beacon.jsonl \
    /tmp/requests.log /tmp/kernel-dry-run.log /tmp/kernel-integration.log /tmp/ports.log
```
Присылать: первую строку `FAIL/BLOCKED` целиком; `STAGE 0` (UA+FW); `logs/beacon.jsonl` прогона; табло kernel-стадий; скриншот экрана консоли; архив логов.